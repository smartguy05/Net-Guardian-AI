"""sFlow v5 parser.

Parses sFlow sampled packet data from network devices.
sFlow provides sampled packet headers and counter data.
"""

import struct
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()

# Ethernet types
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

PROTOCOL_MAP = {
    PROTO_ICMP: "ICMP",
    PROTO_TCP: "TCP",
    PROTO_UDP: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


@register_parser("sflow")
class SFlowParser(BaseParser):
    """Parser for sFlow v5 data.

    sFlow uses sampling to capture packet headers rather than aggregated flows.
    This provides more detail but requires statistical extrapolation.

    Can parse raw binary sFlow datagrams or pre-parsed JSON data.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize sFlow parser.

        Config options:
            include_counters: Include counter samples (default: False)
            exporter_ip: IP of the agent for context
        """
        super().__init__(config)
        self.include_counters = self.config.get("include_counters", False)
        self.exporter_ip = self.config.get("exporter_ip")

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse sFlow data.

        Args:
            raw_data: Either raw bytes (UDP datagram) or parsed JSON dict/list.

        Returns:
            List of ParseResult objects.
        """
        if isinstance(raw_data, bytes):
            return self._parse_binary(raw_data)
        elif isinstance(raw_data, list):
            results = []
            for entry in raw_data:
                if isinstance(entry, dict):
                    result = self._parse_json_entry(entry)
                    if result:
                        results.append(result)
            return results
        elif isinstance(raw_data, dict):
            result = self._parse_json_entry(raw_data)
            return [result] if result else []
        else:
            logger.warning("sflow_parser_invalid_data", data_type=type(raw_data).__name__)
            return []

    def _parse_binary(self, data: bytes) -> list[ParseResult]:
        """Parse binary sFlow v5 datagram.

        sFlow v5 Datagram Header:
        - version: 4 bytes (should be 5)
        - agent_address_type: 4 bytes (1=IPv4, 2=IPv6)
        - agent_address: 4 or 16 bytes
        - sub_agent_id: 4 bytes
        - sequence_number: 4 bytes
        - uptime: 4 bytes
        - num_samples: 4 bytes
        """
        if len(data) < 28:
            logger.warning("sflow_datagram_too_short", length=len(data))
            return []

        offset = 0

        # Version
        version = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4

        if version != 5:
            logger.warning("sflow_unsupported_version", version=version)
            return []

        # Agent address
        addr_type = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4

        if addr_type == 1:  # IPv4
            agent_ip = self._bytes_to_ipv4(data[offset:offset + 4])
            offset += 4
        elif addr_type == 2:  # IPv6
            agent_ip = self._bytes_to_ipv6(data[offset:offset + 16])
            offset += 16
        else:
            agent_ip = "unknown"
            offset += 4

        # Sub-agent ID, sequence, uptime
        sub_agent_id, sequence, uptime = struct.unpack("!III", data[offset:offset + 12])
        offset += 12

        # Number of samples
        num_samples = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4

        timestamp = datetime.now(UTC)
        results = []

        # Parse samples
        for _ in range(num_samples):
            if offset + 8 > len(data):
                break

            # Sample header
            sample_type = struct.unpack("!I", data[offset:offset + 4])[0]
            offset += 4
            sample_length = struct.unpack("!I", data[offset:offset + 4])[0]
            offset += 4

            if offset + sample_length > len(data):
                break

            sample_data = data[offset:offset + sample_length]

            # Enterprise (high 12 bits) and format (low 20 bits)
            enterprise = (sample_type >> 20) & 0xFFF
            format_type = sample_type & 0xFFFFF

            if enterprise == 0:  # Standard sFlow
                if format_type == 1:  # Flow sample
                    result = self._parse_flow_sample(sample_data, agent_ip, timestamp)
                    if result:
                        results.append(result)
                elif format_type == 2:  # Counter sample
                    if self.include_counters:
                        result = self._parse_counter_sample(sample_data, agent_ip, timestamp)
                        if result:
                            results.append(result)
                elif format_type == 3:  # Expanded flow sample
                    result = self._parse_expanded_flow_sample(sample_data, agent_ip, timestamp)
                    if result:
                        results.append(result)

            offset += sample_length

        return results

    def _parse_flow_sample(
        self,
        data: bytes,
        agent_ip: str,
        timestamp: datetime,
    ) -> ParseResult | None:
        """Parse a flow sample record."""
        if len(data) < 32:
            return None

        # Flow sample header
        sequence = struct.unpack("!I", data[0:4])[0]
        _source_id = struct.unpack("!I", data[4:8])[0]  # Available for future use
        sampling_rate = struct.unpack("!I", data[8:12])[0]
        sample_pool = struct.unpack("!I", data[12:16])[0]
        drops = struct.unpack("!I", data[16:20])[0]
        input_if = struct.unpack("!I", data[20:24])[0]
        output_if = struct.unpack("!I", data[24:28])[0]
        num_records = struct.unpack("!I", data[28:32])[0]

        offset = 32
        packet_info = None

        # Parse flow records
        for _ in range(num_records):
            if offset + 8 > len(data):
                break

            record_type = struct.unpack("!I", data[offset:offset + 4])[0]
            record_length = struct.unpack("!I", data[offset + 4:offset + 8])[0]
            offset += 8

            if offset + record_length > len(data):
                break

            record_data = data[offset:offset + record_length]

            # Raw packet header (type 1)
            if record_type == 1 and not packet_info:
                packet_info = self._parse_raw_packet_header(record_data)

            offset += record_length

        if not packet_info:
            return None

        # Build result
        parsed_fields = {
            "sflow_version": 5,
            "agent_ip": agent_ip,
            "sequence": sequence,
            "sampling_rate": sampling_rate,
            "sample_pool": sample_pool,
            "drops": drops,
            "input_interface": input_if,
            "output_interface": output_if,
            **packet_info,
        }

        raw_message = self._build_message(packet_info)
        severity = self._get_sample_severity(packet_info)

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.FLOW,
            severity=severity,
            raw_message=raw_message,
            client_ip=packet_info.get("src_ip"),
            target_ip=packet_info.get("dst_ip"),
            port=packet_info.get("dst_port"),
            protocol=packet_info.get("protocol"),
            action="sample",
            parsed_fields=parsed_fields,
        )

    def _parse_expanded_flow_sample(
        self,
        data: bytes,
        agent_ip: str,
        timestamp: datetime,
    ) -> ParseResult | None:
        """Parse expanded flow sample (similar to flow sample with 64-bit counters)."""
        # Expanded format has similar structure but larger fields
        # For simplicity, delegate to standard parser
        return self._parse_flow_sample(data, agent_ip, timestamp)

    def _parse_counter_sample(
        self,
        data: bytes,
        agent_ip: str,
        timestamp: datetime,
    ) -> ParseResult | None:
        """Parse counter sample record."""
        if len(data) < 12:
            return None

        sequence = struct.unpack("!I", data[0:4])[0]
        source_id = struct.unpack("!I", data[4:8])[0]
        num_records = struct.unpack("!I", data[8:12])[0]

        # Counter samples contain interface statistics
        # Parse basic info and return as system event
        parsed_fields = {
            "sflow_version": 5,
            "sample_type": "counter",
            "agent_ip": agent_ip,
            "sequence": sequence,
            "source_id": source_id,
            "num_records": num_records,
        }

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.FLOW,
            severity=EventSeverity.DEBUG,
            raw_message=f"sFlow counter sample from {agent_ip}",
            client_ip=agent_ip,
            action="counter",
            parsed_fields=parsed_fields,
        )

    def _parse_raw_packet_header(self, data: bytes) -> dict[str, Any] | None:
        """Parse raw packet header record.

        Record format:
        - protocol: 4 bytes (1=ethernet, 11=IPv4, 12=IPv6)
        - frame_length: 4 bytes
        - stripped: 4 bytes
        - header_length: 4 bytes
        - header: variable (the actual packet header)
        """
        if len(data) < 16:
            return None

        protocol = struct.unpack("!I", data[0:4])[0]
        frame_length = struct.unpack("!I", data[4:8])[0]
        _stripped = struct.unpack("!I", data[8:12])[0]  # Bytes stripped from end
        header_length = struct.unpack("!I", data[12:16])[0]

        if len(data) < 16 + header_length:
            return None

        header = data[16:16 + header_length]
        result = {"frame_length": frame_length}

        if protocol == 1:  # Ethernet
            eth_info = self._parse_ethernet(header)
            if eth_info:
                result.update(eth_info)
        elif protocol == 11:  # IPv4
            ipv4_info = self._parse_ipv4(header, 0)
            if ipv4_info:
                result.update(ipv4_info)

        return result

    def _parse_ethernet(self, data: bytes) -> dict[str, Any] | None:
        """Parse Ethernet header."""
        if len(data) < 14:
            return None

        dst_mac = data[0:6].hex(":")
        src_mac = data[6:12].hex(":")
        ethertype = struct.unpack("!H", data[12:14])[0]

        result = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "ethertype": ethertype,
        }

        offset = 14

        # Handle VLAN tags
        while ethertype == ETHERTYPE_VLAN and offset + 4 <= len(data):
            vlan_id = struct.unpack("!H", data[offset:offset + 2])[0] & 0x0FFF
            result["vlan_id"] = vlan_id
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4

        # Parse IP layer
        if ethertype == ETHERTYPE_IPV4:
            ip_info = self._parse_ipv4(data, offset)
            if ip_info:
                result.update(ip_info)
        elif ethertype == ETHERTYPE_IPV6:
            ip_info = self._parse_ipv6(data, offset)
            if ip_info:
                result.update(ip_info)

        return result

    def _parse_ipv4(self, data: bytes, offset: int) -> dict[str, Any] | None:
        """Parse IPv4 header."""
        if len(data) < offset + 20:
            return None

        ip_data = data[offset:]
        version_ihl = ip_data[0]
        version = (version_ihl >> 4) & 0xF
        ihl = (version_ihl & 0xF) * 4

        if version != 4 or len(ip_data) < ihl:
            return None

        protocol = ip_data[9]
        src_ip = self._bytes_to_ipv4(ip_data[12:16])
        dst_ip = self._bytes_to_ipv4(ip_data[16:20])

        result = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": PROTOCOL_MAP.get(protocol, str(protocol)),
            "ip_version": 4,
        }

        # Parse transport layer
        transport_offset = offset + ihl
        if protocol == PROTO_TCP and len(data) >= transport_offset + 20:
            tcp_info = self._parse_tcp(data, transport_offset)
            result.update(tcp_info)
        elif protocol == PROTO_UDP and len(data) >= transport_offset + 8:
            udp_info = self._parse_udp(data, transport_offset)
            result.update(udp_info)

        return result

    def _parse_ipv6(self, data: bytes, offset: int) -> dict[str, Any] | None:
        """Parse IPv6 header."""
        if len(data) < offset + 40:
            return None

        ip_data = data[offset:]
        next_header = ip_data[6]
        src_ip = self._bytes_to_ipv6(ip_data[8:24])
        dst_ip = self._bytes_to_ipv6(ip_data[24:40])

        result = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": PROTOCOL_MAP.get(next_header, str(next_header)),
            "ip_version": 6,
        }

        # Parse transport layer
        transport_offset = offset + 40
        if next_header == PROTO_TCP and len(data) >= transport_offset + 20:
            tcp_info = self._parse_tcp(data, transport_offset)
            result.update(tcp_info)
        elif next_header == PROTO_UDP and len(data) >= transport_offset + 8:
            udp_info = self._parse_udp(data, transport_offset)
            result.update(udp_info)

        return result

    def _parse_tcp(self, data: bytes, offset: int) -> dict[str, Any]:
        """Parse TCP header."""
        tcp_data = data[offset:]
        src_port, dst_port = struct.unpack("!HH", tcp_data[0:4])
        flags = tcp_data[13]

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": flags,
        }

    def _parse_udp(self, data: bytes, offset: int) -> dict[str, Any]:
        """Parse UDP header."""
        udp_data = data[offset:]
        src_port, dst_port = struct.unpack("!HH", udp_data[0:4])

        return {
            "src_port": src_port,
            "dst_port": dst_port,
        }

    def _parse_json_entry(self, entry: dict[str, Any]) -> ParseResult | None:
        """Parse pre-parsed JSON sFlow entry."""
        try:
            ts_str = entry.get("timestamp")
            if ts_str:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now(UTC)

            src_ip = entry.get("src_ip") or entry.get("source_ip")
            dst_ip = entry.get("dst_ip") or entry.get("destination_ip")
            src_port = entry.get("src_port") or entry.get("source_port")
            dst_port = entry.get("dst_port") or entry.get("destination_port")
            protocol = entry.get("protocol", "unknown")

            raw_message = f"sFlow sample: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})"

            # Determine severity based on characteristics
            severity = self._get_sample_severity({
                "dst_port": dst_port,
                "protocol": protocol,
            })

            return ParseResult(
                timestamp=timestamp,
                event_type=EventType.FLOW,
                severity=severity,
                raw_message=raw_message,
                client_ip=src_ip,
                target_ip=dst_ip,
                port=dst_port,
                protocol=str(protocol),
                action="sample",
                parsed_fields=entry,
            )

        except Exception as e:
            logger.warning("sflow_json_parse_error", error=str(e))
            return None

    def _bytes_to_ipv4(self, data: bytes) -> str:
        """Convert 4 bytes to IPv4 string."""
        return ".".join(str(b) for b in data[:4])

    def _bytes_to_ipv6(self, data: bytes) -> str:
        """Convert 16 bytes to IPv6 string."""
        parts = struct.unpack("!HHHHHHHH", data[:16])
        return ":".join(f"{p:x}" for p in parts)

    def _build_message(self, info: dict[str, Any]) -> str:
        """Build human-readable message from packet info."""
        src = info.get("src_ip", "?")
        dst = info.get("dst_ip", "?")
        src_port = info.get("src_port", "")
        dst_port = info.get("dst_port", "")
        proto = info.get("protocol", "?")
        frame_len = info.get("frame_length", "?")

        if src_port and dst_port:
            return f"sFlow sample: {src}:{src_port} -> {dst}:{dst_port} ({proto}) {frame_len} bytes"
        else:
            return f"sFlow sample: {src} -> {dst} ({proto}) {frame_len} bytes"

    def _get_sample_severity(self, info: dict[str, Any]) -> EventSeverity:
        """Determine severity based on sampled packet characteristics."""
        dst_port = info.get("dst_port", 0)
        _protocol = info.get("protocol", "")  # Available for protocol-based severity

        # Suspicious ports
        suspicious_ports = {4444, 5555, 6666, 31337, 1337, 8080, 9001, 12345}
        if dst_port in suspicious_ports:
            return EventSeverity.WARNING

        return EventSeverity.DEBUG
