"""NetFlow v5/v9 parser.

Parses NetFlow data from network devices. Supports:
- NetFlow v5 (fixed format)
- NetFlow v9 (template-based, partial support)
"""

import struct
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Well-known ports
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-SERVER",
    68: "DHCP-CLIENT",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRES",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MONGODB",
}


@register_parser("netflow")
class NetFlowParser(BaseParser):
    """Parser for NetFlow v5/v9 data.

    Can parse raw binary NetFlow packets or pre-parsed JSON data.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize NetFlow parser.

        Config options:
            min_bytes: Minimum bytes to consider significant (default: 0)
            min_packets: Minimum packets to consider significant (default: 0)
            exporter_ip: IP address of the exporter for context
        """
        super().__init__(config)
        self._templates: dict[
            int, dict[int, tuple[tuple[int, int], ...]]
        ] = {}  # NetFlow v9 templates
        self.min_bytes = self.config.get("min_bytes", 0)
        self.min_packets = self.config.get("min_packets", 0)
        self.exporter_ip = self.config.get("exporter_ip")

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse NetFlow data.

        Args:
            raw_data: Either raw bytes (UDP packet) or parsed JSON dict/list.

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
            logger.warning("netflow_parser_invalid_data", data_type=type(raw_data).__name__)
            return []

    def _parse_binary(self, data: bytes) -> list[ParseResult]:
        """Parse binary NetFlow packet."""
        if len(data) < 4:
            logger.warning("netflow_packet_too_short", length=len(data))
            return []

        # Read version from first 2 bytes
        version = struct.unpack("!H", data[0:2])[0]

        if version == 5:
            return self._parse_v5(data)
        elif version == 9:
            return self._parse_v9(data)
        else:
            logger.warning("netflow_unsupported_version", version=version)
            return []

    def _parse_v5(self, data: bytes) -> list[ParseResult]:
        """Parse NetFlow v5 packet.

        NetFlow v5 Header (24 bytes):
        - version: 2 bytes
        - count: 2 bytes (number of flow records)
        - sys_uptime: 4 bytes
        - unix_secs: 4 bytes
        - unix_nsecs: 4 bytes
        - flow_sequence: 4 bytes
        - engine_type: 1 byte
        - engine_id: 1 byte
        - sampling_interval: 2 bytes

        NetFlow v5 Record (48 bytes each):
        - src_addr: 4 bytes
        - dst_addr: 4 bytes
        - nexthop: 4 bytes
        - input: 2 bytes
        - output: 2 bytes
        - packets: 4 bytes
        - octets: 4 bytes
        - first: 4 bytes (uptime at flow start)
        - last: 4 bytes (uptime at flow end)
        - src_port: 2 bytes
        - dst_port: 2 bytes
        - pad1: 1 byte
        - tcp_flags: 1 byte
        - protocol: 1 byte
        - tos: 1 byte
        - src_as: 2 bytes
        - dst_as: 2 bytes
        - src_mask: 1 byte
        - dst_mask: 1 byte
        - pad2: 2 bytes
        """
        if len(data) < 24:
            logger.warning("netflow_v5_header_too_short", length=len(data))
            return []

        # Parse header
        header = struct.unpack("!HHIIIIBBH", data[0:24])
        (
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_seq,
            engine_type,
            engine_id,
            sampling,
        ) = header

        if count == 0:
            return []

        # Validate packet length
        expected_len = 24 + (count * 48)
        if len(data) < expected_len:
            logger.warning("netflow_v5_packet_truncated", expected=expected_len, actual=len(data))
            count = (len(data) - 24) // 48

        # Base timestamp from header
        base_timestamp = datetime.fromtimestamp(unix_secs, tz=UTC)

        results = []
        offset = 24

        for i in range(count):
            record_data = data[offset : offset + 48]
            if len(record_data) < 48:
                break

            record = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", record_data)
            (
                src_addr,
                dst_addr,
                nexthop,
                input_if,
                output_if,
                packets,
                octets,
                first,
                last,
                src_port,
                dst_port,
                pad1,
                tcp_flags,
                protocol,
                tos,
                src_as,
                dst_as,
                src_mask,
                dst_mask,
                pad2,
            ) = record

            # Filter by configured thresholds
            if octets < self.min_bytes or packets < self.min_packets:
                offset += 48
                continue

            # Convert IP addresses
            src_ip = self._int_to_ip(src_addr)
            dst_ip = self._int_to_ip(dst_addr)
            next_hop_ip = self._int_to_ip(nexthop)

            # Calculate flow duration
            duration_ms = last - first if last >= first else 0

            # Build parsed fields
            parsed_fields = {
                "netflow_version": 5,
                "flow_sequence": flow_seq,
                "packets": packets,
                "bytes": octets,
                "duration_ms": duration_ms,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "tos": tos,
                "input_interface": input_if,
                "output_interface": output_if,
                "src_as": src_as,
                "dst_as": dst_as,
                "next_hop": next_hop_ip,
            }
            if self.exporter_ip:
                parsed_fields["exporter_ip"] = self.exporter_ip

            # Determine protocol name
            proto_name = PROTOCOL_MAP.get(protocol, str(protocol))

            # Determine severity based on characteristics
            severity = self._get_flow_severity(protocol, dst_port, octets, packets, tcp_flags)

            # Build raw message
            _port_service = WELL_KNOWN_PORTS.get(
                dst_port, str(dst_port)
            )  # Available for enrichment
            raw_message = (
                f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"({proto_name}) {packets} pkts / {octets} bytes"
            )

            results.append(
                ParseResult(
                    timestamp=base_timestamp,
                    event_type=EventType.FLOW,
                    severity=severity,
                    raw_message=raw_message,
                    client_ip=src_ip,
                    target_ip=dst_ip,
                    port=dst_port,
                    protocol=proto_name,
                    action="flow",
                    parsed_fields=parsed_fields,
                )
            )

            offset += 48

        return results

    def _parse_v9(self, data: bytes) -> list[ParseResult]:
        """Parse NetFlow v9 packet (basic support).

        NetFlow v9 uses templates to define record formats. This implementation
        handles the most common template fields but may not parse all records.
        """
        if len(data) < 20:
            logger.warning("netflow_v9_header_too_short", length=len(data))
            return []

        # Parse header
        header = struct.unpack("!HHIIII", data[0:20])
        version, count, sys_uptime, unix_secs, seq, source_id = header

        base_timestamp = datetime.fromtimestamp(unix_secs, tz=UTC)

        results = []
        offset = 20

        # Process flow sets
        while offset < len(data) - 4:
            flowset_id, flowset_length = struct.unpack("!HH", data[offset : offset + 4])

            if flowset_length < 4:
                break

            flowset_data = data[offset + 4 : offset + flowset_length]

            if flowset_id == 0:
                # Template FlowSet
                self._parse_v9_template(flowset_data, source_id)
            elif flowset_id == 1:
                # Options Template FlowSet (skip for now)
                pass
            elif flowset_id >= 256:
                # Data FlowSet
                template = self._templates.get(source_id, {}).get(flowset_id)
                if template:
                    results.extend(self._parse_v9_data(flowset_data, template, base_timestamp))

            offset += flowset_length

        return results

    def _parse_v9_template(self, data: bytes, source_id: int) -> None:
        """Parse NetFlow v9 template."""
        offset = 0
        while offset < len(data) - 4:
            template_id, field_count = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4

            fields = []
            for _ in range(field_count):
                if offset + 4 > len(data):
                    break
                field_type, field_length = struct.unpack("!HH", data[offset : offset + 4])
                fields.append((field_type, field_length))
                offset += 4

            if source_id not in self._templates:
                self._templates[source_id] = {}
            self._templates[source_id][template_id] = tuple(fields)
            logger.debug(
                "netflow_v9_template_received", template_id=template_id, fields=len(fields)
            )

    def _parse_v9_data(
        self,
        data: bytes,
        template: tuple[tuple[int, int], ...],
        timestamp: datetime,
    ) -> list[ParseResult]:
        """Parse NetFlow v9 data records using template."""
        # Calculate record size
        record_size = sum(length for _, length in template)
        if record_size == 0:
            return []

        results = []
        offset = 0

        while offset + record_size <= len(data):
            record_data = data[offset : offset + record_size]
            parsed = self._parse_v9_record(record_data, template)

            if parsed:
                results.append(
                    ParseResult(
                        timestamp=timestamp,
                        event_type=EventType.FLOW,
                        severity=EventSeverity.DEBUG,
                        raw_message=self._build_v9_message(parsed),
                        client_ip=parsed.get("src_ip"),
                        target_ip=parsed.get("dst_ip"),
                        port=parsed.get("dst_port"),
                        protocol=parsed.get("protocol"),
                        action="flow",
                        parsed_fields={
                            "netflow_version": 9,
                            **parsed,
                        },
                    )
                )

            offset += record_size

        return results

    def _parse_v9_record(
        self, data: bytes, template: tuple[tuple[int, int], ...]
    ) -> dict[str, Any] | None:
        """Parse a single NetFlow v9 record."""
        # Common field type mappings
        field_types = {
            1: ("bytes", "I"),
            2: ("packets", "I"),
            4: ("protocol", "B"),
            7: ("src_port", "H"),
            8: ("src_ip", "4s"),
            11: ("dst_port", "H"),
            12: ("dst_ip", "4s"),
        }

        result = {}
        offset = 0

        for field_type, field_length in template:
            if offset + field_length > len(data):
                break

            field_data = data[offset : offset + field_length]

            if field_type in field_types:
                name, fmt = field_types[field_type]
                try:
                    if fmt == "4s":
                        value = self._int_to_ip(struct.unpack("!I", field_data)[0])
                    else:
                        value = struct.unpack(f"!{fmt}", field_data[: struct.calcsize(fmt)])[0]
                    result[name] = value
                except struct.error:
                    pass

            offset += field_length

        # Convert protocol number to name
        if "protocol" in result:
            proto_num = result["protocol"]
            if isinstance(proto_num, int):
                result["protocol"] = PROTOCOL_MAP.get(proto_num, str(proto_num))

        return result if result else None

    def _build_v9_message(self, parsed: dict[str, Any]) -> str:
        """Build raw message for NetFlow v9 record."""
        src = parsed.get("src_ip", "?")
        dst = parsed.get("dst_ip", "?")
        src_port = parsed.get("src_port", "?")
        dst_port = parsed.get("dst_port", "?")
        proto = parsed.get("protocol", "?")
        packets = parsed.get("packets", "?")
        bytes_val = parsed.get("bytes", "?")

        return f"Flow: {src}:{src_port} -> {dst}:{dst_port} ({proto}) {packets} pkts / {bytes_val} bytes"

    def _parse_json_entry(self, entry: dict[str, Any]) -> ParseResult | None:
        """Parse pre-parsed JSON NetFlow entry."""
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
            packets = entry.get("packets", 0)
            octets = entry.get("bytes") or entry.get("octets", 0)

            # Filter by thresholds
            if octets < self.min_bytes or packets < self.min_packets:
                return None

            raw_message = (
                f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"({protocol}) {packets} pkts / {octets} bytes"
            )

            return ParseResult(
                timestamp=timestamp,
                event_type=EventType.FLOW,
                severity=EventSeverity.DEBUG,
                raw_message=raw_message,
                client_ip=src_ip,
                target_ip=dst_ip,
                port=dst_port,
                protocol=str(protocol),
                action="flow",
                parsed_fields=entry,
            )

        except Exception as e:
            logger.warning("netflow_json_parse_error", error=str(e))
            return None

    def _int_to_ip(self, addr: int) -> str:
        """Convert 32-bit integer to dotted IP string."""
        return f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}"

    def _get_flow_severity(
        self,
        protocol: int,
        dst_port: int,
        bytes_val: int,
        packets: int,
        tcp_flags: int,
    ) -> EventSeverity:
        """Determine flow severity based on characteristics."""
        # Check for suspicious ports
        suspicious_ports = {4444, 5555, 6666, 31337, 1337, 8080, 9001, 12345}
        if dst_port in suspicious_ports:
            return EventSeverity.WARNING

        # Large data transfers
        if bytes_val > 100_000_000:  # 100 MB
            return EventSeverity.INFO

        # Port scan detection (many packets, few bytes, RST flags)
        if packets > 100 and bytes_val < 1000:
            return EventSeverity.WARNING

        # TCP SYN flood detection
        if protocol == 6 and (tcp_flags & 0x02) and not (tcp_flags & 0x10):
            if packets > 50:
                return EventSeverity.WARNING

        return EventSeverity.DEBUG
