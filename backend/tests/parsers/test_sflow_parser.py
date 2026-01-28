"""Tests for the sFlow parser."""

import struct
from datetime import UTC, datetime

import pytest

from app.models.raw_event import EventSeverity, EventType
from app.parsers.sflow_parser import SFlowParser


class TestSFlowParser:
    """Tests for SFlowParser."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SFlowParser()

    @pytest.fixture
    def parser_with_counters(self):
        """Create parser that includes counter samples."""
        return SFlowParser(config={"include_counters": True})

    def _build_sflow_datagram(
        self,
        agent_ip: str = "192.168.1.1",
        samples: list = None,
    ) -> bytes:
        """Build an sFlow v5 datagram for testing.

        Args:
            agent_ip: IP address of the sFlow agent
            samples: List of sample data (flow or counter)
        """
        samples = samples or []

        # Header
        version = 5
        agent_type = 1  # IPv4
        agent_addr = self._ip_to_bytes(agent_ip)
        sub_agent_id = 0
        sequence = 1
        uptime = 1000000
        num_samples = len(samples)

        header = struct.pack("!II", version, agent_type)
        header += agent_addr
        header += struct.pack("!IIII", sub_agent_id, sequence, uptime, num_samples)

        # Samples
        sample_data = b""
        for sample in samples:
            sample_data += sample

        return header + sample_data

    def _build_flow_sample(
        self,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "8.8.8.8",
        src_port: int = 54321,
        dst_port: int = 443,
        protocol: int = 6,
        frame_length: int = 1500,
    ) -> bytes:
        """Build a flow sample for testing."""
        # Flow sample header
        sample_type = 1  # Standard flow sample
        sequence = 1
        source_id = 1
        sampling_rate = 1000
        sample_pool = 1000000
        drops = 0
        input_if = 1
        output_if = 2
        num_records = 1

        # Build raw packet header record
        raw_packet = self._build_raw_packet_record(
            src_ip, dst_ip, src_port, dst_port, protocol, frame_length
        )

        sample_length = 32 + len(raw_packet)

        sample = struct.pack("!II", sample_type, sample_length)
        sample += struct.pack(
            "!IIIIIIII",
            sequence, source_id, sampling_rate, sample_pool,
            drops, input_if, output_if, num_records,
        )
        sample += raw_packet

        return sample

    def _build_raw_packet_record(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        frame_length: int,
    ) -> bytes:
        """Build a raw packet header record."""
        # Record type 1 = raw packet header
        record_type = 1

        # Build Ethernet + IP + TCP/UDP header
        # Ethernet header (14 bytes)
        eth_header = b"\x00" * 6  # dst MAC
        eth_header += b"\x00" * 6  # src MAC
        eth_header += struct.pack("!H", 0x0800)  # IPv4 ethertype

        # IPv4 header (20 bytes)
        ip_header = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0, 0, 64, protocol, 0)
        ip_header += self._ip_to_bytes(src_ip)
        ip_header += self._ip_to_bytes(dst_ip)

        # TCP/UDP header (8 bytes minimum)
        transport_header = struct.pack("!HH", src_port, dst_port)
        transport_header += b"\x00" * 4  # seq/ack or length/checksum

        packet_header = eth_header + ip_header + transport_header
        header_length = len(packet_header)

        # Raw packet record format
        record = struct.pack("!II", record_type, 16 + header_length)
        record += struct.pack("!IIII", 1, frame_length, 0, header_length)  # protocol=ethernet
        record += packet_header

        return record

    def _ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP string to bytes."""
        parts = [int(p) for p in ip.split(".")]
        return struct.pack("BBBB", *parts)

    def test_parse_json_entry(self, parser):
        """Test parsing pre-parsed JSON data."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].event_type == EventType.FLOW
        assert results[0].client_ip == "192.168.1.100"
        assert results[0].target_ip == "8.8.8.8"
        assert results[0].port == 443
        assert results[0].action == "sample"

    def test_parse_json_batch(self, parser):
        """Test parsing a batch of JSON entries."""
        data = [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
            },
            {
                "timestamp": "2024-01-15T10:30:01Z",
                "src_ip": "192.168.1.101",
                "dst_ip": "1.1.1.1",
                "src_port": 54322,
                "dst_port": 53,
                "protocol": "UDP",
            },
        ]

        results = parser.parse(data)
        assert len(results) == 2

    def test_parse_binary_datagram_header(self, parser):
        """Test parsing the sFlow datagram header."""
        datagram = self._build_sflow_datagram(
            agent_ip="192.168.1.1",
            samples=[],
        )

        # Should parse without error even with no samples
        results = parser.parse(datagram)
        assert len(results) == 0

    def test_suspicious_port_detection(self, parser):
        """Test detection of suspicious ports in JSON data."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 4444,  # Suspicious port
            "protocol": "TCP",
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_invalid_version(self, parser):
        """Test handling of unsupported sFlow version."""
        # Build datagram with wrong version
        datagram = struct.pack("!I", 4) + b"\x00" * 24  # Version 4

        results = parser.parse(datagram)
        assert len(results) == 0

    def test_truncated_datagram(self, parser):
        """Test handling of truncated datagrams."""
        datagram = struct.pack("!I", 5) + b"\x00" * 10  # Too short

        results = parser.parse(datagram)
        assert len(results) == 0

    def test_invalid_data_type(self, parser):
        """Test handling of invalid data types."""
        results = parser.parse("invalid string data")
        assert len(results) == 0

    def test_raw_message_format(self, parser):
        """Test that raw messages are properly formatted."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
        }

        results = parser.parse(data)
        assert len(results) == 1

        raw_msg = results[0].raw_message
        assert "sFlow sample" in raw_msg
        assert "192.168.1.100" in raw_msg
        assert "8.8.8.8" in raw_msg
        assert "TCP" in raw_msg

    def test_alternative_field_names(self, parser):
        """Test parsing with alternative field names."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "192.168.1.100",  # Alternative name
            "destination_ip": "8.8.8.8",   # Alternative name
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].client_ip == "192.168.1.100"
        assert results[0].target_ip == "8.8.8.8"

    def test_missing_timestamp_uses_current(self, parser):
        """Test that missing timestamp uses current time."""
        data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
        }

        results = parser.parse(data)
        assert len(results) == 1
        # Timestamp should be recent
        assert (datetime.now(UTC) - results[0].timestamp).total_seconds() < 5

    def test_parsed_fields_preserved(self, parser):
        """Test that all original fields are preserved in parsed_fields."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "custom_field": "custom_value",
            "sampling_rate": 1000,
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].parsed_fields["custom_field"] == "custom_value"
        assert results[0].parsed_fields["sampling_rate"] == 1000


class TestSFlowBinaryParsing:
    """Tests for sFlow binary datagram parsing."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SFlowParser()

    @pytest.fixture
    def parser_with_counters(self):
        """Create parser that includes counter samples."""
        return SFlowParser(config={"include_counters": True})

    def _ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP string to bytes."""
        parts = [int(p) for p in ip.split(".")]
        return struct.pack("BBBB", *parts)

    def _build_sflow_header(
        self,
        agent_ip: str = "192.168.1.1",
        agent_type: int = 1,  # 1=IPv4, 2=IPv6
        num_samples: int = 0,
    ) -> bytes:
        """Build sFlow v5 datagram header."""
        version = 5
        header = struct.pack("!II", version, agent_type)
        if agent_type == 1:
            header += self._ip_to_bytes(agent_ip)
        else:
            # IPv6 - 16 bytes
            header += b"\x00" * 16

        # sub_agent_id, sequence, uptime, num_samples
        header += struct.pack("!IIII", 0, 1, 1000000, num_samples)
        return header

    def _build_flow_sample(
        self,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "8.8.8.8",
        src_port: int = 54321,
        dst_port: int = 443,
        protocol: int = 6,
        frame_length: int = 1500,
    ) -> bytes:
        """Build a complete flow sample with raw packet header."""
        # Sample type 1 = flow sample (enterprise 0, format 1)
        sample_type = 1

        # Build raw packet header record
        raw_packet_record = self._build_raw_packet_record(
            src_ip, dst_ip, src_port, dst_port, protocol, frame_length
        )

        # Flow sample data
        sequence = 1
        source_id = 1
        sampling_rate = 1000
        sample_pool = 1000000
        drops = 0
        input_if = 1
        output_if = 2
        num_records = 1

        sample_data = struct.pack(
            "!IIIIIIII",
            sequence, source_id, sampling_rate, sample_pool,
            drops, input_if, output_if, num_records,
        )
        sample_data += raw_packet_record

        sample_length = len(sample_data)
        return struct.pack("!II", sample_type, sample_length) + sample_data

    def _build_raw_packet_record(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        frame_length: int,
    ) -> bytes:
        """Build a raw packet header record with Ethernet/IP/TCP headers."""
        # Record type 1 = raw packet header
        record_type = 1

        # Build packet header: Ethernet + IPv4 + TCP/UDP
        # Ethernet header (14 bytes)
        eth_header = b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        eth_header += b"\xaa\xbb\xcc\xdd\xee\xff"  # src MAC
        eth_header += struct.pack("!H", 0x0800)  # IPv4 ethertype

        # IPv4 header (20 bytes)
        version_ihl = 0x45
        dscp_ecn = 0
        total_length = 60 if protocol == 6 else 28  # TCP needs more
        identification = 0
        flags_fragment = 0
        ttl = 64
        checksum = 0

        ip_header = struct.pack(
            "!BBHHHBBH",
            version_ihl, dscp_ecn, total_length, identification,
            flags_fragment, ttl, protocol, checksum
        )
        ip_header += self._ip_to_bytes(src_ip)
        ip_header += self._ip_to_bytes(dst_ip)

        # TCP header (20 bytes) or UDP header (8 bytes)
        if protocol == 6:  # TCP
            transport_header = struct.pack("!HH", src_port, dst_port)
            transport_header += struct.pack("!II", 0, 0)  # seq, ack
            transport_header += struct.pack("!BBHHH", 0x50, 0x02, 65535, 0, 0)  # data offset, flags, window, checksum, urgent
        else:  # UDP
            transport_header = struct.pack("!HHHH", src_port, dst_port, 8, 0)

        packet_header = eth_header + ip_header + transport_header
        header_length = len(packet_header)

        # Raw packet record: type (4) + length (4) + protocol (4) + frame_length (4) + stripped (4) + header_length (4) + header
        record_data = struct.pack("!IIII", 1, frame_length, 0, header_length)  # protocol=ethernet
        record_data += packet_header

        record_length = len(record_data)
        return struct.pack("!II", record_type, record_length) + record_data

    def _build_counter_sample(self) -> bytes:
        """Build a counter sample."""
        # Sample type 2 = counter sample
        sample_type = 2
        sequence = 1
        source_id = 1
        num_records = 0

        sample_data = struct.pack("!III", sequence, source_id, num_records)
        sample_length = len(sample_data)

        return struct.pack("!II", sample_type, sample_length) + sample_data

    def _build_expanded_flow_sample(
        self,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "8.8.8.8",
    ) -> bytes:
        """Build an expanded flow sample (type 3)."""
        # Sample type 3 = expanded flow sample
        sample_type = 3

        # Build raw packet header record
        raw_packet_record = self._build_raw_packet_record(
            src_ip, dst_ip, 54321, 443, 6, 1500
        )

        # Expanded flow sample has similar structure to standard flow sample
        sequence = 1
        source_id = 1
        sampling_rate = 1000
        sample_pool = 1000000
        drops = 0
        input_if = 1
        output_if = 2
        num_records = 1

        sample_data = struct.pack(
            "!IIIIIIII",
            sequence, source_id, sampling_rate, sample_pool,
            drops, input_if, output_if, num_records,
        )
        sample_data += raw_packet_record

        sample_length = len(sample_data)
        return struct.pack("!II", sample_type, sample_length) + sample_data

    def test_parse_flow_sample_binary(self, parser):
        """Test parsing a complete binary flow sample."""
        header = self._build_sflow_header(num_samples=1)
        flow_sample = self._build_flow_sample(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,  # TCP
        )

        datagram = header + flow_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.FLOW
        assert result.client_ip == "192.168.1.100"
        assert result.target_ip == "8.8.8.8"
        assert result.port == 443
        assert result.protocol == "TCP"
        assert result.parsed_fields["sflow_version"] == 5
        assert result.parsed_fields["sampling_rate"] == 1000

    def test_parse_multiple_flow_samples(self, parser):
        """Test parsing multiple flow samples in one datagram."""
        header = self._build_sflow_header(num_samples=2)
        flow_sample1 = self._build_flow_sample(src_ip="192.168.1.100", dst_ip="8.8.8.8")
        flow_sample2 = self._build_flow_sample(src_ip="192.168.1.101", dst_ip="1.1.1.1")

        datagram = header + flow_sample1 + flow_sample2
        results = parser.parse(datagram)

        assert len(results) == 2
        ips = {r.client_ip for r in results}
        assert "192.168.1.100" in ips
        assert "192.168.1.101" in ips

    def test_parse_counter_sample_excluded_by_default(self, parser):
        """Test that counter samples are excluded by default."""
        header = self._build_sflow_header(num_samples=1)
        counter_sample = self._build_counter_sample()

        datagram = header + counter_sample
        results = parser.parse(datagram)

        assert len(results) == 0  # Counter samples excluded

    def test_parse_counter_sample_included(self, parser_with_counters):
        """Test that counter samples are included when configured."""
        header = self._build_sflow_header(num_samples=1)
        counter_sample = self._build_counter_sample()

        datagram = header + counter_sample
        results = parser_with_counters.parse(datagram)

        assert len(results) == 1
        assert results[0].action == "counter"
        assert results[0].parsed_fields["sample_type"] == "counter"

    def test_parse_expanded_flow_sample(self, parser):
        """Test parsing expanded flow sample (type 3)."""
        header = self._build_sflow_header(num_samples=1)
        expanded_sample = self._build_expanded_flow_sample()

        datagram = header + expanded_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        assert results[0].event_type == EventType.FLOW

    def test_parse_mixed_samples(self, parser_with_counters):
        """Test parsing datagram with mixed sample types."""
        header = self._build_sflow_header(num_samples=3)
        flow_sample = self._build_flow_sample()
        counter_sample = self._build_counter_sample()
        expanded_sample = self._build_expanded_flow_sample(src_ip="10.0.0.1")

        datagram = header + flow_sample + counter_sample + expanded_sample
        results = parser_with_counters.parse(datagram)

        assert len(results) == 3

    def test_parse_udp_protocol(self, parser):
        """Test parsing flow sample with UDP protocol."""
        header = self._build_sflow_header(num_samples=1)
        flow_sample = self._build_flow_sample(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol=17,  # UDP
        )

        datagram = header + flow_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        assert results[0].protocol == "UDP"
        assert results[0].port == 53

    def test_parse_icmp_protocol(self, parser):
        """Test parsing flow sample with ICMP protocol."""
        header = self._build_sflow_header(num_samples=1)
        flow_sample = self._build_flow_sample(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=0,
            dst_port=0,
            protocol=1,  # ICMP
        )

        datagram = header + flow_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        assert results[0].protocol == "ICMP"

    def test_parse_agent_ip_in_fields(self, parser):
        """Test that agent IP is included in parsed fields."""
        header = self._build_sflow_header(agent_ip="10.0.0.1", num_samples=1)
        flow_sample = self._build_flow_sample()

        datagram = header + flow_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        assert results[0].parsed_fields["agent_ip"] == "10.0.0.1"


class TestSFlowVLANParsing:
    """Tests for VLAN tag parsing in sFlow."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SFlowParser()

    def _ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP string to bytes."""
        parts = [int(p) for p in ip.split(".")]
        return struct.pack("BBBB", *parts)

    def _build_vlan_packet_record(
        self,
        vlan_id: int,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "8.8.8.8",
        src_port: int = 54321,
        dst_port: int = 443,
    ) -> bytes:
        """Build a raw packet record with VLAN tag."""
        record_type = 1

        # Ethernet header with VLAN (18 bytes)
        eth_header = b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        eth_header += b"\xaa\xbb\xcc\xdd\xee\xff"  # src MAC
        eth_header += struct.pack("!H", 0x8100)  # VLAN ethertype
        eth_header += struct.pack("!H", vlan_id)  # VLAN ID
        eth_header += struct.pack("!H", 0x0800)  # IPv4 ethertype

        # IPv4 header (20 bytes)
        ip_header = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0, 0, 64, 6, 0)
        ip_header += self._ip_to_bytes(src_ip)
        ip_header += self._ip_to_bytes(dst_ip)

        # TCP header (8 bytes)
        tcp_header = struct.pack("!HH", src_port, dst_port) + b"\x00" * 4

        packet_header = eth_header + ip_header + tcp_header
        header_length = len(packet_header)

        record_data = struct.pack("!IIII", 1, 1500, 0, header_length)
        record_data += packet_header

        record_length = len(record_data)
        return struct.pack("!II", record_type, record_length) + record_data

    def test_parse_vlan_tag(self, parser):
        """Test that VLAN tags are extracted."""
        # Build datagram with VLAN-tagged packet
        header = struct.pack("!II", 5, 1)  # version, agent_type
        header += b"\xc0\xa8\x01\x01"  # agent IP 192.168.1.1
        header += struct.pack("!IIII", 0, 1, 1000000, 1)  # sub_agent, seq, uptime, num_samples

        # Flow sample with VLAN record
        vlan_record = self._build_vlan_packet_record(vlan_id=100)

        sample_data = struct.pack("!IIIIIIII", 1, 1, 1000, 1000000, 0, 1, 2, 1)
        sample_data += vlan_record

        flow_sample = struct.pack("!II", 1, len(sample_data)) + sample_data

        datagram = header + flow_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        assert results[0].parsed_fields.get("vlan_id") == 100


class TestSFlowIPv6:
    """Tests for IPv6 address handling in sFlow."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SFlowParser()

    def _build_ipv6_packet_record(
        self,
        src_ip: str = "2001:db8::1",
        dst_ip: str = "2001:db8::2",
        src_port: int = 54321,
        dst_port: int = 443,
    ) -> bytes:
        """Build a raw packet record with IPv6."""
        record_type = 1

        # Ethernet header (14 bytes)
        eth_header = b"\x00" * 6 + b"\x00" * 6
        eth_header += struct.pack("!H", 0x86DD)  # IPv6 ethertype

        # IPv6 header (40 bytes)
        ip_header = struct.pack("!IHBB", 0x60000000, 20, 6, 64)  # version, payload_len, next_header (TCP), hop_limit
        # Source IPv6
        ip_header += b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        # Dest IPv6
        ip_header += b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

        # TCP header (8 bytes)
        tcp_header = struct.pack("!HH", src_port, dst_port) + b"\x00" * 4

        packet_header = eth_header + ip_header + tcp_header
        header_length = len(packet_header)

        record_data = struct.pack("!IIII", 1, 1500, 0, header_length)
        record_data += packet_header

        record_length = len(record_data)
        return struct.pack("!II", record_type, record_length) + record_data

    def test_parse_ipv6_addresses(self, parser):
        """Test parsing IPv6 addresses in sFlow samples."""
        # Build datagram with IPv6 packet
        header = struct.pack("!II", 5, 1)  # version, agent_type IPv4
        header += b"\xc0\xa8\x01\x01"  # agent IP 192.168.1.1
        header += struct.pack("!IIII", 0, 1, 1000000, 1)

        ipv6_record = self._build_ipv6_packet_record()

        sample_data = struct.pack("!IIIIIIII", 1, 1, 1000, 1000000, 0, 1, 2, 1)
        sample_data += ipv6_record

        flow_sample = struct.pack("!II", 1, len(sample_data)) + sample_data

        datagram = header + flow_sample
        results = parser.parse(datagram)

        assert len(results) == 1
        result = results[0]
        assert result.parsed_fields.get("ip_version") == 6
        # IPv6 addresses should be parsed
        assert "2001:" in result.client_ip.lower() or ":" in result.client_ip

    def test_parse_ipv6_agent(self, parser):
        """Test parsing datagram from IPv6 agent."""
        # Build header with IPv6 agent address
        header = struct.pack("!II", 5, 2)  # version, agent_type IPv6
        header += b"\x20\x01\x0d\xb8" + b"\x00" * 12  # IPv6 agent address
        header += struct.pack("!IIII", 0, 1, 1000000, 0)  # No samples

        results = parser.parse(header)
        assert len(results) == 0  # No samples, but should parse without error


class TestSFlowEdgeCases:
    """Tests for edge cases in sFlow parsing."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SFlowParser()

    def test_truncated_sample(self, parser):
        """Test handling of truncated sample data."""
        header = struct.pack("!II", 5, 1)
        header += b"\xc0\xa8\x01\x01"
        header += struct.pack("!IIII", 0, 1, 1000000, 1)  # 1 sample

        # Truncated sample (only type and partial length)
        truncated = struct.pack("!I", 1) + b"\x00\x00"

        results = parser.parse(header + truncated)
        assert len(results) == 0

    def test_unknown_sample_type(self, parser):
        """Test handling of unknown sample types."""
        header = struct.pack("!II", 5, 1)
        header += b"\xc0\xa8\x01\x01"
        header += struct.pack("!IIII", 0, 1, 1000000, 1)

        # Unknown sample type (enterprise 999, format 99)
        unknown_type = (999 << 20) | 99
        unknown_sample = struct.pack("!II", unknown_type, 8) + b"\x00" * 8

        results = parser.parse(header + unknown_sample)
        assert len(results) == 0

    def test_empty_flow_sample(self, parser):
        """Test handling of flow sample with no records."""
        header = struct.pack("!II", 5, 1)
        header += b"\xc0\xa8\x01\x01"
        header += struct.pack("!IIII", 0, 1, 1000000, 1)

        # Flow sample with 0 records
        sample_data = struct.pack("!IIIIIIII", 1, 1, 1000, 1000000, 0, 1, 2, 0)
        flow_sample = struct.pack("!II", 1, len(sample_data)) + sample_data

        results = parser.parse(header + flow_sample)
        assert len(results) == 0  # No records means no result

    def test_sample_with_unknown_record_type(self, parser):
        """Test handling of flow sample with unknown record types."""
        header = struct.pack("!II", 5, 1)
        header += b"\xc0\xa8\x01\x01"
        header += struct.pack("!IIII", 0, 1, 1000000, 1)

        # Unknown record type (99)
        unknown_record = struct.pack("!II", 99, 8) + b"\x00" * 8

        sample_data = struct.pack("!IIIIIIII", 1, 1, 1000, 1000000, 0, 1, 2, 1)
        sample_data += unknown_record

        flow_sample = struct.pack("!II", 1, len(sample_data)) + sample_data

        results = parser.parse(header + flow_sample)
        # Should handle gracefully (no result since no raw packet header)
        assert len(results) == 0
