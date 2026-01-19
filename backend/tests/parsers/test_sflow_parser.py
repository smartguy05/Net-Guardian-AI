"""Tests for the sFlow parser."""

import struct
import pytest
from datetime import datetime, timezone

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
        assert (datetime.now(timezone.utc) - results[0].timestamp).total_seconds() < 5

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
