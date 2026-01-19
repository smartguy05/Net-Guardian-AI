"""Tests for the NetFlow parser."""

import struct
import pytest
from datetime import datetime, timezone

from app.models.raw_event import EventSeverity, EventType
from app.parsers.netflow_parser import NetFlowParser


class TestNetFlowParser:
    """Tests for NetFlowParser."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return NetFlowParser()

    @pytest.fixture
    def parser_with_threshold(self):
        """Create parser with minimum thresholds."""
        return NetFlowParser(config={
            "min_bytes": 1000,
            "min_packets": 5,
        })

    def _build_netflow_v5_packet(
        self,
        flows: list,
        unix_secs: int = 1705312200,
    ) -> bytes:
        """Build a NetFlow v5 packet for testing.

        Args:
            flows: List of flow tuples (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes)
            unix_secs: Unix timestamp
        """
        # Header
        version = 5
        count = len(flows)
        sys_uptime = 0
        unix_nsecs = 0
        flow_sequence = 1
        engine_type = 0
        engine_id = 0
        sampling = 0

        header = struct.pack(
            "!HHIIIIBBH",
            version, count, sys_uptime, unix_secs, unix_nsecs,
            flow_sequence, engine_type, engine_id, sampling,
        )

        # Records
        records = b""
        for src_ip, dst_ip, src_port, dst_port, protocol, packets, octets in flows:
            src_addr = self._ip_to_int(src_ip)
            dst_addr = self._ip_to_int(dst_ip)
            nexthop = 0
            input_if = 1
            output_if = 2
            first = 0
            last = 1000
            tcp_flags = 0
            tos = 0
            src_as = 0
            dst_as = 0
            src_mask = 24
            dst_mask = 24

            record = struct.pack(
                "!IIIHHIIIIHHBBBBHHBBH",
                src_addr, dst_addr, nexthop, input_if, output_if,
                packets, octets, first, last,
                src_port, dst_port, 0, tcp_flags, protocol, tos,
                src_as, dst_as, src_mask, dst_mask, 0,
            )
            records += record

        return header + records

    def _ip_to_int(self, ip: str) -> int:
        """Convert IP string to integer."""
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    def test_parse_netflow_v5_binary(self, parser):
        """Test parsing a NetFlow v5 binary packet."""
        packet = self._build_netflow_v5_packet([
            ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10, 5000),  # TCP
        ])

        results = parser.parse(packet)
        assert len(results) == 1

        result = results[0]
        assert result.event_type == EventType.FLOW
        assert result.client_ip == "192.168.1.100"
        assert result.target_ip == "8.8.8.8"
        assert result.port == 443
        assert result.protocol == "TCP"
        assert result.action == "flow"
        assert result.parsed_fields["packets"] == 10
        assert result.parsed_fields["bytes"] == 5000
        assert result.parsed_fields["netflow_version"] == 5

    def test_parse_multiple_flows(self, parser):
        """Test parsing multiple flows in one packet."""
        packet = self._build_netflow_v5_packet([
            ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10, 5000),
            ("192.168.1.101", "1.1.1.1", 54322, 53, 17, 5, 500),  # UDP DNS
            ("192.168.1.102", "10.0.0.1", 54323, 80, 6, 20, 10000),
        ])

        results = parser.parse(packet)
        assert len(results) == 3

    def test_parse_with_thresholds(self, parser_with_threshold):
        """Test that flows below thresholds are filtered."""
        packet = self._build_netflow_v5_packet([
            ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10, 5000),  # Above threshold
            ("192.168.1.101", "1.1.1.1", 54322, 53, 17, 2, 100),   # Below threshold
        ])

        results = parser_with_threshold.parse(packet)
        # Only the first flow should pass
        assert len(results) == 1
        assert results[0].client_ip == "192.168.1.100"

    def test_parse_json_entry(self, parser):
        """Test parsing pre-parsed JSON data."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "packets": 10,
            "bytes": 5000,
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].client_ip == "192.168.1.100"
        assert results[0].target_ip == "8.8.8.8"

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
                "packets": 10,
                "bytes": 5000,
            },
            {
                "timestamp": "2024-01-15T10:30:01Z",
                "src_ip": "192.168.1.101",
                "dst_ip": "1.1.1.1",
                "src_port": 54322,
                "dst_port": 53,
                "protocol": "UDP",
                "packets": 5,
                "bytes": 500,
            },
        ]

        results = parser.parse(data)
        assert len(results) == 2

    def test_suspicious_port_detection(self, parser):
        """Test detection of suspicious ports."""
        packet = self._build_netflow_v5_packet([
            ("192.168.1.100", "10.0.0.1", 54321, 4444, 6, 10, 1000),  # Suspicious port
        ])

        results = parser.parse(packet)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_large_transfer_detection(self, parser):
        """Test detection of large data transfers."""
        packet = self._build_netflow_v5_packet([
            ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10000, 150000000),  # 150 MB
        ])

        results = parser.parse(packet)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO

    def test_invalid_version(self, parser):
        """Test handling of unsupported NetFlow version."""
        # Build packet with invalid version
        packet = struct.pack("!H", 99) + b"\x00" * 20  # Version 99

        results = parser.parse(packet)
        assert len(results) == 0

    def test_truncated_packet(self, parser):
        """Test handling of truncated packets."""
        # Just the header, no records
        packet = self._build_netflow_v5_packet([])[:24]

        results = parser.parse(packet)
        assert len(results) == 0

    def test_invalid_data_type(self, parser):
        """Test handling of invalid data types."""
        results = parser.parse("invalid string data")
        assert len(results) == 0

    def test_protocol_mapping(self, parser):
        """Test that protocol numbers are mapped to names."""
        flows = [
            ("192.168.1.100", "8.8.8.8", 1, 0, 1, 10, 1000),    # ICMP
            ("192.168.1.101", "8.8.8.8", 54321, 443, 6, 10, 1000),  # TCP
            ("192.168.1.102", "8.8.8.8", 54322, 53, 17, 10, 1000),  # UDP
        ]
        packet = self._build_netflow_v5_packet(flows)

        results = parser.parse(packet)
        assert len(results) == 3

        protocols = {r.client_ip: r.protocol for r in results}
        assert protocols["192.168.1.100"] == "ICMP"
        assert protocols["192.168.1.101"] == "TCP"
        assert protocols["192.168.1.102"] == "UDP"
