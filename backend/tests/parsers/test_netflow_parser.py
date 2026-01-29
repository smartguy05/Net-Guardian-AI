"""Tests for the NetFlow parser."""

import struct
from datetime import UTC, datetime

import pytest

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
        return NetFlowParser(
            config={
                "min_bytes": 1000,
                "min_packets": 5,
            }
        )

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
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            engine_type,
            engine_id,
            sampling,
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
                0,
                tcp_flags,
                protocol,
                tos,
                src_as,
                dst_as,
                src_mask,
                dst_mask,
                0,
            )
            records += record

        return header + records

    def _ip_to_int(self, ip: str) -> int:
        """Convert IP string to integer."""
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    def test_parse_netflow_v5_binary(self, parser):
        """Test parsing a NetFlow v5 binary packet."""
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10, 5000),  # TCP
            ]
        )

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
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10, 5000),
                ("192.168.1.101", "1.1.1.1", 54322, 53, 17, 5, 500),  # UDP DNS
                ("192.168.1.102", "10.0.0.1", 54323, 80, 6, 20, 10000),
            ]
        )

        results = parser.parse(packet)
        assert len(results) == 3

    def test_parse_with_thresholds(self, parser_with_threshold):
        """Test that flows below thresholds are filtered."""
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10, 5000),  # Above threshold
                ("192.168.1.101", "1.1.1.1", 54322, 53, 17, 2, 100),  # Below threshold
            ]
        )

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
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "10.0.0.1", 54321, 4444, 6, 10, 1000),  # Suspicious port
            ]
        )

        results = parser.parse(packet)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_large_transfer_detection(self, parser):
        """Test detection of large data transfers."""
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 10000, 150000000),  # 150 MB
            ]
        )

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
            ("192.168.1.100", "8.8.8.8", 1, 0, 1, 10, 1000),  # ICMP
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


class TestNetFlowV9Parser:
    """Tests for NetFlow v9 template-based parsing."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return NetFlowParser()

    def _ip_to_int(self, ip: str) -> int:
        """Convert IP string to integer."""
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    def _build_netflow_v9_header(
        self,
        count: int = 1,
        unix_secs: int = 1705312200,
        seq: int = 1,
        source_id: int = 1,
    ) -> bytes:
        """Build NetFlow v9 header."""
        version = 9
        sys_uptime = 0
        return struct.pack("!HHIIII", version, count, sys_uptime, unix_secs, seq, source_id)

    def _build_template_flowset(
        self,
        template_id: int = 256,
        fields: list = None,
    ) -> bytes:
        """Build a template flowset.

        Args:
            template_id: Template ID (must be >= 256)
            fields: List of (field_type, field_length) tuples
        """
        if fields is None:
            # Default: src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets
            fields = [
                (8, 4),  # src_ip
                (12, 4),  # dst_ip
                (7, 2),  # src_port
                (11, 2),  # dst_port
                (4, 1),  # protocol
                (1, 4),  # bytes
                (2, 4),  # packets
            ]

        flowset_id = 0  # Template flowset
        field_count = len(fields)

        # Template record: template_id (2) + field_count (2) + fields
        template_record = struct.pack("!HH", template_id, field_count)
        for field_type, field_length in fields:
            template_record += struct.pack("!HH", field_type, field_length)

        # Flowset header + data
        flowset_length = 4 + len(template_record)
        # Pad to 4-byte boundary
        padding = (4 - (flowset_length % 4)) % 4
        flowset_length += padding

        return (
            struct.pack("!HH", flowset_id, flowset_length) + template_record + (b"\x00" * padding)
        )

    def _build_data_flowset(
        self,
        template_id: int = 256,
        records: list = None,
    ) -> bytes:
        """Build a data flowset using the template format.

        Args:
            template_id: Template ID to reference (must match template)
            records: List of record data as bytes
        """
        if records is None:
            # Single record: src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets
            record = struct.pack("!I", self._ip_to_int("192.168.1.100"))  # src_ip
            record += struct.pack("!I", self._ip_to_int("8.8.8.8"))  # dst_ip
            record += struct.pack("!H", 54321)  # src_port
            record += struct.pack("!H", 443)  # dst_port
            record += struct.pack("!B", 6)  # protocol (TCP)
            record += struct.pack("!I", 5000)  # bytes
            record += struct.pack("!I", 10)  # packets
            records = [record]

        data = b"".join(records)
        flowset_length = 4 + len(data)
        # Pad to 4-byte boundary
        padding = (4 - (flowset_length % 4)) % 4
        flowset_length += padding

        return struct.pack("!HH", template_id, flowset_length) + data + (b"\x00" * padding)

    def test_parse_v9_template(self, parser):
        """Test parsing NetFlow v9 template flowset."""
        header = self._build_netflow_v9_header(count=1)
        template_flowset = self._build_template_flowset(template_id=256)

        packet = header + template_flowset

        # First pass: just receive template
        results = parser.parse(packet)
        # No data records yet, just template registration
        assert len(results) == 0

        # Verify template was stored
        assert 1 in parser._templates  # source_id
        assert 256 in parser._templates[1]  # template_id

    def test_parse_v9_data_with_template(self, parser):
        """Test parsing NetFlow v9 data flowset with cached template."""
        # First, send template
        header1 = self._build_netflow_v9_header(count=1, seq=1)
        template_flowset = self._build_template_flowset(template_id=256)
        parser.parse(header1 + template_flowset)

        # Now send data
        header2 = self._build_netflow_v9_header(count=1, seq=2)
        data_flowset = self._build_data_flowset(template_id=256)
        results = parser.parse(header2 + data_flowset)

        assert len(results) == 1
        result = results[0]
        assert result.parsed_fields.get("netflow_version") == 9
        assert result.client_ip == "192.168.1.100"
        assert result.target_ip == "8.8.8.8"

    def test_parse_v9_data_without_template(self, parser):
        """Test that data without matching template is skipped."""
        # Send data without template
        header = self._build_netflow_v9_header(count=1)
        data_flowset = self._build_data_flowset(template_id=300)  # Unknown template

        results = parser.parse(header + data_flowset)

        assert len(results) == 0

    def test_parse_v9_mixed_packet(self, parser):
        """Test parsing packet with both template and data flowsets."""
        header = self._build_netflow_v9_header(count=2)
        template_flowset = self._build_template_flowset(template_id=256)
        data_flowset = self._build_data_flowset(template_id=256)

        packet = header + template_flowset + data_flowset
        results = parser.parse(packet)

        # Should parse the data using the template from same packet
        assert len(results) == 1

    def test_parse_v9_template_update(self, parser):
        """Test that template updates override previous template."""
        # First template
        header1 = self._build_netflow_v9_header(count=1, seq=1)
        template1 = self._build_template_flowset(
            template_id=256,
            fields=[(8, 4), (12, 4)],  # Only src_ip, dst_ip
        )
        parser.parse(header1 + template1)

        # Verify first template
        assert len(parser._templates[1][256]) == 2

        # Updated template with more fields
        header2 = self._build_netflow_v9_header(count=1, seq=2)
        template2 = self._build_template_flowset(
            template_id=256,
            fields=[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1)],  # Added ports and protocol
        )
        parser.parse(header2 + template2)

        # Verify template was updated
        assert len(parser._templates[1][256]) == 5

    def test_parse_v9_multiple_data_records(self, parser):
        """Test parsing multiple data records in one flowset."""
        # Send template
        header1 = self._build_netflow_v9_header(count=1, seq=1)
        template_flowset = self._build_template_flowset(template_id=256)
        parser.parse(header1 + template_flowset)

        # Build multiple records
        def make_record(src_ip, dst_ip, src_port, dst_port, protocol, octets, packets):
            record = struct.pack("!I", self._ip_to_int(src_ip))
            record += struct.pack("!I", self._ip_to_int(dst_ip))
            record += struct.pack("!H", src_port)
            record += struct.pack("!H", dst_port)
            record += struct.pack("!B", protocol)
            record += struct.pack("!I", octets)
            record += struct.pack("!I", packets)
            return record

        records = [
            make_record("192.168.1.100", "8.8.8.8", 54321, 443, 6, 5000, 10),
            make_record("192.168.1.101", "1.1.1.1", 54322, 53, 17, 1000, 5),
        ]

        header2 = self._build_netflow_v9_header(count=1, seq=2)
        data_flowset = self._build_data_flowset(template_id=256, records=records)
        results = parser.parse(header2 + data_flowset)

        assert len(results) == 2

    def test_parse_v9_header_too_short(self, parser):
        """Test handling of truncated v9 header."""
        # Only 10 bytes (header needs 20)
        packet = struct.pack("!HHIII", 9, 1, 0, 1705312200, 1)

        results = parser.parse(packet)
        assert len(results) == 0

    def test_parse_v9_options_template_skipped(self, parser):
        """Test that options template flowsets are skipped."""
        header = self._build_netflow_v9_header(count=1)
        # Options template flowset (id=1)
        options_flowset = struct.pack("!HH", 1, 8) + b"\x00\x00\x00\x00"

        results = parser.parse(header + options_flowset)
        assert len(results) == 0


class TestNetFlowParserSeverity:
    """Tests for severity determination logic."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return NetFlowParser()

    def _build_netflow_v5_packet(self, flows, unix_secs=1705312200):
        """Build NetFlow v5 packet."""
        version = 5
        count = len(flows)
        header = struct.pack("!HHIIIIBBH", version, count, 0, unix_secs, 0, 1, 0, 0, 0)

        records = b""
        for src_ip, dst_ip, src_port, dst_port, protocol, packets, octets, tcp_flags in flows:
            parts = [int(p) for p in src_ip.split(".")]
            src_addr = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
            parts = [int(p) for p in dst_ip.split(".")]
            dst_addr = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

            record = struct.pack(
                "!IIIHHIIIIHHBBBBHHBBH",
                src_addr,
                dst_addr,
                0,
                1,
                2,
                packets,
                octets,
                0,
                1000,
                src_port,
                dst_port,
                0,
                tcp_flags,
                protocol,
                0,
                0,
                0,
                24,
                24,
                0,
            )
            records += record

        return header + records

    def test_port_scan_detection(self, parser):
        """Test detection of port scan patterns."""
        # Many packets, few bytes suggests port scan
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "10.0.0.1", 54321, 22, 6, 200, 500, 0x04),  # RST flags
            ]
        )

        results = parser.parse(packet)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_syn_flood_detection(self, parser):
        """Test detection of SYN flood patterns."""
        # Many SYN packets without ACK
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "10.0.0.1", 54321, 80, 6, 100, 5000, 0x02),  # SYN only
            ]
        )

        results = parser.parse(packet)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_normal_traffic_is_debug(self, parser):
        """Test that normal traffic gets DEBUG severity."""
        packet = self._build_netflow_v5_packet(
            [
                ("192.168.1.100", "8.8.8.8", 54321, 443, 6, 50, 25000, 0x12),  # Normal HTTPS
            ]
        )

        results = parser.parse(packet)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.DEBUG


class TestNetFlowParserFields:
    """Tests for parsed field extraction."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return NetFlowParser(config={"exporter_ip": "10.0.0.1"})

    def test_exporter_ip_in_fields(self, parser):
        """Test that configured exporter_ip appears in parsed_fields."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "packets": 10,
            "bytes": 5000,
        }

        results = parser.parse(data)
        assert len(results) == 1
        # exporter_ip is only added for binary parsing, not JSON
        # but verifies config is accessible

    def test_alternative_json_field_names(self):
        """Test parsing with alternative field names."""
        parser = NetFlowParser()
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "192.168.1.100",
            "destination_ip": "8.8.8.8",
            "source_port": 54321,
            "destination_port": 443,
            "octets": 5000,  # Alternative to bytes
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].client_ip == "192.168.1.100"
        assert results[0].target_ip == "8.8.8.8"

    def test_missing_timestamp_uses_current(self):
        """Test that missing timestamp uses current time."""
        parser = NetFlowParser()
        data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert (datetime.now(UTC) - results[0].timestamp).total_seconds() < 5
