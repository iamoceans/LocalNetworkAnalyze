"""
Unit tests for protocol parsing module.
"""

import pytest
from datetime import datetime

from src.protocol.base import (
    ParsedHTTP,
    ParsedDNS,
    ParsedTCP,
    ParsedUDP,
    ProtocolDirection,
    DNSQuestion,
    DNSResourceRecord,
    ParseResult,
    get_direction_from_ports,
    is_text_content,
)
from src.protocol.http import HTTPParser, HTTPUtils, create_http_parser
from src.protocol.dns import DNSParser, DNSUtils, create_dns_parser
from src.protocol.tcp_udp import (
    TCPParser,
    UDPParser,
    TCPUtils,
    UDPUtils,
    create_tcp_parser,
    create_udp_parser,
)
from src.protocol import ParserFactory, create_parser_factory, parse_packet
from src.utils.constants import Port


@pytest.mark.unit
class TestProtocolDirection:
    """Test ProtocolDirection enum."""

    def test_direction_values(self):
        """Test direction enum values."""
        assert ProtocolDirection.REQUEST.value == "request"
        assert ProtocolDirection.RESPONSE.value == "response"
        assert ProtocolDirection.UNKNOWN.value == "unknown"


@pytest.mark.unit
class TestParsedHTTP:
    """Test ParsedHTTP data class."""

    def test_create_request(self):
        """Test creating HTTP request."""
        request = ParsedHTTP(
            protocol="HTTP",
            direction=ProtocolDirection.REQUEST,
            timestamp=datetime.now(),
            raw_data=b"GET / HTTP/1.1",
            method="GET",
            path="/",
            version="HTTP/1.1",
            headers={"Host": "example.com"},
            body=b"",
        )

        assert request.is_request()
        assert not request.is_response()
        assert request.method == "GET"
        assert request.path == "/"

    def test_create_response(self):
        """Test creating HTTP response."""
        response = ParsedHTTP(
            protocol="HTTP",
            direction=ProtocolDirection.RESPONSE,
            timestamp=datetime.now(),
            raw_data=b"HTTP/1.1 200 OK",
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers={"Content-Type": "text/html"},
            body=b"Hello",
        )

        assert response.is_response()
        assert not response.is_request()
        assert response.status_code == 200

    def test_request_without_method_fails(self):
        """Test that request without method raises error."""
        with pytest.raises(ValueError, match="must have method"):
            ParsedHTTP(
                protocol="HTTP",
                direction=ProtocolDirection.REQUEST,
                timestamp=datetime.now(),
                raw_data=b"",
            )

    def test_response_without_status_code_fails(self):
        """Test that response without status code raises error."""
        with pytest.raises(ValueError, match="must have status code"):
            ParsedHTTP(
                protocol="HTTP",
                direction=ProtocolDirection.RESPONSE,
                timestamp=datetime.now(),
                raw_data=b"",
            )

    def test_get_header_case_insensitive(self):
        """Test getting header case-insensitively."""
        http = ParsedHTTP(
            protocol="HTTP",
            direction=ProtocolDirection.REQUEST,
            timestamp=datetime.now(),
            raw_data=b"",
            method="GET",
            path="/",
            headers={"Content-Type": "text/html", "content-length": "123"},
        )

        assert http.get_header("content-type") == "text/html"
        assert http.get_header("CONTENT-TYPE") == "text/html"
        assert http.get_header("Content-Length") == "123"


@pytest.mark.unit
class TestParsedDNS:
    """Test ParsedDNS data class."""

    def test_create_dns_query(self):
        """Test creating DNS query."""
        question = DNSQuestion(name="example.com", type="A", class_="IN")

        dns = ParsedDNS(
            protocol="DNS",
            direction=ProtocolDirection.REQUEST,
            timestamp=datetime.now(),
            raw_data=b"",
            transaction_id=1234,
            flags=0x0100,
            is_query=True,
            is_response=False,
            questions=(question,),
        )

        assert dns.is_query
        assert not dns.is_response
        assert dns.get_domain() == "example.com"

    def test_create_dns_response(self):
        """Test creating DNS response."""
        question = DNSQuestion(name="example.com", type="A", class_="IN")
        answer = DNSResourceRecord(
            name="example.com", type="A", class_="IN", ttl=300, data="1.2.3.4"
        )

        dns = ParsedDNS(
            protocol="DNS",
            direction=ProtocolDirection.RESPONSE,
            timestamp=datetime.now(),
            raw_data=b"",
            transaction_id=1234,
            flags=0x8180,
            is_query=False,
            is_response=True,
            questions=(question,),
            answers=(answer,),
        )

        assert not dns.is_query
        assert dns.is_response
        assert not dns.has_error()


@pytest.mark.unit
class TestHTTPParser:
    """Test HTTP parser."""

    def test_can_parse_request(self):
        """Test identifying HTTP request."""
        parser = HTTPParser()
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

        assert parser.can_parse(data, "TCP")

    def test_can_parse_response(self):
        """Test identifying HTTP response."""
        parser = HTTPParser()
        data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

        assert parser.can_parse(data, "TCP")

    def test_cannot_parse_non_http(self):
        """Test rejecting non-HTTP data."""
        parser = HTTPParser()
        data = b"\x00\x01\x02\x03\x04\x05"

        assert not parser.can_parse(data, "TCP")

    def test_parse_simple_request(self, sample_http_request):
        """Test parsing simple HTTP request."""
        parser = HTTPParser()
        result = parser.parse(sample_http_request, "TCP")

        assert result.success
        assert isinstance(result.data, ParsedHTTP)
        assert result.data.method == "GET"
        assert result.data.path == "/index.html"
        assert result.data.version == "HTTP/1.1"

    def test_parse_simple_response(self, sample_http_response):
        """Test parsing simple HTTP response."""
        parser = HTTPParser()
        result = parser.parse(sample_http_response, "TCP")

        assert result.success
        assert isinstance(result.data, ParsedHTTP)
        assert result.data.status_code == 200
        assert result.data.reason == "OK"

    def test_parser_statistics(self):
        """Test parser statistics tracking."""
        parser = HTTPParser()

        # Parse some data
        data = b"GET / HTTP/1.1\r\n\r\n"
        parser.parse(data, "TCP")

        stats = parser.get_statistics()
        assert stats["parse_count"] == 1


@pytest.mark.unit
class TestDNSParser:
    """Test DNS parser."""

    def test_can_parse_dns(self):
        """Test identifying DNS."""
        parser = DNSParser()

        # Minimum DNS header size
        data = b"\x00" * 12
        assert parser.can_parse(data, "UDP")

    def test_cannot_parse_too_short(self):
        """Test rejecting too-short data."""
        parser = DNSParser()
        data = b"\x00" * 10

        assert not parser.can_parse(data, "UDP")

    def test_get_rcode_text(self):
        """Test response code text conversion."""
        parser = DNSParser()

        assert parser.get_rcode_text(0) == "NoError"
        assert parser.get_rcode_text(3) == "NXDomain"


@pytest.mark.unit
class TestTCPParser:
    """Test TCP parser."""

    def test_can_parse_tcp(self):
        """Test identifying TCP."""
        parser = TCPParser()
        data = b"\x00" * 20  # Minimum TCP header

        assert parser.can_parse(data, "TCP")

    def test_cannot_parse_non_tcp(self):
        """Test rejecting non-TCP data."""
        parser = TCPParser()
        data = b"\x00" * 20

        assert not parser.can_parse(data, "UDP")

    def test_parse_tcp_header(self):
        """Test parsing TCP header."""
        parser = TCPParser()
        # Simple TCP header (SYN packet)
        data = (
            b"\x00\x50"  # src_port = 80
            b"\x00\x50"  # dst_port = 80
            b"\x00\x00\x00\x01"  # seq = 1
            b"\x00\x00\x00\x00"  # ack = 0
            b"\x50"  # data_offset = 5 (20 bytes), flags = 0
            b"\x02"  # flags (SYN)
            b"\x20\x00"  # window = 8192
            b"\x00\x00"  # checksum
            b"\x00\x00"  # urgent
        )

        result = parser.parse(data, "TCP")

        assert result.success
        assert isinstance(result.data, ParsedTCP)


@pytest.mark.unit
class TestUDPParser:
    """Test UDP parser."""

    def test_can_parse_udp(self):
        """Test identifying UDP."""
        parser = UDPParser()
        data = b"\x00" * 8  # Minimum UDP header

        assert parser.can_parse(data, "UDP")

    def test_parse_udp_header(self):
        """Test parsing UDP header."""
        parser = UDPParser()
        data = (
            b"\x00\x35"  # src_port = 53 (DNS)
            b"\x00\x35"  # dst_port = 53
            b"\x00\x10"  # length = 16
            b"\x00\x00"  # checksum
        )

        result = parser.parse(data, "UDP")

        assert result.success
        assert isinstance(result.data, ParsedUDP)
        assert result.data.length == 16


@pytest.mark.unit
class TestTCPUtils:
    """Test TCP utility functions."""

    def test_is_syn_packet(self):
        """Test SYN flag detection."""
        flags = 0x02  # SYN
        assert TCPUtils.is_syn_packet(flags)

    def test_is_ack_packet(self):
        """Test ACK flag detection."""
        flags = 0x10  # ACK
        assert TCPUtils.is_ack_packet(flags)

    def test_is_syn_ack(self):
        """Test SYN-ACK detection."""
        flags = 0x12  # SYN + ACK
        assert TCPUtils.is_syn_ack(flags)

    def test_get_packet_type(self):
        """Test packet type determination."""
        assert TCPUtils.get_packet_type(0x02) == "SYN"
        assert TCPUtils.get_packet_type(0x12) == "SYN-ACK"
        assert TCPUtils.get_packet_type(0x11) == "FIN-ACK"
        assert TCPUtils.get_packet_type(0x10) == "ACK"
        assert TCPUtils.get_packet_type(0x04) == "RST"

    def test_get_flags_string(self):
        """Test flags string representation."""
        assert TCPUtils.get_flags_string(0x02) == "SYN"
        assert TCPUtils.get_flags_string(0x12) == "SYN,ACK"
        assert TCPUtils.get_flags_string(0x00) == "NONE"


@pytest.mark.unit
class TestUDPUtils:
    """Test UDP utility functions."""

    def test_get_payload_length(self):
        """Test payload length calculation."""
        assert UDPUtils.get_payload_length(16) == 8  # 16 - 8 header
        assert UDPUtils.get_payload_length(8) == 0

    def test_is_dns(self):
        """Test DNS traffic detection."""
        assert UDPUtils.is_dns(53, 12345)
        assert UDPUtils.is_dns(12345, 53)
        assert not UDPUtils.is_dns(80, 12345)

    def test_is_dhcp(self):
        """Test DHCP traffic detection."""
        assert UDPUtils.is_dhcp(67, 68)
        assert UDPUtils.is_dhcp(68, 67)
        assert not UDPUtils.is_dhcp(80, 12345)


@pytest.mark.unit
class TestParserFactory:
    """Test parser factory."""

    def test_create_factory(self):
        """Test creating factory with default parsers."""
        factory = create_parser_factory()

        assert "http" in factory.list_protocols()
        assert "dns" in factory.list_protocols()
        assert "tcp" in factory.list_protocols()
        assert "udp" in factory.list_protocols()

    def test_get_parser(self):
        """Test getting specific parser."""
        factory = create_parser_factory()

        http_parser = factory.get_parser("http")
        assert isinstance(http_parser, HTTPParser)

    def test_register_parser(self):
        """Test registering custom parser."""
        factory = create_parser_factory()

        # Register same parser under different name
        custom_parser = HTTPParser()
        factory.register_parser("custom_http", custom_parser)

        assert "custom_http" in factory.list_protocols()
        assert factory.get_parser("custom_http") is custom_parser

    def test_unregister_parser(self):
        """Test unregistering parser."""
        factory = create_parser_factory()

        assert factory.unregister_parser("http")
        assert "http" not in factory.list_protocols()

    def test_parse_http(self, sample_http_request):
        """Test parsing HTTP through factory."""
        factory = create_parser_factory()
        result = factory.parse(sample_http_request, "TCP")

        assert result.success
        assert isinstance(result.data, ParsedHTTP)

    def test_parse_all(self, sample_http_request):
        """Test parsing with all compatible parsers."""
        factory = create_parser_factory()
        results = factory.parse_all(sample_http_request, "TCP")

        # Should have at least one result (HTTP)
        assert len(results) >= 1

    def test_get_statistics(self):
        """Test factory statistics."""
        factory = create_parser_factory()
        data = b"GET / HTTP/1.1\r\n\r\n"

        factory.parse(data, "TCP")
        stats = factory.get_statistics()

        assert stats["parse_count"] == 1
        assert "http" in stats["protocols"]


@pytest.mark.unit
class TestParseResult:
    """Test ParseResult class."""

    def test_ok_result(self):
        """Test creating successful result."""
        data = ParsedHTTP(
            protocol="HTTP",
            direction=ProtocolDirection.REQUEST,
            timestamp=datetime.now(),
            raw_data=b"",
            method="GET",
            path="/",
        )

        result = ParseResult.ok(data)

        assert result.success
        assert result.data is data
        assert result.error is None

    def test_fail_result(self):
        """Test creating failed result."""
        result = ParseResult.fail("Parse error")

        assert not result.success
        assert result.data is None
        assert result.error == "Parse error"

    def test_bool_conversion(self):
        """Test boolean conversion."""
        ok_result = ParseResult.fail("error")
        fail_result = ParseResult.fail("error")

        assert not ok_result
        assert not fail_result


@pytest.mark.unit
class TestUtilityFunctions:
    """Test utility functions."""

    def test_get_direction_from_ports_http(self):
        """Test direction detection for HTTP."""
        assert get_direction_from_ports(12345, 80) == ProtocolDirection.REQUEST
        assert get_direction_from_ports(80, 12345) == ProtocolDirection.RESPONSE

    def test_get_direction_from_ports_unknown(self):
        """Test direction detection for ephemeral ports."""
        assert get_direction_from_ports(50000, 50001) == ProtocolDirection.UNKNOWN

    def test_is_text_content(self):
        """Test text content type detection."""
        assert is_text_content("text/html")
        assert is_text_content("application/json")
        assert is_text_content("application/xml")
        assert not is_text_content("image/png")
        assert not is_text_content("application/octet-stream")
