"""Tests for src.capture.base module."""

import pytest
from datetime import datetime
from src.capture.base import PacketInfo, PacketCapture


class TestPacketInfo:
    """Tests for PacketInfo dataclass."""

    def test_create_packet_info_minimal(self):
        """Test creating PacketInfo with minimal required fields."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=None,
            dst_port=None,
            protocol="TCP",
            length=1024,
            raw_data=b"test data"
        )
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.protocol == "TCP"

    def test_create_packet_info_full(self):
        """Test creating PacketInfo with all fields."""
        now = datetime.now()
        packet = PacketInfo(
            timestamp=now,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=8080,
            dst_port=80,
            protocol="HTTP",
            length=2048,
            raw_data=b"GET / HTTP/1.1\r\nHost: example.com",
            url="http://example.com",
            host="example.com"
        )
        assert packet.src_port == 8080
        assert packet.dst_port == 80
        assert packet.url == "http://example.com"

    def test_packet_info_optional_ports(self):
        """Test PacketInfo with optional port fields."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            length=64,
            raw_data=b"ping"
        )
        assert packet.src_port is None
        assert packet.dst_port is None


class TestPacketCapture:
    """Tests for PacketCapture abstract base class."""

    def test_packet_capture_has_abstract_methods(self):
        """Test that PacketCapture has required abstract methods."""
        abstract_methods = PacketCapture.__abstractmethods__
        assert 'start_capture' in abstract_methods
        assert 'stop_capture' in abstract_methods

    def test_cannot_instantiate_abstract_class(self):
        """Test that PacketCapture cannot be instantiated directly."""
        with pytest.raises(TypeError):
            PacketCapture()
