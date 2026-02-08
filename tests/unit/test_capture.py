"""
Unit tests for packet capture module.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, Mock

from src.capture.base import (
    PacketInfo,
    CaptureState,
    PacketCapture,
    validate_interface,
    validate_bpf_filter,
)
from src.capture.scapy_capture import ScapyCapture
from src.capture import create_capture, get_available_interfaces
from src.core.exceptions import (
    CaptureError,
    InterfaceNotFoundError,
)


@pytest.mark.unit
class TestPacketInfo:
    """Test PacketInfo data class."""

    def test_create_valid_packet(self):
        """Test creating a valid packet."""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        packet = PacketInfo(
            timestamp=timestamp,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1000,
            raw_data=b"test data",
        )

        assert packet.timestamp == timestamp
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.src_port == 12345
        assert packet.dst_port == 80
        assert packet.protocol == "TCP"
        assert packet.length == 1000
        assert packet.raw_data == b"test data"

    def test_packet_without_ports(self):
        """Test creating packet without ports (ICMP)."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            length=64,
            raw_data=b"icmp data",
        )

        assert packet.src_port is None
        assert packet.dst_port is None

    def test_invalid_port_raises_error(self):
        """Test that invalid port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source port"):
            PacketInfo(
                timestamp=datetime.now(),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=70000,  # Invalid port
                dst_port=80,
                protocol="TCP",
                length=1000,
                raw_data=b"test",
            )

    def test_invalid_length_raises_error(self):
        """Test that invalid length raises ValueError."""
        with pytest.raises(ValueError, match="Invalid packet length"):
            PacketInfo(
                timestamp=datetime.now(),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=80,
                dst_port=80,
                protocol="TCP",
                length=-1,  # Invalid length
                raw_data=b"test",
            )

    def test_empty_ip_raises_error(self):
        """Test that empty IP raises ValueError."""
        with pytest.raises(ValueError, match="Source IP cannot be empty"):
            PacketInfo(
                timestamp=datetime.now(),
                src_ip="",  # Empty IP
                dst_ip="192.168.1.2",
                src_port=80,
                dst_port=80,
                protocol="TCP",
                length=1000,
                raw_data=b"test",
            )

    def test_with_raw_data(self):
        """Test creating new packet with different raw data."""
        original = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=80,
            protocol="TCP",
            length=8,
            raw_data=b"original",
        )

        new_packet = original.with_raw_data(b"modified")

        # Should have new raw data and updated length
        assert new_packet.raw_data == b"modified"
        assert new_packet.length == 8

        # Other fields should be the same
        assert new_packet.src_ip == original.src_ip
        assert new_packet.dst_ip == original.dst_ip

    def test_get_connection_key(self):
        """Test getting connection key."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1000,
            raw_data=b"test",
        )

        key = packet.get_connection_key()
        assert key == ("192.168.1.1", "192.168.1.2", 12345, 80)

    def test_get_connection_key_without_ports(self):
        """Test connection key with no ports."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            length=64,
            raw_data=b"test",
        )

        key = packet.get_connection_key()
        assert key == ("192.168.1.1", "192.168.1.2", 0, 0)

    def test_is_bidirectional_pair(self):
        """Test bidirectional pair detection."""
        packet1 = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1000,
            raw_data=b"test",
        )

        packet2 = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=80,
            dst_port=12345,
            protocol="TCP",
            length=500,
            raw_data=b"response",
        )

        assert packet1.is_bidirectional_pair(packet2)
        assert packet2.is_bidirectional_pair(packet1)

    def test_frozen_dataclass(self):
        """Test that PacketInfo is frozen (immutable)."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=80,
            protocol="TCP",
            length=1000,
            raw_data=b"test",
        )

        # Attempting to modify should raise an error
        with pytest.raises(Exception):  # FrozenInstanceError
            packet.src_ip = "192.168.1.3"


@pytest.mark.unit
class TestCaptureState:
    """Test CaptureState enum."""

    def test_state_values(self):
        """Test state enum values."""
        assert CaptureState.STOPPED.value == "stopped"
        assert CaptureState.STARTING.value == "starting"
        assert CaptureState.RUNNING.value == "running"
        assert CaptureState.STOPPING.value == "stopping"
        assert CaptureState.ERROR.value == "error"


@pytest.mark.unit
class TestPacketCaptureAbstract:
    """Test PacketCapture abstract base class."""

    def test_cannot_instantiate_abstract(self):
        """Test that abstract class cannot be instantiated."""
        with pytest.raises(TypeError):
            PacketCapture(interface="eth0")

    def test_concrete_implementation(self):
        """Test that concrete implementation can be created."""

        class ConcreteCapture(PacketCapture):
            def start_capture(self):
                self._set_state(CaptureState.RUNNING)

            def stop_capture(self):
                self._set_state(CaptureState.STOPPED)

            def get_packets(self):
                return iter([])

        capture = ConcreteCapture(interface="eth0")
        assert capture.interface == "eth0"
        assert capture.state == CaptureState.STOPPED

    def test_add_callback(self):
        """Test adding callbacks."""

        class ConcreteCapture(PacketCapture):
            def start_capture(self):
                pass

            def stop_capture(self):
                pass

            def get_packets(self):
                return iter([])

        capture = ConcreteCapture(interface="eth0")
        callback = MagicMock()

        capture.add_callback(callback)
        assert callback in capture._callbacks

    def test_remove_callback(self):
        """Test removing callbacks."""

        class ConcreteCapture(PacketCapture):
            def start_capture(self):
                pass

            def stop_capture(self):
                pass

            def get_packets(self):
                return iter([])

        capture = ConcreteCapture(interface="eth0")
        callback = MagicMock()

        capture.add_callback(callback)
        capture.remove_callback(callback)

        assert callback not in capture._callbacks

    def test_statistics(self):
        """Test statistics tracking."""

        class ConcreteCapture(PacketCapture):
            def start_capture(self):
                self._set_state(CaptureState.RUNNING)

            def stop_capture(self):
                self._set_state(CaptureState.STOPPED)

            def get_packets(self):
                return iter([])

        capture = ConcreteCapture(interface="eth0")
        capture._increment_captured()
        capture._increment_captured()
        capture._increment_dropped()

        assert capture.packets_captured == 2
        assert capture.packets_dropped == 1

        stats = capture.get_statistics()
        assert stats["packets_captured"] == 2
        assert stats["packets_dropped"] == 1

    def test_reset_statistics(self):
        """Test resetting statistics."""

        class ConcreteCapture(PacketCapture):
            def start_capture(self):
                pass

            def stop_capture(self):
                pass

            def get_packets(self):
                return iter([])

        capture = ConcreteCapture(interface="eth0")
        capture._increment_captured()
        capture.reset_statistics()

        assert capture.packets_captured == 0


@pytest.mark.unit
class TestValidateFunctions:
    """Test validation utility functions."""

    def test_validate_interface_valid(self):
        """Test valid interface names."""
        assert validate_interface("eth0")
        assert validate_interface("wlan0")
        assert validate_interface("en0")
        assert validate_interface("")  # Empty is valid (default)
        assert validate_interface("br-0")

    def test_validate_interface_invalid(self):
        """Test invalid interface names."""
        assert not validate_interface("eth$0")  # Invalid character
        assert not validate_interface("wlan@")  # Invalid character

    def test_validate_bpf_filter_valid(self):
        """Test valid BPF filters."""
        assert validate_bpf_filter("")
        assert validate_bpf_filter("tcp port 80")
        assert validate_bpf_filter("host 192.168.1.1")
        assert validate_bpf_filter("tcp and port 443")

    def test_validate_bpf_filter_unbalanced_parens(self):
        """Test BPF filter with unbalanced parentheses."""
        assert not validate_bpf_filter("(tcp port 80")
        assert not validate_bpf_filter("tcp port 80)")

    def test_validate_bpf_filter_unbalanced_quotes(self):
        """Test BPF filter with unbalanced quotes."""
        assert not validate_bpf_filter('host "example.com')


@pytest.mark.unit
class TestScapyCapture:
    """Test ScapyCapture class."""

    def test_init_default(self):
        """Test initialization with defaults."""
        capture = ScapyCapture()

        assert capture.interface == ""
        assert capture.buffer_size == 1000
        assert capture.promiscuous is True

    def test_init_with_params(self):
        """Test initialization with parameters."""
        capture = ScapyCapture(
            interface="eth0",
            filter="tcp port 80",
            buffer_size=500,
            promiscuous=False,
            timeout=60,
        )

        assert capture.interface == "eth0"
        assert capture.filter == "tcp port 80"
        assert capture.buffer_size == 500
        assert capture.promiscuous is False

    def test_initial_state(self):
        """Test initial state is STOPPED."""
        capture = ScapyCapture()
        assert capture.state == CaptureState.STOPPED
        assert not capture.is_running

    def test_get_interfaces_static_method(self):
        """Test getting interfaces list."""
        # This will return actual interfaces on the system
        interfaces = ScapyCapture.get_interfaces()
        assert isinstance(interfaces, list)


@pytest.mark.unit
class TestCreateCapture:
    """Test create_capture factory function."""

    def test_create_default_backend(self):
        """Test creating capture with default backend."""
        capture = create_capture()
        assert isinstance(capture, ScapyCapture)

    def test_create_scapy_backend(self):
        """Test creating capture with scapy backend."""
        capture = create_capture(backend="scapy")
        assert isinstance(capture, ScapyCapture)

    def test_create_invalid_backend(self):
        """Test creating capture with invalid backend."""
        with pytest.raises(ValueError, match="Unsupported capture backend"):
            create_capture(backend="invalid")

    def test_create_with_parameters(self):
        """Test creating capture with parameters."""
        capture = create_capture(
            interface="eth0",
            filter="tcp port 80",
            buffer_size=500,
        )

        assert isinstance(capture, ScapyCapture)
        assert capture.interface == "eth0"
        assert capture.filter == "tcp port 80"
        assert capture.buffer_size == 500


@pytest.mark.unit
class TestGetAvailableInterfaces:
    """Test get_available_interfaces function."""

    def test_returns_list(self):
        """Test that function returns a list."""
        interfaces = get_available_interfaces()
        assert isinstance(interfaces, list)

    def test_interface_structure(self):
        """Test that interface dict has expected keys."""
        interfaces = get_available_interfaces()
        if interfaces:  # Only test if interfaces are available
            iface = interfaces[0]
            assert "name" in iface
            assert "address" in iface
            assert "description" in iface
