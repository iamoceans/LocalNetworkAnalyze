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


@pytest.mark.unit
class TestTrafficAggregator:
    """Test TrafficAggregator class."""

    def test_init_default(self):
        """Test initialization with default max_entries."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()
        assert aggregator._max_entries == 30

    def test_init_custom_max_entries(self):
        """Test initialization with custom max_entries."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator(max_entries=100)
        assert aggregator._max_entries == 100

    def test_add_single_packet(self):
        """Test adding a single packet."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()
        packet = PacketInfo(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            src_ip="192.168.1.1",
            dst_ip="93.184.216.34",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"GET / HTTP/1.1",
        )

        aggregator.add_packet(packet)

        top = aggregator.get_top_destinations(10)
        assert len(top) == 1
        assert top[0]['dst_ip'] == "93.184.216.34"
        assert top[0]['dst_port'] == 80
        assert top[0]['total_bytes'] == 1500
        assert top[0]['packet_count'] == 1

    def test_add_multiple_packets_same_destination(self):
        """Test adding multiple packets to same destination."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        for i in range(5):
            packet = PacketInfo(
                timestamp=datetime(2024, 1, 1, 12, i, 0),
                src_ip="192.168.1.1",
                dst_ip="93.184.216.34",
                src_port=12345 + i,
                dst_port=80,
                protocol="TCP",
                length=1000 + i * 100,
                raw_data=b"data",
            )
            aggregator.add_packet(packet)

        top = aggregator.get_top_destinations(10)
        assert len(top) == 1
        assert top[0]['total_bytes'] == 6000  # Sum: 1000+1100+1200+1300+1400
        assert top[0]['packet_count'] == 5

    def test_add_multiple_destinations(self):
        """Test adding packets to multiple destinations."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        # Add packets to 3 different destinations
        packets_data = [
            ("1.1.1.1", 80, 5000),
            ("2.2.2.2", 443, 8000),
            ("3.3.3.3", 22, 3000),
        ]

        for dst_ip, dst_port, length in packets_data:
            packet = PacketInfo(
                timestamp=datetime(2024, 1, 1, 12, 0, 0),
                src_ip="192.168.1.1",
                dst_ip=dst_ip,
                src_port=12345,
                dst_port=dst_port,
                protocol="TCP",
                length=length,
                raw_data=b"data",
            )
            aggregator.add_packet(packet)

        top = aggregator.get_top_destinations(10)

        # Should return 3 destinations, sorted by traffic
        assert len(top) == 3
        assert top[0]['dst_ip'] == "2.2.2.2"  # 8000 bytes
        assert top[1]['dst_ip'] == "1.1.1.1"  # 5000 bytes
        assert top[2]['dst_ip'] == "3.3.3.3"  # 3000 bytes

    def test_get_top_destinations_respects_limit(self):
        """Test that get_top_destinations respects limit parameter."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        # Add 10 destinations
        for i in range(10):
            packet = PacketInfo(
                timestamp=datetime(2024, 1, 1, 12, 0, 0),
                src_ip="192.168.1.1",
                dst_ip=f"{i}.1.1.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                length=1000 * (10 - i),  # Reverse order to test sorting
                raw_data=b"data",
            )
            aggregator.add_packet(packet)

        top_5 = aggregator.get_top_destinations(5)
        assert len(top_5) == 5

        top_10 = aggregator.get_top_destinations(10)
        assert len(top_10) == 10

    def test_packet_with_host_and_url(self):
        """Test packet with host and URL information."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        packet = PacketInfo(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            src_ip="192.168.1.1",
            dst_ip="93.184.216.34",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            host="example.com",
            url="http://example.com/",
        )

        aggregator.add_packet(packet)

        top = aggregator.get_top_destinations(10)
        assert len(top) == 1
        assert top[0]['host'] == "example.com"
        assert top[0]['url'] == "http://example.com/"

    def test_packet_with_none_port(self):
        """Test packet with None destination port."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        packet = PacketInfo(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            src_ip="192.168.1.1",
            dst_ip="1.1.1.1",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            length=64,
            raw_data=b"icmp data",
        )

        aggregator.add_packet(packet)

        top = aggregator.get_top_destinations(10)
        assert len(top) == 1
        assert top[0]['dst_port'] is None

    def test_get_stats_snapshot(self):
        """Test getting statistics snapshot for change detection."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        # Empty snapshot
        snapshot = aggregator.get_stats_snapshot()
        assert len(snapshot) == 0

        # Add packets
        packet = PacketInfo(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            src_ip="192.168.1.1",
            dst_ip="1.1.1.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"data",
        )
        aggregator.add_packet(packet)

        snapshot = aggregator.get_stats_snapshot()
        assert len(snapshot) == 1
        assert "1.1.1.1:80" in snapshot
        assert snapshot["1.1.1.1:80"] == 1500

    def test_clear(self):
        """Test clearing all statistics."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        # Add some packets
        for i in range(3):
            packet = PacketInfo(
                timestamp=datetime(2024, 1, 1, 12, 0, 0),
                src_ip="192.168.1.1",
                dst_ip=f"{i}.1.1.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                length=1000,
                raw_data=b"data",
            )
            aggregator.add_packet(packet)

        assert len(aggregator.get_stats_snapshot()) == 3

        aggregator.clear()

        assert len(aggregator.get_stats_snapshot()) == 0
        assert aggregator._cached_top is None

    def test_caching_behavior(self):
        """Test that caching works for repeated calls."""
        from src.gui.capture_panel import TrafficAggregator

        aggregator = TrafficAggregator()

        packet = PacketInfo(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            src_ip="192.168.1.1",
            dst_ip="1.1.1.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"data",
        )
        aggregator.add_packet(packet)

        # First call builds cache
        top1 = aggregator.get_top_destinations(10)
        assert top1 is not None

        # Second call with same or smaller limit should use cache
        top2 = aggregator.get_top_destinations(10)
        assert top2 is not None

        # Results should be identical
        assert len(top1) == len(top2)
        assert top1[0]['dst_ip'] == top2[0]['dst_ip']

    def test_thread_safety(self):
        """Test that aggregator is thread-safe."""
        from src.gui.capture_panel import TrafficAggregator
        import threading

        aggregator = TrafficAggregator(max_entries=100)
        errors = []

        def add_packets(thread_id):
            try:
                for i in range(50):
                    packet = PacketInfo(
                        timestamp=datetime(2024, 1, 1, 12, 0, 0),
                        src_ip="192.168.1.1",
                        dst_ip=f"{thread_id}.{i}.1.1",
                        src_port=12345,
                        dst_port=80,
                        protocol="TCP",
                        length=100,
                        raw_data=b"data",
                    )
                    aggregator.add_packet(packet)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for i in range(3):
            t = threading.Thread(target=add_packets, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # No errors should have occurred
        assert len(errors) == 0

        # Should have all packets aggregated
        snapshot = aggregator.get_stats_snapshot()
        assert len(snapshot) == 150  # 3 threads * 50 packets
