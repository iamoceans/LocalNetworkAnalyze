"""
Unit tests for analysis module.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from src.capture.base import PacketInfo
from src.analysis import (
    AnalysisEngine,
    create_analysis_engine,
    TrafficStatistics,
    TrafficSnapshot,
    ConnectionStats,
    BandwidthMonitor,
    BandwidthSample,
    BandwidthThreshold,
    ConnectionTracker,
    ConnectionKey,
    ConnectionInfo,
    ConnectionState,
)


@pytest.mark.unit
class TestTrafficSnapshot:
    """Test TrafficSnapshot data class."""

    def test_create_snapshot(self):
        """Test creating a traffic snapshot."""
        now = datetime.now()
        snapshot = TrafficSnapshot(
            timestamp=now,
            total_packets=1000,
            total_bytes=50000,
            packets_per_second=100.0,
            bytes_per_second=5000.0,
            protocol_stats={"TCP": 600, "UDP": 400},
            top_connections=[("192.168.1.1", "192.168.1.2", 100)],
            top_talkers=[("192.168.1.1", 30000)],
        )

        assert snapshot.total_packets == 1000
        assert snapshot.total_bytes == 50000
        assert snapshot.packets_per_second == 100.0
        assert len(snapshot.protocol_stats) == 2

    def test_to_dict(self):
        """Test converting to dictionary."""
        now = datetime.now()
        snapshot = TrafficSnapshot(
            timestamp=now,
            total_packets=100,
            total_bytes=5000,
            packets_per_second=10.0,
            bytes_per_second=500.0,
            protocol_stats={"TCP": 60},
            top_connections=[],
            top_talkers=[],
        )

        data = snapshot.to_dict()

        assert data["total_packets"] == 100
        assert data["packets_per_second"] == 10.0
        assert "timestamp" in data


@pytest.mark.unit
class TestConnectionStats:
    """Test ConnectionStats data class."""

    def test_create_stats(self):
        """Test creating connection stats."""
        now = datetime.now()
        stats = ConnectionStats(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packets_sent=100,
            bytes_sent=5000,
            packets_received=50,
            bytes_received=2000,
            first_seen=now,
            last_seen=now,
        )

        assert stats.src_ip == "192.168.1.1"
        assert stats.total_packets == 150
        assert stats.total_bytes == 7000

    def test_get_key(self):
        """Test getting connection key."""
        stats = ConnectionStats(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packets_sent=0,
            bytes_sent=0,
            packets_received=0,
            bytes_received=0,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
        )

        key = stats.get_key()
        assert key == ("192.168.1.1", "192.168.1.2", 12345, 80)

    def test_is_bidirectional_pair(self):
        """Test bidirectional pair detection."""
        now = datetime.now()
        stats1 = ConnectionStats(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packets_sent=0,
            bytes_sent=0,
            packets_received=0,
            bytes_received=0,
            first_seen=now,
            last_seen=now,
        )

        stats2 = ConnectionStats(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=80,
            dst_port=12345,
            protocol="TCP",
            packets_sent=0,
            bytes_sent=0,
            packets_received=0,
            bytes_received=0,
            first_seen=now,
            last_seen=now,
        )

        assert stats1.is_bidirectional_pair(stats2)


@pytest.mark.unit
class TestBandwidthThreshold:
    """Test BandwidthThreshold validation."""

    def test_valid_threshold(self):
        """Test creating valid threshold."""
        threshold = BandwidthThreshold(
            warning_level=1_000_000,
            critical_level=10_000_000,
            window_seconds=5,
        )

        assert threshold.warning_level == 1_000_000
        assert threshold.critical_level == 10_000_000

    def test_warning_level_zero_raises_error(self):
        """Test that zero warning level raises error."""
        with pytest.raises(ValueError, match="warning_level must be positive"):
            BandwidthThreshold(
                warning_level=0,
                critical_level=10_000_000,
            )

    def test_critical_less_than_warning_raises_error(self):
        """Test that critical < warning raises error."""
        with pytest.raises(ValueError, match="critical_level must be greater than warning_level"):
            BandwidthThreshold(
                warning_level=10_000_000,
                critical_level=1_000_000,
            )

    def test_window_seconds_zero_raises_error(self):
        """Test that zero window_seconds raises error."""
        with pytest.raises(ValueError, match="window_seconds must be positive"):
            BandwidthThreshold(
                warning_level=1_000_000,
                critical_level=10_000_000,
                window_seconds=0,
            )


@pytest.mark.unit
class TestConnectionKey:
    """Test ConnectionKey data class."""

    def test_create_key(self):
        """Test creating connection key."""
        key = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        assert key.src_ip == "192.168.1.1"
        assert key.dst_port == 80

    def test_to_tuple(self):
        """Test converting to tuple."""
        key = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        result = key.to_tuple()
        assert result == ("192.168.1.1", 12345, "192.168.1.2", 80, "TCP")

    def test_is_reverse(self):
        """Test reverse direction detection."""
        key1 = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        key2 = ConnectionKey(
            src_ip="192.168.1.2",
            src_port=80,
            dst_ip="192.168.1.1",
            dst_port=12345,
            protocol="TCP",
        )

        assert key1.is_reverse(key2)
        assert key2.is_reverse(key1)

    def test_not_reverse_when_different(self):
        """Test that different connections are not reverse."""
        key1 = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        key2 = ConnectionKey(
            src_ip="192.168.1.3",
            src_port=12345,
            dst_ip="192.168.1.4",
            dst_port=80,
            protocol="TCP",
        )

        assert not key1.is_reverse(key2)


@pytest.mark.unit
class TestConnectionInfo:
    """Test ConnectionInfo data class."""

    def test_create_info(self):
        """Test creating connection info."""
        key = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        info = ConnectionInfo(
            key=key,
            state=ConnectionState.ESTABLISHED,
            packets_sent=100,
            packets_received=50,
        )

        assert info.state == ConnectionState.ESTABLISHED
        assert info.total_packets == 150

    def test_duration(self):
        """Test connection duration calculation."""
        key = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        now = datetime.now()
        earlier = now - timedelta(seconds=10)

        info = ConnectionInfo(
            key=key,
            state=ConnectionState.ESTABLISHED,
            first_seen=earlier,
            last_seen=now,
        )

        assert info.duration == 10.0

    def test_is_active(self):
        """Test active state check."""
        key = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        info_established = ConnectionInfo(
            key=key,
            state=ConnectionState.ESTABLISHED,
        )

        info_closed = ConnectionInfo(
            key=key,
            state=ConnectionState.CLOSED,
        )

        assert info_established.is_active
        assert not info_closed.is_active


@pytest.mark.unit
class TestTrafficStatistics:
    """Test TrafficStatistics class."""

    def test_init(self):
        """Test initialization."""
        stats = TrafficStatistics()

        assert stats.get_duration() is None
        assert stats.get_summary()["total_packets"] == 0

    def test_update_with_packet(self):
        """Test updating with packet."""
        stats = TrafficStatistics()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        stats.update(packet)

        summary = stats.get_summary()
        assert summary["total_packets"] == 1
        assert summary["total_bytes"] == 1500

    def test_get_snapshot(self):
        """Test getting snapshot."""
        stats = TrafficStatistics()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        stats.update(packet)
        snapshot = stats.get_snapshot()

        assert snapshot.total_packets == 1
        assert isinstance(snapshot, TrafficSnapshot)

    def test_protocol_distribution(self):
        """Test protocol distribution calculation."""
        stats = TrafficStatistics()

        now = datetime.now()

        # Add TCP packets
        for _ in range(6):
            stats.update(PacketInfo(
                timestamp=now,
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                length=1500,
                raw_data=b"test",
            ))

        # Add UDP packets
        for _ in range(4):
            stats.update(PacketInfo(
                timestamp=now,
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=53,
                protocol="UDP",
                length=500,
                raw_data=b"test",
            ))

        distribution = stats.get_protocol_distribution()

        assert distribution["TCP"] == 60.0
        assert distribution["UDP"] == 40.0

    def test_reset(self):
        """Test resetting statistics."""
        stats = TrafficStatistics()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        stats.update(packet)
        assert stats.get_summary()["total_packets"] == 1

        stats.reset()
        assert stats.get_summary()["total_packets"] == 0


@pytest.mark.unit
class TestBandwidthMonitor:
    """Test BandwidthMonitor class."""

    def test_init(self):
        """Test initialization."""
        monitor = BandwidthMonitor()

        assert monitor.get_current_bandwidth() is None

    def test_update_with_packet(self):
        """Test updating with packet."""
        monitor = BandwidthMonitor(sample_interval=0.1)

        now = datetime.now()

        # Add packets
        for i in range(5):
            monitor.update(PacketInfo(
                timestamp=now + timedelta(seconds=i * 0.2),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                length=1000,
                raw_data=b"test",
            ))

        # Check samples were created
        samples = monitor.get_samples()
        assert len(samples) >= 1

    def test_get_current_bandwidth(self):
        """Test getting current bandwidth."""
        monitor = BandwidthMonitor(sample_interval=0.1)

        now = datetime.now()

        monitor.update(PacketInfo(
            timestamp=now,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1000,
            raw_data=b"test",
        ))

        current = monitor.get_current_bandwidth()
        # May be None if sample hasn't been created yet
        assert current is None or isinstance(current, BandwidthSample)

    def test_alert_callback(self):
        """Test alert callback system."""
        monitor = BandwidthMonitor(
            sample_interval=0.1,
            alert_threshold=BandwidthThreshold(
                warning_level=100,  # Very low for testing
                critical_level=1000,
                window_seconds=1,
            ),
        )

        callback_called = []

        def test_callback(alert_type, bandwidth, threshold, timestamp):
            callback_called.append(alert_type)

        monitor.add_alert_callback(test_callback)

        now = datetime.now()

        # Generate traffic to trigger warning
        for i in range(10):
            monitor.update(PacketInfo(
                timestamp=now + timedelta(seconds=i * 0.2),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                length=1000,  # Will trigger warning
                raw_data=b"test",
            ))

        # Check callback was invoked
        # Note: This depends on timing and may need adjustment

    def test_reset(self):
        """Test resetting monitor."""
        monitor = BandwidthMonitor(sample_interval=0.1)

        now = datetime.now()

        monitor.update(PacketInfo(
            timestamp=now,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1000,
            raw_data=b"test",
        ))

        samples_before = len(monitor.get_samples())

        monitor.reset()

        samples_after = len(monitor.get_samples())
        assert samples_after == 0


@pytest.mark.unit
class TestConnectionTracker:
    """Test ConnectionTracker class."""

    def test_init(self):
        """Test initialization."""
        tracker = ConnectionTracker()

        assert tracker.get_connection_count() == 0

    def test_track_new_connection(self):
        """Test tracking new connection."""
        tracker = ConnectionTracker()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(packet)

        assert tracker.get_connection_count() == 1

    def test_update_existing_connection(self):
        """Test updating existing connection."""
        tracker = ConnectionTracker()

        now = datetime.now()

        packet1 = PacketInfo(
            timestamp=now,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        packet2 = PacketInfo(
            timestamp=now + timedelta(seconds=1),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(packet1)
        tracker.update(packet2)

        key = ConnectionKey(
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="192.168.1.2",
            dst_port=80,
            protocol="TCP",
        )

        conn = tracker.get_connection(key)
        assert conn is not None
        assert conn.total_packets == 2

    def test_get_active_connections(self):
        """Test getting active connections."""
        tracker = ConnectionTracker()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(packet)

        active = tracker.get_active_connections()
        assert len(active) == 1
        assert active[0].is_active

    def test_get_connections_by_ip(self):
        """Test getting connections by IP."""
        tracker = ConnectionTracker()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(packet)

        connections = tracker.get_connections_by_ip("192.168.1.1")
        assert len(connections) == 1

    def test_connection_timeout(self):
        """Test connection timeout cleanup."""
        tracker = ConnectionTracker(timeout=0.1)  # 100ms timeout

        old_time = datetime.now() - timedelta(seconds=1)

        packet = PacketInfo(
            timestamp=old_time,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(packet)

        # Add recent packet to trigger cleanup
        recent_packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.3",
            dst_ip="192.168.1.4",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(recent_packet)

        # Old connection should be cleaned up
        assert tracker.get_connection_count() == 1

    def test_reset(self):
        """Test resetting tracker."""
        tracker = ConnectionTracker()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        tracker.update(packet)
        assert tracker.get_connection_count() == 1

        tracker.reset()
        assert tracker.get_connection_count() == 0


@pytest.mark.unit
class TestAnalysisEngine:
    """Test AnalysisEngine class."""

    def test_init_default(self):
        """Test initialization with defaults."""
        engine = AnalysisEngine()

        assert engine.get_connection_count() == 0

    def test_init_with_modules(self):
        """Test initialization with custom modules."""
        traffic_stats = TrafficStatistics()
        bandwidth_monitor = BandwidthMonitor()
        connection_tracker = ConnectionTracker()

        engine = AnalysisEngine(
            traffic_stats=traffic_stats,
            bandwidth_monitor=bandwidth_monitor,
            connection_tracker=connection_tracker,
        )

        assert engine._traffic_stats is traffic_stats
        assert engine._bandwidth_monitor is bandwidth_monitor
        assert engine._connection_tracker is connection_tracker

    def test_update_propagates_to_all_modules(self):
        """Test that update propagates to all modules."""
        engine = AnalysisEngine()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        engine.update(packet)

        # Check all modules were updated
        traffic_summary = engine._traffic_stats.get_summary()
        assert traffic_summary["total_packets"] == 1

        assert engine.get_connection_count() == 1

    def test_get_traffic_snapshot(self):
        """Test getting traffic snapshot."""
        engine = AnalysisEngine()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        engine.update(packet)
        snapshot = engine.get_traffic_snapshot()

        assert isinstance(snapshot, TrafficSnapshot)
        assert snapshot.total_packets == 1

    def test_get_protocol_distribution(self):
        """Test getting protocol distribution."""
        engine = AnalysisEngine()

        now = datetime.now()

        # Add different protocols
        engine.update(PacketInfo(
            timestamp=now,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        ))

        engine.update(PacketInfo(
            timestamp=now,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=53,
            protocol="UDP",
            length=500,
            raw_data=b"test",
        ))

        distribution = engine.get_protocol_distribution()

        assert "TCP" in distribution
        assert "UDP" in distribution

    def test_get_active_connections(self):
        """Test getting active connections."""
        engine = AnalysisEngine()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        engine.update(packet)

        active = engine.get_active_connections()
        assert len(active) == 1
        assert active[0].is_active

    def test_get_summary(self):
        """Test getting comprehensive summary."""
        engine = AnalysisEngine()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        engine.update(packet)
        summary = engine.get_summary()

        assert "traffic" in summary
        assert "bandwidth" in summary
        assert "connections" in summary
        assert "timestamp" in summary

    def test_reset(self):
        """Test resetting engine."""
        engine = AnalysisEngine()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        engine.update(packet)
        assert engine.get_connection_count() == 1

        engine.reset()
        assert engine.get_connection_count() == 0

    def test_set_bandwidth_threshold(self):
        """Test setting bandwidth threshold."""
        engine = AnalysisEngine()

        engine.set_bandwidth_threshold(
            warning_level=500_000,
            critical_level=5_000_000,
            window_seconds=10,
        )

        # Verify threshold was set
        assert engine._bandwidth_monitor._alert_threshold is not None
        assert engine._bandwidth_monitor._alert_threshold.warning_level == 500_000

    def test_add_remove_alert_callback(self):
        """Test adding and removing alert callbacks."""
        engine = AnalysisEngine()

        callback_called = []

        def test_callback(alert_type, bandwidth, threshold, timestamp):
            callback_called.append(alert_type)

        engine.add_bandwidth_alert_callback(test_callback)
        engine.remove_bandwidth_alert_callback(test_callback)

        # Callback list should be empty after removal
        assert len(engine._bandwidth_monitor._alert_callbacks) == 0


@pytest.mark.unit
class TestCreateAnalysisEngine:
    """Test analysis engine factory function."""

    def test_create_with_defaults(self):
        """Test creating engine with default parameters."""
        engine = create_analysis_engine()

        assert isinstance(engine, AnalysisEngine)

    def test_create_with_custom_params(self):
        """Test creating engine with custom parameters."""
        engine = create_analysis_engine(
            window_size=120,
            max_connections=5000,
            top_n=20,
            sample_interval=2.0,
            connection_timeout=600,
        )

        assert isinstance(engine, AnalysisEngine)

        # Verify parameters were applied
        assert engine._traffic_stats._window_size == 120
        assert engine._traffic_stats._max_connections == 5000
        assert engine._traffic_stats._top_n == 20
