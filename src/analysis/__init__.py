"""
Analysis engine module.

Provides unified traffic analysis combining statistics,
bandwidth monitoring, and connection tracking.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime

from src.capture.base import PacketInfo
from src.core.logger import get_logger

from .traffic_stats import (
    TrafficStatistics,
    TrafficSnapshot,
    ConnectionStats,
    create_traffic_statistics,
)
from .bandwidth_monitor import (
    BandwidthMonitor,
    BandwidthSample,
    BandwidthThreshold,
    BandwidthAlert,
    create_bandwidth_monitor,
)
from .connection_tracker import (
    ConnectionTracker,
    ConnectionKey,
    ConnectionInfo,
    ConnectionState,
    create_connection_tracker,
)


class AnalysisEngine:
    """Combined traffic analysis engine.

    Integrates traffic statistics, bandwidth monitoring,
    and connection tracking into a unified interface.
    """

    def __init__(
        self,
        traffic_stats: Optional[TrafficStatistics] = None,
        bandwidth_monitor: Optional[BandwidthMonitor] = None,
        connection_tracker: Optional[ConnectionTracker] = None,
    ) -> None:
        """Initialize analysis engine.

        Args:
            traffic_stats: Traffic statistics module
            bandwidth_monitor: Bandwidth monitoring module
            connection_tracker: Connection tracking module
        """
        self._traffic_stats = traffic_stats or create_traffic_statistics()
        self._bandwidth_monitor = bandwidth_monitor or create_bandwidth_monitor()
        self._connection_tracker = connection_tracker or create_connection_tracker()

        logger = get_logger(__name__)
        self._logger = logger

    def update(self, packet: PacketInfo) -> None:
        """Update analysis with a new packet.

        Args:
            packet: Captured packet information
        """
        self._traffic_stats.update(packet)
        self._bandwidth_monitor.update(packet)
        self._connection_tracker.update(packet)

    def get_traffic_snapshot(self) -> TrafficSnapshot:
        """Get current traffic statistics snapshot.

        Returns:
            TrafficSnapshot with current statistics
        """
        return self._traffic_stats.get_snapshot()

    def get_current_bandwidth(self) -> Optional[BandwidthSample]:
        """Get current bandwidth measurement.

        Returns:
            Most recent bandwidth sample or None
        """
        return self._bandwidth_monitor.get_current_bandwidth()

    def get_average_bandwidth(self, window_seconds: float = 60) -> Optional[float]:
        """Get average bandwidth over time window.

        Args:
            window_seconds: Time window in seconds

        Returns:
            Average bandwidth in B/s or None
        """
        return self._bandwidth_monitor.get_average_bandwidth(window_seconds)

    def get_peak_bandwidth(self, window_seconds: Optional[float] = None) -> Optional[float]:
        """Get peak bandwidth over time window.

        Args:
            window_seconds: Time window in seconds (None for all time)

        Returns:
            Peak bandwidth in B/s or None
        """
        return self._bandwidth_monitor.get_peak_bandwidth(window_seconds)

    def get_active_connections(self) -> List[ConnectionInfo]:
        """Get all active connections.

        Returns:
            List of active connection information
        """
        return self._connection_tracker.get_active_connections()

    def get_connection(self, key: ConnectionKey) -> Optional[ConnectionInfo]:
        """Get connection info.

        Args:
            key: Connection key

        Returns:
            ConnectionInfo or None if not found
        """
        return self._connection_tracker.get_connection(key)

    def get_connections_by_ip(self, ip: str) -> List[ConnectionInfo]:
        """Get all connections for an IP.

        Args:
            ip: IP address

        Returns:
            List of connection information
        """
        return self._connection_tracker.get_connections_by_ip(ip)

    def get_protocol_distribution(self) -> Dict[str, float]:
        """Get protocol distribution as percentages.

        Returns:
            Dictionary of protocol -> percentage
        """
        return self._traffic_stats.get_protocol_distribution()

    def get_top_connections(self, limit: int = 10) -> List[tuple]:
        """Get top connections by packet count.

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of (src_ip, dst_ip, packet_count) tuples
        """
        snapshot = self._traffic_stats.get_snapshot()
        return snapshot.top_connections[:limit]

    def get_top_talkers(self, limit: int = 10) -> List[tuple]:
        """Get top talkers by bytes transferred.

        Args:
            limit: Maximum number of talkers to return

        Returns:
            List of (ip, bytes) tuples
        """
        snapshot = self._traffic_stats.get_snapshot()
        return snapshot.top_talkers[:limit]

    def get_connection_count(self) -> int:
        """Get total number of tracked connections.

        Returns:
            Connection count
        """
        return self._connection_tracker.get_connection_count()

    def get_bandwidth_samples(self, limit: Optional[int] = None) -> List[BandwidthSample]:
        """Get bandwidth samples.

        Args:
            limit: Maximum number of samples to return

        Returns:
            List of bandwidth samples
        """
        return self._bandwidth_monitor.get_samples(limit)

    def add_bandwidth_alert_callback(self, callback: BandwidthAlert) -> None:
        """Add bandwidth alert callback.

        Args:
            callback: Function to call on alert
        """
        self._bandwidth_monitor.add_alert_callback(callback)

    def remove_bandwidth_alert_callback(self, callback: BandwidthAlert) -> None:
        """Remove bandwidth alert callback.

        Args:
            callback: Callback to remove
        """
        self._bandwidth_monitor.remove_alert_callback(callback)

    def set_bandwidth_threshold(
        self,
        warning_level: float,
        critical_level: float,
        window_seconds: int = 5,
    ) -> None:
        """Set bandwidth alert threshold.

        Args:
            warning_level: Warning threshold in B/s
            critical_level: Critical threshold in B/s
            window_seconds: Time window to average over
        """
        threshold = BandwidthThreshold(
            warning_level=warning_level,
            critical_level=critical_level,
            window_seconds=window_seconds,
        )
        self._bandwidth_monitor._alert_threshold = threshold

        self._logger.info(
            f"Bandwidth threshold set: warning={warning_level} B/s, "
            f"critical={critical_level} B/s"
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary.

        Returns:
            Dictionary with summary statistics from all modules
        """
        traffic_summary = self._traffic_stats.get_summary()
        bandwidth_summary = self._bandwidth_monitor.get_summary()
        connection_summary = self._connection_tracker.get_connection_summary()

        snapshot = self._traffic_stats.get_snapshot()

        return {
            "timestamp": datetime.now().isoformat(),
            "traffic": traffic_summary,
            "bandwidth": bandwidth_summary,
            "connections": connection_summary,
            "protocol_distribution": self.get_protocol_distribution(),
            "top_connections": snapshot.top_connections[:5],
            "top_talkers": snapshot.top_talkers[:5],
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get combined statistics for dashboard display.

        Returns:
            Dictionary with traffic statistics including:
            - total_packets: Total packet count
            - total_bytes: Total bytes transferred
            - packets_per_second: Packet rate
            - bytes_per_second: Byte rate
            - active_connections: Active connection count
            - protocol_stats: Protocol distribution dict
            - top_connections: Top connections list
        """
        snapshot = self._traffic_stats.get_snapshot()
        active_conns = self._connection_tracker.get_active_connections()

        return {
            "total_packets": snapshot.total_packets,
            "total_bytes": snapshot.total_bytes,
            "packets_per_second": snapshot.packets_per_second,
            "bytes_per_second": snapshot.bytes_per_second,
            "active_connections": len(active_conns),
            "protocol_stats": snapshot.protocol_stats,
            "top_connections": snapshot.top_connections,
        }

    def reset(self) -> None:
        """Reset all analysis modules."""
        self._traffic_stats.reset()
        self._bandwidth_monitor.reset()
        self._connection_tracker.reset()

        self._logger.info("Analysis engine reset")


def create_analysis_engine(
    window_size: int = 60,
    max_connections: int = 10000,
    top_n: int = 10,
    sample_interval: float = 1.0,
    bandwidth_window_size: int = 60,
    warning_level: float = 1_000_000,
    critical_level: float = 10_000_000,
    alert_window: int = 5,
    connection_timeout: float = 300,
) -> AnalysisEngine:
    """Create configured analysis engine.

    Args:
        window_size: Time window for traffic statistics
        max_connections: Maximum connections to track
        top_n: Number of top items to track
        sample_interval: Bandwidth sample interval in seconds
        bandwidth_window_size: Bandwidth samples history size
        warning_level: Bandwidth warning threshold in B/s
        critical_level: Bandwidth critical threshold in B/s
        alert_window: Bandwidth alert time window
        connection_timeout: Connection timeout in seconds

    Returns:
        Configured AnalysisEngine instance

    Example:
        >>> engine = create_analysis_engine()
        >>> engine.update(packet)
        >>> summary = engine.get_summary()
    """
    traffic_stats = create_traffic_statistics(
        window_size=window_size,
        max_connections=max_connections,
        top_n=top_n,
    )

    bandwidth_monitor = create_bandwidth_monitor(
        sample_interval=sample_interval,
        window_size=bandwidth_window_size,
        warning_level=warning_level,
        critical_level=critical_level,
        alert_window=alert_window,
    )

    connection_tracker = create_connection_tracker(
        timeout=connection_timeout,
        max_connections=max_connections,
    )

    return AnalysisEngine(
        traffic_stats=traffic_stats,
        bandwidth_monitor=bandwidth_monitor,
        connection_tracker=connection_tracker,
    )


__all__ = [
    "AnalysisEngine",
    "create_analysis_engine",
    "TrafficStatistics",
    "TrafficSnapshot",
    "ConnectionStats",
    "BandwidthMonitor",
    "BandwidthSample",
    "BandwidthThreshold",
    "BandwidthAlert",
    "ConnectionTracker",
    "ConnectionKey",
    "ConnectionInfo",
    "ConnectionState",
]
