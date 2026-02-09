"""
Traffic statistics module.

Provides real-time traffic statistics and analysis including
protocol distribution, top talkers, and connection tracking.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from threading import Lock
import time

from src.core.logger import get_logger
from src.capture.base import PacketInfo
from src.utils.constants import Protocol


@dataclass(frozen=True)
class TrafficSnapshot:
    """Immutable traffic statistics snapshot.

    Attributes:
        timestamp: When the snapshot was taken
        total_packets: Total packets counted
        total_bytes: Total bytes transferred
        packets_per_second: Packet rate
        bytes_per_second: Byte rate
        protocol_stats: Dictionary of protocol -> counts
        top_connections: Top connections details (list of dicts)
        top_talkers: Top IPs by bytes transferred
    """
    timestamp: datetime
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    protocol_stats: Dict[str, int]
    top_connections: List[Dict]  # Changed from List[Tuple] to List[Dict]
    top_talkers: List[Tuple[str, int]]  # (ip, bytes)

    def to_dict(self) -> dict:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "protocol_stats": dict(self.protocol_stats),
            "top_connections": self.top_connections,
            "top_talkers": self.top_talkers,
        }


@dataclass(frozen=True)
class ConnectionStats:
    """Connection statistics.

    Attributes:
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port
        dst_port: Destination port
        protocol: Protocol type
        packets_sent: Number of packets sent
        bytes_sent: Number of bytes sent
        packets_received: Number of packets received
        bytes_received: Number of bytes received
        first_seen: When connection was first observed
        last_seen: When connection was last observed
    """
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packets_sent: int
    bytes_sent: int
    packets_received: int
    bytes_received: int
    first_seen: datetime
    last_seen: datetime

    @property
    def total_packets(self) -> int:
        """Get total packets in both directions."""
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """Get total bytes in both directions."""
        return self.bytes_sent + self.bytes_received

    def get_key(self) -> Tuple[str, str, int, int]:
        """Get connection key.

        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port)
        """
        return (self.src_ip, self.dst_ip, self.src_port or 0, self.dst_port or 0)

    def is_bidirectional_pair(self, other: "ConnectionStats") -> bool:
        """Check if this is the reverse direction of another connection.

        Args:
            other: Another connection stats

        Returns:
            True if reverse direction
        """
        return (
            self.src_ip == other.dst_ip
            and self.dst_ip == other.src_ip
            and self.src_port == other.dst_port
            and self.dst_port == other.src_port
        )


class TrafficStatistics:
    """Real-time traffic statistics collector.

    Tracks packet counts, byte counts, protocol distribution,
    top connections, and top talkers.
    """

    def __init__(
        self,
        window_size: int = 60,
        max_connections: int = 10000,
        top_n: int = 10,
    ) -> None:
        """Initialize traffic statistics.

        Args:
            window_size: Time window in seconds for rate calculations
            max_connections: Maximum number of connections to track
            top_n: Number of top items to track
        """
        self._window_size = window_size
        self._max_connections = max_connections
        self._top_n = top_n

        # Counters
        self._total_packets = 0
        self._total_bytes = 0

        # Protocol statistics
        self._protocol_counts: Dict[str, int] = defaultdict(int)

        # Connection tracking
        self._connections: Dict[
            Tuple[str, str, int, int],
            ConnectionStats
        ] = {}
        self._connections_lock = Lock()

        # Time tracking
        self._start_time: Optional[datetime] = None
        self._last_update: Optional[datetime] = None

        # Rate calculation
        self._packet_history: deque = deque(maxlen=window_size)
        self._byte_history: deque = deque(maxlen=window_size)

        # Thread safety
        self._lock = Lock()

        logger = get_logger(__name__)
        self._logger = logger

    def update(self, packet: PacketInfo) -> None:
        """Update statistics with a new packet.

        Args:
            packet: Captured packet information
        """
        with self._lock:
            if self._start_time is None:
                self._start_time = packet.timestamp

            self._last_update = packet.timestamp

            # Update counters
            self._total_packets += 1
            self._total_bytes += packet.length

            # Update protocol stats
            self._protocol_counts[packet.protocol] += 1

            # Update connection tracking
            self._update_connection(packet)

            # Update history for rate calculation
            now = time.time()
            self._packet_history.append((now, 1))
            self._byte_history.append((now, packet.length))

    def _update_connection(self, packet: PacketInfo) -> None:
        """Update connection statistics.

        Args:
            packet: Captured packet information
        """
        # Create connection key
        key = packet.get_connection_key()

        with self._connections_lock:
            now = packet.timestamp

            if key in self._connections:
                # Update existing connection
                conn = self._connections[key]
                # This is a simplified update - assumes packet direction
                # Real implementation would track bidirectional flow
                self._connections[key] = ConnectionStats(
                    src_ip=conn.src_ip,
                    dst_ip=conn.dst_ip,
                    src_port=conn.src_port,
                    dst_port=conn.dst_port,
                    protocol=conn.protocol,
                    packets_sent=conn.packets_sent + 1,
                    bytes_sent=conn.bytes_sent + packet.length,
                    packets_received=conn.packets_received,
                    bytes_received=conn.bytes_received,
                    first_seen=conn.first_seen,
                    last_seen=now,
                )
            else:
                # New connection
                if len(self._connections) >= self._max_connections:
                    # Remove oldest connection
                    oldest = min(
                        self._connections.values(),
                        key=lambda c: c.last_seen,
                    )
                    del self._connections[oldest.get_key()]

                self._connections[key] = ConnectionStats(
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    packets_sent=1,
                    bytes_sent=packet.length,
                    packets_received=0,
                    bytes_received=0,
                    first_seen=now,
                    last_seen=now,
                )

    def get_snapshot(self) -> TrafficSnapshot:
        """Get current traffic snapshot.

        Returns:
            TrafficSnapshot with current statistics
        """
        with self._lock:
            now = datetime.now()

            # Calculate rates
            packets_per_sec = self._calculate_rate(self._packet_history)
            bytes_per_sec = self._calculate_rate(self._byte_history)

            # Get top connections
            top_connections = self._get_top_connections()

            # Get top talkers
            top_talkers = self._get_top_talkers()

            return TrafficSnapshot(
                timestamp=now,
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                packets_per_second=packets_per_sec,
                bytes_per_second=bytes_per_sec,
                protocol_stats=dict(self._protocol_counts),
                top_connections=top_connections,
                top_talkers=top_talkers,
            )

    def _calculate_rate(self, history: deque) -> float:
        """Calculate rate from history.

        Args:
            history: Deque of (timestamp, value) tuples

        Returns:
            Rate per second
        """
        if not history:
            return 0.0

        now = time.time()
        window_start = now - self._window_size

        # Sum values within time window
        total = sum(value for ts, value in history if ts >= window_start)

        # Calculate rate
        if len(history) >= 2:
            time_span = min(
                self._window_size,
                history[-1][0] - history[0][0],
            )
            if time_span > 0:
                return total / time_span

        return 0.0

    def _get_top_connections(self) -> List[Dict]:
        """Get top connections by packet count.

        Returns:
            List of connection dictionaries with full details
        """
        with self._connections_lock:
            # Group by bidirectional connections and sum counts
            # We also need to keep track of a representative connection object to get ports/protocol
            bidi_stats: Dict[Tuple[str, str], Dict] = {}

            for conn in self._connections.values():
                # Normalize key to ensure bidirectional grouping
                if conn.src_ip < conn.dst_ip:
                    key = (conn.src_ip, conn.dst_ip)
                else:
                    key = (conn.dst_ip, conn.src_ip)
                
                if key not in bidi_stats:
                    bidi_stats[key] = {
                        "src_ip": conn.src_ip,
                        "dst_ip": conn.dst_ip,
                        "src_port": conn.src_port,
                        "dst_port": conn.dst_port,
                        "protocol": conn.protocol,
                        "total_packets": 0,
                        "total_bytes": 0
                    }
                
                bidi_stats[key]["total_packets"] += conn.total_packets
                bidi_stats[key]["total_bytes"] += conn.total_bytes

            # Get top N based on packet count
            sorted_connections = sorted(
                bidi_stats.values(),
                key=lambda x: x["total_packets"],
                reverse=True,
            )[:self._top_n]

            return sorted_connections

    def get_top_talkers(self, limit: int = 10, time_window: Optional[float] = None) -> List[Tuple[str, int]]:
        """Get top talkers by bytes transferred.

        Args:
            limit: Maximum number of talkers to return
            time_window: Time window in seconds (None for all time)

        Returns:
            List of (ip, bytes) tuples
        """
        # Aggregate bytes by IP
        ip_bytes: Dict[str, int] = defaultdict(int)
        
        now = datetime.now()

        with self._connections_lock:
            for conn in self._connections.values():
                # Filter by time window if specified
                # Note: This logic assumes conn.last_seen represents the time of activity.
                # For long-running connections, this might include older bytes if we sum total_bytes.
                # However, for "top talkers in last hour", using total_bytes of connections active
                # in the last hour is a reasonable approximation given current data structure.
                # To be perfectly precise, we would need time-series data for each connection,
                # which is computationally expensive.
                
                if time_window is not None:
                    elapsed = (now - conn.last_seen).total_seconds()
                    if elapsed > time_window:
                        continue
                        
                ip_bytes[conn.src_ip] += conn.total_bytes
                ip_bytes[conn.dst_ip] += conn.total_bytes

        # Get top N
        sorted_ips = sorted(
            ip_bytes.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:limit]

        return sorted_ips

    def _get_top_talkers(self) -> List[Tuple[str, int]]:
        """Get top talkers by bytes transferred (internal use).

        Returns:
            List of (ip, bytes) tuples
        """
        return self.get_top_talkers(self._top_n)

    def get_protocol_distribution(self) -> Dict[str, float]:
        """Get protocol distribution as percentages.

        Returns:
            Dictionary of protocol -> percentage
        """
        with self._lock:
            if self._total_packets == 0:
                return {}

            distribution = {}
            for protocol, count in self._protocol_counts.items():
                distribution[protocol] = (count / self._total_packets) * 100

            return distribution

    def get_connections(
        self,
        limit: Optional[int] = None,
    ) -> List[ConnectionStats]:
        """Get connection statistics.

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection statistics
        """
        with self._connections_lock:
            connections = list(self._connections.values())

            # Sort by last seen (most recent first)
            connections.sort(key=lambda c: c.last_seen, reverse=True)

            if limit:
                connections = connections[:limit]

            return connections

    def get_connection_stats(
        self,
        src_ip: str,
        dst_ip: str,
    ) -> Optional[ConnectionStats]:
        """Get statistics for specific connection.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address

        Returns:
            ConnectionStats or None if not found
        """
        with self._connections_lock:
            # Find matching connection (either direction)
            for conn in self._connections.values():
                if (conn.src_ip == src_ip and conn.dst_ip == dst_ip) or (
                    conn.src_ip == dst_ip and conn.dst_ip == src_ip
                ):
                    return conn

        return None

    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_counts.clear()

            with self._connections_lock:
                self._connections.clear()

            self._packet_history.clear()
            self._byte_history.clear()

            self._start_time = None
            self._last_update = None

            self._logger.info("Traffic statistics reset")

    def get_duration(self) -> Optional[float]:
        """Get statistics collection duration in seconds.

        Returns:
            Duration in seconds or None if not started
        """
        if self._start_time is None:
            return None

        end = self._last_update or datetime.now()
        return (end - self._start_time).total_seconds()

    def get_summary(self) -> dict:
        """Get statistics summary.

        Returns:
            Dictionary with summary statistics
        """
        snapshot = self.get_snapshot()

        return {
            "duration_seconds": self.get_duration(),
            "total_packets": snapshot.total_packets,
            "total_bytes": snapshot.total_bytes,
            "packets_per_second": snapshot.packets_per_second,
            "bytes_per_second": snapshot.bytes_per_second,
            "unique_protocols": len(snapshot.protocol_stats),
            "total_connections": len(self._connections),
            "top_protocol": max(
                snapshot.protocol_stats.items(),
                key=lambda x: x[1],
            )[0] if snapshot.protocol_stats else None,
        }


def create_traffic_statistics(
    window_size: int = 60,
    max_connections: int = 10000,
    top_n: int = 10,
) -> TrafficStatistics:
    """Create traffic statistics instance.

    Args:
        window_size: Time window for rate calculations
        max_connections: Maximum connections to track
        top_n: Number of top items to track

    Returns:
        Configured TrafficStatistics instance
    """
    return TrafficStatistics(
        window_size=window_size,
        max_connections=max_connections,
        top_n=top_n,
    )
