"""
Connection tracking module.

Tracks network connections including TCP state tracking,
connection lifecycle, and session statistics.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set
from threading import Lock
from collections import defaultdict

from src.core.logger import get_logger
from src.capture.base import PacketInfo
from src.utils.constants import TCPState


class ConnectionState(Enum):
    """Connection states.

    Attributes:
        NEW: Connection just created
        ESTABLISHED: Connection active
        CLOSING: Connection being closed
        CLOSED: Connection closed
        TIMEOUT: Connection timed out
    """
    NEW = "new"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ConnectionKey:
    """Immutable connection identifier.

    Attributes:
        src_ip: Source IP address
        src_port: Source port
        dst_ip: Destination IP address
        dst_port: Destination port
        protocol: Protocol type
    """
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    protocol: str

    def to_tuple(self) -> Tuple[str, int, str, int, str]:
        """Convert to tuple.

        Returns:
            Tuple of (src_ip, src_port, dst_ip, dst_port, protocol)
        """
        return (self.src_ip, self.src_port or 0, self.dst_ip, self.dst_port or 0, self.protocol)

    def is_reverse(self, other: "ConnectionKey") -> bool:
        """Check if this is the reverse of another connection.

        Args:
            other: Another connection key

        Returns:
            True if reverse direction
        """
        return (
            self.src_ip == other.dst_ip
            and self.dst_ip == other.src_ip
            and self.src_port == other.dst_port
            and self.dst_port == other.src_port
            and self.protocol == other.protocol
        )


@dataclass
class ConnectionInfo:
    """Mutable connection information.

    Attributes:
        key: Connection identifier
        state: Current connection state
        packets_sent: Packets sent (src -> dst)
        packets_received: Packets received (dst -> src)
        bytes_sent: Bytes sent
        bytes_received: Bytes received
        first_seen: When connection was first observed
        last_seen: When connection was last observed
        last_activity: Time of last packet
        client_ip: Client IP address (assuming server ports)
        server_ip: Server IP address (assuming server ports)
        tcp_flags: Last observed TCP flags
    """
    key: ConnectionKey
    state: ConnectionState
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    tcp_flags: int = 0

    @property
    def total_packets(self) -> int:
        """Get total packets."""
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """Get total bytes."""
        return self.bytes_sent + self.bytes_received

    @property
    def duration(self) -> float:
        """Get connection duration in seconds.

        Returns:
            Duration in seconds
        """
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def is_active(self) -> bool:
        """Check if connection is active.

        Returns:
            True if connection is in active state
        """
        return self.state in (
            ConnectionState.NEW,
            ConnectionState.ESTABLISHED,
        )

    @property
    def age(self) -> float:
        """Get connection age in seconds.

        Returns:
            Age in seconds
        """
        return (datetime.now() - self.first_seen).total_seconds()

    def update_from_packet(self, packet: PacketInfo) -> None:
        """Update connection info from packet.

        Args:
            packet: Captured packet information
        """
        self.last_seen = packet.timestamp
        self.last_activity = packet.timestamp

        # Determine direction
        if self._is_client_to_server(packet):
            self.packets_sent += 1
            self.bytes_sent += packet.length
        else:
            self.packets_received += 1
            self.bytes_received += packet.length

        # Update TCP flags if applicable
        if packet.protocol == "TCP":
            # Extract flags from packet if possible
            # This is simplified - real implementation would parse TCP header
            pass

    def _is_client_to_server(self, packet: PacketInfo) -> bool:
        """Determine if packet is from client to server.

        Args:
            packet: Packet information

        Returns:
            True if packet is client->server direction
        """
        # Use server IP if known
        if self.server_ip:
            return packet.src_ip != self.server_ip

        # Check if using well-known server port
        if packet.dst_port and packet.dst_port < 1024:
            return True
        if packet.src_port and packet.src_port < 1024:
            return False

        # Default: assume current direction is correct
        return True


class ConnectionTracker:
    """Network connection tracker.

    Tracks TCP connections and other flows through the network,
    maintaining state and statistics for each connection.
    """

    def __init__(
        self,
        timeout: float = 300,
        max_connections: int = 10000,
    ) -> None:
        """Initialize connection tracker.

        Args:
            timeout: Connection timeout in seconds
            max_connections: Maximum number of connections to track
        """
        self._timeout = timeout
        self._max_connections = max_connections

        # Connection storage
        self._connections: Dict[ConnectionKey, ConnectionInfo] = {}
        self._connections_lock = Lock()

        # Quick lookup by IP
        self._connections_by_ip: Dict[str, Set[ConnectionKey]] = defaultdict(set)

        # Statistics
        self._total_connections_seen = 0

        logger = get_logger(__name__)
        self._logger = logger

    def update(self, packet: PacketInfo) -> None:
        """Update tracker with a new packet.

        Args:
            packet: Captured packet information
        """
        # Create connection key
        key = ConnectionKey(
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        with self._connections_lock:
            if key in self._connections:
                # Update existing connection
                conn_info = self._connections[key]
                conn_info.update_from_packet(packet)

                # Update state based on protocol
                self._update_connection_state(key, packet)

            else:
                # Create new connection
                conn_info = self._create_new_connection(key, packet)
                self._add_connection(key, conn_info)

        # Clean up timed out connections
        self._cleanup_timeout_connections()

    def _create_new_connection(
        self,
        key: ConnectionKey,
        packet: PacketInfo,
    ) -> ConnectionInfo:
        """Create new connection info.

        Args:
            key: Connection key
            packet: First packet of connection

        Returns:
            New ConnectionInfo
        """
        self._total_connections_seen += 1

        # Determine client/server roles
        client_ip, server_ip = self._determine_roles(packet)

        conn_info = ConnectionInfo(
            key=key,
            state=ConnectionState.NEW,
            client_ip=client_ip,
            server_ip=server_ip,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
            last_activity=packet.timestamp,
        )

        # Count the first packet
        conn_info.update_from_packet(packet)

        # Update based on protocol
        self._update_connection_state(key, packet)

        return conn_info

    def _add_connection(
        self,
        key: ConnectionKey,
        conn_info: ConnectionInfo,
    ) -> None:
        """Add connection to tracking.

        Args:
            key: Connection key
            conn_info: Connection information
        """
        # Check capacity
        if len(self._connections) >= self._max_connections:
            # Remove oldest connection
            self._remove_oldest_connection()

        # Add connection
        self._connections[key] = conn_info

        # Update IP index
        self._connections_by_ip[conn_info.client_ip or key.src_ip].add(key)
        self._connections_by_ip[conn_info.server_ip or key.dst_ip].add(key)

        self._logger.debug(
            f"New connection: {key.src_ip}:{key.src_port} -> "
            f"{key.dst_ip}:{key.dst_port} ({key.protocol})"
        )

    def _determine_roles(self, packet: PacketInfo) -> Tuple[Optional[str], Optional[str]]:
        """Determine client and server roles.

        Args:
            packet: Packet information

        Returns:
            Tuple of (client_ip, server_ip)
        """
        # Use well-known ports to determine roles
        if packet.dst_port and packet.dst_port < 1024:
            return (packet.src_ip, packet.dst_ip)
        elif packet.src_port and packet.src_port < 1024:
            return (packet.dst_ip, packet.src_ip)

        return (None, None)

    def _update_connection_state(self, key: ConnectionKey, packet: PacketInfo) -> None:
        """Update connection state based on packet.

        Args:
            key: Connection key
            packet: Packet information
        """
        if key not in self._connections:
            return

        conn_info = self._connections[key]

        # TCP state tracking (simplified)
        if packet.protocol == "TCP":
            # Real implementation would parse TCP flags
            if conn_info.state == ConnectionState.NEW:
                conn_info.state = ConnectionState.ESTABLISHED

        # UDP and other protocols stay in ESTABLISHED
        elif conn_info.state == ConnectionState.NEW:
            conn_info.state = ConnectionState.ESTABLISHED

    def _remove_oldest_connection(self) -> None:
        """Remove the oldest connection."""
        if not self._connections:
            return

        oldest_key = min(
            self._connections.keys(),
            key=lambda k: self._connections[k].last_seen,
        )

        self._remove_connection(oldest_key)

    def _remove_connection(self, key: ConnectionKey) -> None:
        """Remove connection from tracking.

        Args:
            key: Connection key to remove
        """
        if key not in self._connections:
            return

        conn_info = self._connections[key]

        # Remove from IP index
        if conn_info.client_ip:
            self._connections_by_ip[conn_info.client_ip].discard(key)
        if conn_info.server_ip:
            self._connections_by_ip[conn_info.server_ip].discard(key)

        # Remove connection
        del self._connections[key]

        self._logger.debug(f"Removed connection: {key.to_tuple()}")

    def _cleanup_timeout_connections(self) -> None:
        """Remove timed out connections."""
        now = datetime.now()
        timeout_cutoff = now - timedelta(seconds=self._timeout)

        # Find expired connections
        expired_keys = [
            key for key, conn in self._connections.items()
            if conn.last_activity < timeout_cutoff
        ]

        for key in expired_keys:
            conn = self._connections[key]
            conn.state = ConnectionState.TIMEOUT
            self._remove_connection(key)

    def get_connection(self, key: ConnectionKey) -> Optional[ConnectionInfo]:
        """Get connection info.

        Args:
            key: Connection key

        Returns:
            ConnectionInfo or None if not found
        """
        return self._connections.get(key)

    def get_connections_by_ip(self, ip: str) -> List[ConnectionInfo]:
        """Get all connections for an IP.

        Args:
            ip: IP address

        Returns:
            List of connection information
        """
        connections = []

        for key in self._connections_by_ip.get(ip, set()):
            if key in self._connections:
                connections.append(self._connections[key])

        return connections

    def get_active_connections(self) -> List[ConnectionInfo]:
        """Get all active connections.

        Returns:
            List of active connection information
        """
        return [
            conn for conn in self._connections.values()
            if conn.is_active
        ]

    def get_connection_count(self) -> int:
        """Get total number of tracked connections.

        Returns:
            Connection count
        """
        return len(self._connections)

    def get_connection_summary(self) -> dict:
        """Get connection tracking summary.

        Returns:
            Dictionary with summary statistics
        """
        active = self.get_active_connections()
        established = [
            conn for conn in active
            if conn.state == ConnectionState.ESTABLISHED
        ]

        return {
            "total_connections": len(self._connections),
            "active_connections": len(active),
            "established_connections": len(established),
            "total_seen": self._total_connections_seen,
        }

    def reset(self) -> None:
        """Reset connection tracker."""
        with self._connections_lock:
            self._connections.clear()
            self._connections_by_ip.clear()
            self._total_connections_seen = 0

        self._logger.info("Connection tracker reset")


def create_connection_tracker(
    timeout: float = 300,
    max_connections: int = 10000,
) -> ConnectionTracker:
    """Create connection tracker instance.

    Args:
        timeout: Connection timeout in seconds
        max_connections: Maximum connections to track

    Returns:
        Configured ConnectionTracker instance
    """
    return ConnectionTracker(
        timeout=timeout,
        max_connections=max_connections,
    )
