"""
Base classes for packet capture functionality.

Defines the abstract interface for packet capture and the
immutable data structure for packet information.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Iterator, Protocol
from threading import Lock, Condition

from src.core.exceptions import (
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
    CaptureTimeoutError,
)


class CaptureState(Enum):
    """Packet capture states.

    Attributes:
        STOPPED: Capture is not running
        STARTING: Capture is being initialized
        RUNNING: Capture is active
        STOPPING: Capture is being stopped
        ERROR: Capture encountered an error
    """
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass(frozen=True)
class PacketInfo:
    """Immutable packet information.

    This class represents a single captured packet with all relevant
    metadata. It is frozen to ensure immutability and thread safety.

    Attributes:
        timestamp: When the packet was captured
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port (None for non-transport protocols)
        dst_port: Destination port (None for non-transport protocols)
        protocol: Protocol name (TCP, UDP, ICMP, etc.)
        length: Packet length in bytes
        raw_data: Raw packet bytes
        interface: Network interface where packet was captured
        mac_src: Source MAC address (optional)
        mac_dst: Destination MAC address (optional)
    """
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    raw_data: bytes
    interface: str = ""
    mac_src: Optional[str] = None
    mac_dst: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate packet information."""
        # Validate ports
        if self.src_port is not None and not (0 <= self.src_port <= 65535):
            raise ValueError(f"Invalid source port: {self.src_port}")
        if self.dst_port is not None and not (0 <= self.dst_port <= 65535):
            raise ValueError(f"Invalid destination port: {self.dst_port}")

        # Validate length
        if self.length < 0:
            raise ValueError(f"Invalid packet length: {self.length}")

        # Validate IPs are non-empty
        if not self.src_ip:
            raise ValueError("Source IP cannot be empty")
        if not self.dst_ip:
            raise ValueError("Destination IP cannot be empty")

        # Validate protocol
        if not self.protocol:
            raise ValueError("Protocol cannot be empty")

    def with_raw_data(self, raw_data: bytes) -> "PacketInfo":
        """Return a new PacketInfo with updated raw data.

        This is useful when you want to modify the raw data while
        keeping all other fields the same.

        Args:
            raw_data: New raw packet data

        Returns:
            New PacketInfo instance with updated raw_data
        """
        return PacketInfo(
            timestamp=self.timestamp,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            length=len(raw_data),  # Update length to match new data
            raw_data=raw_data,
            interface=self.interface,
            mac_src=self.mac_src,
            mac_dst=self.mac_dst,
        )

    def get_connection_key(self) -> tuple[str, str, int, int]:
        """Get a connection identifier key.

        Returns a tuple that uniquely identifies a connection.
        Useful for tracking connections.

        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port)
            Ports are 0 if not applicable
        """
        src_port = self.src_port or 0
        dst_port = self.dst_port or 0
        return (self.src_ip, self.dst_ip, src_port, dst_port)

    def is_bidirectional_pair(self, other: "PacketInfo") -> bool:
        """Check if this packet is the reverse direction of another.

        Args:
            other: Another packet to compare with

        Returns:
            True if packets are part of the same bidirectional flow
        """
        return (
            self.src_ip == other.dst_ip
            and self.dst_ip == other.src_ip
            and self.src_port == other.dst_port
            and self.dst_port == other.src_port
        )


class CaptureCallback(Protocol):
    """Protocol for capture callback functions.

    A callback function that receives captured packets.
    """

    def __call__(self, packet: PacketInfo) -> None:
        """Process a captured packet.

        Args:
            packet: The captured packet information
        """
        ...


class PacketCapture(ABC):
    """Abstract base class for packet capture implementations.

    This class defines the interface that all capture implementations
    must follow. It provides thread-safe state management and
    callback registration.

    Example:
        >>> class MyCapture(PacketCapture):
        ...     def start_capture(self) -> None:
        ...         # Implementation
        ...         pass
    """

    def __init__(
        self,
        interface: str,
        filter: str = "",
        buffer_size: int = 1000,
        promiscuous: bool = True,
    ) -> None:
        """Initialize packet capture.

        Args:
            interface: Network interface name (empty for default)
            filter: BPF filter string for packet filtering
            buffer_size: Maximum packets to buffer
            promiscuous: Enable promiscuous mode
        """
        self._interface = interface
        self._filter = filter
        self._buffer_size = buffer_size
        self._promiscuous = promiscuous

        # State management
        self._state = CaptureState.STOPPED
        self._state_lock = Lock()
        self._state_condition = Condition(self._state_lock)

        # Callbacks
        self._callbacks: list[CaptureCallback] = []
        self._callbacks_lock = Lock()

        # Statistics
        self._packets_captured = 0
        self._packets_dropped = 0
        self._start_time: Optional[datetime] = None
        self._stats_lock = Lock()

    @property
    def interface(self) -> str:
        """Get the network interface.

        Returns:
            Interface name
        """
        return self._interface

    @property
    def filter(self) -> str:
        """Get the BPF filter.

        Returns:
            BPF filter string
        """
        return self._filter

    @property
    def buffer_size(self) -> int:
        """Get the buffer size.

        Returns:
            Maximum packets to buffer
        """
        return self._buffer_size

    @property
    def promiscuous(self) -> bool:
        """Get promiscuous mode setting.

        Returns:
            True if promiscuous mode is enabled
        """
        return self._promiscuous

    @property
    def state(self) -> CaptureState:
        """Get the current capture state.

        Returns:
            Current capture state
        """
        with self._state_lock:
            return self._state

    @property
    def is_running(self) -> bool:
        """Check if capture is currently running.

        Returns:
            True if capture is running
        """
        return self.state == CaptureState.RUNNING

    @property
    def packets_captured(self) -> int:
        """Get the number of packets captured.

        Returns:
            Packet count
        """
        with self._stats_lock:
            return self._packets_captured

    @property
    def packets_dropped(self) -> int:
        """Get the number of packets dropped.

        Returns:
            Dropped packet count
        """
        with self._stats_lock:
            return self._packets_dropped

    @property
    def start_time(self) -> Optional[datetime]:
        """Get the capture start time.

        Returns:
            Start time or None if not started
        """
        return self._start_time

    @abstractmethod
    def start_capture(self) -> None:
        """Start packet capture.

        This method should block until capture is fully started
        or raise an exception if startup fails.

        Raises:
            InterfaceNotFoundError: If interface doesn't exist
            PermissionDeniedError: If lacking required permissions
            CaptureError: For other capture errors
        """
        pass

    @abstractmethod
    def stop_capture(self) -> None:
        """Stop packet capture.

        This method should block until capture is fully stopped.
        """
        pass

    @abstractmethod
    def get_packets(self) -> Iterator[PacketInfo]:
        """Get captured packets.

        Returns an iterator over captured packets.
        The iterator may be infinite for continuous capture.

        Yields:
            PacketInfo: Captured packet information

        Raises:
            CaptureError: If capture is not running
        """
        pass

    def add_callback(self, callback: CaptureCallback) -> None:
        """Add a packet callback.

        The callback will be invoked for each captured packet.

        Args:
            callback: Function to call with each packet
        """
        with self._callbacks_lock:
            self._callbacks.append(callback)

    def remove_callback(self, callback: CaptureCallback) -> None:
        """Remove a packet callback.

        Args:
            callback: Callback function to remove
        """
        with self._callbacks_lock:
            try:
                self._callbacks.remove(callback)
            except ValueError:
                pass  # Callback not in list

    def _set_state(self, state: CaptureState) -> None:
        """Set the capture state (thread-safe).

        Args:
            state: New capture state
        """
        with self._state_condition:
            self._state = state
            self._state_condition.notify_all()

    def _notify_callbacks(self, packet: PacketInfo) -> None:
        """Notify all registered callbacks.

        Args:
            packet: Packet to pass to callbacks
        """
        with self._callbacks_lock:
            callbacks = self._callbacks.copy()

        for callback in callbacks:
            try:
                callback(packet)
            except Exception:
                # Don't let one bad callback break others
                pass

    def _increment_captured(self) -> None:
        """Increment captured packet counter."""
        with self._stats_lock:
            self._packets_captured += 1

    def _increment_dropped(self) -> None:
        """Increment dropped packet counter."""
        with self._stats_lock:
            self._packets_dropped += 1

    def wait_for_state(
        self,
        state: CaptureState,
        timeout: Optional[float] = None,
    ) -> bool:
        """Wait for capture to reach a specific state.

        Args:
            state: State to wait for
            timeout: Maximum time to wait in seconds (None = infinite)

        Returns:
            True if state was reached, False if timeout
        """
        with self._state_condition:
            while self._state != state:
                if timeout is not None and timeout <= 0:
                    return False
                wait_time = timeout if timeout is not None else None
                self._state_condition.wait(wait_time)
                if timeout is not None:
                    timeout = 0  # Don't wait again
            return True

    def get_statistics(self) -> dict:
        """Get capture statistics.

        Returns:
            Dictionary with capture statistics
        """
        with self._stats_lock:
            duration = None
            if self._start_time is not None:
                duration = (datetime.now() - self._start_time).total_seconds()

            return {
                "state": self._state.value,
                "packets_captured": self._packets_captured,
                "packets_dropped": self._packets_dropped,
                "start_time": self._start_time.isoformat() if self._start_time else None,
                "duration_seconds": duration,
                "packets_per_second": (
                    self._packets_captured / duration if duration and duration > 0 else 0
                ),
            }

    def reset_statistics(self) -> None:
        """Reset capture statistics."""
        with self._stats_lock:
            self._packets_captured = 0
            self._packets_dropped = 0
            self._start_time = datetime.now()


def validate_interface(interface: str) -> bool:
    """Validate an interface name.

    Args:
        interface: Interface name to validate

    Returns:
        True if interface name appears valid
    """
    if not interface:
        return True  # Empty means use default

    # Basic validation - alphanumeric, underscores, hyphens
    return bool(interface) and all(c.isalnum() or c in "._-" for c in interface)


def validate_bpf_filter(filter: str) -> bool:
    """Validate a BPF filter string.

    This is a basic validation. Full validation would require
    compiling with libpcap.

    Args:
        filter: BPF filter string

    Returns:
        True if filter appears valid
    """
    if not filter:
        return True  # Empty filter is valid

    # Check for balanced parentheses
    paren_count = filter.count("(") - filter.count(")")
    if paren_count != 0:
        return False

    # Check for balanced quotes
    quote_count = filter.count('"') + filter.count("'")
    if quote_count % 2 != 0:
        return False

    return True
