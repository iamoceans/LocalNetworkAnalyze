"""
Scapy-based packet capture implementation.

Uses the Scapy library for packet capture and parsing.
Provides a production-ready implementation of PacketCapture.
"""

import queue
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional, Iterator, Callable

from scapy.all import (
    sniff,
    get_if_list,
    get_if_addr,
    Packet as ScapyPacket,
)
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

from src.core.exceptions import (
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
)
from src.core.logger import get_logger
from .base import (
    PacketCapture,
    PacketInfo,
    CaptureState,
    CaptureCallback,
)

logger = get_logger(__name__)


class ScapyCapture(PacketCapture):
    """Packet capture implementation using Scapy.

    This class uses Scapy's sniff() function to capture packets
    from a network interface. It runs sniff() in a separate thread
    and provides packets through a queue.

    Example:
        >>> capture = ScapyCapture("eth0")
        >>> capture.start_capture()
        >>> for packet in capture.get_packets():
        ...     print(f"{packet.src_ip} -> {packet.dst_ip}")
    """

    def __init__(
        self,
        interface: str = "",
        filter: str = "",
        buffer_size: int = 1000,
        promiscuous: bool = True,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize Scapy capture.

        Args:
            interface: Network interface name (empty for default)
            filter: BPF filter string
            buffer_size: Maximum packets to buffer in queue
            promiscuous: Enable promiscuous mode
            timeout: Capture timeout in seconds (None = no timeout)
        """
        super().__init__(interface, filter, buffer_size, promiscuous)

        self._timeout = timeout

        # Packet queue
        self._packet_queue: queue.Queue[PacketInfo] = queue.Queue(maxsize=buffer_size)

        # Capture thread
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Packet buffer for iteration
        self._buffer_lock = threading.Lock()
        self._buffer: deque[PacketInfo] = deque()

        # Statistics
        self._last_packet_time: Optional[datetime] = None

    def start_capture(self) -> None:
        """Start packet capture.

        Raises:
            InterfaceNotFoundError: If interface doesn't exist
            PermissionDeniedError: If lacking required permissions
            CaptureError: If capture fails to start
        """
        if self.is_running:
            logger.warning("Capture already running")
            return

        self._set_state(CaptureState.STARTING)

        try:
            # Validate interface
            interface = self._resolve_interface()
            if interface and not self._interface_exists(interface):
                raise InterfaceNotFoundError(
                    f"Network interface '{interface}' not found",
                    {
                        "interface": interface,
                        "available": get_if_list(),
                    },
                )

            # Reset stop event
            self._stop_event.clear()

            # Start capture thread
            self._capture_thread = threading.Thread(
                target=self._capture_loop,
                name=f"ScapyCapture-{interface}",
                daemon=True,
            )
            self._capture_thread.start()

            # Wait for capture to actually start
            if not self.wait_for_state(CaptureState.RUNNING, timeout=5):
                raise CaptureError("Capture failed to start within timeout")

            logger.info(f"Capture started on interface {interface}")

        except PermissionError as e:
            self._set_state(CaptureState.ERROR)
            raise PermissionDeniedError(
                "Administrator privileges required for packet capture",
                {"suggestion": "Run with administrator/root privileges"},
            )
        except OSError as e:
            self._set_state(CaptureState.ERROR)
            if "Permission denied" in str(e) or "Operation not permitted" in str(e):
                raise PermissionDeniedError(
                    "Permission denied for packet capture",
                    {"error": str(e)},
                )
            raise CaptureError(f"Failed to start capture: {e}")

    def stop_capture(self) -> None:
        """Stop packet capture."""
        if not self.is_running:
            return

        self._set_state(CaptureState.STOPPING)

        # Signal capture thread to stop
        self._stop_event.set()

        # Wait for capture thread to finish
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)

        self._set_state(CaptureState.STOPPED)
        logger.info("Capture stopped")

    def get_packets(self) -> Iterator[PacketInfo]:
        """Get captured packets.

        Yields packets as they arrive. This is an infinite iterator
        that will block until packets arrive or capture stops.

        Yields:
            PacketInfo: Captured packet information

        Raises:
            CaptureError: If capture is not running
        """
        if not self.is_running:
            raise CaptureError("Cannot get packets: capture is not running")

        while self.is_running and not self._stop_event.is_set():
            try:
                # Try to get packet from queue with timeout
                packet = self._packet_queue.get(timeout=0.5)
                yield packet
            except queue.Empty:
                # No packet available, continue loop
                continue

    def _resolve_interface(self) -> str:
        """Resolve the interface to use.

        Returns:
            Interface name to use

        Raises:
            InterfaceNotFoundError: If no suitable interface found
        """
        if self._interface:
            return self._interface

        # Try to find a suitable default interface
        interfaces = get_if_list()

        # Filter out loopback
        for iface in interfaces:
            if iface.lower() not in ("lo", "loopback"):
                try:
                    # Check if interface has an IP address
                    addr = get_if_addr(iface)
                    if addr and addr != "0.0.0.0":
                        return iface
                except Exception:
                    continue

        # Fallback to first interface
        if interfaces:
            return interfaces[0]

        raise InterfaceNotFoundError(
            "No suitable network interface found",
            {"available_interfaces": get_if_list()},
        )

    def _interface_exists(self, interface: str) -> bool:
        """Check if an interface exists.

        Args:
            interface: Interface name

        Returns:
            True if interface exists
        """
        return interface in get_if_list()

    def _capture_loop(self) -> None:
        """Main capture loop (runs in separate thread)."""
        interface = self._resolve_interface()

        try:
            self._set_state(CaptureState.RUNNING)

            # Build sniff arguments
            sniff_args = {
                "iface": interface,
                "prn": self._packet_callback,
                "store": False,  # Don't store packets in memory
                "stop_filter": lambda p: self._stop_event.is_set(),
            }

            # Add filter if specified
            if self._filter:
                sniff_args["filter"] = self._filter

            # Add timeout if specified
            if self._timeout:
                sniff_args["timeout"] = self._timeout

            # Start sniffing
            logger.debug(f"Starting sniff on {interface} with filter: {self._filter}")
            sniff(**sniff_args)

        except PermissionError as e:
            logger.error(f"Permission denied: {e}")
            self._set_state(CaptureState.ERROR)
        except OSError as e:
            logger.error(f"OS error during capture: {e}")
            self._set_state(CaptureState.ERROR)
        except Exception as e:
            logger.error(f"Unexpected error in capture loop: {e}")
            self._set_state(CaptureState.ERROR)
        finally:
            self._set_state(CaptureState.STOPPED)

    def _packet_callback(self, packet: ScapyPacket) -> None:
        """Callback for each captured packet.

        Called by Scapy for each captured packet.
        Parses the packet and adds it to the queue.

        Args:
            packet: Raw Scapy packet
        """
        try:
            # Parse packet
            packet_info = self._parse_packet(packet)

            # Add to queue (non-blocking, drop if full)
            try:
                self._packet_queue.put_nowait(packet_info)
            except queue.Full:
                # Queue is full, drop packet
                self._increment_dropped()
                logger.debug("Packet queue full, dropping packet")

            # Update statistics
            self._increment_captured()
            self._last_packet_time = packet_info.timestamp

            # Notify callbacks
            self._notify_callbacks(packet_info)

            # Add to buffer for iteration
            with self._buffer_lock:
                self._buffer.append(packet_info)
                # Limit buffer size
                if len(self._buffer) > self._buffer_size:
                    self._buffer.popleft()

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _parse_packet(self, packet: ScapyPacket) -> PacketInfo:
        """Parse a Scapy packet into PacketInfo.

        Args:
            packet: Scapy packet

        Returns:
            Parsed PacketInfo
        """
        # Extract timestamp
        timestamp = datetime.fromtimestamp(float(packet.time))

        # Initialize with defaults
        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None
        protocol = "RAW"
        mac_src = None
        mac_dst = None

        # Extract Ethernet layer if present
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst

        # Extract IP layer
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        elif packet.haslayer(ARP):
            # ARP packet
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            mac_src = packet[ARP].hwsrc
            mac_dst = packet[ARP].hwdst
            protocol = "ARP"

        # Extract transport layer
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        # Get raw bytes
        raw_data = bytes(packet)

        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(raw_data),
            raw_data=raw_data,
            interface=self._interface,
            mac_src=mac_src,
            mac_dst=mac_dst,
        )

    def get_buffer(self) -> list[PacketInfo]:
        """Get current packet buffer.

        Returns a copy of the current packet buffer.
        Useful for getting recent packets without waiting.

        Returns:
            List of buffered packets
        """
        with self._buffer_lock:
            return list(self._buffer)

    def get_buffer_size(self) -> int:
        """Get current buffer size.

        Returns:
            Number of packets in buffer
        """
        with self._buffer_lock:
            return len(self._buffer)

    def clear_buffer(self) -> None:
        """Clear the packet buffer."""
        with self._buffer_lock:
            self._buffer.clear()

    @staticmethod
    def get_interfaces() -> list[dict]:
        """Get list of available network interfaces.

        Returns:
            List of interface information dictionaries
        """
        interfaces = []

        for iface_name in get_if_list():
            try:
                addr = get_if_addr(iface_name)
                interfaces.append({
                    "name": iface_name,
                    "address": addr,
                    "description": iface_name,
                })
            except Exception:
                interfaces.append({
                    "name": iface_name,
                    "address": "",
                    "description": iface_name,
                })

        return interfaces

    @staticmethod
    def find_interface_by_address(address: str) -> Optional[str]:
        """Find interface by IP address.

        Args:
            address: IP address to search for

        Returns:
            Interface name or None if not found
        """
        for iface_name in get_if_list():
            try:
                if get_if_addr(iface_name) == address:
                    return iface_name
            except Exception:
                continue
        return None


def create_scapy_capture(
    interface: str = "",
    filter: str = "",
    buffer_size: int = 1000,
    promiscuous: bool = True,
    timeout: Optional[int] = None,
) -> ScapyCapture:
    """Create a Scapy capture instance.

    Factory function for creating ScapyCapture with default settings.

    Args:
        interface: Network interface name
        filter: BPF filter string
        buffer_size: Maximum packets to buffer
        promiscuous: Enable promiscuous mode
        timeout: Capture timeout in seconds

    Returns:
        Configured ScapyCapture instance

    Example:
        >>> capture = create_scapy_capture(interface="eth0")
        >>> capture.start_capture()
    """
    return ScapyCapture(
        interface=interface,
        filter=filter,
        buffer_size=buffer_size,
        promiscuous=promiscuous,
        timeout=timeout,
    )
