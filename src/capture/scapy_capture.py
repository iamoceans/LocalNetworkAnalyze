"""
Scapy-based packet capture implementation.

Uses the Scapy library for packet capture and parsing.
Provides a production-ready implementation of PacketCapture.
"""

import queue
import threading
import time
import os
import ctypes
from collections import deque
from datetime import datetime
from typing import Optional, Iterator, Callable, Dict, Any

from scapy.all import (
    sniff,
    get_if_list,
    get_if_addr,
    Packet as ScapyPacket,
)
from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

from src.core.exceptions import (
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
)
from src.core.logger import get_logger
from src.utils.network import get_active_wifi_interface
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

    @staticmethod
    def check_capture_environment() -> Dict[str, Any]:
        """Check if the capture environment is properly configured.

        Performs the following checks:
        1. Administrator/root privileges
        2. Npcap/WinPcap installation (Windows)
        3. Npcap service status (Windows)

        Returns:
            Dictionary with check results:
            {
                'is_admin': bool,
                'npcap_installed': bool,
                'npcap_service_running': bool,
                'issues': list of str,
                'suggestions': list of str
            }
        """
        result = {
            'is_admin': False,
            'npcap_installed': True,  # Assume true on non-Windows
            'npcap_service_running': True,
            'issues': [],
            'suggestions': []
        }

        # Check for administrator privileges
        try:
            if os.name == 'nt':  # Windows
                # Check if running as administrator
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                result['is_admin'] = bool(is_admin)
            else:
                # On Unix-like systems, check if we are root
                result['is_admin'] = (os.geteuid() == 0)
        except Exception:
            result['is_admin'] = False

        if not result['is_admin']:
            result['issues'].append("Not running with administrator privileges")
            if os.name == 'nt':
                result['suggestions'].append("Right-click the program and select 'Run as administrator'")
            else:
                result['suggestions'].append("Run the program with sudo: sudo python src/main.py")

        # Check for Npcap/WinPcap on Windows
        if os.name == 'nt':
            # Check if Npcap is available via Scapy
            try:
                result['npcap_installed'] = conf.use_pcap

                if not conf.use_pcap:
                    result['issues'].append("Npcap/WinPcap not detected")
                    result['suggestions'].append("Download and install Npcap from https://npcap.com/")
                    result['suggestions'].append("During installation, check 'Install Npcap in WinPcap API-compatible Mode'")
            except Exception:
                result['npcap_installed'] = False

            # Check Npcap service status
            try:
                import subprocess
                output = subprocess.check_output(
                    'sc query npcap',
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode('gbk', errors='ignore')
                result['npcap_service_running'] = 'RUNNING' in output
            except Exception:
                # If service check fails, assume Npcap is not properly installed
                if not result['npcap_installed']:
                    result['npcap_service_running'] = False

            if not result['npcap_service_running'] and result['npcap_installed']:
                result['issues'].append("Npcap service is not running")
                result['suggestions'].append("Start the Npcap service: net start npcap")

        return result

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
        
        # Error tracking
        self._error: Optional[Exception] = None

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

        # Check environment before starting
        env_check = self.check_capture_environment()
        if env_check['issues']:
            logger.warning(f"Environment issues detected: {env_check['issues']}")

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
            self._error = None

            # Start capture thread
            self._capture_thread = threading.Thread(
                target=self._capture_loop,
                name=f"ScapyCapture-{interface}",
                daemon=True,
            )
            self._capture_thread.start()

            # Wait for capture to actually start
            if not self.wait_for_state(CaptureState.RUNNING, timeout=5):
                if self.state == CaptureState.ERROR and self._error:
                    raise self._error
                raise CaptureError("Capture failed to start within timeout")

            logger.info(f"Capture started on interface {interface}")

        except PermissionError as e:
            self._set_state(CaptureState.ERROR)
            env_check = self.check_capture_environment()
            suggestions = env_check.get('suggestions', [])

            error_msg = "Administrator privileges required for packet capture"
            details = {"error": str(e)}

            if suggestions:
                details["suggestion"] = suggestions[0]
                if len(suggestions) > 1:
                    details["additional_suggestions"] = suggestions[1:]

            raise PermissionDeniedError(error_msg, details)
        except OSError as e:
            self._set_state(CaptureState.ERROR)
            error_msg = str(e).lower()

            if "permission denied" in error_msg or "operation not permitted" in error_msg:
                env_check = self.check_capture_environment()
                suggestions = env_check.get('suggestions', [])

                details = {"error": str(e)}
                if suggestions:
                    details["suggestion"] = suggestions[0]

                raise PermissionDeniedError(
                    "Permission denied for packet capture",
                    details,
                )

            # Check for Npcap-related errors on Windows
            if os.name == 'nt':
                if "socket" in error_msg or "no such device" in error_msg:
                    raise CaptureError(
                        "Npcap driver not available or not properly installed",
                        {
                            "error": str(e),
                            "suggestion": "Install Npcap from https://npcap.com/ and select 'Install Npcap in WinPcap API-compatible Mode'",
                            "troubleshooting": "Ensure Npcap service is running: sc query npcap",
                        }
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
        interfaces = self.get_interfaces()
        
        # Try to identify the active Wi-Fi interface using system routing
        active_wifi = get_active_wifi_interface()
        active_wifi_ip = active_wifi[1] if active_wifi else None
        
        if active_wifi:
            logger.info(f"Detected active Wi-Fi interface: {active_wifi[0]} ({active_wifi[1]})")

        candidates = []
        
        for iface in interfaces:
            ip = iface.get("address", "")
            name = iface.get("name", "").lower()
            desc = iface.get("description", "").lower()
            
            # Skip loopback and empty IPs
            if not ip or ip == "0.0.0.0" or ip == "127.0.0.1":
                continue
                
            # Skip link-local addresses (169.254.x.x) usually indicating no connectivity
            if ip.startswith("169.254."):
                continue
                
            # Score the interface
            score = 0
            
            # CRITICAL: Match against the detected active Wi-Fi IP
            # This ensures we pick the specific Scapy interface that corresponds 
            # to the system's active Wi-Fi adapter
            if active_wifi_ip and ip == active_wifi_ip:
                score += 100
                logger.info(f"Interface {iface['name']} matches active Wi-Fi IP {ip}, boosting score.")
            
            # Prioritize WiFi/Wireless interfaces as requested by user context
            if "wi-fi" in desc or "wireless" in desc or "802.11" in desc or "wlan" in desc:
                score += 20  # Boost WiFi score significantly
            elif "ethernet" in desc:
                score += 5
            elif "adapter" in desc:
                score += 2
                
            candidates.append((score, iface["name"]))
            
        # Sort by score descending
        candidates.sort(key=lambda x: x[0], reverse=True)
        
        if candidates:
            logger.info(f"Auto-selected interface: {candidates[0][1]}")
            return candidates[0][1]

        # Fallback to Scapy's default logic
        if conf.iface:
             return conf.iface.name

        raise InterfaceNotFoundError(
            "No suitable network interface found",
            {"available_interfaces": [i["name"] for i in interfaces]},
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

            # Check for Npcap/WinPcap on Windows
            if not conf.use_pcap:
                logger.warning("Npcap/WinPcap not found. Attempting fallback to L3 capture (requires Admin).")
                # Fallback to Layer 3 capture
                sniff_args["L2socket"] = conf.L3socket

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
            self._error = e
            self._set_state(CaptureState.ERROR)
            # The thread will exit, and start_capture will pick up the error
        except OSError as e:
            logger.error(f"OS error during capture: {e}")
            if "install Npcap" in str(e) or "administrator" in str(e).lower():
                 self._error = CaptureError(
                    "Capture failed: Npcap not installed or Admin rights missing.",
                    {"error": str(e), "suggestion": "Install Npcap (https://npcap.com/) and run as Administrator."}
                )
            else:
                self._error = CaptureError(f"OS Error: {e}")
            self._set_state(CaptureState.ERROR)
        except RuntimeError as e:
            logger.error(f"Runtime error during capture: {e}")
            if "winpcap is not installed" in str(e):
                 self._error = CaptureError(
                    "Npcap is not installed.",
                    {"error": str(e), "suggestion": "Please install Npcap (select 'Install Npcap in WinPcap API-compatible Mode')."}
                )
            else:
                self._error = CaptureError(f"Runtime Error: {e}")
            self._set_state(CaptureState.ERROR)
        except Exception as e:
            logger.error(f"Unexpected error in capture loop: {e}")
            self._error = CaptureError(f"Unexpected error: {e}")
            self._set_state(CaptureState.ERROR)
        finally:
            if self.state != CaptureState.ERROR:
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

        # Extract HTTP/HTTPS information
        url = None
        host = None

        # Check for HTTP traffic (port 80)
        if dst_port == 80 or src_port == 80:
            try:
                # Try to extract HTTP request from raw payload
                raw_data = bytes(packet)

                # Look for HTTP request line
                if b"GET " in raw_data or b"POST " in raw_data or b"HEAD " in raw_data:
                    # Try to decode as text
                    try:
                        payload_str = raw_data.decode('utf-8', errors='ignore')

                        # Find the HTTP request line
                        lines = payload_str.split('\r\n')
                        if lines:
                            request_line = lines[0]
                            parts = request_line.split(' ')
                            if len(parts) >= 2 and parts[0] in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'):
                                path = parts[1]
                                # Extract Host header
                                for line in lines[1:]:
                                    if line.lower().startswith('host:'):
                                        host = line.split(':', 1)[1].strip()
                                        # Construct full URL
                                        url = f"http://{host}{path}"
                                        break
                    except Exception:
                        pass

            except Exception:
                pass

        # For HTTPS (port 443), we can only extract SNI from TLS ClientHello
        # This is more complex and may require additional libraries
        # For now, we'll mark HTTPS traffic but won't extract the URL
        elif dst_port == 443 or src_port == 443:
            try:
                raw_data = bytes(packet)
                # TLS ClientHello starts with \x16\x03
                if raw_data[:2] == b'\x16\x03':
                    # This is likely a TLS packet
                    # For HTTPS traffic without SNI parsing, we just mark it
                    # A full TLS parser would be needed to extract SNI
                    pass
            except Exception:
                pass

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
            url=url,
            host=host,
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
            List of interface information dictionaries with correct device names
        """
        interfaces = []

        # First, get the list of interface names that Scapy can actually use
        # These are the long format names like \Device\NPF_{...}
        valid_iface_names = get_if_list()

        # Build a map of IP address to device name (for matching with conf.ifaces)
        ip_to_device = {}
        for device_name in valid_iface_names:
            try:
                ip = get_if_addr(device_name)
                # Skip interfaces with no IP or 0.0.0.0
                if ip and ip != "0.0.0.0":
                    ip_to_device[ip] = device_name
            except Exception:
                pass

        # Try to get friendly names from conf.ifaces
        try:
            for iface in conf.ifaces.values():
                try:
                    ip = iface.ip
                    # Skip if no IP or not in our valid interface list
                    if not ip or ip == "0.0.0.0":
                        continue

                    # Get the actual device name
                    device_name = ip_to_device.get(ip)

                    if not device_name:
                        continue

                    description = iface.description
                    mac = iface.mac

                    # Use description as friendly name
                    friendly_name = description if description else device_name

                    interfaces.append({
                        "name": device_name,  # Use actual device name that Scapy needs
                        "address": ip,
                        "description": friendly_name,
                        "mac": mac
                    })
                except Exception as e:
                    logger.warning(f"Error processing interface {iface}: {e}")
                    continue
        except Exception as e:
            logger.debug(f"Error getting interfaces from Scapy conf: {e}")

        # If we didn't get any interfaces from conf.ifaces, use get_if_list directly
        if not interfaces:
            for device_name in valid_iface_names:
                try:
                    ip = get_if_addr(device_name)
                    # Skip empty IPs
                    if not ip or ip == "0.0.0.0":
                        continue

                    interfaces.append({
                        "name": device_name,
                        "address": ip,
                        "description": device_name,  # No friendly name available
                        "mac": None
                    })
                except Exception:
                    continue

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
