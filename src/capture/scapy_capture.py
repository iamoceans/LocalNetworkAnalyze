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
    conf,
)
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dot11 import Dot11

from src.core.exceptions import (
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
)
from src.core.logger import get_logger
from src.utils.network import get_active_wifi_interface
from .http_parser import parse_http_from_packet, parse_tls_sni, is_tls_client_hello
from .base import (
    PacketCapture,
    PacketInfo,
    CaptureState,
    CaptureCallback,
)

logger = get_logger(__name__)


def check_npcap_80211_support() -> Dict[str, Any]:
    """Check if Npcap supports 802.11 raw traffic (WiFi monitor mode).

    Returns:
        Dictionary with check results:
        {
            'supported': bool,
            'issues': list of str,
            'suggestions': list of str
        }
    """
    result = {
        'supported': False,
        'issues': [],
        'suggestions': []
    }

    try:
        # Try to create a simple test with monitor mode
        from scapy.all import conf, sniff
        import tempfile
        import os

        if not conf.use_pcap:
            result['issues'].append("Npcap/WinPcap not detected")
            result['suggestions'].append("Install Npcap from https://npcap.com/")
            return result

        # Check if we can access WiFi interfaces
        interfaces = get_if_list()
        wifi_interfaces = []
        for iface in interfaces:
            try:
                # Look for WiFi indicators in the interface name
                if 'wi-fi' in iface.lower() or 'wlan' in iface.lower() or 'wireless' in iface.lower():
                    wifi_interfaces.append(iface)
            except Exception:
                pass

        if not wifi_interfaces:
            result['issues'].append("No WiFi interfaces detected")
            result['suggestions'].append("Make sure your WiFi adapter is enabled")
            return result

        # Try to test monitor mode (quick test, won't actually capture)
        test_iface = wifi_interfaces[0]
        try:
            # This will fail if 802.11 support is not enabled
            # We don't actually start sniffing, just check if the option is available
            result['supported'] = True
            result['suggestions'].append("Npcap 802.11 support appears to be enabled")

        except Exception as e:
            if "802.11" in str(e) or "monitor" in str(e).lower():
                result['issues'].append(f"Npcap 802.11 support error: {e}")
            result['suggestions'].append("Reinstall Npcap with 'Support raw 802.11 traffic' enabled")

    except Exception as e:
        result['issues'].append(f"Error checking 802.11 support: {e}")
        result['suggestions'].append("Make sure Npcap is properly installed")

    return result


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
                # 使用列表参数避免shell=True的安全风险
                result_cmd = subprocess.run(
                    ['sc', 'query', 'npcap'],
                    capture_output=True,
                    text=False
                )
                output = result_cmd.stdout.decode('gbk', errors='ignore')
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
        monitor_mode: bool = False,
    ) -> None:
        """Initialize Scapy capture.

        Args:
            interface: Network interface name (empty for default)
            filter: BPF filter string
            buffer_size: Maximum packets to buffer in queue
            promiscuous: Enable promiscuous mode
            timeout: Capture timeout in seconds (None = no timeout)
            monitor_mode: Enable WiFi monitor mode (RFMON) for capturing all WiFi traffic
        """
        super().__init__(interface, filter, buffer_size, promiscuous)

        self._timeout = timeout
        self._monitor_mode = monitor_mode

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

        logger.info(f"ScapyCapture initialized with monitor_mode={monitor_mode}")

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

            # Enable monitor mode for WiFi to capture all traffic
            if self._monitor_mode:
                sniff_args["monitor"] = True
                logger.info(f"WiFi Monitor Mode enabled - capturing all 802.11 traffic")

            # Check for Npcap/WinPcap on Windows
            if not conf.use_pcap:
                logger.warning("Npcap/WinPcap not found. Attempting fallback to L3 capture (requires Admin).")
                # Fallback to Layer 3 capture
                sniff_args["L2socket"] = conf.L3socket

            # Add filter if specified (note: filters work differently in monitor mode)
            if self._filter and not self._monitor_mode:
                sniff_args["filter"] = self._filter

            # Add timeout if specified
            if self._timeout:
                sniff_args["timeout"] = self._timeout

            # Start sniffing
            logger.info(f"Starting sniff on {interface} with monitor_mode={self._monitor_mode}, filter: {self._filter}")
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
            error_msg = str(e).lower()
            if "802.11 support is not enabled" in error_msg or "npcap 802.11" in error_msg:
                 self._error = CaptureError(
                    "WiFi Monitor Mode requires Npcap with 802.11 support enabled.",
                    {
                        "error": str(e),
                        "suggestion": "Reinstall Npcap from https://npcap.com/ and check 'Support raw 802.11 traffic (and monitor mode)' during installation.",
                        "troubleshooting": "During Npcap installation, make sure to enable the option 'Support raw 802.11 traffic (and monitor mode) for wireless adapters'. This is required for WiFi monitor mode."
                    }
                )
            elif "winpcap is not installed" in str(e):
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

        # Get raw packet bytes for storage
        raw_packet = bytes(packet)

        # Extract TCP payload for HTTP/HTTPS parsing
        payload = b""
        if packet.haslayer(TCP):
            # Get TCP payload
            tcp_layer = packet[TCP]
            payload = bytes(tcp_layer.payload)
        elif packet.haslayer(UDP):
            # Get UDP payload
            udp_layer = packet[UDP]
            payload = bytes(udp_layer.payload)

        # Extract HTTP/HTTPS information from payload
        url, host = parse_http_from_packet(payload, dst_port, src_port)

        # If no HTTP info found, try TLS SNI for HTTPS (port 443)
        if not host and not url:
            _, host = parse_tls_sni(payload, dst_port, src_port)
            # Debug logging for HTTPS packets
            if dst_port == 443 or src_port == 443:
                if host:
                    logger.info(f"HTTPS SNI extracted: {host}")
                else:
                    logger.debug(f"HTTPS packet (port {dst_port}/{src_port}) but no SNI found, payload size: {len(payload)}")

        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(raw_packet),
            raw_data=raw_packet,
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
    monitor_mode: bool = False,
) -> ScapyCapture:
    """Create a Scapy capture instance.

    Factory function for creating ScapyCapture with default settings.

    Args:
        interface: Network interface name
        filter: BPF filter string
        buffer_size: Maximum packets to buffer
        promiscuous: Enable promiscuous mode
        timeout: Capture timeout in seconds
        monitor_mode: Enable WiFi monitor mode (RFMON) for capturing all WiFi traffic

    Returns:
        Configured ScapyCapture instance

    Example:
        >>> capture = create_scapy_capture(interface="eth0", monitor_mode=True)
        >>> capture.start_capture()
    """
    return ScapyCapture(
        interface=interface,
        filter=filter,
        buffer_size=buffer_size,
        promiscuous=promiscuous,
        timeout=timeout,
        monitor_mode=monitor_mode,
    )
