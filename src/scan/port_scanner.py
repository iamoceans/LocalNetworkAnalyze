"""
Port scanner for network service discovery.

Scans specific ports on target hosts to discover running services.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional, Set, Dict

from scapy.all import IP, TCP, UDP, sr, sr1, conf
from scapy.packet import Packet

from src.core.logger import get_logger
from src.core.exceptions import ScanError
from src.utils.constants import Port
from .base import (
    NetworkScanner,
    ScanResult,
    ScanReport,
    ScanType,
    ScanState,
    validate_targets,
)


class PortScanner(NetworkScanner):
    """Port scanner for service discovery.

    Scans specific ports on target hosts to identify open ports
    and running services.
    """

    # Common ports to scan by default
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP Alt
        27017, # MongoDB
    ]

    def __init__(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        timeout: float = 1.0,
        threads: int = 50,
        scan_type: ScanType = ScanType.TCP_SYN,
    ) -> None:
        """Initialize port scanner.

        Args:
            targets: List of target IP addresses
            ports: List of ports to scan (None for common ports)
            timeout: Timeout per port in seconds
            threads: Number of parallel threads
            scan_type: Type of port scan to perform
        """
        super().__init__(targets, timeout, threads)
        self._ports = ports or self.COMMON_PORTS
        self._scan_type = scan_type
        self._cancel_event = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None

        logger = get_logger(__name__)
        self._logger = logger

    def get_scan_type(self) -> ScanType:
        """Get scan type.

        Returns:
            Scan type
        """
        return self._scan_type

    def scan(self) -> ScanReport:
        """Perform port scan.

        Returns:
            ScanReport with port scan results

        Raises:
            ScanError: If scan fails
        """
        self._set_state(ScanState.PREPARING)
        self._start_time = datetime.now()
        self._end_time = None

        try:
            # Validate and expand targets
            targets = validate_targets(self._targets)
            self._logger.info(
                f"Starting {self._scan_type.value} scan for "
                f"{len(targets)} hosts, {len(self._ports)} ports"
            )

            self._set_state(ScanState.SCANNING)

            # Perform scan
            results = self._scan_all(targets)

            alive_count = sum(1 for r in results if r.is_alive)

            self._results = results
            self._end_time = datetime.now()
            self._set_state(ScanState.COMPLETED)

            report = ScanReport(
                scan_type=self._scan_type,
                start_time=self._start_time,
                end_time=self._end_time,
                targets=self._targets,
                results=results,
                alive_count=alive_count,
                state=ScanState.COMPLETED,
            )

            self._logger.info(
                f"Port scan completed: {alive_count}/{len(targets)} hosts "
                f"with open ports"
            )

            return report

        except Exception as e:
            self._end_time = datetime.now()
            self._set_state(ScanState.FAILED)
            raise ScanError(f"Port scan failed: {e}")

    def cancel(self) -> None:
        """Cancel the scan."""
        self._cancel_event.set()

        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

        self._set_state(ScanState.CANCELLED)
        self._logger.info("Port scan cancelled")

    def _scan_all(self, targets: List[str]) -> List[ScanResult]:
        """Scan all targets.

        Args:
            targets: List of IP addresses

        Returns:
            List of scan results
        """
        # Group results by IP
        results_by_ip: Dict[str, Dict[int, bool]] = {target: {} for target in targets}

        total_scans = len(targets) * len(self._ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            # Submit scan tasks
            futures = []
            for target in targets:
                for port in self._ports:
                    if self._cancel_event.is_set():
                        break
                    future = executor.submit(self._scan_port, target, port)
                    futures.append((future, target, port))

            # Process results
            for future, target, port in futures:
                if self._cancel_event.is_set():
                    break

                try:
                    is_open = future.result(timeout=self._timeout + 1)
                    results_by_ip[target][port] = is_open
                    completed += 1

                    if completed % 10 == 0:  # Notify every 10 ports
                        self._notify_progress(completed, total_scans, target)

                except Exception as e:
                    self._logger.debug(f"Error scanning {target}:{port}: {e}")
                    results_by_ip[target][port] = False

        # Convert to ScanResult objects
        results = []
        for target, ports_status in results_by_ip.items():
            open_ports = {p for p, is_open in ports_status.items() if is_open}

            results.append(
                ScanResult(
                    ip=target,
                    is_alive=len(open_ports) > 0,
                    scan_type=self._scan_type,
                    open_ports=frozenset(open_ports),
                    services=self._identify_services(open_ports),
                )
            )

        return results

    def _scan_port(self, target: str, port: int) -> bool:
        """Scan a single port on a target.

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is open
        """
        if self._scan_type == ScanType.TCP_SYN:
            return self._scan_tcp_syn(target, port)
        elif self._scan_type == ScanType.TCP_CONNECT:
            return self._scan_tcp_connect(target, port)
        elif self._scan_type == ScanType.UDP:
            return self._scan_udp(target, port)
        else:
            return False

    def _scan_tcp_syn(self, target: str, port: int) -> bool:
        """Scan port using TCP SYN (stealth scan).

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is open
        """
        try:
            # Create SYN packet
            packet = IP(dst=target) / TCP(dport=port, flags="S")

            # Send and wait for response
            response = sr1(packet, timeout=self._timeout, verbose=0)

            if response is None:
                return False

            # Check if SYN-ACK received
            if response.haslayer(TCP):
                tcp_layer = response[TCP]
                if tcp_layer.flags & 0x12:  # SYN-ACK
                    return True
                elif tcp_layer.flags & 0x14:  # RST-ACK
                    return False

            return False

        except Exception:
            return False

    def _scan_tcp_connect(self, target: str, port: int) -> bool:
        """Scan port using TCP connect (full connection).

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is open
        """
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)

            result = sock.connect_ex((target, port))
            sock.close()

            return result == 0

        except Exception:
            return False

    def _scan_udp(self, target: str, port: int) -> bool:
        """Scan UDP port.

        Args:
            target: IP address
            port: Port number

        Returns:
            True if port is likely open
        """
        try:
            # Create UDP packet
            packet = IP(dst=target) / UDP(dport=port)

            # Send and wait for response
            response = sr1(packet, timeout=self._timeout, verbose=0)

            # UDP scanning is less reliable
            # If we get any response, the port is likely open
            return response is not None

        except Exception:
            return False

    def _identify_services(self, open_ports: Set[int]) -> Dict[str, str]:
        """Identify services for open ports.

        Args:
            open_ports: Set of open port numbers

        Returns:
            Dictionary of port -> service name
        """
        services = {}

        service_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-alt",
            27017: "mongodb",
        }

        for port in sorted(open_ports):
            if port in service_map:
                services[str(port)] = service_map[port]
            else:
                services[str(port)] = "unknown"

        return services


def create_port_scanner(
    targets: List[str],
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    threads: int = 50,
    scan_type: ScanType = ScanType.TCP_SYN,
) -> PortScanner:
    """Create port scanner instance.

    Args:
        targets: List of target IP addresses
        ports: List of ports to scan (None for common ports)
        timeout: Timeout per port in seconds
        threads: Number of parallel threads
        scan_type: Type of port scan

    Returns:
        Configured PortScanner instance

    Example:
        >>> scanner = create_port_scanner(["192.168.1.1"])
        >>> report = scanner.scan()
        >>> for result in report.results:
        ...     if result.is_alive:
        ...         print(f"{result.ip}: {result.open_ports}")
    """
    return PortScanner(
        targets=targets,
        ports=ports,
        timeout=timeout,
        threads=threads,
        scan_type=scan_type,
    )
