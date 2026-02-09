"""
Network scanning module.

Provides functionality for discovering and scanning hosts
on the local network.
"""

from typing import List, Optional

from .base import (
    NetworkScanner,
    ScanResult,
    ScanReport,
    ScanType,
    ScanState,
    validate_targets,
    parse_ip_range,
    get_local_network,
    is_valid_ip,
    is_valid_cidr,
)
from .arp_scanner import ARPScanner, create_arp_scanner
from .icmp_scanner import ICMPScanner, create_icmp_scanner
from .port_scanner import PortScanner, create_port_scanner

__all__ = [
    # Base classes
    "NetworkScanner",
    "ScanResult",
    "ScanReport",
    "ScanType",
    "ScanState",
    # Scanners
    "ARPScanner",
    "ICMPScanner",
    "PortScanner",
    # Factory functions
    "create_arp_scanner",
    "create_icmp_scanner",
    "create_port_scanner",
    "create_scanner",
    "create_network_scanner",
    # Utility functions
    "validate_targets",
    "parse_ip_range",
    "get_local_network",
    "is_valid_ip",
    "is_valid_cidr",
]


def create_scanner(
    scan_type: ScanType,
    targets: List[str],
    timeout: float = 1.0,
    threads: int = 10,
    **kwargs,
) -> NetworkScanner:
    """Create a scanner instance based on type.

    Factory function that creates the appropriate scanner implementation.

    Args:
        scan_type: Type of scan to perform
        targets: List of target IP addresses or CIDR ranges
        timeout: Timeout per target/port in seconds
        threads: Number of parallel threads
        **kwargs: Additional scanner-specific arguments

    Returns:
        Configured NetworkScanner instance

    Raises:
        ValueError: If scan type is not supported

    Example:
        >>> scanner = create_scanner(ScanType.ARP, ["192.168.1.0/24"])
        >>> report = scanner.scan()
        >>> print(f"Found {report.alive_count} hosts")
    """
    if scan_type == ScanType.ARP:
        interface = kwargs.get("interface", "")
        return create_arp_scanner(targets, timeout, threads, interface)

    elif scan_type == ScanType.ICMP:
        return create_icmp_scanner(targets, timeout, threads)

    elif scan_type in (ScanType.TCP_SYN, ScanType.TCP_CONNECT, ScanType.UDP):
        ports = kwargs.get("ports")
        return create_port_scanner(targets, ports, timeout, threads, scan_type)

    else:
        raise ValueError(f"Unsupported scan type: {scan_type}")


def quick_scan(
    network: str = "auto",
    scan_type: ScanType = ScanType.ARP,
    timeout: float = 1.0,
) -> ScanReport:
    """Perform a quick scan of the local network.

    Convenience function for common scanning tasks.

    Args:
        network: Network to scan (CIDR or "auto" for local network)
        scan_type: Type of scan to perform
        timeout: Timeout per target in seconds

    Returns:
        ScanReport with results

    Example:
        >>> report = quick_scan()
        >>> for host in report.get_alive_hosts():
        ...     print(f"{host.ip} - {host.mac}")
    """
    # Determine targets
    if network == "auto":
        network = get_local_network() or "192.168.1.0/24"

    targets = [network]

    # Create and run scanner
    scanner = create_scanner(scan_type, targets, timeout=timeout)
    return scanner.scan()


def scan_hosts(
    hosts: List[str],
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
) -> ScanReport:
    """Scan specific hosts for open ports.

    Args:
        hosts: List of IP addresses to scan
        ports: List of ports to scan (None for common ports)
        timeout: Timeout per port in seconds

    Returns:
        ScanReport with port scan results

    Example:
        >>> report = scan_hosts(["192.168.1.1", "192.168.1.2"])
        >>> for result in report.results:
        ...     if result.is_alive:
        ...         print(f"{result.ip}: {result.open_ports}")
    """
    scanner = create_port_scanner(
        targets=hosts,
        ports=ports,
        timeout=timeout,
        scan_type=ScanType.TCP_SYN,
    )
    return scanner.scan()


class NetworkScannerWrapper:
    """Wrapper that provides a simple interface for all scan types.

    This class provides a convenient interface for performing different
    types of network scans without needing to manage scanner instances.
    """

    def __init__(self, timeout: float = 1.0, threads: int = 10) -> None:
        """Initialize network scanner wrapper.

        Args:
            timeout: Timeout per target/port in seconds
            threads: Number of parallel threads
        """
        self._timeout = timeout
        self._threads = threads

    def arp_scan(self, target: str, interface: str = "") -> List[dict]:
        """Perform ARP scan on target.

        Args:
            target: Target IP address or CIDR range
            interface: Network interface to use (empty for default)

        Returns:
            List of scan result dictionaries
        """
        scanner = create_arp_scanner(
            targets=[target],
            timeout=self._timeout,
            threads=self._threads,
            interface=interface,
        )
        report = scanner.scan()
        return self._report_to_dict_list(report)

    def icmp_scan(self, target: str) -> List[dict]:
        """Perform ICMP scan on target.

        Args:
            target: Target IP address or CIDR range

        Returns:
            List of scan result dictionaries
        """
        scanner = create_icmp_scanner(
            targets=[target],
            timeout=self._timeout,
            threads=self._threads,
        )
        report = scanner.scan()
        return self._report_to_dict_list(report)

    def port_scan(self, target: str, ports: List[int]) -> List[dict]:
        """Perform TCP port scan on target.

        Args:
            target: Target IP address
            ports: List of ports to scan

        Returns:
            List of scan result dictionaries
        """
        scanner = create_port_scanner(
            targets=[target],
            ports=ports,
            timeout=self._timeout,
            threads=self._threads,
            scan_type=ScanType.TCP_SYN,
        )
        report = scanner.scan()
        return self._report_to_dict_list(report)

    def _report_to_dict_list(self, report: ScanReport) -> List[dict]:
        """Convert scan report to list of dictionaries.

        Args:
            report: Scan report

        Returns:
            List of result dictionaries
        """
        results = []
        for result in report.results:
            result_dict = {
                "ip": result.ip,
                "alive": result.is_alive,
                "mac": result.mac,
                "hostname": result.hostname,
                "latency": result.response_time,
                "ports": list(result.open_ports) if result.open_ports else [],
            }
            results.append(result_dict)
        return results


def create_network_scanner(
    timeout: float = 1.0,
    threads: int = 10,
) -> NetworkScannerWrapper:
    """Create a network scanner instance.

    Factory function that creates a scanner with all scan types available.

    Args:
        timeout: Timeout per target/port in seconds
        threads: Number of parallel threads

    Returns:
        NetworkScannerWrapper instance

    Example:
        >>> scanner = create_network_scanner()
        >>> results = scanner.arp_scan("192.168.1.0/24")
        >>> for host in results:
        ...     if host['alive']:
        ...         print(f"{host['ip']} is up")
    """
    return NetworkScannerWrapper(timeout=timeout, threads=threads)
