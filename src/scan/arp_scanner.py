"""
ARP network scanner.

Discovers hosts on the local network using ARP requests.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional, Dict

from scapy.all import ARP, Ether, srp, conf
from scapy.arch import get_if_hwaddr, get_if_addr

from src.core.logger import get_logger
from src.core.exceptions import ScanError
from .base import (
    NetworkScanner,
    ScanResult,
    ScanReport,
    ScanType,
    ScanState,
    ScanProgressCallback,
    validate_targets,
)


class ARPScanner(NetworkScanner):
    """ARP scanner for local network discovery.

    Sends ARP requests to discover hosts on the local network.
    Fast and reliable for local subnet discovery.
    """

    def __init__(
        self,
        targets: List[str],
        timeout: float = 1.0,
        threads: int = 10,
        interface: str = "",
    ) -> None:
        """Initialize ARP scanner.

        Args:
            targets: List of target IP addresses or CIDR ranges
            timeout: Timeout per ARP request in seconds
            threads: Number of parallel threads
            interface: Network interface to use (empty for default)
        """
        super().__init__(targets, timeout, threads)
        self._interface = interface
        self._cancel_event = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None

        logger = get_logger(__name__)
        self._logger = logger

    def get_scan_type(self) -> ScanType:
        """Get scan type.

        Returns:
            ScanType.ARP
        """
        return ScanType.ARP

    def scan(self) -> ScanReport:
        """Perform ARP scan.

        Returns:
            ScanReport with all discovered hosts

        Raises:
            ScanError: If scan fails
        """
        self._set_state(ScanState.PREPARING)
        self._start_time = datetime.now()
        self._end_time = None

        try:
            # Validate and expand targets
            targets = validate_targets(self._targets)
            self._logger.info(f"Starting ARP scan for {len(targets)} targets")

            # Get interface info
            interface = self._interface or self._get_default_interface()
            src_mac = get_if_hwaddr(interface)
            src_ip = get_if_addr(interface)

            self._set_state(ScanState.SCANNING)

            # Scan targets
            results = []
            alive_count = 0

            if self._threads > 1:
                # Parallel scanning
                results = self._scan_parallel(targets, interface, src_mac)
            else:
                # Sequential scanning
                results = self._scan_sequential(targets, interface, src_mac)

            alive_count = sum(1 for r in results if r.is_alive)

            self._results = results
            self._end_time = datetime.now()
            self._set_state(ScanState.COMPLETED)

            report = ScanReport(
                scan_type=ScanType.ARP,
                start_time=self._start_time,
                end_time=self._end_time,
                targets=self._targets,
                results=results,
                alive_count=alive_count,
                state=ScanState.COMPLETED,
            )

            self._logger.info(
                f"ARP scan completed: {alive_count}/{len(targets)} hosts alive"
            )

            return report

        except Exception as e:
            self._end_time = datetime.now()
            self._set_state(ScanState.FAILED)
            raise ScanError(f"ARP scan failed: {e}")

    def cancel(self) -> None:
        """Cancel the scan."""
        self._cancel_event.set()

        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

        self._set_state(ScanState.CANCELLED)
        self._logger.info("ARP scan cancelled")

    def _scan_parallel(
        self,
        targets: List[str],
        interface: str,
        src_mac: str,
    ) -> List[ScanResult]:
        """Scan targets in parallel.

        Args:
            targets: List of IP addresses to scan
            interface: Network interface
            src_mac: Source MAC address

        Returns:
            List of scan results
        """
        results = []
        total = len(targets)
        completed = 0

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            # Submit all scan tasks
            future_to_target = {
                executor.submit(self._scan_single, target, interface, src_mac): target
                for target in targets
            }

            # Process results as they complete
            for future in as_completed(future_to_target):
                if self._cancel_event.is_set():
                    break

                target = future_to_target[future]
                try:
                    result = future.result(timeout=self._timeout + 1)
                    results.append(result)
                    completed += 1

                    if result.is_alive:
                        self._notify_progress(completed, total, target)

                except Exception as e:
                    self._logger.warning(f"Error scanning {target}: {e}")
                    # Add failed result
                    results.append(
                        ScanResult(
                            ip=target,
                            is_alive=False,
                            scan_type=ScanType.ARP,
                        )
                    )
                    completed += 1

        return results

    def _scan_sequential(
        self,
        targets: List[str],
        interface: str,
        src_mac: str,
    ) -> List[ScanResult]:
        """Scan targets sequentially.

        Args:
            targets: List of IP addresses to scan
            interface: Network interface
            src_mac: Source MAC address

        Returns:
            List of scan results
        """
        results = []
        total = len(targets)

        for i, target in enumerate(targets, start=1):
            if self._cancel_event.is_set():
                break

            result = self._scan_single(target, interface, src_mac)
            results.append(result)

            if result.is_alive:
                self._notify_progress(i, total, target)

        return results

    def _scan_single(
        self,
        target: str,
        interface: str,
        src_mac: str,
    ) -> ScanResult:
        """Scan a single target.

        Args:
            target: IP address to scan
            interface: Network interface
            src_mac: Source MAC address

        Returns:
            ScanResult for the target
        """
        start_time = time.time()

        try:
            # Create ARP packet
            arp_packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                pdst=target
            )

            # Send and receive
            result = srp(arp_packet, timeout=self._timeout, iface=interface, verbose=0)

            response_time = (time.time() - start_time) * 1000  # ms

            # Check for responses
            if result and result[0]:
                received = result[0][0]  # Get first response
                arp = received[1]

                return ScanResult(
                    ip=target,
                    mac=arp.hwsrc,
                    is_alive=True,
                    response_time=round(response_time, 2),
                    scan_type=ScanType.ARP,
                )
            else:
                return ScanResult(
                    ip=target,
                    is_alive=False,
                    scan_type=ScanType.ARP,
                )

        except Exception as e:
            self._logger.debug(f"Error scanning {target}: {e}")
            return ScanResult(
                ip=target,
                is_alive=False,
                scan_type=ScanType.ARP,
            )

    def _get_default_interface(self) -> str:
        """Get default network interface.

        Returns:
            Interface name
        """
        if conf.iface:
            return conf.iface

        # Try to find a suitable interface
        from scapy.arch import get_if_list

        interfaces = get_if_list()
        for iface in interfaces:
            if iface.lower() not in ("lo", "loopback"):
                try:
                    addr = get_if_addr(iface)
                    if addr and addr != "0.0.0.0":
                        return iface
                except Exception:
                    continue

        # Fallback
        return interfaces[0] if interfaces else "eth0"


def create_arp_scanner(
    targets: List[str],
    timeout: float = 1.0,
    threads: int = 10,
    interface: str = "",
) -> ARPScanner:
    """Create ARP scanner instance.

    Args:
        targets: List of target IP addresses or CIDR ranges
        timeout: Timeout per ARP request in seconds
        threads: Number of parallel threads
        interface: Network interface to use

    Returns:
        Configured ARPScanner instance

    Example:
        >>> scanner = create_arp_scanner(["192.168.1.0/24"])
        >>> report = scanner.scan()
        >>> print(f"Found {report.alive_count} hosts")
    """
    return ARPScanner(
        targets=targets,
        timeout=timeout,
        threads=threads,
        interface=interface,
    )
