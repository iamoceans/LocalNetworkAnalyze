"""
ICMP network scanner.

Discovers hosts using ICMP echo requests (ping).
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional

from scapy.all import IP, ICMP, sr, conf

from src.core.logger import get_logger
from src.core.exceptions import ScanError
from .base import (
    NetworkScanner,
    ScanResult,
    ScanReport,
    ScanType,
    ScanState,
    validate_targets,
)


class ICMPScanner(NetworkScanner):
    """ICMP scanner for network discovery.

    Sends ICMP echo requests (ping) to discover hosts.
    Works across subnets but may be blocked by firewalls.
    """

    def __init__(
        self,
        targets: List[str],
        timeout: float = 1.0,
        threads: int = 10,
    ) -> None:
        """Initialize ICMP scanner.

        Args:
            targets: List of target IP addresses or CIDR ranges
            timeout: Timeout per ICMP request in seconds
            threads: Number of parallel threads
        """
        super().__init__(targets, timeout, threads)
        self._cancel_event = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None

        logger = get_logger(__name__)
        self._logger = logger

    def get_scan_type(self) -> ScanType:
        """Get scan type.

        Returns:
            ScanType.ICMP
        """
        return ScanType.ICMP

    def scan(self) -> ScanReport:
        """Perform ICMP scan.

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
            self._logger.info(f"Starting ICMP scan for {len(targets)} targets")

            self._set_state(ScanState.SCANNING)

            # Scan targets
            results = []

            if self._threads > 1:
                results = self._scan_parallel(targets)
            else:
                results = self._scan_sequential(targets)

            alive_count = sum(1 for r in results if r.is_alive)

            self._results = results
            self._end_time = datetime.now()
            self._set_state(ScanState.COMPLETED)

            report = ScanReport(
                scan_type=ScanType.ICMP,
                start_time=self._start_time,
                end_time=self._end_time,
                targets=self._targets,
                results=results,
                alive_count=alive_count,
                state=ScanState.COMPLETED,
            )

            self._logger.info(
                f"ICMP scan completed: {alive_count}/{len(targets)} hosts alive"
            )

            return report

        except Exception as e:
            self._end_time = datetime.now()
            self._set_state(ScanState.FAILED)
            raise ScanError(f"ICMP scan failed: {e}")

    def cancel(self) -> None:
        """Cancel the scan."""
        self._cancel_event.set()

        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

        self._set_state(ScanState.CANCELLED)
        self._logger.info("ICMP scan cancelled")

    def _scan_parallel(self, targets: List[str]) -> List[ScanResult]:
        """Scan targets in parallel.

        Args:
            targets: List of IP addresses to scan

        Returns:
            List of scan results
        """
        results = []
        total = len(targets)
        completed = 0

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            future_to_target = {
                executor.submit(self._scan_single, target): target
                for target in targets
            }

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
                    results.append(
                        ScanResult(
                            ip=target,
                            is_alive=False,
                            scan_type=ScanType.ICMP,
                        )
                    )
                    completed += 1

        return results

    def _scan_sequential(self, targets: List[str]) -> List[ScanResult]:
        """Scan targets sequentially.

        Args:
            targets: List of IP addresses to scan

        Returns:
            List of scan results
        """
        results = []
        total = len(targets)

        for i, target in enumerate(targets, start=1):
            if self._cancel_event.is_set():
                break

            result = self._scan_single(target)
            results.append(result)

            if result.is_alive:
                self._notify_progress(i, total, target)

        return results

    def _scan_single(self, target: str) -> ScanResult:
        """Scan a single target.

        Args:
            target: IP address to scan

        Returns:
            ScanResult for the target
        """
        start_time = time.time()

        try:
            # Create ICMP echo request
            icmp_packet = IP(dst=target) / ICMP()

            # Send and receive
            response = sr(icmp_packet, timeout=self._timeout, verbose=0)

            response_time = (time.time() - start_time) * 1000  # ms

            # Check for responses
            if response and response[0]:
                return ScanResult(
                    ip=target,
                    is_alive=True,
                    response_time=round(response_time, 2),
                    scan_type=ScanType.ICMP,
                )
            else:
                return ScanResult(
                    ip=target,
                    is_alive=False,
                    scan_type=ScanType.ICMP,
                )

        except Exception as e:
            self._logger.debug(f"Error scanning {target}: {e}")
            return ScanResult(
                ip=target,
                is_alive=False,
                scan_type=ScanType.ICMP,
            )


def create_icmp_scanner(
    targets: List[str],
    timeout: float = 1.0,
    threads: int = 10,
) -> ICMPScanner:
    """Create ICMP scanner instance.

    Args:
        targets: List of target IP addresses or CIDR ranges
        timeout: Timeout per ICMP request in seconds
        threads: Number of parallel threads

    Returns:
        Configured ICMPScanner instance

    Example:
        >>> scanner = create_icmp_scanner(["192.168.1.0/24"])
        >>> report = scanner.scan()
        >>> print(f"Found {report.alive_count} hosts")
    """
    return ICMPScanner(
        targets=targets,
        timeout=timeout,
        threads=threads,
    )
