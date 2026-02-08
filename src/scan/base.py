"""
Base classes for network scanning functionality.

Defines the abstract interface for network scanners and
common data structures for scan results.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Callable, Protocol
from threading import Lock, Condition
import ipaddress

from src.core.exceptions import ScanError, InvalidRangeError


class ScanType(Enum):
    """Network scan types.

    Attributes:
        ARP: ARP scan (send ARP requests to discover hosts)
        ICMP: ICMP ping scan (send ICMP echo requests)
        TCP_SYN: TCP SYN scan (send SYN packets)
        TCP_CONNECT: TCP connect scan (full connection)
        UDP: UDP scan (send UDP packets)
        HOST_DISCOVERY: Host discovery (combined methods)
    """
    ARP = "arp"
    ICMP = "icmp"
    TCP_SYN = "tcp_syn"
    TCP_CONNECT = "tcp_connect"
    UDP = "udp"
    HOST_DISCOVERY = "host_discovery"


class ScanState(Enum):
    """Scan states.

    Attributes:
        IDLE: Scan not started
        PREPARING: Preparing for scan
        SCANNING: Actively scanning
        FINISHING: Cleaning up after scan
        COMPLETED: Scan completed successfully
        FAILED: Scan failed
        CANCELLED: Scan was cancelled
    """
    IDLE = "idle"
    PREPARING = "preparing"
    SCANNING = "scanning"
    FINISHING = "finishing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ScanResult:
    """Immutable scan result for a single host.

    Attributes:
        ip: IP address of the host
        mac: MAC address (if available)
        hostname: Hostname (if resolved)
        is_alive: Whether the host is responsive
        response_time: Response time in milliseconds (0 if not available)
        scan_type: Type of scan performed
        timestamp: When the scan result was recorded
        open_ports: Set of open ports found
        services: Dictionary of port -> service mappings
        os_guess: Operating system guess (if available)
        mac_vendor: MAC address vendor (if available)
    """
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    is_alive: bool = False
    response_time: float = 0.0
    scan_type: ScanType = ScanType.HOST_DISCOVERY
    timestamp: datetime = field(default_factory=datetime.now)
    open_ports: frozenset[int] = frozenset()
    services: Dict[str, str] = field(default_factory=dict)
    os_guess: Optional[str] = None
    mac_vendor: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate scan result."""
        # Validate IP address
        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {self.ip}")

        # Validate response time
        if self.response_time < 0:
            raise ValueError("Response time cannot be negative")

    def to_dict(self) -> dict:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of scan result
        """
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "scan_type": self.scan_type.value,
            "timestamp": self.timestamp.isoformat(),
            "open_ports": sorted(self.open_ports),
            "services": dict(self.services),
            "os_guess": self.os_guess,
            "mac_vendor": self.mac_vendor,
        }

    def with_hostname(self, hostname: str) -> "ScanResult":
        """Return new ScanResult with updated hostname.

        Args:
            hostname: New hostname

        Returns:
            New ScanResult instance
        """
        return ScanResult(
            ip=self.ip,
            mac=self.mac,
            hostname=hostname,
            is_alive=self.is_alive,
            response_time=self.response_time,
            scan_type=self.scan_type,
            timestamp=self.timestamp,
            open_ports=self.open_ports,
            services=self.services,
            os_guess=self.os_guess,
            mac_vendor=self.mac_vendor,
        )

    def with_open_ports(self, ports: List[int]) -> "ScanResult":
        """Return new ScanResult with updated open ports.

        Args:
            ports: List of open ports

        Returns:
            New ScanResult instance
        """
        return ScanResult(
            ip=self.ip,
            mac=self.mac,
            hostname=self.hostname,
            is_alive=self.is_alive,
            response_time=self.response_time,
            scan_type=self.scan_type,
            timestamp=self.timestamp,
            open_ports=frozenset(ports),
            services=self.services,
            os_guess=self.os_guess,
            mac_vendor=self.mac_vendor,
        )


@dataclass(frozen=True)
class ScanReport:
    """Immutable scan report containing all results.

    Attributes:
        scan_type: Type of scan performed
        start_time: When the scan started
        end_time: When the scan ended (None if in progress)
        targets: List of target IPs/addresses
        results: List of scan results
        alive_count: Number of alive hosts found
        total_hosts: Total number of hosts scanned
        state: Current scan state
    """
    scan_type: ScanType
    start_time: datetime
    end_time: Optional[datetime]
    targets: List[str]
    results: List[ScanResult] = field(default_factory=list)
    alive_count: int = 0
    state: ScanState = ScanState.IDLE

    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds.

        Returns:
            Duration in seconds or None if scan not complete
        """
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time).total_seconds()

    @property
    def completion_rate(self) -> float:
        """Get scan completion rate.

        Returns:
            Percentage of targets scanned (0-100)
        """
        if not self.targets:
            return 100.0
        return len(self.results) / len(self.targets) * 100

    def get_alive_hosts(self) -> List[ScanResult]:
        """Get list of alive hosts from results.

        Returns:
            List of scan results for alive hosts
        """
        return [r for r in self.results if r.is_alive]

    def get_host_by_ip(self, ip: str) -> Optional[ScanResult]:
        """Get scan result for specific IP.

        Args:
            ip: IP address to find

        Returns:
            ScanResult or None if not found
        """
        for result in self.results:
            if result.ip == ip:
                return result
        return None


class ScanProgressCallback(Protocol):
    """Protocol for scan progress callbacks."""

    def __call__(
        self,
        current: int,
        total: int,
        current_target: str,
    ) -> None:
        """Report scan progress.

        Args:
            current: Current number of targets scanned
            total: Total number of targets to scan
            current_target: Currently scanning target
        """
        ...


class NetworkScanner(ABC):
    """Abstract base class for network scanners.

    All network scanners must inherit from this class and implement
    the required scanning methods.
    """

    def __init__(
        self,
        targets: List[str],
        timeout: float = 1.0,
        threads: int = 10,
    ) -> None:
        """Initialize network scanner.

        Args:
            targets: List of target IP addresses or ranges
            timeout: Timeout per target in seconds
            threads: Number of parallel scan threads
        """
        self._targets = targets
        self._timeout = timeout
        self._threads = threads

        # State management
        self._state = ScanState.IDLE
        self._state_lock = Lock()
        self._state_condition = Condition(self._state_lock)

        # Results
        self._results: List[ScanResult] = []
        self._results_lock = Lock()

        # Progress tracking
        self._current_target = ""
        self._scanned_count = 0
        self._progress_lock = Lock()

        # Callbacks
        self._progress_callbacks: List[ScanProgressCallback] = []
        self._callbacks_lock = Lock()

        # Timing
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None

    @property
    def state(self) -> ScanState:
        """Get current scan state.

        Returns:
            Current scan state
        """
        with self._state_lock:
            return self._state

    @property
    def is_running(self) -> bool:
        """Check if scan is currently running.

        Returns:
            True if scan is in progress
        """
        return self.state in (ScanState.PREPARING, ScanState.SCANNING)

    @property
    def results(self) -> List[ScanResult]:
        """Get current scan results.

        Returns:
            List of scan results
        """
        with self._results_lock:
            return self._results.copy()

    @abstractmethod
    def scan(self) -> ScanReport:
        """Perform the network scan.

        This method should block until the scan is complete
        or fails.

        Returns:
            ScanReport with all results

        Raises:
            ScanError: If scan fails
        """
        pass

    @abstractmethod
    def cancel(self) -> None:
        """Cancel the ongoing scan.

        This method should return immediately and signal
        the scan to stop.
        """
        pass

    def add_progress_callback(self, callback: ScanProgressCallback) -> None:
        """Add a progress callback.

        Args:
            callback: Function to call with progress updates
        """
        with self._callbacks_lock:
            self._progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: ScanProgressCallback) -> None:
        """Remove a progress callback.

        Args:
            callback: Callback function to remove
        """
        with self._callbacks_lock:
            try:
                self._progress_callbacks.remove(callback)
            except ValueError:
                pass

    def _set_state(self, state: ScanState) -> None:
        """Set the scan state (thread-safe).

        Args:
            state: New scan state
        """
        with self._state_condition:
            self._state = state
            self._state_condition.notify_all()

    def _add_result(self, result: ScanResult) -> None:
        """Add a scan result (thread-safe).

        Args:
            result: Scan result to add
        """
        with self._results_lock:
            self._results.append(result)

    def _notify_progress(
        self,
        current: int,
        total: int,
        current_target: str,
    ) -> None:
        """Notify progress callbacks.

        Args:
            current: Current progress count
            total: Total count
            current_target: Currently scanning target
        """
        with self._callbacks_lock:
            callbacks = self._progress_callbacks.copy()

        for callback in callbacks:
            try:
                callback(current, total, current_target)
            except Exception:
                pass

    def wait_for_state(
        self,
        state: ScanState,
        timeout: Optional[float] = None,
    ) -> bool:
        """Wait for scan to reach a specific state.

        Args:
            state: State to wait for
            timeout: Maximum time to wait in seconds

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
                    timeout = 0
            return True

    def get_report(self) -> ScanReport:
        """Get current scan report.

        Returns:
            ScanReport with current results
        """
        with self._results_lock:
            results = self._results.copy()
            alive_count = sum(1 for r in results if r.is_alive)

        return ScanReport(
            scan_type=self.get_scan_type(),
            start_time=self._start_time or datetime.now(),
            end_time=self._end_time,
            targets=self._targets,
            results=results,
            alive_count=alive_count,
            state=self._state,
        )

    @abstractmethod
    def get_scan_type(self) -> ScanType:
        """Get the type of scan this scanner performs.

        Returns:
            Scan type
        """
        pass


def validate_targets(targets: List[str]) -> List[str]:
    """Validate and expand target list.

    Args:
        targets: List of IP addresses or CIDR ranges

    Returns:
        Expanded list of valid IP addresses

    Raises:
        InvalidRangeError: If any target is invalid
    """
    expanded = []

    for target in targets:
        try:
            # Check if it's a CIDR range
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                expanded.extend(str(ip) for ip in network.hosts())
            else:
                # Single IP
                ip = ipaddress.ip_address(target)
                expanded.append(str(ip))
        except ValueError as e:
            raise InvalidRangeError(
                f"Invalid target '{target}': {e}",
                {"target": target},
            )

    return expanded


def parse_ip_range(start_ip: str, end_ip: str) -> List[str]:
    """Parse IP range and return list of IPs.

    Args:
        start_ip: Starting IP address
        end_ip: Ending IP address

    Returns:
        List of IP addresses in range

    Raises:
        InvalidRangeError: If range is invalid
    """
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
    except ValueError as e:
        raise InvalidRangeError(
            f"Invalid IP address in range: {e}",
            {"start_ip": start_ip, "end_ip": end_ip},
        )

    if start > end:
        raise InvalidRangeError(
            f"Start IP must be less than or equal to end IP",
            {"start_ip": str(start), "end_ip": str(end)},
        )

    return [
        str(ipaddress.IPv4Address(ip))
        for ip in range(int(start), int(end) + 1)
    ]


def get_local_network() -> Optional[str]:
    """Get the local network CIDR.

    Attempts to detect the local network range.

    Returns:
        CIDR notation of local network or None
    """
    try:
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Assume /24 for common setups
        parts = local_ip.split(".")
        parts[3] = "0"
        network_ip = ".".join(parts)

        return f"{network_ip}/24"
    except Exception:
        return None


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address.

    Args:
        ip: IP address string

    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Check if string is a valid CIDR notation.

    Args:
        cidr: CIDR notation string

    Returns:
        True if valid CIDR
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False
