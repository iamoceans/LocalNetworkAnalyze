"""
Port scan detection module.

Detects various types of port scanning activities including
TCP SYN scan, TCP connect scan, and stealth scans.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, List, Tuple
from collections import defaultdict
from threading import Lock
import ipaddress

from src.core.logger import get_logger
from src.capture.base import PacketInfo
from src.utils.constants import Protocol, TCPFlag
from .base import (
    Detector,
    DetectionType,
    DetectionResult,
    Severity,
    Alert,
    DetectorStatistics,
    create_alert_id,
    calculate_severity,
)


@dataclass
class PortScanConfig:
    """Configuration for port scan detection.

    Attributes:
        min_ports: Minimum number of ports to trigger detection
        time_window: Time window in seconds to check for scans
        include_private_ranges: Whether to include private IP ranges
        max_destinations: Maximum number of destination IPs to track per source
        syn_scan_threshold: Threshold for SYN scan detection
        connect_scan_threshold: Threshold for connect scan detection
    """
    min_ports: int = 10
    time_window: float = 60.0
    include_private_ranges: bool = True
    max_destinations: int = 100
    syn_scan_threshold: int = 5
    connect_scan_threshold: int = 10

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.min_ports < 1:
            raise ValueError("min_ports must be at least 1")
        if self.time_window < 1.0:
            raise ValueError("time_window must be at least 1 second")
        if self.max_destinations < 1:
            raise ValueError("max_destinations must be at least 1")


@dataclass(frozen=True)
class PortAccessRecord:
    """Record of port access.

    Attributes:
        src_ip: Source IP address
        dst_ip: Destination IP address
        dst_port: Destination port
        first_seen: When first access was observed
        last_seen: When last access was observed
        packet_count: Number of packets to this port
        syn_count: Number of SYN packets
        ack_count: Number of ACK packets
        rst_count: Number of RST packets
    """
    src_ip: str
    dst_ip: str
    dst_port: int
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 1
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0


@dataclass
class ScanTracker:
    """Tracks scanning activity for a single source IP.

    Attributes:
        src_ip: Source IP address
        ports_accessed: Set of destination ports accessed
        destinations: Set of destination IPs
        first_seen: When activity was first observed
        last_seen: When activity was last observed
        total_packets: Total packets from this source
        scan_type: Detected scan type
    """
    src_ip: str
    ports_accessed: Set[int] = field(default_factory=set)
    destinations: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_packets: int = 0
    scan_type: Optional[str] = None

    def get_scan_score(self) -> int:
        """Get scan severity score.

        Returns:
            Score based on number of ports accessed
        """
        return len(self.ports_accessed)

    def is_active(self, timeout_seconds: float = 300.0) -> bool:
        """Check if scanning activity is still active.

        Args:
            timeout_seconds: Seconds of inactivity before considering inactive

        Returns:
            True if still active
        """
        if self.last_seen is None:
            return True

        elapsed = (datetime.now() - self.last_seen).total_seconds()
        return elapsed <= timeout_seconds


class PortScanDetector(Detector):
    """Port scan detection engine.

    Detects various types of port scanning by monitoring
    connection attempts to multiple ports.
    """

    def __init__(
        self,
        config: Optional[PortScanConfig] = None,
    ) -> None:
        """Initialize port scan detector.

        Args:
            config: Detection configuration
        """
        super().__init__()

        self._config = config or PortScanConfig()

        # Track scanning activity by source IP
        self._scanners: Dict[str, ScanTracker] = {}
        self._scanners_lock = Lock()

        # Track port access records
        self._port_records: Dict[Tuple[str, str, int], PortAccessRecord] = {}
        self._records_lock = Lock()

        # Statistics
        self._stats = DetectorStatistics()

        # Whitelist (IPs to ignore)
        self._whitelist: Set[str] = set()

        self._logger.info(
            f"Port scan detector initialized (min_ports={self._config.min_ports}, "
            f"time_window={self._config.time_window}s)"
        )

    def get_detection_type(self) -> DetectionType:
        """Get detection type.

        Returns:
            DetectionType.PORT_SCAN
        """
        return DetectionType.PORT_SCAN

    def process(self, packet: PacketInfo) -> Optional[DetectionResult]:
        """Process packet for port scan detection.

        Args:
            packet: Packet to analyze

        Returns:
            DetectionResult if scan detected, None otherwise
        """
        if not self._enabled:
            return None

        self._stats.record_packet()

        # Only process TCP packets for port scan detection
        if packet.protocol != Protocol.TCP:
            return None

        # Skip if source is whitelisted
        if packet.src_ip in self._whitelist:
            return None

        # Skip private IP ranges if configured
        if not self._config.include_private_ranges:
            try:
                src_addr = ipaddress.ip_address(packet.src_ip)
                if src_addr.is_private:
                    return None
            except ValueError:
                pass

        # Check if it's a destination port (port to check)
        if packet.dst_port is None or packet.dst_port == 0:
            return None

        # Update tracking
        self._update_tracking(packet)

        # Check for scan patterns
        return self._check_for_scan(packet.src_ip)

    def _update_tracking(self, packet: PacketInfo) -> None:
        """Update scan tracking with packet.

        Args:
            packet: Packet to track
        """
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        dst_port = packet.dst_port

        with self._scanners_lock:
            # Get or create scanner tracker
            if src_ip not in self._scanners:
                self._scanners[src_ip] = ScanTracker(
                    src_ip=src_ip,
                    first_seen=packet.timestamp,
                    last_seen=packet.timestamp,
                )

            scanner = self._scanners[src_ip]

            # Update scanner
            scanner.ports_accessed.add(dst_port)
            scanner.destinations.add(dst_ip)
            scanner.last_seen = packet.timestamp
            scanner.total_packets += 1

            # Prune old destinations
            if len(scanner.destinations) > self._config.max_destinations:
                scanner.destinations = set(list(scanner.destinations)[-self._config.max_destinations:])

        with self._records_lock:
            # Update port access record
            key = (src_ip, dst_ip, dst_port)
            if key in self._port_records:
                # Immutable record, create new one
                old_record = self._port_records[key]
                self._port_records[key] = PortAccessRecord(
                    src_ip=old_record.src_ip,
                    dst_ip=old_record.dst_ip,
                    dst_port=old_record.dst_port,
                    first_seen=old_record.first_seen,
                    last_seen=packet.timestamp,
                    packet_count=old_record.packet_count + 1,
                    syn_count=old_record.syn_count,
                    ack_count=old_record.ack_count,
                    rst_count=old_record.rst_count,
                )
            else:
                self._port_records[key] = PortAccessRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    first_seen=packet.timestamp,
                    last_seen=packet.timestamp,
                    syn_count=1,  # Assume SYN for new connection
                )

        # Cleanup old records
        self._cleanup_old_records()

    def _check_for_scan(self, src_ip: str) -> Optional[DetectionResult]:
        """Check if source IP is scanning ports.

        Args:
            src_ip: Source IP to check

        Returns:
            DetectionResult if scan detected, None otherwise
        """
        with self._scanners_lock:
            if src_ip not in self._scanners:
                return None

            scanner = self._scanners[src_ip]

            # Check time window
            if scanner.first_seen is None or scanner.last_seen is None:
                return None

            time_elapsed = (scanner.last_seen - scanner.first_seen).total_seconds()

            # Check if within time window
            if time_elapsed > self._config.time_window:
                # Too old, reset if inactive
                if not scanner.is_active(self._config.time_window):
                    self._scanners[src_ip] = ScanTracker(src_ip=src_ip)
                return None

            # Check if minimum port threshold reached
            port_count = len(scanner.ports_accessed)
            if port_count < self._config.min_ports:
                return None

            # Determine scan type
            scan_type = self._determine_scan_type(scanner)
            scanner.scan_type = scan_type

            # Calculate confidence based on ports accessed and time
            confidence = min(0.5 + (port_count / 50.0), 1.0)

            # Create alert
            alert = Alert(
                id=create_alert_id(),
                detection_type=DetectionType.PORT_SCAN,
                severity=calculate_severity(confidence, Severity.HIGH),
                title=f"Port Scan Detected from {src_ip}",
                description=(
                    f"Source IP {src_ip} has attempted to connect to "
                    f"{port_count} different ports in {time_elapsed:.1f} seconds. "
                    f"This is consistent with {scan_type} scanning behavior."
                ),
                timestamp=datetime.now(),
                confidence=confidence,
                source_ip=src_ip,
                evidence={
                    "ports_accessed": sorted(scanner.ports_accessed),
                    "destination_count": len(scanner.destinations),
                    "port_count": port_count,
                    "time_elapsed_seconds": time_elapsed,
                    "scan_type": scan_type,
                    "first_seen": scanner.first_seen.isoformat(),
                    "last_seen": scanner.last_seen.isoformat(),
                },
                metadata={
                    "total_packets": scanner.total_packets,
                },
            )

            self._stats.record_alert()
            self._trigger_alert(alert)

            return DetectionResult(
                detected=True,
                alerts=[alert],
                confidence=confidence,
                details={
                    "scan_type": scan_type,
                    "ports_accessed": port_count,
                    "time_elapsed": time_elapsed,
                },
            )

    def _determine_scan_type(self, scanner: ScanTracker) -> str:
        """Determine the type of port scan.

        Args:
            scanner: Scanner tracker to analyze

        Returns:
            Scan type description
        """
        port_count = len(scanner.ports_accessed)

        # Get SYN to RST ratio for this scanner
        syn_count = 0
        rst_count = 0

        with self._records_lock:
            for key, record in self._port_records.items():
                if key[0] == scanner.src_ip:
                    syn_count += record.syn_count
                    rst_count += record.rst_count

        if syn_count > 0 and rst_count == 0:
            return "SYN scan (stealth)"
        elif rst_count > syn_count:
            return "SYN/ACK scan"
        elif port_count > 50:
            return "comprehensive"
        elif port_count > 20:
            return "aggressive"
        else:
            return "standard"

    def _cleanup_old_records(self) -> None:
        """Remove old port access records."""
        cutoff = datetime.now() - timedelta(seconds=self._config.time_window)

        with self._records_lock:
            keys_to_remove = [
                key for key, record in self._port_records.items()
                if record.last_seen < cutoff
            ]

            for key in keys_to_remove:
                del self._port_records[key]

    def add_to_whitelist(self, ip: str) -> None:
        """Add IP to whitelist.

        Args:
            ip: IP address to whitelist
        """
        try:
            ipaddress.ip_address(ip)
            self._whitelist.add(ip)
            self._logger.info(f"Added {ip} to port scan detector whitelist")
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    def remove_from_whitelist(self, ip: str) -> None:
        """Remove IP from whitelist.

        Args:
            ip: IP address to remove from whitelist
        """
        self._whitelist.discard(ip)
        self._logger.info(f"Removed {ip} from port scan detector whitelist")

    def get_whitelist(self) -> Set[str]:
        """Get current whitelist.

        Returns:
            Set of whitelisted IPs
        """
        return self._whitelist.copy()

    def get_active_scanners(self) -> List[Dict[str, any]]:
        """Get list of active scanners.

        Returns:
            List of scanner information
        """
        with self._scanners_lock:
            active_scanners = []

            for src_ip, scanner in self._scanners.items():
                if scanner.is_active(self._config.time_window):
                    active_scanners.append({
                        "source_ip": src_ip,
                        "ports_accessed": len(scanner.ports_accessed),
                        "destinations": len(scanner.destinations),
                        "total_packets": scanner.total_packets,
                        "scan_type": scanner.scan_type,
                        "first_seen": scanner.first_seen.isoformat() if scanner.first_seen else None,
                        "last_seen": scanner.last_seen.isoformat() if scanner.last_seen else None,
                    })

            return active_scanners

    def get_statistics(self) -> Dict[str, any]:
        """Get detector statistics.

        Returns:
            Dictionary with statistics
        """
        stats = self._stats.get_summary()

        with self._scanners_lock:
            stats.update({
                "active_scanners": len([
                    s for s in self._scanners.values()
                    if s.is_active(self._config.time_window)
                ]),
                "total_scanners": len(self._scanners),
                "whitelisted_ips": len(self._whitelist),
            })

        return stats

    def reset(self) -> None:
        """Reset detector state."""
        with self._scanners_lock:
            self._scanners.clear()

        with self._records_lock:
            self._port_records.clear()

        self._stats.reset()

        super().reset()


def create_port_scan_detector(
    min_ports: int = 10,
    time_window: float = 60.0,
    include_private_ranges: bool = True,
) -> PortScanDetector:
    """Create configured port scan detector.

    Args:
        min_ports: Minimum ports to trigger detection
        time_window: Time window in seconds
        include_private_ranges: Whether to include private IPs

    Returns:
        Configured PortScanDetector instance
    """
    config = PortScanConfig(
        min_ports=min_ports,
        time_window=time_window,
        include_private_ranges=include_private_ranges,
    )

    return PortScanDetector(config=config)
