"""
Detection module base classes.

Provides abstract base classes and data models for
network security detection and alerting.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Callable
from threading import Lock
from collections import defaultdict
import ipaddress

from src.core.logger import get_logger
from src.capture.base import PacketInfo


class Severity(Enum):
    """Alert severity levels.

    Attributes:
        INFO: Informational, no immediate action needed
        LOW: Low severity, monitor for changes
        MEDIUM: Medium severity, investigate when possible
        HIGH: High severity, investigate immediately
        CRITICAL: Critical severity, immediate action required
    """
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def get_score(self) -> int:
        """Get numeric severity score.

        Returns:
            Integer score (0-100)
        """
        scores = {
            Severity.INFO: 10,
            Severity.LOW: 25,
            Severity.MEDIUM: 50,
            Severity.HIGH: 75,
            Severity.CRITICAL: 100,
        }
        return scores[self]

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        """Get severity from numeric score.

        Args:
            score: Numeric score (0-100)

        Returns:
            Corresponding Severity level
        """
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.INFO


class DetectionType(Enum):
    """Types of security detections.

    Attributes:
        PORT_SCAN: Port scanning activity
        DOS_ATTACK: Denial of service attack
        BRUTE_FORCE: Brute force login attempt
        SQL_INJECTION: SQL injection attack
        XSS_ATTACK: Cross-site scripting attack
        TRAFFIC_ANOMALY: Abnormal traffic patterns
        PROTOCOL_ANOMALY: Unusual protocol behavior
        MALWARE_C2: Malware command and control
        DATA_EXFILTRATION: Large data transfer
        UNAUTHORIZED_ACCESS: Unauthorized access attempt
    """
    PORT_SCAN = "port_scan"
    DOS_ATTACK = "dos_attack"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    MALWARE_C2 = "malware_c2"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass(frozen=True)
class Alert:
    """Security alert.

    Attributes:
        id: Unique alert identifier
        detection_type: Type of detection
        severity: Alert severity level
        title: Alert title
        description: Detailed description
        source_ip: Source IP address
        destination_ip: Destination IP address (optional)
        source_port: Source port (optional)
        destination_port: Destination port (optional)
        timestamp: When the alert was generated
        confidence: Confidence score (0.0-1.0)
        evidence: Dictionary of supporting evidence
        metadata: Additional metadata
    """
    id: str
    detection_type: DetectionType
    severity: Severity
    title: str
    description: str
    timestamp: datetime
    confidence: float = 0.8
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate alert fields."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

        if self.source_ip:
            try:
                ipaddress.ip_address(self.source_ip)
            except ValueError:
                raise ValueError(f"Invalid source IP: {self.source_ip}")

        if self.destination_ip:
            try:
                ipaddress.ip_address(self.destination_ip)
            except ValueError:
                raise ValueError(f"Invalid destination IP: {self.destination_ip}")

        if self.source_port is not None and not 0 <= self.source_port <= 65535:
            raise ValueError(f"Invalid source port: {self.source_port}")

        if self.destination_port is not None and not 0 <= self.destination_port <= 65535:
            raise ValueError(f"Invalid destination port: {self.destination_port}")

    def to_dict(self) -> dict:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of alert
        """
        return {
            "id": self.id,
            "detection_type": self.detection_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }

    def get_summary(self) -> str:
        """Get alert summary string.

        Returns:
            Formatted summary string
        """
        parts = [
            f"[{self.severity.value.upper()}]",
            self.title,
        ]

        if self.source_ip:
            parts.append(f"from {self.source_ip}")

        if self.destination_ip:
            parts.append(f"to {self.destination_ip}")

        return " ".join(parts)


@dataclass(frozen=True)
class DetectionResult:
    """Result of a detection operation.

    Attributes:
        detected: Whether a threat was detected
        alerts: List of generated alerts
        confidence: Overall confidence score (0.0-1.0)
        details: Additional detection details
    """
    detected: bool
    alerts: List[Alert] = field(default_factory=list)
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate detection result."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")


class AlertCallback:
    """Protocol for alert callbacks."""

    def __call__(self, alert: Alert) -> None:
        """Handle alert callback.

        Args:
            alert: The alert to handle
        """
        pass


class Detector(ABC):
    """Abstract base class for security detectors.

    All detectors must inherit from this class and implement
    the required detection methods.
    """

    def __init__(self) -> None:
        """Initialize detector."""
        self._callbacks: List[AlertCallback] = []
        self._lock = Lock()
        self._enabled = True

        logger = get_logger(__name__)
        self._logger = logger

    @abstractmethod
    def get_detection_type(self) -> DetectionType:
        """Get the detection type.

        Returns:
            DetectionType that this detector handles
        """
        pass

    @abstractmethod
    def process(self, packet: PacketInfo) -> Optional[DetectionResult]:
        """Process a packet for detection.

        Args:
            packet: Packet to analyze

        Returns:
            DetectionResult if threat detected, None otherwise
        """
        pass

    @abstractmethod
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics.

        Returns:
            Dictionary with detector statistics
        """
        pass

    def add_callback(self, callback: AlertCallback) -> None:
        """Add an alert callback.

        Args:
            callback: Callback function to add
        """
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def remove_callback(self, callback: AlertCallback) -> None:
        """Remove an alert callback.

        Args:
            callback: Callback function to remove
        """
        with self._lock:
            try:
                self._callbacks.remove(callback)
            except ValueError:
                pass

    def _trigger_alert(self, alert: Alert) -> None:
        """Trigger alert callbacks.

        Args:
            alert: Alert to trigger
        """
        self._logger.warning(
            f"Alert triggered: {alert.get_summary()} "
            f"(confidence: {alert.confidence:.2f})"
        )

        with self._lock:
            for callback in self._callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self._logger.error(f"Error in alert callback: {e}")

    def enable(self) -> None:
        """Enable the detector."""
        self._enabled = True
        self._logger.info(f"{self.get_detection_type().value} detector enabled")

    def disable(self) -> None:
        """Disable the detector."""
        self._enabled = False
        self._logger.info(f"{self.get_detection_type().value} detector disabled")

    def is_enabled(self) -> bool:
        """Check if detector is enabled.

        Returns:
            True if enabled
        """
        return self._enabled

    def reset(self) -> None:
        """Reset detector state."""
        self._logger.info(f"{self.get_detection_type().value} detector reset")


class DetectorStatistics:
    """Statistics tracker for detectors."""

    def __init__(self) -> None:
        """Initialize statistics tracker."""
        self._packets_processed = 0
        self._alerts_generated = 0
        self._detections_made = 0
        self._start_time: Optional[datetime] = None
        self._last_detection: Optional[datetime] = None
        self._false_positives = 0
        self._true_positives = 0

    def record_packet(self) -> None:
        """Record a processed packet."""
        self._packets_processed += 1
        if self._start_time is None:
            self._start_time = datetime.now()

    def record_alert(self, is_true_positive: bool = False) -> None:
        """Record a generated alert.

        Args:
            is_true_positive: Whether this was a true positive
        """
        self._alerts_generated += 1
        self._detections_made += 1
        self._last_detection = datetime.now()

        if is_true_positive:
            self._true_positives += 1
        else:
            self._false_positives += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary.

        Returns:
            Dictionary with statistics
        """
        duration = None
        if self._start_time:
            duration = (datetime.now() - self._start_time).total_seconds()

        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "detections_made": self._detections_made,
            "true_positives": self._true_positives,
            "false_positives": self._false_positives,
            "detection_rate": (
                self._detections_made / self._packets_processed
                if self._packets_processed > 0
                else 0.0
            ),
            "false_positive_rate": (
                self._false_positives / self._alerts_generated
                if self._alerts_generated > 0
                else 0.0
            ),
            "duration_seconds": duration,
            "last_detection": (
                self._last_detection.isoformat()
                if self._last_detection
                else None
            ),
        }

    def reset(self) -> None:
        """Reset statistics."""
        self._packets_processed = 0
        self._alerts_generated = 0
        self._detections_made = 0
        self._start_time = None
        self._last_detection = None
        self._false_positives = 0
        self._true_positives = 0


def create_alert_id() -> str:
    """Generate a unique alert ID.

    Returns:
        Unique alert identifier
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    # Simple ID generation - in production use UUID
    import random
    random_part = "".join(random.choices("0123456789abcdef", k=8))
    return f"alert_{timestamp}_{random_part}"


def validate_confidence(confidence: float) -> None:
    """Validate confidence score.

    Args:
        confidence: Confidence score to validate

    Raises:
        ValueError: If confidence is invalid
    """
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("Confidence must be between 0.0 and 1.0")


def calculate_severity(
    confidence: float,
    base_severity: Severity = Severity.MEDIUM,
) -> Severity:
    """Calculate severity based on confidence and base level.

    Args:
        confidence: Detection confidence (0.0-1.0)
        base_severity: Base severity level

    Returns:
        Calculated severity
    """
    if confidence >= 0.9:
        return Severity.CRITICAL
    elif confidence >= 0.75:
        return Severity.HIGH
    elif confidence >= 0.5:
        return base_severity
    elif confidence >= 0.25:
        return Severity.LOW if base_severity != Severity.INFO else Severity.INFO
    else:
        return Severity.INFO
