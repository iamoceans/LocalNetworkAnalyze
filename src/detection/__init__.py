"""
Detection engine module.

Provides unified threat detection combining
multiple security detectors.
"""

from typing import List, Optional, Dict, Any, Callable
from datetime import datetime
from collections import defaultdict
from threading import Lock

from src.core.logger import get_logger
from src.capture.base import PacketInfo

from .base import (
    Detector,
    DetectionType,
    DetectionResult,
    Alert,
    Severity,
    AlertCallback,
    DetectorStatistics,
    create_alert_id,
)

from .port_scan_detector import (
    PortScanDetector,
    PortScanConfig,
    create_port_scan_detector,
)

from .anomaly_detector import (
    AnomalyDetector,
    AnomalyConfig,
    create_anomaly_detector,
)


class DetectionEngine:
    """Unified threat detection engine.

    Coordinates multiple detectors and provides
    a single interface for threat detection.
    """

    def __init__(
        self,
        detectors: Optional[List[Detector]] = None,
    ) -> None:
        """Initialize detection engine.

        Args:
            detectors: List of detectors to use
        """
        self._detectors: Dict[DetectionType, Detector] = {}
        self._detectors_lock = Lock()

        self._callbacks: List[AlertCallback] = []
        self._callbacks_lock = Lock()

        # Alert history
        self._alert_history: List[Alert] = []
        self._history_lock = Lock()
        self._max_history = 1000

        # Statistics
        self._total_alerts = 0
        self._alerts_by_type: Dict[str, int] = defaultdict(int)
        self._alerts_by_severity: Dict[str, int] = defaultdict(int)

        logger = get_logger(__name__)
        self._logger = logger

        # Add provided detectors
        if detectors:
            for detector in detectors:
                self.add_detector(detector)

        self._logger.info("Detection engine initialized")

    def add_detector(self, detector: Detector) -> None:
        """Add a detector to the engine.

        Args:
            detector: Detector to add
        """
        with self._detectors_lock:
            det_type = detector.get_detection_type()
            self._detectors[det_type] = detector

            # Add engine callback to detector
            detector.add_callback(self._on_detector_alert)

        self._logger.info(f"Added detector: {det_type.value}")

    def remove_detector(self, detection_type: DetectionType) -> None:
        """Remove a detector from the engine.

        Args:
            detection_type: Type of detector to remove
        """
        with self._detectors_lock:
            if detection_type in self._detectors:
                detector = self._detectors[detection_type]
                detector.remove_callback(self._on_detector_alert)
                del self._detectors[detection_type]

        self._logger.info(f"Removed detector: {detection_type.value}")

    def get_detector(self, detection_type: DetectionType) -> Optional[Detector]:
        """Get a detector by type.

        Args:
            detection_type: Type of detector

        Returns:
            Detector or None if not found
        """
        with self._detectors_lock:
            return self._detectors.get(detection_type)

    def has_detector(self, detection_type: DetectionType) -> bool:
        """Check if a detector is registered.

        Args:
            detection_type: Type to check

        Returns:
            True if detector exists
        """
        with self._detectors_lock:
            return detection_type in self._detectors

    def process(self, packet: PacketInfo) -> List[DetectionResult]:
        """Process packet through all detectors.

        Args:
            packet: Packet to analyze

        Returns:
            List of detection results
        """
        results: List[DetectionResult] = []

        with self._detectors_lock:
            detectors = list(self._detectors.values())

        for detector in detectors:
            if not detector.is_enabled():
                continue

            try:
                result = detector.process(packet)
                if result and result.detected:
                    results.append(result)
            except Exception as e:
                self._logger.error(
                    f"Error in {detector.get_detection_type().value} detector: {e}"
                )

        return results

    def _on_detector_alert(self, alert: Alert) -> None:
        """Handle alert from detector.

        Args:
            alert: Alert from detector
        """
        # Add to history
        with self._history_lock:
            self._alert_history.append(alert)

            # Trim history if needed
            if len(self._alert_history) > self._max_history:
                self._alert_history = self._alert_history[-self._max_history:]

        # Update statistics
        with self._callbacks_lock:
            self._total_alerts += 1
            self._alerts_by_type[alert.detection_type.value] += 1
            self._alerts_by_severity[alert.severity.value] += 1

        # Trigger engine callbacks
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception as e:
                self._logger.error(f"Error in alert callback: {e}")

    def add_callback(self, callback: AlertCallback) -> None:
        """Add alert callback.

        Args:
            callback: Callback function
        """
        with self._callbacks_lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def remove_callback(self, callback: AlertCallback) -> None:
        """Remove alert callback.

        Args:
            callback: Callback to remove
        """
        with self._callbacks_lock:
            try:
                self._callbacks.remove(callback)
            except ValueError:
                pass

    def get_alert_history(
        self,
        limit: Optional[int] = None,
        detection_type: Optional[DetectionType] = None,
        severity: Optional[Severity] = None,
    ) -> List[Alert]:
        """Get alert history.

        Args:
            limit: Maximum number of alerts to return
            detection_type: Filter by detection type
            severity: Filter by severity

        Returns:
            List of alerts
        """
        with self._history_lock:
            alerts = self._alert_history.copy()

        # Apply filters
        if detection_type:
            alerts = [a for a in alerts if a.detection_type == detection_type]

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        # Apply limit
        if limit:
            alerts = alerts[:limit]

        return alerts

    def get_alerts_by_source(self, source_ip: str) -> List[Alert]:
        """Get alerts for a specific source IP.

        Args:
            source_ip: Source IP address

        Returns:
            List of alerts from that source
        """
        with self._history_lock:
            alerts = [
                a for a in self._alert_history
                if a.source_ip == source_ip
            ]

        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return alerts

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics.

        Returns:
            Dictionary with statistics
        """
        with self._detectors_lock:
            detector_stats = {}
            for det_type, detector in self._detectors.items():
                detector_stats[det_type.value] = detector.get_statistics()

        return {
            "total_alerts": self._total_alerts,
            "alerts_by_type": dict(self._alerts_by_type),
            "alerts_by_severity": dict(self._alerts_by_severity),
            "alerts_in_history": len(self._alert_history),
            "detectors": detector_stats,
            "detector_count": len(self._detectors),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get detection summary.

        Returns:
            Dictionary with summary information
        """
        stats = self.get_statistics()

        # Get recent alerts
        recent = self.get_alert_history(limit=10)

        return {
            "timestamp": datetime.now().isoformat(),
            "total_alerts": stats["total_alerts"],
            "detector_count": stats["detector_count"],
            "recent_alerts": [
                {
                    "type": a.detection_type.value,
                    "severity": a.severity.value,
                    "title": a.title,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in recent
            ],
        }

    def get_recent_alerts(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get recent alerts for dashboard display.

        Args:
            limit: Maximum number of alerts to return

        Returns:
            List of alert dictionaries with fields: title, severity, timestamp
        """
        alerts = self.get_alert_history(limit=limit)

        return [
            {
                "title": alert.title,
                "severity": alert.severity.value,
                "timestamp": alert.timestamp,
            }
            for alert in alerts
        ]

    def enable_detector(self, detection_type: DetectionType) -> None:
        """Enable a specific detector.

        Args:
            detection_type: Type of detector to enable
        """
        detector = self.get_detector(detection_type)
        if detector:
            detector.enable()

    def disable_detector(self, detection_type: DetectionType) -> None:
        """Disable a specific detector.

        Args:
            detection_type: Type of detector to disable
        """
        detector = self.get_detector(detection_type)
        if detector:
            detector.disable()

    def enable_all(self) -> None:
        """Enable all detectors."""
        with self._detectors_lock:
            for detector in self._detectors.values():
                detector.enable()

        self._logger.info("All detectors enabled")

    def disable_all(self) -> None:
        """Disable all detectors."""
        with self._detectors_lock:
            for detector in self._detectors.values():
                detector.disable()

        self._logger.info("All detectors disabled")

    def clear_alert_history(self) -> None:
        """Clear alert history."""
        with self._history_lock:
            self._alert_history.clear()
            self._total_alerts = 0
            self._alerts_by_type.clear()
            self._alerts_by_severity.clear()

        self._logger.info("Alert history cleared")

    def reset(self) -> None:
        """Reset all detectors and statistics."""
        with self._detectors_lock:
            for detector in self._detectors.values():
                detector.reset()

        self.clear_alert_history()

        self._logger.info("Detection engine reset")


def create_detection_engine(
    enable_port_scan: bool = True,
    enable_anomaly: bool = True,
    port_scan_threshold: int = 10,
    anomaly_baseline: int = 100,
) -> DetectionEngine:
    """Create configured detection engine.

    Args:
        enable_port_scan: Enable port scan detection
        enable_anomaly: Enable anomaly detection
        port_scan_threshold: Ports threshold for scan detection
        anomaly_baseline: Sample count for anomaly baseline

    Returns:
        Configured DetectionEngine instance

    Example:
        >>> engine = create_detection_engine()
        >>> engine.process(packet)
        >>> alerts = engine.get_alert_history(limit=10)
    """
    detectors: List[Detector] = []

    if enable_port_scan:
        port_scanner = create_port_scan_detector(min_ports=port_scan_threshold)
        detectors.append(port_scanner)

    if enable_anomaly:
        anomaly_detector = create_anomaly_detector(baseline_window=anomaly_baseline)
        detectors.append(anomaly_detector)

    return DetectionEngine(detectors=detectors)


__all__ = [
    "DetectionEngine",
    "create_detection_engine",
    "Detector",
    "DetectionType",
    "DetectionResult",
    "Alert",
    "Severity",
    "AlertCallback",
    "PortScanDetector",
    "PortScanConfig",
    "create_port_scan_detector",
    "AnomalyDetector",
    "AnomalyConfig",
    "create_anomaly_detector",
]
