"""
Traffic anomaly detection module.

Detects abnormal network traffic patterns using statistical
analysis and machine learning techniques.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Deque
from collections import defaultdict, deque
from threading import Lock
import statistics
import ipaddress

from src.core.logger import get_logger
from src.capture.base import PacketInfo
from src.utils.constants import Protocol
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
class AnomalyConfig:
    """Configuration for anomaly detection.

    Attributes:
        baseline_window: Number of samples to establish baseline
        threshold_std_dev: Number of standard deviations for threshold
        min_samples: Minimum samples required for detection
        check_interval: Seconds between anomaly checks
        enable_volume_anomaly: Enable traffic volume detection
        enable_protocol_anomaly: Enable protocol distribution detection
        enable_packet_size_anomaly: Enable packet size detection
        volume_threshold: Multiplier for volume anomaly (e.g., 3x)
        protocol_change_threshold: Percentage change for protocol anomaly
    """
    baseline_window: int = 100
    threshold_std_dev: float = 3.0
    min_samples: int = 30
    check_interval: float = 60.0
    enable_volume_anomaly: bool = True
    enable_protocol_anomaly: bool = True
    enable_packet_size_anomaly: bool = True
    volume_threshold: float = 3.0
    protocol_change_threshold: float = 50.0  # 50% change

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.baseline_window < self.min_samples:
            raise ValueError("baseline_window must be >= min_samples")
        if self.threshold_std_dev < 1.0:
            raise ValueError("threshold_std_dev must be >= 1.0")
        if self.min_samples < 10:
            raise ValueError("min_samples must be >= 10")


@dataclass
class TrafficSample:
    """Traffic measurement sample.

    Attributes:
        timestamp: When sample was taken
        packets_per_second: Packet rate
        bytes_per_second: Byte rate
        avg_packet_size: Average packet size
        protocol_distribution: Protocol usage percentages
        total_connections: Number of active connections
    """
    timestamp: datetime
    packets_per_second: float
    bytes_per_second: float
    avg_packet_size: float
    protocol_distribution: Dict[str, float]
    total_connections: int


class AnomalyDetector(Detector):
    """Statistical anomaly detection engine.

    Detects unusual network traffic patterns using statistical
    analysis and baseline comparison.
    """

    def __init__(
        self,
        config: Optional[AnomalyConfig] = None,
    ) -> None:
        """Initialize anomaly detector.

        Args:
            config: Detection configuration
        """
        super().__init__()

        self._config = config or AnomalyConfig()

        # Traffic samples history
        self._samples: Deque[TrafficSample] = deque(maxlen=self._config.baseline_window)
        self._samples_lock = Lock()

        # Current window counters
        self._current_window_packets: List[Tuple[datetime, int]] = []
        self._current_window_bytes: List[Tuple[datetime, int]] = []
        self._current_packet_sizes: List[int] = []
        self._current_protocols: Dict[str, int] = defaultdict(int)
        self._window_start: Optional[datetime] = None
        self._window_packets = 0
        self._window_bytes = 0

        # Baseline statistics
        self._baseline_established = False
        self._baseline_stats: Dict[str, float] = {}

        # Statistics
        self._stats = DetectorStatistics()
        self._last_check: Optional[datetime] = None

        self._logger.info(
            f"Anomaly detector initialized (baseline_window={self._config.baseline_window}, "
            f"threshold={self._config.threshold_std_dev} std deviations)"
        )

    def get_detection_type(self) -> DetectionType:
        """Get detection type.

        Returns:
            DetectionType.TRAFFIC_ANOMALY
        """
        return DetectionType.TRAFFIC_ANOMALY

    def process(self, packet: PacketInfo) -> Optional[DetectionResult]:
        """Process packet for anomaly detection.

        Args:
            packet: Packet to analyze

        Returns:
            DetectionResult if anomaly detected, None otherwise
        """
        if not self._enabled:
            return None

        self._stats.record_packet()

        # Add to current window
        self._add_to_window(packet)

        # Check if it's time to analyze
        if self._should_check():
            return self._analyze_window()

        return None

    def _add_to_window(self, packet: PacketInfo) -> None:
        """Add packet to current analysis window.

        Args:
            packet: Packet to add
        """
        if self._window_start is None:
            self._window_start = packet.timestamp

        self._current_window_packets.append((packet.timestamp, 1))
        self._current_window_bytes.append((packet.timestamp, packet.length))
        self._current_packet_sizes.append(packet.length)
        self._current_protocols[packet.protocol] += 1

        self._window_packets += 1
        self._window_bytes += packet.length

    def _should_check(self) -> bool:
        """Check if it's time to analyze the window.

        Returns:
            True if analysis should run
        """
        if self._window_start is None:
            return False

        if self._last_check is None:
            return False

        elapsed = (datetime.now() - self._last_check).total_seconds()
        return elapsed >= self._config.check_interval

    def _analyze_window(self) -> Optional[DetectionResult]:
        """Analyze current window for anomalies.

        Returns:
            DetectionResult if anomaly found, None otherwise
        """
        if self._window_packets < self._config.min_samples:
            return None

        # Create traffic sample
        sample = self._create_sample()
        if sample is None:
            return None

        alerts: List[Alert] = []
        detected = False

        with self._samples_lock:
            # Add sample to history
            self._samples.append(sample)

            # Check if we have enough samples for baseline
            if len(self._samples) < self._config.min_samples:
                self._reset_window()
                self._last_check = datetime.now()
                return None

            # Establish baseline if not yet done
            if not self._baseline_established:
                self._establish_baseline()
                self._logger.info("Baseline established for anomaly detection")
                self._reset_window()
                self._last_check = datetime.now()
                return None

            # Check for anomalies
            if self._config.enable_volume_anomaly:
                volume_alert = self._check_volume_anomaly(sample)
                if volume_alert:
                    alerts.append(volume_alert)
                    detected = True

            if self._config.enable_protocol_anomaly:
                protocol_alert = self._check_protocol_anomaly(sample)
                if protocol_alert:
                    alerts.append(protocol_alert)
                    detected = True

            if self._config.enable_packet_size_anomaly:
                size_alert = self._check_packet_size_anomaly(sample)
                if size_alert:
                    alerts.append(size_alert)
                    detected = True

        # Reset window and update last check time
        self._reset_window()
        self._last_check = datetime.now()

        if detected and alerts:
            self._stats.record_alert()

            # Trigger all alerts
            for alert in alerts:
                self._trigger_alert(alert)

            return DetectionResult(
                detected=True,
                alerts=alerts,
                confidence=max(a.confidence for a in alerts),
                details={
                    "anomaly_types": [a.detection_type.value for a in alerts],
                    "sample": {
                        "packets_per_second": sample.packets_per_second,
                        "bytes_per_second": sample.bytes_per_second,
                        "avg_packet_size": sample.avg_packet_size,
                    },
                },
            )

        return None

    def _create_sample(self) -> Optional[TrafficSample]:
        """Create traffic sample from current window.

        Returns:
            TrafficSample or None if window is empty
        """
        if self._window_start is None or self._window_packets == 0:
            return None

        now = datetime.now()
        time_span = max((now - self._window_start).total_seconds(), 1.0)

        # Calculate rates
        packets_per_sec = self._window_packets / time_span
        bytes_per_sec = self._window_bytes / time_span
        avg_packet_size = (
            sum(self._current_packet_sizes) / len(self._current_packet_sizes)
            if self._current_packet_sizes
            else 0.0
        )

        # Calculate protocol distribution
        protocol_dist = {}
        total = sum(self._current_protocols.values())
        for protocol, count in self._current_protocols.items():
            protocol_dist[protocol] = (count / total) * 100 if total > 0 else 0.0

        return TrafficSample(
            timestamp=now,
            packets_per_second=packets_per_sec,
            bytes_per_second=bytes_per_sec,
            avg_packet_size=avg_packet_size,
            protocol_distribution=protocol_dist,
            total_connections=0,  # Would need connection tracker for this
        )

    def _establish_baseline(self) -> None:
        """Establish statistical baseline from samples."""
        samples = list(self._samples)

        if len(samples) < self._config.min_samples:
            return

        # Calculate baseline statistics
        packet_rates = [s.packets_per_second for s in samples]
        byte_rates = [s.bytes_per_second for s in samples]
        packet_sizes = [s.avg_packet_size for s in samples]

        self._baseline_stats = {
            "packet_rate_mean": statistics.mean(packet_rates),
            "packet_rate_stdev": statistics.stdev(packet_rates) if len(packet_rates) > 1 else 0.0,
            "byte_rate_mean": statistics.mean(byte_rates),
            "byte_rate_stdev": statistics.stdev(byte_rates) if len(byte_rates) > 1 else 0.0,
            "packet_size_mean": statistics.mean(packet_sizes),
            "packet_size_stdev": statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0.0,
        }

        # Calculate baseline protocol distribution
        protocol_totals: Dict[str, List[float]] = defaultdict(list)
        for sample in samples:
            for protocol, percentage in sample.protocol_distribution.items():
                protocol_totals[protocol].append(percentage)

        self._baseline_stats["protocol_means"] = {
            protocol: statistics.mean(values)
            for protocol, values in protocol_totals.items()
        }

        self._baseline_established = True

    def _check_volume_anomaly(self, sample: TrafficSample) -> Optional[Alert]:
        """Check for traffic volume anomalies.

        Args:
            sample: Current traffic sample

        Returns:
            Alert if anomaly detected, None otherwise
        """
        if not self._baseline_established:
            return None

        mean = self._baseline_stats.get("byte_rate_mean", 0)
        stdev = self._baseline_stats.get("byte_rate_stdev", 0)

        if stdev == 0:
            return None

        # Check if current rate is significantly above baseline
        z_score = (sample.bytes_per_second - mean) / stdev

        if z_score >= self._config.threshold_std_dev:
            # Also check against absolute threshold
            if mean > 0 and sample.bytes_per_second >= mean * self._config.volume_threshold:
                confidence = min(z_score / (self._config.threshold_std_dev * 2), 1.0)

                return Alert(
                    id=create_alert_id(),
                    detection_type=DetectionType.TRAFFIC_ANOMALY,
                    severity=calculate_severity(confidence, Severity.HIGH),
                    title="Unusual Traffic Volume Detected",
                    description=(
                        f"Current traffic volume ({sample.bytes_per_second:.2f} B/s) is "
                        f"{z_score:.1f} standard deviations above baseline "
                        f"({mean:.2f} B/s). This may indicate a data exfiltration "
                        f"or DoS attack."
                    ),
                    timestamp=datetime.now(),
                    confidence=confidence,
                    evidence={
                        "current_bytes_per_second": sample.bytes_per_second,
                        "baseline_mean": mean,
                        "baseline_stdev": stdev,
                        "z_score": z_score,
                        "threshold": self._config.threshold_std_dev,
                    },
                )

        return None

    def _check_protocol_anomaly(self, sample: TrafficSample) -> Optional[Alert]:
        """Check for protocol distribution anomalies.

        Args:
            sample: Current traffic sample

        Returns:
            Alert if anomaly detected, None otherwise
        """
        if not self._baseline_established:
            return None

        protocol_means = self._baseline_stats.get("protocol_means", {})
        anomalies: List[str] = []

        for protocol, current_percentage in sample.protocol_distribution.items():
            baseline_percentage = protocol_means.get(protocol, 0.0)

            if baseline_percentage > 0:
                change_percent = abs(current_percentage - baseline_percentage) / baseline_percentage * 100

                if change_percent >= self._config.protocol_change_threshold:
                    anomalies.append(
                        f"{protocol}: {baseline_percentage:.1f}% -> {current_percentage:.1f}% "
                        f"({change_percent:.1f}% change)"
                    )

        if anomalies:
            confidence = min(len(anomalies) / 5.0, 1.0)

            return Alert(
                id=create_alert_id(),
                detection_type=DetectionType.PROTOCOL_ANOMALY,
                severity=calculate_severity(confidence, Severity.MEDIUM),
                title="Unusual Protocol Distribution Detected",
                description=(
                    f"Significant changes detected in protocol usage patterns. "
                    f"This may indicate tunneling, covert channels, or unusual "
                    f"application behavior."
                ),
                timestamp=datetime.now(),
                confidence=confidence,
                evidence={
                    "anomalies": anomalies,
                    "current_distribution": sample.protocol_distribution,
                    "baseline_distribution": protocol_means,
                },
            )

        return None

    def _check_packet_size_anomaly(self, sample: TrafficSample) -> Optional[Alert]:
        """Check for packet size anomalies.

        Args:
            sample: Current traffic sample

        Returns:
            Alert if anomaly detected, None otherwise
        """
        if not self._baseline_established:
            return None

        mean = self._baseline_stats.get("packet_size_mean", 0)
        stdev = self._baseline_stats.get("packet_size_stdev", 0)

        if stdev == 0:
            return None

        z_score = abs(sample.avg_packet_size - mean) / stdev

        if z_score >= self._config.threshold_std_dev:
            confidence = min(z_score / (self._config.threshold_std_dev * 2), 1.0)

            direction = "larger" if sample.avg_packet_size > mean else "smaller"

            return Alert(
                id=create_alert_id(),
                detection_type=DetectionType.TRAFFIC_ANOMALY,
                severity=calculate_severity(confidence, Severity.MEDIUM),
                title=f"Unusual Packet Size Detected",
                description=(
                    f"Average packet size is {direction} than normal. "
                    f"Current: {sample.avg_packet_size:.0f} bytes, "
                    f"Baseline: {mean:.0f} bytes. "
                    f"This may indicate unusual traffic patterns or data "
                    f"exfiltration attempts."
                ),
                timestamp=datetime.now(),
                confidence=confidence,
                evidence={
                    "current_avg_size": sample.avg_packet_size,
                    "baseline_mean": mean,
                    "baseline_stdev": stdev,
                    "z_score": z_score,
                },
            )

        return None

    def _reset_window(self) -> None:
        """Reset current analysis window."""
        self._current_window_packets.clear()
        self._current_window_bytes.clear()
        self._current_packet_sizes.clear()
        self._current_protocols.clear()
        self._window_start = None
        self._window_packets = 0
        self._window_bytes = 0

    def get_baseline(self) -> Dict[str, float]:
        """Get current baseline statistics.

        Returns:
            Dictionary with baseline statistics
        """
        return self._baseline_stats.copy()

    def reset_baseline(self) -> None:
        """Reset baseline and re-establish from samples."""
        self._baseline_established = False
        self._baseline_stats.clear()
        self._samples.clear()
        self._logger.info("Baseline reset - will re-establish from new samples")

    def is_baseline_established(self) -> bool:
        """Check if baseline has been established.

        Returns:
            True if baseline is established
        """
        return self._baseline_established

    def get_statistics(self) -> Dict[str, any]:
        """Get detector statistics.

        Returns:
            Dictionary with statistics
        """
        stats = self._stats.get_summary()

        stats.update({
            "baseline_established": self._baseline_established,
            "samples_collected": len(self._samples),
            "current_window_packets": self._window_packets,
            "last_check": (
                self._last_check.isoformat()
                if self._last_check
                else None
            ),
        })

        if self._baseline_established:
            stats["baseline"] = self._baseline_stats

        return stats

    def reset(self) -> None:
        """Reset detector state."""
        self._samples.clear()
        self._reset_window()
        self._baseline_established = False
        self._baseline_stats.clear()
        self._stats.reset()
        self._last_check = None

        super().reset()


def create_anomaly_detector(
    baseline_window: int = 100,
    threshold_std_dev: float = 3.0,
    enable_volume_anomaly: bool = True,
    enable_protocol_anomaly: bool = True,
    enable_packet_size_anomaly: bool = True,
) -> AnomalyDetector:
    """Create configured anomaly detector.

    Args:
        baseline_window: Number of samples for baseline
        threshold_std_dev: Standard deviation threshold
        enable_volume_anomaly: Enable volume detection
        enable_protocol_anomaly: Enable protocol detection
        enable_packet_size_anomaly: Enable packet size detection

    Returns:
        Configured AnomalyDetector instance
    """
    config = AnomalyConfig(
        baseline_window=baseline_window,
        threshold_std_dev=threshold_std_dev,
        enable_volume_anomaly=enable_volume_anomaly,
        enable_protocol_anomaly=enable_protocol_anomaly,
        enable_packet_size_anomaly=enable_packet_size_anomaly,
    )

    return AnomalyDetector(config=config)
