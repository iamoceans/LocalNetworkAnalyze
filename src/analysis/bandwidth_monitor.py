"""
Bandwidth monitoring module.

Provides real-time bandwidth monitoring and alerting
based on configurable thresholds.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Callable, Dict
from threading import Lock
import time

from src.core.logger import get_logger
from src.capture.base import PacketInfo


@dataclass(frozen=True)
class BandwidthSample:
    """Bandwidth measurement sample.

    Attributes:
        timestamp: When the sample was taken
        bytes_per_second: Current bandwidth rate in B/s
        packets_per_second: Current packet rate
        interface: Network interface
    """
    timestamp: datetime
    bytes_per_second: float
    packets_per_second: float
    interface: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "bytes_per_second": self.bytes_per_second,
            "packets_per_second": self.packets_per_second,
            "interface": self.interface,
        }


@dataclass(frozen=True)
class BandwidthThreshold:
    """Bandwidth threshold for alerting.

    Attributes:
        warning_level: Warning threshold in B/s
        critical_level: Critical threshold in B/s
        window_seconds: Time window to average over
    """
    warning_level: float
    critical_level: float
    window_seconds: int = 5

    def __post_init__(self) -> None:
        """Validate thresholds."""
        if self.warning_level <= 0:
            raise ValueError("warning_level must be positive")
        if self.critical_level <= 0:
            raise ValueError("critical_level must be positive")
        if self.critical_level <= self.warning_level:
            raise ValueError("critical_level must be greater than warning_level")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")


class BandwidthAlert:
    """Callback protocol for bandwidth alerts."""

    def __call__(
        self,
        alert_type: str,  # "warning" or "critical"
        current_bandwidth: float,
        threshold: BandwidthThreshold,
        timestamp: datetime,
    ) -> None:
        """Handle bandwidth alert.

        Args:
            alert_type: Type of alert
            current_bandwidth: Current bandwidth in B/s
            threshold: Threshold that was triggered
            timestamp: When alert occurred
        """
        pass


class BandwidthMonitor:
    """Real-time bandwidth monitor.

    Tracks bandwidth usage and can trigger alerts when
    thresholds are exceeded.
    """

    def __init__(
        self,
        sample_interval: float = 1.0,
        window_size: int = 60,
        alert_threshold: Optional[BandwidthThreshold] = None,
    ) -> None:
        """Initialize bandwidth monitor.

        Args:
            sample_interval: Interval between samples in seconds
            window_size: Number of samples to keep in history
            alert_threshold: Optional threshold for alerting
        """
        self._sample_interval = sample_interval
        self._window_size = window_size
        self._alert_threshold = alert_threshold

        # Sample history
        self._samples: deque[BandwidthSample] = deque(maxlen=window_size)

        # Current window data
        self._current_window_bytes: List[int] = []
        self._current_window_packets: List[int] = []
        self._window_start: Optional[datetime] = None

        # Counters for current interval
        self._interval_bytes = 0
        self._interval_packets = 0
        self._last_sample_time: Optional[datetime] = None

        # Alert state
        self._alert_callbacks: List[BandwidthAlert] = []
        self._last_alert_level: Optional[str] = None

        # Thread safety
        self._lock = Lock()

        # Timing
        self._start_time: Optional[datetime] = None

        logger = get_logger(__name__)
        self._logger = logger

    def update(self, packet: PacketInfo) -> None:
        """Update monitor with a new packet.

        Args:
            packet: Captured packet information
        """
        with self._lock:
            if self._start_time is None:
                self._start_time = packet.timestamp
                self._window_start = packet.timestamp

            now = packet.timestamp

            # Add to current interval
            self._interval_bytes += packet.length
            self._interval_packets += 1

            # Check if it's time to create a sample
            if self._last_sample_time is not None:
                time_diff = (now - self._last_sample_time).total_seconds()
                if time_diff >= self._sample_interval:
                    self._create_sample(now)

            self._last_sample_time = now

    def _create_sample(self, timestamp: datetime) -> None:
        """Create a bandwidth sample from current interval.

        Args:
            timestamp: Current timestamp
        """
        # Calculate time since last sample
        if self._window_start is None:
            return

        time_diff = (timestamp - self._window_start).total_seconds()
        if time_diff <= 0:
            return

        # Calculate rates
        bytes_per_sec = self._interval_bytes / time_diff
        packets_per_sec = self._interval_packets / time_diff

        # Create sample
        sample = BandwidthSample(
            timestamp=timestamp,
            bytes_per_second=bytes_per_sec,
            packets_per_second=packets_per_sec,
        )

        # Add to history
        self._samples.append(sample)

        # Add to alert window
        self._current_window_bytes.append(self._interval_bytes)
        self._current_window_packets.append(self._interval_packets)

        # Check alert threshold
        self._check_alerts(sample)

        # Reset interval counters
        self._interval_bytes = 0
        self._interval_packets = 0
        self._window_start = timestamp

    def _check_alerts(self, sample: BandwidthSample) -> None:
        """Check if alert threshold is exceeded.

        Args:
            sample: Current bandwidth sample
        """
        if self._alert_threshold is None:
            return

        # Calculate average over alert window
        window_seconds = self._alert_threshold.window_seconds
        now = time.time()
        window_start = now - window_seconds

        # Get samples within window
        window_samples = [
            s for s in self._samples
            if (now - s.timestamp.timestamp()) <= window_seconds
        ]

        if not window_samples:
            return

        # Calculate average bandwidth
        avg_bandwidth = sum(s.bytes_per_second for s in window_samples) / len(
            window_samples
        )

        # Check thresholds
        alert_type = None

        if avg_bandwidth >= self._alert_threshold.critical_level:
            alert_type = "critical"
        elif avg_bandwidth >= self._alert_threshold.warning_level:
            alert_type = "warning"

        if alert_type and alert_type != self._last_alert_level:
            # Trigger alert
            self._trigger_alert(alert_type, avg_bandwidth, sample.timestamp)
            self._last_alert_level = alert_type
        elif avg_bandwidth < self._alert_threshold.warning_level:
            # Reset alert state if below warning level
            self._last_alert_level = None

    def _trigger_alert(
        self,
        alert_type: str,
        bandwidth: float,
        timestamp: datetime,
    ) -> None:
        """Trigger bandwidth alert.

        Args:
            alert_type: Type of alert ("warning" or "critical")
            bandwidth: Current bandwidth
            timestamp: When alert occurred
        """
        self._logger.warning(
            f"Bandwidth {alert_type} alert: {bandwidth:.2f} B/s"
        )

        for callback in self._alert_callbacks:
            try:
                callback(alert_type, bandwidth, self._alert_threshold, timestamp)
            except Exception as e:
                self._logger.error(f"Error in alert callback: {e}")

    def get_current_bandwidth(self) -> Optional[BandwidthSample]:
        """Get current bandwidth measurement.

        Returns:
            Most recent sample or None if no samples yet
        """
        with self._lock:
            if self._samples:
                return self._samples[-1]
            return None

    def get_average_bandwidth(
        self,
        window_seconds: float = 60,
    ) -> Optional[float]:
        """Get average bandwidth over time window.

        Args:
            window_seconds: Time window in seconds

        Returns:
            Average bandwidth in B/s or None
        """
        with self._lock:
            if not self._samples:
                return None

            now = time.time()
            window_start = now - window_seconds

            # Get samples within window
            window_samples = [
                s.bytes_per_second for s in self._samples
                if (now - s.timestamp.timestamp()) <= window_start
            ]

            if not window_samples:
                return None

            return sum(window_samples) / len(window_samples)

    def get_peak_bandwidth(
        self,
        window_seconds: Optional[float] = None,
    ) -> Optional[float]:
        """Get peak bandwidth over time window.

        Args:
            window_seconds: Time window in seconds (None for all time)

        Returns:
            Peak bandwidth in B/s or None
        """
        with self._lock:
            if not self._samples:
                return None

            samples = list(self._samples)

            # Filter by time window if specified
            if window_seconds is not None:
                now = time.time()
                window_start = now - window_seconds
                samples = [
                    s for s in samples
                    if (now - s.timestamp.timestamp()) >= window_start
                ]

            if not samples:
                return None

            return max(s.bytes_per_second for s in samples)

    def get_samples(
        self,
        limit: Optional[int] = None,
    ) -> List[BandwidthSample]:
        """Get bandwidth samples.

        Args:
            limit: Maximum number of samples to return

        Returns:
            List of bandwidth samples
        """
        with self._lock:
            samples = list(self._samples)

            if limit:
                samples = samples[-limit:]

            return samples

    def add_alert_callback(self, callback: BandwidthAlert) -> None:
        """Add an alert callback.

        Args:
            callback: Function to call on alert
        """
        with self._lock:
            self._alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: BandwidthAlert) -> None:
        """Remove an alert callback.

        Args:
            callback: Callback to remove
        """
        with self._lock:
            try:
                self._alert_callbacks.remove(callback)
            except ValueError:
                pass

    def reset(self) -> None:
        """Reset monitor state."""
        with self._lock:
            self._samples.clear()
            self._current_window_bytes.clear()
            self._current_window_packets.clear()
            self._interval_bytes = 0
            self._interval_packets = 0
            self._window_start = None
            self._last_sample_time = None
            self._start_time = None
            self._last_alert_level = None

            self._logger.info("Bandwidth monitor reset")

    def get_summary(self) -> dict:
        """Get bandwidth summary.

        Returns:
            Dictionary with summary statistics
        """
        current = self.get_current_bandwidth()
        average = self.get_average_bandwidth()
        peak = self.get_peak_bandwidth()

        return {
            "current_bytes_per_sec": current.bytes_per_second if current else 0,
            "current_packets_per_sec": current.packets_per_second if current else 0,
            "average_bytes_per_sec": average or 0,
            "peak_bytes_per_sec": peak or 0,
            "sample_count": len(self._samples),
            "alert_enabled": self._alert_threshold is not None,
        }


def create_bandwidth_monitor(
    sample_interval: float = 1.0,
    window_size: int = 60,
    warning_level: float = 1_000_000,  # 1 MB/s
    critical_level: float = 10_000_000,  # 10 MB/s
    alert_window: int = 5,
) -> BandwidthMonitor:
    """Create bandwidth monitor instance.

    Args:
        sample_interval: Interval between samples in seconds
        window_size: Number of samples to keep
        warning_level: Warning threshold in B/s
        critical_level: Critical threshold in B/s
        alert_window: Time window for alert averaging

    Returns:
        Configured BandwidthMonitor instance
    """
    threshold = BandwidthThreshold(
        warning_level=warning_level,
        critical_level=critical_level,
        window_seconds=alert_window,
    )

    return BandwidthMonitor(
        sample_interval=sample_interval,
        window_size=window_size,
        alert_threshold=threshold,
    )
