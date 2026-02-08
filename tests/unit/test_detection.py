"""
Unit tests for detection module.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from src.capture.base import PacketInfo
from src.detection import (
    DetectionEngine,
    DetectionType,
    DetectionResult,
    Alert,
    Severity,
    PortScanDetector,
    PortScanConfig,
    AnomalyDetector,
    AnomalyConfig,
    create_detection_engine,
    create_port_scan_detector,
    create_anomaly_detector,
)
from src.detection.base import (
    DetectorStatistics,
    create_alert_id,
    calculate_severity,
    validate_confidence,
)


@pytest.mark.unit
class TestSeverity:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_get_score(self):
        """Test getting severity scores."""
        assert Severity.INFO.get_score() == 10
        assert Severity.LOW.get_score() == 25
        assert Severity.MEDIUM.get_score() == 50
        assert Severity.HIGH.get_score() == 75
        assert Severity.CRITICAL.get_score() == 100

    def test_from_score(self):
        """Test getting severity from score."""
        assert Severity.from_score(100) == Severity.CRITICAL
        assert Severity.from_score(80) == Severity.HIGH
        assert Severity.from_score(50) == Severity.MEDIUM
        assert Severity.from_score(25) == Severity.LOW
        assert Severity.from_score(10) == Severity.INFO
        assert Severity.from_score(5) == Severity.INFO


@pytest.mark.unit
class TestAlert:
    """Test Alert data class."""

    def test_create_alert(self):
        """Test creating an alert."""
        alert = Alert(
            id="test_alert",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.HIGH,
            title="Test Alert",
            description="Test description",
            timestamp=datetime.now(),
            confidence=0.9,
            source_ip="192.168.1.1",
        )

        assert alert.id == "test_alert"
        assert alert.detection_type == DetectionType.PORT_SCAN
        assert alert.confidence == 0.9

    def test_invalid_confidence_raises_error(self):
        """Test that invalid confidence raises error."""
        with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
            Alert(
                id="test",
                detection_type=DetectionType.PORT_SCAN,
                severity=Severity.MEDIUM,
                title="Test",
                description="Test",
                timestamp=datetime.now(),
                confidence=1.5,
            )

    def test_invalid_source_ip_raises_error(self):
        """Test that invalid IP raises error."""
        with pytest.raises(ValueError, match="Invalid source IP"):
            Alert(
                id="test",
                detection_type=DetectionType.PORT_SCAN,
                severity=Severity.MEDIUM,
                title="Test",
                description="Test",
                timestamp=datetime.now(),
                source_ip="invalid-ip",
            )

    def test_invalid_port_raises_error(self):
        """Test that invalid port raises error."""
        with pytest.raises(ValueError, match="Invalid source port"):
            Alert(
                id="test",
                detection_type=DetectionType.PORT_SCAN,
                severity=Severity.MEDIUM,
                title="Test",
                description="Test",
                timestamp=datetime.now(),
                source_port=99999,
            )

    def test_to_dict(self):
        """Test converting to dictionary."""
        now = datetime.now()
        alert = Alert(
            id="test_alert",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.HIGH,
            title="Test Alert",
            description="Test description",
            timestamp=now,
            confidence=0.9,
        )

        data = alert.to_dict()

        assert data["id"] == "test_alert"
        assert data["detection_type"] == "port_scan"
        assert data["severity"] == "high"
        assert data["confidence"] == 0.9

    def test_get_summary(self):
        """Test getting alert summary."""
        alert = Alert(
            id="test",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.HIGH,
            title="Port Scan Detected",
            description="Test",
            timestamp=datetime.now(),
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
        )

        summary = alert.get_summary()

        assert "[HIGH]" in summary
        assert "Port Scan Detected" in summary
        assert "from 192.168.1.1" in summary
        assert "to 192.168.1.2" in summary


@pytest.mark.unit
class TestDetectionResult:
    """Test DetectionResult data class."""

    def test_create_result(self):
        """Test creating detection result."""
        alert = Alert(
            id="test",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            timestamp=datetime.now(),
        )

        result = DetectionResult(
            detected=True,
            alerts=[alert],
            confidence=0.9,
            details={"key": "value"},
        )

        assert result.detected is True
        assert len(result.alerts) == 1
        assert result.confidence == 0.9

    def test_invalid_confidence_raises_error(self):
        """Test that invalid confidence raises error."""
        with pytest.raises(ValueError):
            DetectionResult(
                detected=True,
                confidence=2.0,
            )


@pytest.mark.unit
class TestPortScanConfig:
    """Test PortScanConfig data class."""

    def test_default_config(self):
        """Test default configuration."""
        config = PortScanConfig()

        assert config.min_ports == 10
        assert config.time_window == 60.0

    def test_custom_config(self):
        """Test custom configuration."""
        config = PortScanConfig(
            min_ports=5,
            time_window=30.0,
        )

        assert config.min_ports == 5
        assert config.time_window == 30.0

    def test_invalid_min_ports_raises_error(self):
        """Test that invalid min_ports raises error."""
        with pytest.raises(ValueError):
            PortScanConfig(min_ports=0)

    def test_invalid_time_window_raises_error(self):
        """Test that invalid time_window raises error."""
        with pytest.raises(ValueError):
            PortScanConfig(time_window=0.5)


@pytest.mark.unit
class TestPortScanDetector:
    """Test PortScanDetector class."""

    def test_init_default(self):
        """Test initialization with defaults."""
        detector = PortScanDetector()

        assert detector.get_detection_type() == DetectionType.PORT_SCAN
        assert detector.is_enabled()

    def test_init_with_config(self):
        """Test initialization with config."""
        config = PortScanConfig(min_ports=5, time_window=30.0)
        detector = PortScanDetector(config)

        assert detector._config.min_ports == 5

    def test_process_non_tcp(self):
        """Test processing non-TCP packet."""
        detector = PortScanDetector()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=53,
            protocol="UDP",
            length=512,
            raw_data=b"test",
        )

        result = detector.process(packet)
        assert result is None

    def test_process_tcp_packet(self):
        """Test processing TCP packet."""
        detector = PortScanDetector()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        result = detector.process(packet)
        # No detection yet (need more ports)
        assert result is None or result.detected is False

    def test_detect_port_scan(self):
        """Test port scan detection."""
        config = PortScanConfig(min_ports=5, time_window=10.0)
        detector = PortScanDetector(config)

        now = datetime.now()

        # Send packets to different ports
        for port in [20, 21, 22, 23, 25, 80]:
            packet = PacketInfo(
                timestamp=now,
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=54321,
                dst_port=port,
                protocol="TCP",
                length=1500,
                raw_data=b"test",
            )
            result = detector.process(packet)

        # Should trigger detection
        assert detector.get_statistics()["active_scanners"] >= 1

    def test_whitelist(self):
        """Test IP whitelist functionality."""
        detector = PortScanDetector()
        detector.add_to_whitelist("192.168.1.10")

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.10",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        result = detector.process(packet)
        # Should be ignored (whitelisted)
        assert result is None

    def test_get_active_scanners(self):
        """Test getting active scanners."""
        detector = PortScanDetector()

        # No scanners initially
        assert len(detector.get_active_scanners()) == 0

    def test_enable_disable(self):
        """Test enabling/disabling detector."""
        detector = PortScanDetector()

        assert detector.is_enabled()

        detector.disable()
        assert not detector.is_enabled()

        detector.enable()
        assert detector.is_enabled()


@pytest.mark.unit
class TestAnomalyConfig:
    """Test AnomalyConfig data class."""

    def test_default_config(self):
        """Test default configuration."""
        config = AnomalyConfig()

        assert config.baseline_window == 100
        assert config.threshold_std_dev == 3.0

    def test_invalid_baseline_window_raises_error(self):
        """Test that invalid baseline_window raises error."""
        with pytest.raises(ValueError):
            AnomalyConfig(baseline_window=10, min_samples=30)


@pytest.mark.unit
class TestAnomalyDetector:
    """Test AnomalyDetector class."""

    def test_init_default(self):
        """Test initialization with defaults."""
        detector = AnomalyDetector()

        assert detector.get_detection_type() == DetectionType.TRAFFIC_ANOMALY
        assert detector.is_enabled()

    def test_init_with_config(self):
        """Test initialization with config."""
        config = AnomalyConfig(
            baseline_window=50,
            threshold_std_dev=2.0,
        )
        detector = AnomalyDetector(config)

        assert detector._config.baseline_window == 50

    def test_process_packet(self):
        """Test processing packet."""
        detector = AnomalyDetector()

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        result = detector.process(packet)
        # No detection without baseline
        assert result is None

    def test_baseline_not_established_initially(self):
        """Test that baseline is not established initially."""
        detector = AnomalyDetector()

        assert not detector.is_baseline_established()

    def test_reset_baseline(self):
        """Test resetting baseline."""
        detector = AnomalyDetector()

        # Manually establish baseline for testing
        detector._baseline_established = True
        assert detector.is_baseline_established()

        detector.reset_baseline()
        assert not detector.is_baseline_established()

    def test_enable_disable(self):
        """Test enabling/disabling detector."""
        detector = AnomalyDetector()

        assert detector.is_enabled()

        detector.disable()
        assert not detector.is_enabled()

        detector.enable()
        assert detector.is_enabled()


@pytest.mark.unit
class TestDetectionEngine:
    """Test DetectionEngine class."""

    def test_init_empty(self):
        """Test initialization without detectors."""
        engine = DetectionEngine()

        assert engine.get_statistics()["detector_count"] == 0

    def test_init_with_detectors(self):
        """Test initialization with detectors."""
        port_scanner = PortScanDetector()
        anomaly_detector = AnomalyDetector()

        engine = DetectionEngine(detectors=[port_scanner, anomaly_detector])

        assert engine.get_statistics()["detector_count"] == 2

    def test_add_detector(self):
        """Test adding detector."""
        engine = DetectionEngine()
        detector = PortScanDetector()

        engine.add_detector(detector)

        assert engine.has_detector(DetectionType.PORT_SCAN)

    def test_remove_detector(self):
        """Test removing detector."""
        detector = PortScanDetector()
        engine = DetectionEngine(detectors=[detector])

        assert engine.has_detector(DetectionType.PORT_SCAN)

        engine.remove_detector(DetectionType.PORT_SCAN)

        assert not engine.has_detector(DetectionType.PORT_SCAN)

    def test_get_detector(self):
        """Test getting detector."""
        detector = PortScanDetector()
        engine = DetectionEngine(detectors=[detector])

        retrieved = engine.get_detector(DetectionType.PORT_SCAN)

        assert retrieved is detector

    def test_process_packet(self):
        """Test processing packet through engine."""
        detector = PortScanDetector()
        engine = DetectionEngine(detectors=[detector])

        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test",
        )

        results = engine.process(packet)
        # Empty list (no detection)
        assert isinstance(results, list)

    def test_get_alert_history(self):
        """Test getting alert history."""
        engine = DetectionEngine()

        history = engine.get_alert_history()
        assert isinstance(history, list)

    def test_enable_disable_detector(self):
        """Test enabling/disabling specific detector."""
        detector = PortScanDetector()
        engine = DetectionEngine(detectors=[detector])

        engine.disable_detector(DetectionType.PORT_SCAN)
        assert not detector.is_enabled()

        engine.enable_detector(DetectionType.PORT_SCAN)
        assert detector.is_enabled()

    def test_enable_disable_all(self):
        """Test enabling/disabling all detectors."""
        detector1 = PortScanDetector()
        detector2 = AnomalyDetector()
        engine = DetectionEngine(detectors=[detector1, detector2])

        engine.disable_all()
        assert not detector1.is_enabled()
        assert not detector2.is_enabled()

        engine.enable_all()
        assert detector1.is_enabled()
        assert detector2.is_enabled()

    def test_clear_alert_history(self):
        """Test clearing alert history."""
        engine = DetectionEngine()
        engine.clear_alert_history()

        assert engine.get_statistics()["alerts_in_history"] == 0

    def test_reset(self):
        """Test resetting engine."""
        detector = PortScanDetector()
        engine = DetectionEngine(detectors=[detector])

        engine.reset()

        # Should clear statistics
        assert engine.get_statistics()["total_alerts"] == 0


@pytest.mark.unit
class TestUtilityFunctions:
    """Test utility functions."""

    def test_create_alert_id(self):
        """Test alert ID generation."""
        id1 = create_alert_id()
        id2 = create_alert_id()

        assert id1.startswith("alert_")
        assert id2.startswith("alert_")
        assert id1 != id2  # Should be unique

    def test_validate_confidence_valid(self):
        """Test validating valid confidence."""
        # Should not raise
        validate_confidence(0.0)
        validate_confidence(0.5)
        validate_confidence(1.0)

    def test_validate_confidence_invalid(self):
        """Test validating invalid confidence."""
        with pytest.raises(ValueError):
            validate_confidence(-0.1)

        with pytest.raises(ValueError):
            validate_confidence(1.1)

    def test_calculate_severity(self):
        """Test severity calculation."""
        # High confidence -> CRITICAL
        assert calculate_severity(0.95) == Severity.CRITICAL

        # Medium confidence -> HIGH
        assert calculate_severity(0.8) == Severity.HIGH

        # Medium confidence -> base severity
        assert calculate_severity(0.5, Severity.MEDIUM) == Severity.MEDIUM

        # Low confidence -> LOW
        assert calculate_severity(0.3) == Severity.LOW

        # Very low confidence -> INFO
        assert calculate_severity(0.1) == Severity.INFO


@pytest.mark.unit
class TestFactoryFunctions:
    """Test factory functions."""

    def test_create_port_scan_detector(self):
        """Test port scan detector factory."""
        detector = create_port_scan_detector(
            min_ports=15,
            time_window=45.0,
        )

        assert isinstance(detector, PortScanDetector)
        assert detector._config.min_ports == 15

    def test_create_anomaly_detector(self):
        """Test anomaly detector factory."""
        detector = create_anomaly_detector(
            baseline_window=150,
            threshold_std_dev=2.5,
        )

        assert isinstance(detector, AnomalyDetector)
        assert detector._config.baseline_window == 150

    def test_create_detection_engine_default(self):
        """Test detection engine factory with defaults."""
        engine = create_detection_engine()

        assert isinstance(engine, DetectionEngine)
        # Should have both detectors by default
        assert engine.has_detector(DetectionType.PORT_SCAN)
        assert engine.has_detector(DetectionType.TRAFFIC_ANOMALY)

    def test_create_detection_engine_custom(self):
        """Test detection engine factory with custom params."""
        engine = create_detection_engine(
            enable_port_scan=True,
            enable_anomaly=False,
            port_scan_threshold=20,
        )

        assert engine.has_detector(DetectionType.PORT_SCAN)
        assert not engine.has_detector(DetectionType.TRAFFIC_ANOMALY)
