"""Tests for src.core.exceptions module."""

import pytest
from src.core.exceptions import (
    LocalNetworkAnalyzerError,
    ConfigurationError,
    InvalidConfigValueError,
    MissingConfigError,
    CaptureError,
    InterfaceNotFoundError,
    PermissionDeniedError,
    CaptureTimeoutError,
    ProtocolError,
    MalformedPacketError,
    UnsupportedProtocolError,
    ScanError,
    ScanTimeoutError,
    InvalidRangeError,
    StorageError,
    DatabaseError,
    ExportError,
    FileWriteError,
    DetectionError,
    ModelNotFoundError,
    InvalidThresholdError,
    GuiError,
    WidgetError,
    ThreadError,
    format_error,
    is_recoverable
)


@pytest.mark.unit
class TestLocalNetworkAnalyzerError:
    """Test base exception class."""

    def test_create_error(self):
        """Test creating error with message."""
        error = LocalNetworkAnalyzerError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.details == {}

    def test_create_error_with_details(self):
        """Test creating error with details."""
        error = LocalNetworkAnalyzerError(
            "Test error",
            details={"key": "value"}
        )
        assert "key=value" in str(error)
        assert error.details == {"key": "value"}

    def test_str_with_details(self):
        """Test string representation with details."""
        error = LocalNetworkAnalyzerError(
            "Error occurred",
            details={"code": 500, "url": "/test"}
        )
        error_str = str(error)
        assert "Error occurred" in error_str
        assert "code=500" in error_str


@pytest.mark.unit
class TestConfigurationErrors:
    """Test configuration-related errors."""

    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError("Invalid configuration")
        assert isinstance(error, LocalNetworkAnalyzerError)
        assert "Invalid configuration" in str(error)

    def test_invalid_config_value_error(self):
        """Test InvalidConfigValueError."""
        error = InvalidConfigValueError(
            "Port must be positive",
            details={"port": -1}
        )
        assert isinstance(error, ConfigurationError)
        assert "-1" in str(error)

    def test_missing_config_error(self):
        """Test MissingConfigError."""
        error = MissingConfigError(
            "Database path not configured",
            details={"field": "database.path"}
        )
        assert isinstance(error, ConfigurationError)


@pytest.mark.unit
class TestCaptureErrors:
    """Test capture-related errors."""

    def test_capture_error(self):
        """Test CaptureError."""
        error = CaptureError("Capture failed")
        assert isinstance(error, LocalNetworkAnalyzerError)

    def test_interface_not_found_error(self):
        """Test InterfaceNotFoundError."""
        error = InterfaceNotFoundError(
            "Interface 'eth99' not found",
            details={"interface": "eth99", "available": ["eth0", "lo"]}
        )
        assert isinstance(error, CaptureError)
        assert "eth99" in str(error)

    def test_permission_denied_error(self):
        """Test PermissionDeniedError."""
        error = PermissionDeniedError(
            "Administrator privileges required",
            details={"suggestion": "Run as admin"}
        )
        assert isinstance(error, CaptureError)

    def test_capture_timeout_error(self):
        """Test CaptureTimeoutError."""
        error = CaptureTimeoutError(
            "No packets captured",
            details={"timeout_seconds": 30}
        )
        assert isinstance(error, CaptureError)


@pytest.mark.unit
class TestProtocolErrors:
    """Test protocol-related errors."""

    def test_protocol_error(self):
        """Test ProtocolError."""
        error = ProtocolError("Protocol error")
        assert isinstance(error, LocalNetworkAnalyzerError)

    def test_malformed_packet_error(self):
        """Test MalformedPacketError."""
        error = MalformedPacketError(
            "Invalid TCP header",
            details={"protocol": "TCP", "expected_length": 20}
        )
        assert isinstance(error, ProtocolError)

    def test_unsupported_protocol_error(self):
        """Test UnsupportedProtocolError."""
        error = UnsupportedProtocolError(
            "Protocol 0xFF not supported",
            details={"protocol": 0xFF}
        )
        assert isinstance(error, ProtocolError)


@pytest.mark.unit
class TestScanErrors:
    """Test scan-related errors."""

    def test_scan_error(self):
        """Test ScanError."""
        error = ScanError("Scan failed")
        assert isinstance(error, LocalNetworkAnalyzerError)

    def test_scan_timeout_error(self):
        """Test ScanTimeoutError."""
        error = ScanTimeoutError(
            "Scan timed out",
            details={"timeout_seconds": 60}
        )
        assert isinstance(error, ScanError)

    def test_invalid_range_error(self):
        """Test InvalidRangeError."""
        error = InvalidRangeError(
            "Invalid IP range",
            details={"range": "192.168.1.300", "reason": "octet > 255"}
        )
        assert isinstance(error, ScanError)


@pytest.mark.unit
class TestStorageErrors:
    """Test storage-related errors."""

    def test_storage_error(self):
        """Test StorageError."""
        error = StorageError("Storage failed")
        assert isinstance(error, LocalNetworkAnalyzerError)

    def test_database_error(self):
        """Test DatabaseError."""
        error = DatabaseError(
            "Failed to insert",
            details={"table": "packets", "error": "UNIQUE constraint"}
        )
        assert isinstance(error, StorageError)

    def test_export_error(self):
        """Test ExportError."""
        error = ExportError(
            "Export failed",
            details={"format": "csv", "path": "/tmp/test.csv"}
        )
        assert isinstance(error, StorageError)

    def test_file_write_error(self):
        """Test FileWriteError."""
        error = FileWriteError(
            "Cannot write file",
            details={"path": "/tmp/test", "reason": "Permission denied"}
        )
        assert isinstance(error, StorageError)


@pytest.mark.unit
class TestDetectionErrors:
    """Test detection-related errors."""

    def test_detection_error(self):
        """Test DetectionError."""
        error = DetectionError("Detection failed")
        assert isinstance(error, LocalNetworkAnalyzerError)

    def test_model_not_found_error(self):
        """Test ModelNotFoundError."""
        error = ModelNotFoundError(
            "Model not found",
            details={"model_type": "port_scan", "path": "/models/port_scan.pkl"}
        )
        assert isinstance(error, DetectionError)

    def test_invalid_threshold_error(self):
        """Test InvalidThresholdError."""
        error = InvalidThresholdError(
            "Threshold must be positive",
            details={"threshold": -1}
        )
        assert isinstance(error, DetectionError)


@pytest.mark.unit
class TestGuiErrors:
    """Test GUI-related errors."""

    def test_gui_error(self):
        """Test GuiError."""
        error = GuiError("GUI error")
        assert isinstance(error, LocalNetworkAnalyzerError)

    def test_widget_error(self):
        """Test WidgetError."""
        error = WidgetError(
            "Widget update failed",
            details={"widget": "chart", "reason": "No data"}
        )
        assert isinstance(error, GuiError)

    def test_thread_error(self):
        """Test ThreadError."""
        error = ThreadError(
            "Thread update failed",
            details={"suggestion": "Use thread-safe methods"}
        )
        assert isinstance(error, GuiError)


@pytest.mark.unit
class TestUtilityFunctions:
    """Test utility functions."""

    def test_format_error_custom(self):
        """Test formatting custom error."""
        error = LocalNetworkAnalyzerError("Custom error", {"key": "value"})
        formatted = format_error(error)
        assert "Custom error" in formatted

    def test_format_error_permission(self):
        """Test formatting permission error."""
        error = PermissionError("Access denied")
        formatted = format_error(error)
        assert "Permission denied" in formatted

    def test_format_error_file_not_found(self):
        """Test formatting file not found error."""
        error = FileNotFoundError("/path/to/file")
        formatted = format_error(error)
        assert "File not found" in formatted

    def test_format_error_value(self):
        """Test formatting value error."""
        error = ValueError("Invalid value")
        formatted = format_error(error)
        assert "Invalid value" in formatted

    def test_format_error_os(self):
        """Test formatting OS error."""
        error = OSError("System error")
        formatted = format_error(error)
        assert "System error" in formatted

    def test_format_error_unknown(self):
        """Test formatting unknown error."""
        error = RuntimeError("Unknown error")
        formatted = format_error(error)
        assert "Unexpected error" in formatted

    def test_is_recoverable_timeout(self):
        """Test is_recoverable with timeout errors."""
        error = CaptureTimeoutError("Timeout")
        assert is_recoverable(error) is True

        error = ScanTimeoutError("Timeout")
        assert is_recoverable(error) is True

    def test_is_recoverable_not_recoverable(self):
        """Test is_recoverable with non-recoverable errors."""
        error = PermissionDeniedError("No permission")
        assert is_recoverable(error) is False

        error = DatabaseError("DB error")
        assert is_recoverable(error) is False

    def test_is_recoverable_unknown(self):
        """Test is_recoverable with unknown error."""
        error = ValueError("Unknown")
        assert is_recoverable(error) is False
