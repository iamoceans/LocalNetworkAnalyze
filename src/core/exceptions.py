"""
Custom exceptions for the Local Network Analyzer application.

Provides a hierarchy of exceptions for different error scenarios,
enabling precise error handling and user-friendly error messages.
"""

from typing import Optional


class LocalNetworkAnalyzerError(Exception):
    """Base exception for all application errors.

    All custom exceptions inherit from this base class,
    allowing catching of all application-specific errors.
    """

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        """Initialize exception with message and optional details.

        Args:
            message: Human-readable error message
            details: Additional error context for debugging
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return formatted error message."""
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


# Configuration Errors


class ConfigurationError(LocalNetworkAnalyzerError):
    """Raised when there is an error in configuration.

    This includes:
    - Invalid configuration values
    - Missing required configuration
    - Configuration file parsing errors
    """

    pass


class InvalidConfigValueError(ConfigurationError):
    """Raised when a configuration value is invalid.

    Example:
        raise InvalidConfigValueError(
            "buffer_size must be positive",
            {"field": "buffer_size", "value": -1}
        )
    """

    pass


class MissingConfigError(ConfigurationError):
    """Raised when required configuration is missing.

    Example:
        raise MissingConfigError(
            "Database path not configured",
            {"field": "database.path"}
        )
    """

    pass


# Network Capture Errors


class CaptureError(LocalNetworkAnalyzerError):
    """Base exception for packet capture errors.

    Raised when there are issues with:
    - Starting/stopping packet capture
    - Network interface access
    - Permission issues
    """

    pass


class InterfaceNotFoundError(CaptureError):
    """Raised when specified network interface doesn't exist.

    Example:
        raise InterfaceNotFoundError(
            "Network interface 'eth99' not found",
            {"interface": "eth99", "available": ["eth0", "lo"]}
        )
    """

    pass


class PermissionDeniedError(CaptureError):
    """Raised when lacking required permissions.

    Packet capture typically requires administrator/root privileges.

    Example:
        raise PermissionDeniedError(
            "Administrator privileges required for packet capture",
            {"suggestion": "Run with administrator/root privileges"}
        )
    """

    pass


class CaptureTimeoutError(CaptureError):
    """Raised when packet capture times out.

    Example:
        raise CaptureTimeoutError(
            "No packets captured within timeout period",
            {"timeout_seconds": 30}
        )
    """

    pass


# Protocol Parsing Errors


class ProtocolError(LocalNetworkAnalyzerError):
    """Base exception for protocol parsing errors.

    Raised when there are issues with:
    - Invalid protocol format
    - Malformed packets
    - Unsupported protocol versions
    """

    pass


class MalformedPacketError(ProtocolError):
    """Raised when a packet is malformed or incomplete.

    Example:
        raise MalformedPacketError(
            "Invalid TCP header",
            {"protocol": "TCP", "expected_length": 20, "actual_length": 15}
        )
    """

    pass


class UnsupportedProtocolError(ProtocolError):
    """Raised when encountering an unsupported protocol.

    Example:
        raise UnsupportedProtocolError(
            "Protocol not supported",
            {"protocol": 0xFF, "suggestion": "Update protocol parsers"}
        )
    """

    pass


# Network Scanning Errors


class ScanError(LocalNetworkAnalyzerError):
    """Base exception for network scanning errors.

    Raised when there are issues with:
    - ARP/ICMP scanning
    - Port scanning
    - Device discovery
    """

    pass


class ScanTimeoutError(ScanError):
    """Raised when network scan times out.

    Example:
        raise ScanTimeoutError(
            "Network scan timed out",
            {"timeout_seconds": 60, "scanned_hosts": 5}
        )
    """

    pass


class InvalidRangeError(ScanError):
    """Raised when scan range is invalid.

    Example:
        raise InvalidRangeError(
            "Invalid IP range",
            {"range": "192.168.1.300", "reason": "octet > 255"}
        )
    """

    pass


# Storage Errors


class StorageError(LocalNetworkAnalyzerError):
    """Base exception for data storage errors.

    Raised when there are issues with:
    - Database operations
    - File I/O
    - Data export
    """

    pass


class DatabaseError(StorageError):
    """Raised for database-related errors.

    Example:
        raise DatabaseError(
            "Failed to insert packet record",
            {"table": "packets", "error": "UNIQUE constraint failed"}
        )
    """

    pass


class ExportError(StorageError):
    """Raised when data export fails.

    Example:
        raise ExportError(
            "Failed to export to CSV",
            {"format": "csv", "path": "/path/to/file.csv"}
        )
    """

    pass


class FileWriteError(StorageError):
    """Raised when file write operation fails.

    Example:
        raise FileWriteError(
            "Cannot write to file",
            {"path": "/path/to/file", "reason": "Permission denied"}
        )
    """

    pass


# Detection Errors


class DetectionError(LocalNetworkAnalyzerError):
    """Base exception for anomaly detection errors.

    Raised when there are issues with:
    - Anomaly detection algorithms
    - Pattern matching
    - Threshold calculations
    """

    pass


class ModelNotFoundError(DetectionError):
    """Raised when detection model is not found.

    Example:
        raise ModelNotFoundError(
            "Detection model not found",
            {"model_type": "port_scan", "expected_path": "/models/port_scan.pkl"}
        )
    """

    pass


class InvalidThresholdError(DetectionError):
    """Raised when detection threshold is invalid.

    Example:
        raise InvalidThresholdError(
            "Detection threshold must be positive",
            {"threshold": -1, "field": "connection_count"}
        )
    """

    pass


# GUI Errors


class GuiError(LocalNetworkAnalyzerError):
    """Base exception for GUI-related errors.

    Raised when there are issues with:
    - Window creation
    - Widget updates
    - Event handling
    """

    pass


class WidgetError(GuiError):
    """Raised when widget operation fails.

    Example:
        raise WidgetError(
            "Failed to update chart widget",
            {"widget": "traffic_chart", "reason": "No data available"}
        )
    """

    pass


class ThreadError(GuiError):
    """Raised when GUI thread operation fails.

    Example:
        raise ThreadError(
            "Failed to update UI from background thread",
            {"suggestion": "Use thread-safe UI update methods"}
        )
    """

    pass


# Utility function for error handling


def format_error(error: Exception) -> str:
    """Format an exception for user display.

    Args:
        error: The exception to format

    Returns:
        User-friendly error message
    """
    if isinstance(error, LocalNetworkAnalyzerError):
        return str(error)
    elif isinstance(error, PermissionError):
        return f"Permission denied: {error}"
    elif isinstance(error, FileNotFoundError):
        return f"File not found: {error}"
    elif isinstance(error, ValueError):
        return f"Invalid value: {error}"
    elif isinstance(error, OSError):
        return f"System error: {error}"
    else:
        return f"Unexpected error: {error}"


def is_recoverable(error: Exception) -> bool:
    """Check if an error is recoverable.

    Args:
        error: The exception to check

    Returns:
        True if the error can be recovered from
    """
    # Recoverable errors
    if isinstance(error, (CaptureTimeoutError, ScanTimeoutError)):
        return True

    # Not recoverable
    if isinstance(error, (PermissionDeniedError, DatabaseError)):
        return False

    # Default to not recoverable for unknown errors
    return False
