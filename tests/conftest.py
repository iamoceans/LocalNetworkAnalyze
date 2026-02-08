"""
Pytest configuration and shared fixtures.

This module contains the pytest configuration and common fixtures
used across all tests.
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# pytest markers
def pytest_configure(config) -> None:
    """Configure custom pytest markers.

    Markers:
        - unit: Unit tests (fast, isolated)
        - integration: Integration tests (slower, may use external resources)
        - slow: Slow-running tests
        - network: Tests that require network access
        - gui: GUI-related tests
    """
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow-running tests")
    config.addinivalue_line("markers", "network: Tests requiring network access")
    config.addinivalue_line("markers", "gui: GUI-related tests")


# Fixtures


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files.

    The directory is automatically cleaned up after the test.

    Yields:
        Path to temporary directory
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_file(temp_dir: Path) -> Generator[Path, None, None]:
    """Create a temporary file.

    Args:
        temp_dir: Temporary directory fixture

    Yields:
        Path to temporary file
    """
    file_path = temp_dir / "test_file.txt"
    file_path.touch()
    yield file_path


@pytest.fixture
def mock_config(temp_dir: Path) -> dict:
    """Create a mock application configuration.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Dictionary containing mock configuration
    """
    return {
        "capture": {
            "interface": "",
            "filter": "",
            "buffer_size": 100,
            "promiscuous": True,
            "timeout": 5,
        },
        "database": {
            "path": str(temp_dir / "test.db"),
            "pool_size": 1,
        },
        "detection": {
            "enable_port_scan_detection": True,
            "enable_ddos_detection": True,
            "enable_anomaly_detection": True,
            "threshold_connections": 10,
            "threshold_bandwidth": 1024,
            "scan_time_window": 2,
        },
        "gui": {
            "theme": "dark",
            "update_interval": 500,
            "max_display_packets": 100,
            "window_width": 800,
            "window_height": 600,
        },
        "log": {
            "level": "DEBUG",
            "path": str(temp_dir / "test.log"),
            "max_bytes": 1024,
            "backup_count": 1,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    }


@pytest.fixture
def mock_packet() -> dict:
    """Create a mock packet info dictionary.

    Returns:
        Dictionary with mock packet data
    """
    from datetime import datetime

    return {
        "timestamp": datetime(2024, 1, 1, 12, 0, 0),
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 1500,
        "raw_data": b"mock packet data",
    }


@pytest.fixture
def mock_packets() -> list[dict]:
    """Create a list of mock packets.

    Returns:
        List of mock packet dictionaries
    """
    from datetime import datetime, timedelta

    base_time = datetime(2024, 1, 1, 12, 0, 0)
    packets = []

    # Generate packets from different IPs
    for i in range(50):
        packets.append({
            "timestamp": base_time + timedelta(seconds=i),
            "src_ip": f"192.168.1.{100 + i % 10}",
            "dst_ip": "192.168.1.1",
            "src_port": 10000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 500 + i * 10,
            "raw_data": b"mock packet data",
        })

    return packets


@pytest.fixture
def mock_alert() -> dict:
    """Create a mock alert dictionary.

    Returns:
        Dictionary with mock alert data
    """
    from datetime import datetime

    return {
        "alert_id": "test-alert-001",
        "timestamp": datetime(2024, 1, 1, 12, 0, 0),
        "type": "Port Scan",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "target_ips": ["192.168.1.1", "192.168.1.2"],
        "target_ports": {22, 80, 443, 8080},
        "description": "Port scan detected from 192.168.1.100",
        "packet_count": 25,
    }


@pytest.fixture
def mock_device() -> dict:
    """Create a mock device dictionary.

    Returns:
        Dictionary with mock device data
    """
    from datetime import datetime

    return {
        "ip": "192.168.1.100",
        "mac": "00:11:22:33:44:55",
        "hostname": "test-device",
        "vendor": "Test Vendor",
        "first_seen": datetime(2024, 1, 1, 10, 0, 0),
        "last_seen": datetime(2024, 1, 1, 12, 0, 0),
        "open_ports": {22, 80, 443},
        "is_gateway": False,
    }


@pytest.fixture
def sample_http_request() -> bytes:
    """Create a sample HTTP request.

    Returns:
        Raw bytes of HTTP GET request
    """
    return b"GET /index.html HTTP/1.1\r\n" \
           b"Host: example.com\r\n" \
           b"User-Agent: Mozilla/5.0\r\n" \
           b"Accept: */*\r\n" \
           b"\r\n"


@pytest.fixture
def sample_http_response() -> bytes:
    """Create a sample HTTP response.

    Returns:
        Raw bytes of HTTP response
    """
    return b"HTTP/1.1 200 OK\r\n" \
           b"Content-Type: text/html\r\n" \
           b"Content-Length: 13\r\n" \
           b"\r\n" \
           b"Hello, World!"


@pytest.fixture
def skip_network_tests() -> None:
    """Fixture to skip tests that require network access.

    Use this fixture when network tests should be skipped:
        @pytest.mark.skipif(
            'os.getenv("CI")',
            reason="Network tests skipped in CI"
        )
        def test_network_operation(skip_network_tests):
            ...
    """
    if os.getenv("CI"):
        pytest.skip("Network tests skipped in CI environment")


@pytest.fixture
def skip_gui_tests() -> None:
    """Fixture to skip GUI tests in headless environments.

    Use this fixture to skip GUI tests when no display is available.
    """
    if os.getenv("DISPLAY") is None and sys.platform != "darwin":
        pytest.skip("GUI tests skipped (no display available)")


@pytest.fixture
def mock_logger() -> MagicMock:
    """Create a mock logger.

    Returns:
        MagicMock object configured as a logger
    """
    logger = MagicMock()
    logger.debug = MagicMock()
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.critical = MagicMock()
    return logger


@pytest.fixture(autouse=True)
def reset_singletons() -> Generator[None, None, None]:
    """Reset singleton instances between tests.

    This fixture runs automatically for every test to ensure
    singleton classes start in a clean state.
    """
    # Reset before test
    yield

    # Reset after test
    from src.core.logger import Logger
    from src.core.config import AppConfig

    # Reset logger singleton
    if hasattr(Logger, "_instance"):
        Logger._instance = None
    if hasattr(Logger, "_logger"):
        Logger._logger = None


# Test helper functions


def assert_packet_info_valid(packet: dict) -> None:
    """Assert that a packet info dictionary is valid.

    Args:
        packet: Packet info dictionary to validate

    Raises:
        AssertionError: If packet is invalid
    """
    assert "timestamp" in packet
    assert "src_ip" in packet
    assert "dst_ip" in packet
    assert "protocol" in packet
    assert "length" in packet

    assert isinstance(packet["src_ip"], str)
    assert isinstance(packet["dst_ip"], str)
    assert isinstance(packet["protocol"], str)
    assert isinstance(packet["length"], int)
    assert packet["length"] > 0


def assert_alert_valid(alert: dict) -> None:
    """Assert that an alert dictionary is valid.

    Args:
        alert: Alert dictionary to validate

    Raises:
        AssertionError: If alert is invalid
    """
    assert "alert_id" in alert
    assert "timestamp" in alert
    assert "type" in alert
    assert "severity" in alert

    assert isinstance(alert["alert_id"], str)
    assert isinstance(alert["type"], str)
    assert alert["severity"] in ("low", "medium", "high", "critical")


def assert_device_valid(device: dict) -> None:
    """Assert that a device dictionary is valid.

    Args:
        device: Device dictionary to validate

    Raises:
        AssertionError: If device is invalid
    """
    assert "ip" in device
    assert "mac" in device

    assert isinstance(device["ip"], str)
    assert isinstance(device["mac"], str)

    # Validate IP format (basic check)
    parts = device["ip"].split(".")
    assert len(parts) == 4
    assert all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    # Validate MAC format (basic check)
    mac_parts = device["mac"].split(":")
    assert len(mac_parts) == 6
    assert all(len(part) == 2 for part in mac_parts)
