"""Pytest configuration and fixtures."""

import sys
import os
from pathlib import Path
from unittest.mock import Mock
import pytest

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def mock_logger():
    """Mock logger fixture."""
    logger = Mock()
    logger.debug = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.critical = Mock()
    return logger


@pytest.fixture
def temp_db_path(tmp_path):
    """Temporary database path fixture."""
    return tmp_path / "test.db"


@pytest.fixture
def mock_packet():
    """Mock packet info fixture."""
    from datetime import datetime
    from src.capture.base import PacketInfo

    return PacketInfo(
        timestamp=datetime.now(),
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        length=1024
    )


@pytest.fixture
def mock_capture():
    """Mock capture engine fixture."""
    capture = Mock()
    capture.get_interfaces = Mock(return_value=[
        {"name": "eth0", "description": "Ethernet", "address": "192.168.1.1"},
        {"name": "wlan0", "description": "Wi-Fi", "address": "192.168.1.2"}
    ])
    capture.add_callback = Mock()
    capture.start_capture = Mock()
    capture.stop_capture = Mock()
    return capture


@pytest.fixture
def sample_http_request():
    """Sample HTTP request data for testing."""
    return b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"


@pytest.fixture
def sample_http_response():
    """Sample HTTP response data for testing."""
    return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nHello"
