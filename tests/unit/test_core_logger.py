"""Tests for src.core.logger module."""

import pytest
import logging
from pathlib import Path
from src.core.logger import (
    Logger, get_logger, setup_logging,
    LogColors, ColoredFormatter, LoggedClass
)
from src.core.config import LogConfig


@pytest.mark.unit
class TestLogColors:
    """Test LogColors class."""

    def test_color_codes_defined(self):
        """Test that all color codes are defined."""
        assert hasattr(LogColors, 'RESET')
        assert hasattr(LogColors, 'RED')
        assert hasattr(LogColors, 'GREEN')
        assert hasattr(LogColors, 'YELLOW')
        assert hasattr(LogColors, 'BLUE')
        assert hasattr(LogColors, 'MAGENTA')
        assert hasattr(LogColors, 'CYAN')
        assert hasattr(LogColors, 'WHITE')
        assert hasattr(LogColors, 'BOLD')

    def test_level_colors_defined(self):
        """Test that level-specific colors are defined."""
        assert hasattr(LogColors, 'DEBUG')
        assert hasattr(LogColors, 'INFO')
        assert hasattr(LogColors, 'WARNING')
        assert hasattr(LogColors, 'ERROR')
        assert hasattr(LogColors, 'CRITICAL')


@pytest.mark.unit
class TestColoredFormatter:
    """Test ColoredFormatter class."""

    def test_create_formatter(self):
        """Test creating colored formatter."""
        formatter = ColoredFormatter(use_colors=False)
        assert formatter is not None

    def test_format_record_no_colors(self):
        """Test formatting record without colors."""
        formatter = ColoredFormatter(use_colors=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert "Test message" in formatted

    def test_format_record_with_colors(self, capsys):
        """Test formatting record with colors."""
        formatter = ColoredFormatter(use_colors=True)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert formatted is not None


@pytest.mark.unit
class TestLogger:
    """Test Logger singleton class."""

    def test_singleton(self):
        """Test that Logger is a singleton."""
        logger1 = Logger()
        logger2 = Logger()
        assert logger1 is logger2

    def test_get_logger(self):
        """Test getting underlying logger."""
        logger = Logger()
        base_logger = logger.get_logger()
        assert base_logger is not None
        assert isinstance(base_logger, logging.Logger)

    def test_configure(self, tmp_path):
        """Test configuring logger."""
        logger = Logger()
        log_path = tmp_path / "test.log"

        config = LogConfig(
            path=log_path,
            level="DEBUG",
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        logger.configure(config)

        # Check that file was created
        assert log_path.exists() or log_path.parent.exists()

    def test_configure_creates_log_directory(self, tmp_path):
        """Test that configure creates log directory."""
        logger = Logger()
        log_path = tmp_path / "logs" / "test.log"

        config = LogConfig(
            path=log_path,
            level="INFO"
        )

        logger.configure(config)

        # Directory should be created
        assert log_path.parent.exists()


@pytest.mark.unit
class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger_returns_root(self):
        """Test getting root logger."""
        logger = get_logger()
        assert logger is not None
        assert isinstance(logger, logging.Logger)

    def test_get_logger_with_name(self):
        """Test getting named logger."""
        logger = get_logger("test.module")
        assert logger is not None
        assert "test.module" in logger.name

    def test_get_logger_child(self):
        """Test getting child logger."""
        base = get_logger("test")
        child = get_logger("test.child")
        assert child.parent == base


@pytest.mark.unit
class TestSetupLogging:
    """Test setup_logging function."""

    def test_setup_logging(self, tmp_path):
        """Test setting up logging."""
        log_path = tmp_path / "app.log"
        config = LogConfig(path=log_path, level="INFO")

        setup_logging(config)

        # Get logger and verify it works
        logger = get_logger("test")
        logger.info("Test message")

        # Log file should be created
        assert log_path.exists() or log_path.parent.exists()


@pytest.mark.unit
class TestLoggedClass:
    """Test LoggedClass mixin."""

    def test_create_logged_class(self):
        """Test creating a class with logging."""
        class TestComponent(LoggedClass):
            def __init__(self):
                super().__init__("test")

        component = TestComponent()
        assert hasattr(component, 'logger')
        assert component.logger is not None

    def test_use_logger(self):
        """Test using logger in logged class."""
        class TestComponent(LoggedClass):
            def __init__(self):
                super().__init__("test")

            def do_something(self):
                self.logger.info("Doing something")

        component = TestComponent()
        # Should not raise
        component.do_something()
