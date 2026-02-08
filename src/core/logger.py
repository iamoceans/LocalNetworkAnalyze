"""
Logging module for the Local Network Analyzer application.

Provides a centralized logging configuration with:
- Rotating file handler
- Console handler with color support
- Structured logging format
- Thread-safe logging
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

from .config import LogConfig
from .exceptions import ConfigurationError


# Color codes for console output
class LogColors:
    """ANSI color codes for console logging."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"

    # Level-specific colors
    DEBUG = CYAN
    INFO = GREEN
    WARNING = YELLOW
    ERROR = RED
    CRITICAL = MAGENTA + BOLD


class ColoredFormatter(logging.Formatter):
    """Console formatter with color support.

    Adds ANSI color codes to log messages based on their level.
    Colors are only applied when outputting to a terminal.
    """

    COLORS = {
        logging.DEBUG: LogColors.DEBUG,
        logging.INFO: LogColors.INFO,
        logging.WARNING: LogColors.WARNING,
        logging.ERROR: LogColors.ERROR,
        logging.CRITICAL: LogColors.CRITICAL,
    }

    def __init__(self, fmt: Optional[str] = None, use_colors: bool = True) -> None:
        """Initialize colored formatter.

        Args:
            fmt: Log message format string
            use_colors: Whether to use colors (auto-detected if None)
        """
        super().__init__(fmt)
        self.use_colors = use_colors and self._supports_color()

    def _supports_color(self) -> bool:
        """Check if the terminal supports color output.

        Returns:
            True if terminal supports colors
        """
        # Check if we're writing to a terminal
        if not hasattr(sys.stdout, "isatty"):
            return False
        if not sys.stdout.isatty():
            return False

        # Windows 10+ supports ANSI colors
        return True

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors.

        Args:
            record: Log record to format

        Returns:
            Formatted log message with colors
        """
        if self.use_colors:
            level_color = self.COLORS.get(record.levelno, "")
            reset_color = LogColors.RESET
            # Add color to levelname
            record.levelname = f"{level_color}{record.levelno}{reset_color}"

        return super().format(record)


class Logger:
    """Application logger with file and console handlers.

    Provides a singleton instance for application-wide logging.
    """

    _instance: Optional["Logger"] = None
    _logger: Optional[logging.Logger] = None

    def __new__(cls) -> "Logger":
        """Create singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize logger (only on first access)."""
        if self._logger is None:
            self._logger = logging.getLogger("LocalNetworkAnalyzer")
            self._logger.setLevel(logging.DEBUG)
            self._logger.propagate = False

    def configure(self, config: LogConfig) -> None:
        """Configure logger with the provided configuration.

        This method should be called once at application startup.
        It will clear any existing handlers and add new ones.

        Args:
            config: Logging configuration

        Raises:
            ConfigurationError: If log directory cannot be created
        """
        # Clear existing handlers
        self._logger.handlers.clear()

        # Convert log level string to logging constant
        level = getattr(logging, config.level.upper(), logging.INFO)
        self._logger.setLevel(level)

        # Create formatters
        file_formatter = logging.Formatter(config.format)
        console_formatter = ColoredFormatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            use_colors=True,
        )

        # Add file handler
        try:
            file_handler = self._create_file_handler(config, file_formatter)
            self._logger.addHandler(file_handler)
        except OSError as e:
            raise ConfigurationError(
                f"Failed to create log file handler: {e}",
                {"path": str(config.path)},
            )

        # Add console handler
        console_handler = self._create_console_handler(console_formatter, level)
        self._logger.addHandler(console_handler)

        # Log initialization
        self._logger.info(f"Logger initialized with level {config.level}")

    def _create_file_handler(
        self,
        config: LogConfig,
        formatter: logging.Formatter,
    ) -> RotatingFileHandler:
        """Create rotating file handler.

        Args:
            config: Log configuration
            formatter: Log formatter

        Returns:
            Configured rotating file handler

        Raises:
            OSError: If log file cannot be created
        """
        # Ensure log directory exists
        log_path = config.path
        if not log_path.parent.exists():
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise OSError(f"Failed to create log directory: {e}")

        # Create rotating file handler
        file_handler = RotatingFileHandler(
            filename=log_path,
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)  # File gets all messages
        file_handler.setFormatter(formatter)

        return file_handler

    def _create_console_handler(
        self,
        formatter: logging.Formatter,
        level: int,
    ) -> logging.StreamHandler:
        """Create console handler.

        Args:
            formatter: Log formatter
            level: Log level for console output

        Returns:
            Configured console handler
        """
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)  # Console respects configured level
        console_handler.setFormatter(formatter)

        return console_handler

    def get_logger(self) -> logging.Logger:
        """Get the underlying logger instance.

        Returns:
            Logger instance for use in application code
        """
        return self._logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance for the specified name.

    This is the preferred way to get a logger in application code.

    Args:
        name: Logger name (typically __name__ of the module)
            If None, returns the root application logger

    Returns:
        Logger instance

    Example:
        >>> from src.core.logger import get_logger
        >>> logger = get_logger(__name__)
        >>> logger.info("Application started")
    """
    app_logger = Logger()
    base_logger = app_logger.get_logger()

    if name is None:
        return base_logger

    # Return a child logger with the specified name
    return base_logger.getChild(name)


def setup_logging(config: LogConfig) -> None:
    """Setup logging with the provided configuration.

    This is a convenience function that should be called once at
    application startup.

    Args:
        config: Logging configuration

    Example:
        >>> from src.core.config import LogConfig
        >>> from src.core.logger import setup_logging
        >>> config = LogConfig(level="DEBUG")
        >>> setup_logging(config)
    """
    logger = Logger()
    logger.configure(config)


class LoggedClass:
    """Base class for classes that need logging capabilities.

    Provides a self.logger attribute that can be used directly.

    Example:
        >>> class MyComponent(LoggedClass):
        ...     def __init__(self):
        ...         super().__init__(__name__)
        ...         self.logger.info("Component initialized")
    """

    def __init__(self, name: str) -> None:
        """Initialize logged class.

        Args:
            name: Logger name (typically __name__ of the module)
        """
        self.logger = get_logger(name)
