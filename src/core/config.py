"""
Configuration management module.

Provides immutable configuration dataclasses for the application.
All configuration classes use frozen dataclass to ensure immutability.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import json
import os


@dataclass(frozen=True)
class CaptureConfig:
    """Packet capture configuration.

    Attributes:
        interface: Network interface to capture from (empty for default)
        filter: BPF filter string for packet filtering
        buffer_size: Maximum number of packets to buffer
        promiscuous: Enable promiscuous mode
        timeout: Capture timeout in seconds
    """
    interface: str = ""
    filter: str = ""
    buffer_size: int = 1000
    promiscuous: bool = True
    timeout: int = 30

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if self.buffer_size <= 0:
            raise ValueError("buffer_size must be positive")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")


@dataclass(frozen=True)
class DatabaseConfig:
    """Database configuration.

    Attributes:
        path: Path to the SQLite database file
        pool_size: Connection pool size
    """
    path: Path = field(default_factory=lambda: Path("data/database/traffic.db"))
    pool_size: int = 5

    def __post_init__(self) -> None:
        """Validate and initialize database configuration."""
        if self.pool_size <= 0:
            raise ValueError("pool_size must be positive")

        # Ensure parent directory exists
        db_path = self.path
        if not db_path.parent.exists():
            db_path.parent.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class DetectionConfig:
    """Anomaly detection configuration.

    Attributes:
        enable_port_scan_detection: Enable port scan detection
        enable_ddos_detection: Enable DDoS detection
        enable_anomaly_detection: Enable statistical anomaly detection
        threshold_connections: Connection count threshold for scan detection
        threshold_bandwidth: Bandwidth threshold in bytes per second
        scan_time_window: Time window in seconds for scan detection
    """
    enable_port_scan_detection: bool = True
    enable_ddos_detection: bool = True
    enable_anomaly_detection: bool = True
    threshold_connections: int = 100
    threshold_bandwidth: int = 10485760  # 10MB
    scan_time_window: int = 5

    def __post_init__(self) -> None:
        """Validate detection configuration."""
        if self.threshold_connections <= 0:
            raise ValueError("threshold_connections must be positive")
        if self.threshold_bandwidth <= 0:
            raise ValueError("threshold_bandwidth must be positive")
        if self.scan_time_window <= 0:
            raise ValueError("scan_time_window must be positive")


@dataclass(frozen=True)
class GuiConfig:
    """GUI configuration.

    Attributes:
        theme: UI theme (light, dark, system)
        color_theme: Color theme name (e.g., blue, dark-blue, green)
        language: Interface language (en, zh)
        update_interval: Dashboard update interval in milliseconds
        max_display_packets: Maximum packets to display in table
        window_width: Default window width
        window_height: Default window height
    """
    theme: str = "dark"
    color_theme: str = "clam"
    language: str = "en"
    update_interval: int = 1000  # 1 second
    max_display_packets: int = 1000
    window_width: int = 1280
    window_height: int = 720

    def __post_init__(self) -> None:
        """Validate GUI configuration."""
        if self.theme not in ("light", "dark", "system"):
            raise ValueError("theme must be 'light', 'dark', or 'system'")
        if self.language not in ("en", "zh"):
            raise ValueError("language must be 'en' or 'zh'")
        if self.update_interval <= 0:
            raise ValueError("update_interval must be positive")
        if self.max_display_packets <= 0:
            raise ValueError("max_display_packets must be positive")
        if self.window_width <= 0:
            raise ValueError("window_width must be positive")
        if self.window_height <= 0:
            raise ValueError("window_height must be positive")


@dataclass(frozen=True)
class LogConfig:
    """Logging configuration.

    Attributes:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        path: Path to log file
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        format: Log message format string
    """
    level: str = "INFO"
    path: Path = field(default_factory=lambda: Path("logs/app.log"))
    max_bytes: int = 10485760  # 10MB
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    def __post_init__(self) -> None:
        """Validate logging configuration."""
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        if self.level.upper() not in valid_levels:
            raise ValueError(f"level must be one of {valid_levels}")
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if self.backup_count < 0:
            raise ValueError("backup_count must be non-negative")

        # Ensure log directory exists
        log_path = self.path
        if not log_path.parent.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class AppConfig:
    """Main application configuration.

    This is the top-level configuration that contains all sub-configurations.

    Attributes:
        capture: Packet capture settings
        database: Database settings
        detection: Anomaly detection settings
        gui: GUI settings
        log: Logging settings
    """
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    gui: GuiConfig = field(default_factory=GuiConfig)
    log: LogConfig = field(default_factory=LogConfig)

    @classmethod
    def from_file(cls, path: Path) -> "AppConfig":
        """Load configuration from JSON file.

        Args:
            path: Path to the configuration file

        Returns:
            AppConfig instance with loaded values

        Raises:
            FileNotFoundError: If configuration file doesn't exist
            ValueError: If configuration file is invalid
        """
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Convert nested dicts to config objects
            if "capture" in data and isinstance(data["capture"], dict):
                data["capture"] = CaptureConfig(**data["capture"])
            if "database" in data and isinstance(data["database"], dict):
                if "path" in data["database"] and isinstance(data["database"]["path"], str):
                    data["database"]["path"] = Path(data["database"]["path"])
                data["database"] = DatabaseConfig(**data["database"])
            if "detection" in data and isinstance(data["detection"], dict):
                data["detection"] = DetectionConfig(**data["detection"])
            if "gui" in data and isinstance(data["gui"], dict):
                data["gui"] = GuiConfig(**data["gui"])
            if "log" in data and isinstance(data["log"], dict):
                if "path" in data["log"] and isinstance(data["log"]["path"], str):
                    data["log"]["path"] = Path(data["log"]["path"])
                data["log"] = LogConfig(**data["log"])

            return cls(**data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}")
        except TypeError as e:
            raise ValueError(f"Invalid configuration structure: {e}")

    def to_file(self, path: Path) -> None:
        """Save configuration to JSON file.

        Args:
            path: Path to save the configuration file

        Raises:
            OSError: If file cannot be written
        """
        # Convert Path objects to strings for JSON serialization
        def convert_to_dict(obj):
            if isinstance(obj, Path):
                return str(obj)
            elif isinstance(obj, (CaptureConfig, DatabaseConfig,
                                 DetectionConfig, GuiConfig, LogConfig)):
                return {k: convert_to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, AppConfig):
                return {k: convert_to_dict(v) for k, v in obj.__dict__.items()}
            return obj

        data = convert_to_dict(self)

        # Ensure parent directory exists
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Load configuration from environment variables.

        Environment variables:
            LNA_INTERFACE: Network interface
            LNA_LOG_LEVEL: Logging level
            LNA_DB_PATH: Database path
            LNA_THEME: GUI theme

        Returns:
            AppConfig with values from environment
        """
        capture_config = CaptureConfig(
            interface=os.getenv("LNA_INTERFACE", ""),
        )

        log_config = LogConfig(
            level=os.getenv("LNA_LOG_LEVEL", "INFO"),
            path=Path(os.getenv("LNA_DB_PATH", "logs/app.log")),
        )

        gui_config = GuiConfig(
            theme=os.getenv("LNA_THEME", "dark"),
        )

        db_config = DatabaseConfig(
            path=Path(os.getenv("LNA_DB_PATH", "data/database/traffic.db")),
        )

        return cls(
            capture=capture_config,
            log=log_config,
            gui=gui_config,
            database=db_config,
        )

    def with_log_level(self, level: str) -> "AppConfig":
        """Return a new config with updated log level.

        Args:
            level: New log level

        Returns:
            New AppConfig instance with updated log config
        """
        new_log = LogConfig(
            level=level,
            path=self.log.path,
            max_bytes=self.log.max_bytes,
            backup_count=self.log.backup_count,
            format=self.log.format,
        )
        return AppConfig(
            capture=self.capture,
            database=self.database,
            detection=self.detection,
            gui=self.gui,
            log=new_log,
        )

    def with_language(self, language: str) -> "AppConfig":
        """Return a new config with updated language.

        Args:
            language: New language code (en or zh)

        Returns:
            New AppConfig instance with updated gui config
        """
        new_gui = GuiConfig(
            theme=self.gui.theme,
            color_theme=self.gui.color_theme,
            language=language,
            update_interval=self.gui.update_interval,
            max_display_packets=self.gui.max_display_packets,
            window_width=self.gui.window_width,
            window_height=self.gui.window_height,
        )
        return AppConfig(
            capture=self.capture,
            database=self.database,
            detection=self.detection,
            gui=new_gui,
            log=self.log,
        )
