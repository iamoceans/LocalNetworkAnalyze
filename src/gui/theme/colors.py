"""
Color configuration for the Local Network Analyzer UI.

Implements iOS design system with light/dark theme support
following Apple's Human Interface Guidelines.
"""

from dataclasses import dataclass
from typing import Tuple, Dict, Optional


def _rgba_to_hex(r: int, g: int, b: int, a: float) -> str:
    """Convert RGBA to hex color with alpha simulation.

    For dark backgrounds, we simulate alpha by darkening the color.

    Args:
        r: Red component (0-255)
        g: Green component (0-255)
        b: Blue component (0-255)
        a: Alpha component (0.0-1.0)

    Returns:
        Hex color string simulating the rgba color on dark background
    """
    # For dark backgrounds, blend with black
    bg_r, bg_g, bg_b = 0x00, 0x00, 0x00

    r = int(r * a + bg_r * (1 - a))
    g = int(g * a + bg_g * (1 - a))
    b = int(b * a + bg_b * (1 - a))

    return f"#{r:02x}{g:02x}{b:02x}"


@dataclass(frozen=True)
class ThemeColors:
    """Main theme color palette.

    iOS-style theme with OLED-friendly dark mode
    and clean light mode support.
    """

    # iOS System colors
    system_blue: str = "#007AFF"
    system_green: str = "#34C759"
    system_red: str = "#FF3B30"
    system_yellow: str = "#FFCC00"
    system_orange: str = "#FF9500"
    system_gray: str = "#8E8E93"

    # Dark mode (default)
    bg_primary: str = "#000000"          # Pure black (OLED friendly)
    bg_secondary: str = "#1C1C1E"      # Dark gray-blue
    bg_tertiary: str = "#2C2C2E"       # Lighter dark
    bg_card: str = "#1C1C1E"           # Card background
    bg_hover: str = "#2C2C2E"          # Hover state
    bg_input: str = "#1C1C1E"           # Input background

    # Text colors (dark mode)
    text_primary: str = "#FFFFFF"         # High contrast white
    text_secondary: str = "#8E8E93"     # Secondary gray
    text_muted: str = "#636366"         # Muted gray
    text_inverse: str = "#000000"         # Inverted for light bg

    # Light mode colors
    light_bg_primary: str = "#FFFFFF"
    light_bg_secondary: str = "#F2F2F7"
    light_bg_card: str = "#F2F2F7"
    light_text_primary: str = "#000000"
    light_text_secondary: str = "#8E8E93"

    # Border colors
    border_default: str = "#38383A"       # iOS dark separator
    border_focus: str = "#007AFF"          # iOS blue for focus
    border_muted: str = "#1C1C1E"        # Subtle border

    # Separator
    separator: str = "#38383A"
    separator_opaque: str = "#38383A"

    # Semantic colors (dark mode)
    success: str = "#32D74B"           # iOS green
    success_bg: str = "#1C3B29"

    error: str = "#FF453A"             # iOS red
    error_bg: str = "#3C1E1E"

    warning: str = "#FFD60A"           # iOS yellow
    warning_bg: str = "#3D3100"

    info: str = "#0A84FF"              # iOS blue
    info_bg: str = "#001B3C"

    # Alert severity levels (dark mode)
    critical: str = "#FF3B30"
    critical_bg: str = "#3C1512"
    high: str = "#FF9500"
    high_bg: str = "#3D2600"
    medium: str = "#FFCC00"
    medium_bg: str = "#3D3000"
    low: str = "#34C759"
    low_bg: str = "#0F3D1A"

    # Operational states
    active: str = "#34C759"
    inactive: str = "#8E8E93"
    disabled: str = "#3C3C43"
    processing: str = "#0A84FF"


@dataclass(frozen=True)
class ProtocolColors:
    """Protocol-specific color mapping following iOS palette."""

    tcp: str = "#007AFF"       # Blue
    udp: str = "#5856D6"       # Indigo
    http: str = "#34C759"      # Green
    https: str = "#30D158"      # Dark green
    dns: str = "#FF9500"       # Orange
    icmp: str = "#FF3B30"      # Red
    ftp: str = "#AF52DE"       # Purple
    ssh: str = "#5AC8FA"       # Cyan
    other: str = "#8E8E93"     # Gray


@dataclass(frozen=True)
class ChartColors:
    """Chart color palette.

    iOS-inspired color scheme for data visualization.
    """

    CHART_PALETTE: Tuple[str, ...] = (
        "#007AFF",  # Blue
        "#34C759",  # Green
        "#FFCC00",  # Yellow
        "#FF9500",  # Orange
        "#FF3B30",  # Red
        "#AF52DE",  # Purple
        "#FF2D55",  # Pink
        "#5AC8FA",  # Teal
    )


@dataclass(frozen=True)
class iOSCardConfig:
    """iOS card component configuration.

    Defines the visual parameters for iOS-style cards
    used throughout the UI.
    """

    # Card appearance
    corner_radius: int = 12
    border_width: int = 0.5
    border_color: str = "#38383A"

    # Background
    bg_color: str = "#1C1C1E"
    bg_color_light: str = "#F2F2F7"

    # Shadow (simulated via border)
    shadow_color: str = "#000000"


@dataclass(frozen=True)
class iOSShapes:
    """iOS shape specifications.

    Corner radius and spacing following Apple's design language.
    """

    # Corner radius
    corner_small: int = 8       # Small elements
    corner_medium: int = 10     # Default buttons
    corner_large: int = 12     # Cards, panels
    corner_xlarge: int = 16    # Large containers
    corner_xxlarge: int = 20   # Modals


@dataclass(frozen=True)
class iOSSpacing:
    """iOS spacing system based on 4-point grid."""

    xs: int = 4
    sm: int = 8
    md: int = 12
    lg: int = 16
    xl: int = 24
    xxl: int = 32


class ThemeMode:
    """Manages current theme mode (light/dark/auto)."""

    _current_mode: str = "dark"  # Default: dark
    _auto_mode: bool = True     # Auto-detect from system

    @classmethod
    def set_mode(cls, mode: str) -> None:
        """Set theme mode.

        Args:
            mode: 'light', 'dark', or 'auto'
        """
        if mode in ("light", "dark", "auto"):
            cls._current_mode = mode
            if mode != "auto":
                cls._auto_mode = False

    @classmethod
    def get_mode(cls) -> str:
        """Get current theme mode.

        Returns:
            'light' or 'dark'
        """
        if cls._auto_mode:
            # Could implement system theme detection here
            return "dark"  # Default to dark
        return cls._current_mode

    @classmethod
    def is_light(cls) -> bool:
        """Check if light mode is active.

        Returns:
            True if light mode
        """
        return cls.get_mode() == "light"

    @classmethod
    def is_dark(cls) -> bool:
        """Check if dark mode is active.

        Returns:
            True if dark mode
        """
        return cls.get_mode() == "dark"

    @classmethod
    def toggle(cls) -> None:
        """Toggle between light and dark mode."""
        cls._current_mode = "light" if cls.is_dark() else "dark"
        cls._auto_mode = False


class Colors:
    """Main color configuration class.

    Provides access to all color schemes used in application.
    """

    THEME = ThemeColors()
    PROTOCOL = ProtocolColors()
    CHART = ChartColors()
    CARD = iOSCardConfig()
    SHAPES = iOSShapes()
    SPACING = iOSSpacing()

    # Legacy support - lazy initialization for NeonColors (defined later in file)
    _neon_instance = None

    @classmethod
    def _get_neon(cls):
        """Get NeonColors instance (lazy initialization)."""
        if cls._neon_instance is None:
            cls._neon_instance = NeonColors()
        return cls._neon_instance

    # Create property-like access for NEON
    class _NeonAccessor:
        """Descriptor to provide class-level NEON access."""
        def __get__(self, obj, objtype=None):
            return Colors._get_neon()

    NEON = _NeonAccessor()

    # Protocol color mapping
    PROTOCOL_COLORS: Dict[str, str] = {
        "TCP": ProtocolColors.tcp,
        "UDP": ProtocolColors.udp,
        "HTTP": ProtocolColors.http,
        "HTTPS": ProtocolColors.https,
        "DNS": ProtocolColors.dns,
        "ICMP": ProtocolColors.icmp,
        "FTP": ProtocolColors.ftp,
        "SSH": ProtocolColors.ssh,
        "Other": ProtocolColors.other,
    }

    @classmethod
    def get_protocol_color(cls, protocol: str) -> str:
        """Get color for a specific protocol.

        Args:
            protocol: Protocol name (e.g., "TCP", "UDP")

        Returns:
            Hex color string for protocol
        """
        return cls.PROTOCOL_COLORS.get(protocol.upper(), cls.PROTOCOL.other)

    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Get color for alert severity level.

        Args:
            severity: Severity level (critical, high, medium, low)

        Returns:
            Hex color string for severity
        """
        return getattr(cls.THEME, f"{severity.lower()}", cls.THEME.low)

    @classmethod
    def get_chart_color(cls, index: int) -> str:
        """Get color from chart palette.

        Args:
            index: Index in palette

        Returns:
            Hex color string
        """
        return cls.CHART.CHART_PALETTE[index % len(cls.CHART.CHART_PALETTE)]

    @classmethod
    def get_bg_color(cls) -> str:
        """Get background color based on current theme mode.

        Returns:
            Hex color for background
        """
        return cls.THEME.light_bg_primary if ThemeMode.is_light() else cls.THEME.bg_primary

    @classmethod
    def get_card_color(cls) -> str:
        """Get card background color based on theme mode.

        Returns:
            Hex color for card background
        """
        return cls.THEME.light_bg_card if ThemeMode.is_light() else cls.THEME.bg_card

    @classmethod
    def get_text_color(cls) -> str:
        """Get primary text color based on theme mode.

        Returns:
            Hex color for text
        """
        return cls.THEME.light_text_primary if ThemeMode.is_light() else cls.THEME.text_primary

    @classmethod
    def get_text_secondary(cls) -> str:
        """Get secondary text color based on theme mode.

        Returns:
            Hex color for secondary text
        """
        return cls.THEME.light_text_secondary if ThemeMode.is_light() else cls.THEME.text_secondary


# Legacy support class for backward compatibility
class NeonColors:
    """Legacy neon colors for backward compatibility.

    Maps old neon color references to iOS equivalents.
    """

    neon_green: str = "#34C759"
    neon_green_dim: str = "#0F3D1A"

    neon_red: str = "#FF3B30"
    neon_red_dim: str = "#3C1512"

    neon_cyan: str = "#0A84FF"
    neon_cyan_dim: str = "#001B3C"

    neon_yellow: str = "#FFD60A"
    neon_yellow_dim: str = "#3D3100"

    neon_orange: str = "#FF9500"
    neon_orange_dim: str = "#3D2600"


# Legacy class name
GlassConfig = iOSCardConfig


__all__ = [
    "Colors",
    "ThemeColors",
    "NeonColors",
    "ProtocolColors",
    "ChartColors",
    "iOSCardConfig",
    "GlassConfig",
    "iOSShapes",
    "iOSSpacing",
    "ThemeMode",
]
