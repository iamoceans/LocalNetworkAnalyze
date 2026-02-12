"""
iOS Theme Configuration for Local Network Analyzer.

Provides iOS design system colors, typography, shapes, and spacing
following Apple's Human Interface Guidelines.
"""

from dataclasses import dataclass
from typing import Tuple, Dict, Optional


class iOSColors:
    """iOS system colors following Apple's HIG.

    Colors support both light and dark mode through
    the theme manager.
    """

    # System colors
    system_blue = "#007AFF"
    system_green = "#34C759"
    system_red = "#FF3B30"
    system_yellow = "#FFCC00"
    system_orange = "#FF9500"
    system_pink = "#FF2D55"
    system_purple = "#AF52DE"
    system_teal = "#5AC8FA"
    system_indigo = "#5856D6"
    system_gray = "#8E8E93"

    # Light mode colors
    light_bg = "#FFFFFF"
    light_secondary_bg = "#F2F2F7"
    light_tertiary_bg = "#FFFFFF"
    light_grouped_bg = "#F2F2F7"

    light_text = "#000000"
    light_secondary_text = "#8E8E93"
    light_tertiary_text = "#8E8E93"
    light_quaternary_text = "#8E8E93"

    light_separator = "#C6C6C8"
    light_separator_opaque = "#C6C6C8"

    light_fill = "#78788080"  # 30% opacity
    light_secondary_fill = "#78788012"  # 5% opacity
    light_tertiary_fill = "#76768040"  # 15% opacity
    light_quaternary_fill = "#74748012"  # 3% opacity

    # Dark mode colors
    dark_bg = "#000000"
    dark_secondary_bg = "#1C1C1E"
    dark_tertiary_bg = "#2C2C2E"
    dark_grouped_bg = "#000000"

    dark_text = "#FFFFFF"
    dark_secondary_text = "#8E8E93"
    dark_tertiary_text = "#8E8E93"
    dark_quaternary_text = "#8E8E93"

    dark_separator = "#38383A"
    dark_separator_opaque = "#38383A"

    dark_fill = "#78788028"  # 10% opacity
    dark_secondary_fill = "#78788012"  # 5% opacity
    dark_tertiary_fill = "#78788028"  # 10% opacity
    dark_quaternary_fill = "#78788018"  # 7% opacity

    # Semantic colors (light mode)
    success_light = "#34C759"
    success_bg_light = "#E8F5E9"

    error_light = "#FF3B30"
    error_bg_light = "#FFE5E5"

    warning_light = "#FFCC00"
    warning_bg_light = "#FFF5CC"

    info_light = "#007AFF"
    info_bg_light = "#E5F1FF"

    # Semantic colors (dark mode)
    success_dark = "#32D74B"
    success_bg_dark = "#1C3B29"

    error_dark = "#FF453A"
    error_bg_dark = "#3C1E1E"

    warning_dark = "#FFD60A"
    warning_bg_dark = "#3D3100"

    info_dark = "#0A84FF"
    info_bg_dark = "#001B3C"

    # Severity colors
    critical = "#FF3B30"
    critical_bg = "#3C1512"
    high = "#FF9500"
    high_bg = "#3D2600"
    medium = "#FFCC00"
    medium_bg = "#3D3000"
    low = "#34C759"
    low_bg = "#0F3D1A"

    # Protocol colors (iOS style palette)
    protocol_tcp = "#007AFF"
    protocol_udp = "#5856D6"
    protocol_http = "#34C759"
    protocol_https = "#30D158"
    protocol_dns = "#FF9500"
    protocol_icmp = "#FF3B30"
    protocol_ftp = "#AF52DE"
    protocol_ssh = "#5AC8FA"
    protocol_other = "#8E8E93"

    # Chart colors (iOS inspired palette)
    chart_palette: Tuple[str, ...] = (
        "#007AFF",  # Blue
        "#34C759",  # Green
        "#FFCC00",  # Yellow
        "#FF9500",  # Orange
        "#FF3B30",  # Red
        "#AF52DE",  # Purple
        "#FF2D55",  # Pink
        "#5AC8FA",  # Teal
    )


class iOSTypography:
    """iOS typography scale following SF Pro font hierarchy.

    Sizes based on Apple's Human Interface Guidelines.
    Uses SF Pro Display for large titles and SF Pro Text for body.
    """

    # SF Pro Display (large, impactful text)
    large_title = 34  # Bold, for hero content
    title1 = 28       # Bold, for navigation titles
    title2 = 22       # Bold, for modal titles
    title3 = 20       # Semibold, for list titles

    # SF Pro Text (body content)
    headline = 17     # Semibold, for emphasis
    body = 17         # Regular, for standard text
    body_emphasized = 17  # Semibold, for emphasized body
    callout = 16     # Regular, for secondary content
    subheadline = 15  # Regular, for supporting text
    footnote = 13    # Regular, for captions
    caption1 = 12   # Regular, for secondary captions
    caption2 = 11   # Regular, for tertiary captions

    # Legacy/compatibility sizes
    h1 = 28
    h2 = 22
    h3 = 20
    h4 = 17
    h5 = 15
    h6 = 13


class iOSShapes:
    """iOS corner radius and shadow specifications.

    Based on Apple's design language with consistent
    rounding throughout the interface.
    """

    # Corner radius
    corner_small = 8      # Small elements (buttons, tags)
    corner_medium = 10     # Default buttons, cards
    corner_large = 12     # Standard cards, panels
    corner_xlarge = 16    # Large cards, modal containers
    corner_xxlarge = 20   # Special containers

    # Navigation bar
    nav_corner = 0       # Navigation bars use square corners on iOS

    # Modal sheets
    sheet_corner = 12     # Bottom sheets
    sheet_corner_large = 16  # Large modal presentations

    # Shadow specifications (for reference)
    shadow_radius = 8
    shadow_offset = (0, 2)
    shadow_opacity = 0.15

    # Border width
    border_thin = 0.5
    border_default = 1
    border_thick = 2


class iOSSpacing:
    """iOS spacing system based on 4-point grid.

    All spacing values are multiples of 4 for consistency.
    """

    # Base spacing
    xs = 4     # Extra small
    sm = 8     # Small
    md = 12    # Medium
    lg = 16    # Large (standard)
    xl = 24    # Extra large
    xxl = 32   # Extra extra large
    xxxl = 48  # Hero spacing

    # Component-specific spacing
    button_padding = 12
    card_padding = 16
    list_padding = 12
    section_spacing = 24
    page_margin = 16

    # Navigation bar
    nav_height = 44
    nav_padding = 16
    nav_icon_size = 24
    nav_text_spacing = 8

    # Tab bar
    tab_height = 65
    tab_icon_size = 24
    tab_padding = 4

    # List/table
    list_row_height = 44
    list_padding = 16
    list_separator_height = 0.5

    # Modal
    modal_padding = 20
    modal_button_height = 44
    modal_corner = 14


class iOSFontFamilies:
    """Font family names for iOS-style typography.

    Falls back gracefully to system fonts if SF Pro unavailable.
    """

    # Primary fonts (SF Pro)
    sf_pro_display = "SF Pro Display"
    sf_pro_text = "SF Pro Text"

    # Fallback fonts by platform
    macos_fallback = "-apple-system"
    windows_fallback = "Segoe UI"
    linux_fallback = "Ubuntu"

    # Monospace fallback
    mono_fallback = "SF Mono, Consolas, Monaco, monospace"

    # Generic fallback chain
    fallback_chain = "SF Pro Display, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"


@dataclass(frozen=True)
class iOSTheme:
    """Complete iOS theme configuration.

    Provides access to all iOS design tokens.
    """

    colors: iOSColors = iOSColors()
    typography: iOSTypography = iOSTypography()
    shapes: iOSShapes = iOSShapes()
    spacing: iOSSpacing = iOSSpacing()
    fonts: iOSFontFamilies = iOSFontFamilies()

    def get_color(self, key: str, mode: str = "dark") -> str:
        """Get color by key with theme mode.

        Args:
            key: Color key (e.g., 'bg', 'text', 'system_blue')
            mode: Theme mode ('light' or 'dark')

        Returns:
            Hex color string
        """
        mode_suffix = f"_light" if mode == "light" else "_dark"
        color_key = f"{key}{mode_suffix}"

        if hasattr(self.colors, color_key):
            return getattr(self.colors, color_key)
        elif hasattr(self.colors, key):
            return getattr(self.colors, key)
        return self.colors.system_gray

    def get_font(self, style: str = "body", weight: str = "normal", size: Optional[int] = None) -> Tuple:
        """Get font tuple for CustomTkinter.

        Args:
            style: Font style (large_title, title1, body, etc.)
            weight: Font weight (normal, bold, semibold)
            size: Optional size override

        Returns:
            Font tuple (family, size, weight)
        """
        if size is None:
            size = getattr(self.typography, style, self.typography.body)

        # Map weight to CTk-compatible values
        weight_map = {
            "normal": "normal",
            "semibold": "bold",
            "bold": "bold",
        }
        ctK_weight = weight_map.get(weight.lower(), "normal")

        return (self.fonts.sf_pro_text, size, ctK_weight)


# Default iOS theme instance
iOSTheme = iOSTheme()


# Theme mode management
class ThemeMode:
    """Manages current theme mode (light/dark)."""

    _current_mode: str = "dark"  # Default to dark mode

    @classmethod
    def set_mode(cls, mode: str) -> None:
        """Set current theme mode.

        Args:
            mode: 'light' or 'dark'
        """
        if mode in ("light", "dark"):
            cls._current_mode = mode

    @classmethod
    def get_mode(cls) -> str:
        """Get current theme mode.

        Returns:
            'light' or 'dark'
        """
        return cls._current_mode

    @classmethod
    def toggle_mode(cls) -> None:
        """Toggle between light and dark mode."""
        cls._current_mode = "light" if cls._current_mode == "dark" else "dark"

    @classmethod
    def is_light(cls) -> bool:
        """Check if current mode is light.

        Returns:
            True if light mode, False otherwise
        """
        return cls._current_mode == "light"

    @classmethod
    def is_dark(cls) -> bool:
        """Check if current mode is dark.

        Returns:
            True if dark mode, False otherwise
        """
        return cls._current_mode == "dark"


__all__ = [
    "iOSColors",
    "iOSTypography",
    "iOSShapes",
    "iOSSpacing",
    "iOSFontFamilies",
    "iOSTheme",
    "iOSTheme",
    "ThemeMode",
]
