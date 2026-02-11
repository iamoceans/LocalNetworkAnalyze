"""
Color configuration for the Local Network Analyzer UI.

Implements a cyber-security themed dark mode design with
neon green/red accents and glassmorphism effects.
"""

from dataclasses import dataclass
from typing import Tuple, Dict


def _rgba_to_hex(r: int, g: int, b: int, a: float) -> str:
    """Convert RGBA to hex color with alpha simulation.

    For dark backgrounds, we simulate alpha by darkening the color.
    For example, rgba(255,255,255,0.1) on a dark background becomes
    a very light gray.

    Args:
        r: Red component (0-255)
        g: Green component (0-255)
        b: Blue component (0-255)
        a: Alpha component (0.0-1.0)

    Returns:
        Hex color string simulating the rgba color on dark background
    """
    # For dark backgrounds, blend the color with background (#020617)
    bg_r, bg_g, bg_b = 0x02, 0x06, 0x17

    r = int(r * a + bg_r * (1 - a))
    g = int(g * a + bg_g * (1 - a))
    b = int(b * a + bg_b * (1 - b))

    return f"#{r:02x}{g:02x}{b:02x}"


@dataclass(frozen=True)
class ThemeColors:
    """Main theme color palette.

    Dark cyber-security theme with OLED-friendly background
    and neon accent colors.
    """

    # Background colors
    bg_primary: str = "#020617"      # Deep black (OLED friendly)
    bg_card: str = "#0F172A"          # Dark blue-gray
    bg_hover: str = "#1E293B"         # Lighter blue-gray
    bg_input: str = "#020617"         # Input background

    # Text colors
    text_primary: str = "#F8FAFC"     # High contrast white
    text_secondary: str = "#94A3B8"   # Gray text
    text_muted: str = "#64748B"       # Muted gray
    text_inverse: str = "#020617"     # Inverted for light bg

    # Border colors - converted from rgba to hex for dark theme
    border_default: str = "#1A202C"      # Very dark gray for subtle borders
    border_focus: str = "#004D14"       # Dim green for focus
    border_muted: str = "#12151C"       # Even more muted border

    # Shadow colors (for documentation only - not used in CTk)
    shadow_sm: str = "0 2px 8px rgba(0,0,0,0.4)"
    shadow_md: str = "0 4px 16px rgba(0,0,0,0.5)"
    shadow_lg: str = "0 8px 32px rgba(0,0,0,0.6)"
    shadow_neon: str = "0 0 12px rgba(0,255,65,0.5), 0 0 24px rgba(0,255,65,0.2)"


@dataclass(frozen=True)
class NeonColors:
    """Neon accent colors for cyber-security theme.

    Medium intensity glow for visual appeal without being overwhelming.
    """

    # Primary neon (matrix green for success/normal)
    neon_green: str = "#00FF41"
    neon_green_dim: str = "#004D14"      # Dim version of green
    neon_green_glow: str = "0 0 12px rgba(0,255,65,0.5), 0 0 24px rgba(0,255,65,0.2)"

    # Alert neon (red for danger/error)
    neon_red: str = "#FF3333"
    neon_red_dim: str = "#4D1414"        # Dim version of red
    neon_red_glow: str = "0 0 12px rgba(255,51,51,0.5), 0 0 24px rgba(255,51,51,0.2)"

    # Secondary neon (cyan for info)
    neon_cyan: str = "#00D9FF"
    neon_cyan_dim: str = "#00414D"       # Dim version of cyan

    # Accent neon (yellow for warning)
    neon_yellow: str = "#FFD700"
    neon_yellow_dim: str = "#4D3D00"     # Dim version of yellow

    # Accent neon (orange for high severity)
    neon_orange: str = "#FF8C00"
    neon_orange_dim: str = "#4D2900"     # Dim version of orange


@dataclass(frozen=True)
class StatusColors:
    """Semantic status colors mapping.

    Colors are mapped to severity levels and operational states.
    """

    # Success states
    success: str = NeonColors.neon_green
    success_bg: str = NeonColors.neon_green_dim

    # Error states
    error: str = NeonColors.neon_red
    error_bg: str = NeonColors.neon_red_dim

    # Warning states
    warning: str = NeonColors.neon_yellow
    warning_bg: str = NeonColors.neon_yellow_dim

    # Info states
    info: str = NeonColors.neon_cyan
    info_bg: str = NeonColors.neon_cyan_dim

    # Alert severity levels
    critical: str = NeonColors.neon_red
    high: str = NeonColors.neon_orange
    medium: str = NeonColors.neon_yellow
    low: str = NeonColors.neon_green

    # Operational states
    active: str = NeonColors.neon_green
    inactive: str = "#64748B"
    disabled: str = "#475569"
    processing: str = NeonColors.neon_cyan


@dataclass(frozen=True)
class GlassConfig:
    """Glassmorphism effect configuration.

    Defines the visual parameters for the frosted glass effect
    used throughout the UI.
    """

    # Blur intensity (higher = more blur)
    blur_amount: int = 15

    # Glass transparency
    opacity: float = 0.15

    # Border settings
    border_width: int = 1
    border_color: str = "#1A202C"  # Very subtle border color
    border_radius: int = 16

    # Shadow (for documentation only)
    shadow: str = "0 8px 32px rgba(0,0,0,0.3)"

    # Background color (simulated glass effect)
    bg_color: str = "#091020"  # Dark semi-transparent blue-gray


class Colors:
    """Main color configuration class.

    Provides access to all color schemes used in the application.
    """

    THEME = ThemeColors()
    NEON = NeonColors()
    STATUS = StatusColors()
    GLASS = GlassConfig()

    # Protocol color mapping
    PROTOCOL_COLORS: Dict[str, str] = {
        "TCP": "#3B82F6",      # Blue
        "UDP": "#8B5CF6",      # Purple
        "HTTP": "#10B981",     # Green
        "HTTPS": "#059669",    # Dark Green
        "DNS": "#F59E0B",      # Amber
        "ICMP": "#EF4444",     # Red
        "FTP": "#EC4899",      # Pink
        "SSH": "#6366F1",      # Indigo
        "Other": "#64748B",    # Gray
    }

    # Chart colors
    CHART_PALETTE: Tuple[str, ...] = (
        "#00FF41",  # Neon Green
        "#00D9FF",  # Cyan
        "#FFD700",  # Yellow
        "#FF8C00",  # Orange
        "#FF3333",  # Red
        "#A855F7",  # Purple
        "#EC4899",  # Pink
        "#14B8A6",  # Teal
    )

    @classmethod
    def get_protocol_color(cls, protocol: str) -> str:
        """Get color for a specific protocol.

        Args:
            protocol: Protocol name (e.g., "TCP", "UDP")

        Returns:
            Hex color string for the protocol
        """
        return cls.PROTOCOL_COLORS.get(protocol.upper(), cls.PROTOCOL_COLORS["Other"])

    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Get color for alert severity level.

        Args:
            severity: Severity level (critical, high, medium, low)

        Returns:
            Hex color string for the severity
        """
        return getattr(cls.STATUS, severity.lower(), cls.STATUS.low)

    @classmethod
    def get_chart_color(cls, index: int) -> str:
        """Get color from chart palette.

        Args:
            index: Index in palette

        Returns:
            Hex color string
        """
        return cls.CHART_PALETTE[index % len(cls.CHART_PALETTE)]


__all__ = [
    "Colors",
    "ThemeColors",
    "NeonColors",
    "StatusColors",
    "GlassConfig",
]
