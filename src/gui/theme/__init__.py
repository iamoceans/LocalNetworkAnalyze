"""
Theme system for Local Network Analyzer.

Provides color schemes, typography, and visual effects
for iOS-style UI design.
"""

from src.gui.theme.colors import (
    Colors,
    ThemeMode,
    ProtocolColors,
    ChartColors,
    iOSCardConfig,
    GlassConfig,
    iOSShapes,
    iOSSpacing,
)

from src.gui.theme.typography import (
    Fonts,
    iOSFontFamily,
    iOSFontSize,
    iOSFontWeight,
    Typography,
)

# Import iOS theme configuration (optional, if available)
try:
    from src.gui.theme.ios_theme import (
        iOSColors,
        iOSTypography,
        iOSShapes as iOS_iOSShapes,
        iOSSpacing as iOS_iOSSpacing,
        iOSFontFamilies,
        iOSTheme,
        ThemeMode as iOSThemeMode,
    )
    IOS_THEME_AVAILABLE = True
except ImportError:
    IOS_THEME_AVAILABLE = False


__all__ = [
    # Core theme classes
    "Colors",
    "ThemeMode",
    "ProtocolColors",
    "ChartColors",
    "iOSCardConfig",
    "GlassConfig",
    "iOSShapes",
    "iOSSpacing",

    # Legacy names
    "ThemeColors",
    "NeonColors",

    # Typography
    "Fonts",
    "iOSFontFamily",
    "iOSFontSize",
    "iOSFontWeight",
    "Typography",

    # iOS theme (optional)
    "iOSColors",
    "iOSTypography",
    "iOS_iOSShapes",
    "iOS_iOSSpacing",
    "iOSFontFamilies",
    "iOSTheme",
    "iOSThemeMode",
    "IOS_THEME_AVAILABLE",
]
