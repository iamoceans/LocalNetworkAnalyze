"""
Typography configuration for Local Network Analyzer UI.

Implements iOS-style SF Pro font hierarchy following
Apple's Human Interface Guidelines.
"""

from dataclasses import dataclass
from typing import Tuple


class iOSFontFamily:
    """Font family names and configurations.

    Uses SF Pro (San Francisco) for authentic iOS appearance
    with fallback to system fonts for cross-platform support.
    """

    # Primary fonts (SF Pro)
    heading: str = "SF Pro Display"
    body: str = "SF Pro Text"
    mono: str = "SF Mono"

    # Fallback families by platform
    macos_fallback: str = "-apple-system, BlinkMacSystemFont"
    windows_fallback: str = "Segoe UI"
    linux_fallback: str = "Ubuntu"

    # Generic fallback chain (closest to SF Pro appearance)
    fallback: str = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    sans_fallback: str = "SF Pro Text, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    mono_fallback: str = "SF Mono, Consolas, Monaco, 'Courier New', monospace"


@dataclass(frozen=True)
class iOSFontSize:
    """Font size definitions following iOS typography scale.

    Based on Apple's Human Interface Guidelines for
    consistent visual hierarchy.
    """

    # Large titles (SF Pro Display)
    large_title: int = 34       # Hero content, special displays
    title1: int = 28           # Navigation titles, large headers
    title2: int = 22           # Modal titles, form headers

    # Headlines and body (SF Pro Text)
    title3: int = 20           # Semibold for emphasis
    headline: int = 17          # Semibold for important text
    body: int = 17             # Regular for standard content
    callout: int = 16           # Regular for secondary content
    subheadline: int = 15       # Regular for supporting text
    footnote: int = 13          # Regular for captions
    caption1: int = 12         # Regular for secondary captions
    caption2: int = 11         # Regular for tertiary captions

    # Legacy/compatibility aliases
    h1: int = 28             # Main titles
    h2: int = 22             # Section titles
    h3: int = 20             # Subsection titles
    h4: int = 17             # Card titles, body emphasis
    h5: int = 15             # Secondary text
    h6: int = 13             # Caption text

    # UI element sizes
    button: int = 17           # Button text (headline)
    input: int = 17            # Input fields (body)
    label: int = 13            # Form labels (footnote)
    stat_large: int = 28        # Large statistics
    stat_medium: int = 22       # Medium statistics
    stat_small: int = 17        # Small statistics
    code: int = 13             # Monospace code
    nav: int = 17              # Navigation text


@dataclass(frozen=True)
class iOSFontWeight:
    """Font weight definitions.

    iOS uses semantic weight names. CustomTkinter supports
    limited weights, so we map appropriately.
    """

    # iOS weights (SF Pro)
    ultralight: str = "Ultralight"
    thin: str = "Thin"
    light: str = "Light"
    regular: str = "Regular"
    medium: str = "Medium"
    semibold: str = "Semibold"
    bold: str = "Bold"
    heavy: str = "Heavy"
    black: str = "Black"

    # CustomTkinter compatible weights
    ctK_normal: str = "normal"
    ctK_bold: str = "bold"
    ctK_italic: str = "italic"
    ctK_bold_italic: str = "bold italic"


@dataclass(frozen=True)
class iOSFontLineHeight:
    """Line height definitions.

    Multipliers relative to font size for iOS-style
    comfortable reading experience.
    """

    tight: float = 1.2      # Compact UI
    normal: float = 1.4      # Standard text
    relaxed: float = 1.5      # Comfortable reading


class Fonts:
    """Main font configuration class.

    Provides access to all typography settings and pre-configured
    font tuples for CustomTkinter.
    """

    FAMILY = iOSFontFamily()
    SIZE = iOSFontSize()
    WEIGHT = iOSFontWeight()
    LINE_HEIGHT = iOSFontLineHeight()

    # Pre-configured font tuples for CustomTkinter
    # Format: (family, size, weight)

    # Large titles (SF Pro Display)
    LARGE_TITLE = (iOSFontFamily.heading, iOSFontSize.large_title, iOSFontWeight.ctK_bold)
    TITLE1 = (iOSFontFamily.heading, iOSFontSize.title1, iOSFontWeight.ctK_bold)

    # Titles (SF Pro Display or Text)
    TITLE2 = (iOSFontFamily.heading, iOSFontSize.title2, iOSFontWeight.ctK_bold)
    TITLE3 = (iOSFontFamily.body, iOSFontSize.title3, iOSFontWeight.ctK_bold)

    # Body text (SF Pro Text)
    HEADLINE = (iOSFontFamily.body, iOSFontSize.headline, iOSFontWeight.ctK_bold)
    BODY = (iOSFontFamily.body, iOSFontSize.body, iOSFontWeight.ctK_normal)
    BODY_EMPHASIZED = (iOSFontFamily.body, iOSFontSize.body, iOSFontWeight.ctK_bold)
    CALLOUT = (iOSFontFamily.body, iOSFontSize.callout, iOSFontWeight.ctK_normal)
    SUBHEADLINE = (iOSFontFamily.body, iOSFontSize.subheadline, iOSFontWeight.ctK_normal)
    FOOTNOTE = (iOSFontFamily.body, iOSFontSize.footnote, iOSFontWeight.ctK_normal)
    CAPTION1 = (iOSFontFamily.body, iOSFontSize.caption1, iOSFontWeight.ctK_normal)
    CAPTION2 = (iOSFontFamily.body, iOSFontSize.caption2, iOSFontWeight.ctK_normal)

    # Legacy aliases
    H1 = (iOSFontFamily.heading, iOSFontSize.h1, iOSFontWeight.ctK_bold)
    H2 = (iOSFontFamily.heading, iOSFontSize.h2, iOSFontWeight.ctK_bold)
    H3 = (iOSFontFamily.heading, iOSFontSize.h3, iOSFontWeight.ctK_bold)
    H4 = (iOSFontFamily.body, iOSFontSize.h4, iOSFontWeight.ctK_bold)

    # UI Elements
    BUTTON = (iOSFontFamily.body, iOSFontSize.button, iOSFontWeight.ctK_bold)
    INPUT = (iOSFontFamily.body, iOSFontSize.input, iOSFontWeight.ctK_normal)
    LABEL = (iOSFontFamily.body, iOSFontSize.label, iOSFontWeight.ctK_normal)

    # Statistics display
    STAT_LARGE = (iOSFontFamily.body, iOSFontSize.stat_large, iOSFontWeight.ctK_bold)
    STAT_MEDIUM = (iOSFontFamily.body, iOSFontSize.stat_medium, iOSFontWeight.ctK_bold)
    STAT_SMALL = (iOSFontFamily.body, iOSFontSize.stat_small, iOSFontWeight.ctK_bold)

    # Code
    CODE = (iOSFontFamily.mono, iOSFontSize.code, iOSFontWeight.ctK_normal)
    CODE_BLOCK = (iOSFontFamily.mono, 12, iOSFontWeight.ctK_normal)

    @classmethod
    def get_font(cls, size: int = 17, weight: str = "normal", family: str = None) -> Tuple:
        """Get a custom font tuple.

        Args:
            size: Font size in points
            weight: Font weight ("normal", "bold", "semibold")
            family: Font family name (defaults to body font)

        Returns:
            Font tuple for CustomTkinter: (family, size, weight)
        """
        if family is None:
            family = cls.FAMILY.body

        # Map weight to CTk-compatible values
        weight_map = {
            "normal": cls.WEIGHT.ctK_normal,
            "regular": cls.WEIGHT.ctK_normal,
            "semibold": cls.WEIGHT.ctK_bold,
            "bold": cls.WEIGHT.ctK_bold,
        }
        ctK_weight = weight_map.get(weight.lower(), cls.WEIGHT.ctK_normal)

        return (family, size, ctK_weight)

    @classmethod
    def get_heading(cls, level: int = 1) -> Tuple:
        """Get heading font by level.

        Args:
            level: Heading level (1-3)

        Returns:
            Font tuple for heading
        """
        heading_map = {
            1: cls.TITLE1,
            2: cls.TITLE2,
            3: cls.TITLE3,
        }
        return heading_map.get(level, cls.TITLE3)

    @classmethod
    def get_stat_font(cls, size: str = "medium") -> Tuple:
        """Get statistics display font.

        Args:
            size: Size category (large, medium, small)

        Returns:
            Font tuple for stat display
        """
        stat_map = {
            "large": cls.STAT_LARGE,
            "medium": cls.STAT_MEDIUM,
            "small": cls.STAT_SMALL,
        }
        return stat_map.get(size, cls.STAT_MEDIUM)

    @classmethod
    def get_system_font(cls, style: str = "body") -> str:
        """Get system font string for CSS/HTML.

        Args:
            style: Font style (heading, body, mono)

        Returns:
            System font string
        """
        if style == "mono":
            return cls.FAMILY.mono_fallback
        elif style == "heading":
            return cls.FAMILY.fallback
        return cls.FAMILY.sans_fallback


class Typography:
    """Typography utilities and configurations.

    Provides helper methods and standard typography
    settings for iOS-style interface.
    """

    # Font configurations for different UI elements
    NAVIGATION = Fonts.BUTTON
    STATUS_BAR = Fonts.CAPTION1
    CARD_TITLE = Fonts.H4
    CARD_VALUE = Fonts.STAT_MEDIUM
    CARD_LABEL = Fonts.SUBHEADLINE

    # Text alignment
    ALIGN_LEFT = "w"
    ALIGN_CENTER = "center"
    ALIGN_RIGHT = "e"

    # Text wrapping
    WRAP_WORD = "word"
    WRAP_CHAR = "char"
    WRAP_NONE = "none"


__all__ = [
    "Fonts",
    "iOSFontFamily",
    "iOSFontSize",
    "iOSFontWeight",
    "iOSFontLineHeight",
    "Typography",
]
