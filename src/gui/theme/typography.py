"""
Typography configuration for the Local Network Analyzer UI.

Implements a technical font scheme using Fira Code for headings
and data display, and Fira Sans for body text.
"""

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class FontFamily:
    """Font family names and configurations.

    Uses Fira Code for a technical, code-focused aesthetic
    and Fira Sans for readable body text.
    """

    # Primary font families
    heading: str = "Fira Code"        # Headings and titles
    body: str = "Fira Sans"           # Body text and labels
    mono: str = "Fira Code"           # Monospace for code/data
    ui: str = "Fira Sans"             # UI elements

    # Fallback families
    fallback: str = "Consolas, Monaco, monospace"
    sans_fallback: str = "Segoe UI, Roboto, Helvetica, Arial, sans-serif"


@dataclass(frozen=True)
class FontSize:
    """Font size definitions in points.

    Sizes are optimized for readability at 1080p+ resolutions.
    """

    # Heading sizes
    h1: int = 32       # Main titles
    h2: int = 24       # Section titles
    h3: int = 20       # Subsection titles
    h4: int = 16       # Card titles

    # Body sizes
    body_large: int = 14   # Emphasized body text
    body: int = 12         # Standard body text
    body_small: int = 11   # Secondary text

    # UI sizes
    button: int = 14       # Button text
    input: int = 12        # Input fields
    label: int = 11        # Form labels

    # Display sizes
    stat_large: int = 32   # Large statistics
    stat_medium: int = 24  # Medium statistics
    stat_small: int = 18   # Small statistics

    # Code sizes
    code: int = 11         # Inline code
    code_block: int = 12   # Code blocks


@dataclass(frozen=True)
class FontWeight:
    """Font weight definitions.

    Uses string weights for Tkinter compatibility.
    Tkinter only supports: "normal", "bold", "italic", "bold italic"
    """

    normal: str = "normal"
    bold: str = "bold"
    italic: str = "italic"
    bold_italic: str = "bold italic"


@dataclass(frozen=True)
class FontLineHeight:
    """Line height definitions.

    Multipliers relative to font size.
    """

    tight: float = 1.0     # Compact
    normal: float = 1.25   # Standard text
    relaxed: float = 1.5   # Comfortable reading
    loose: float = 1.75    # Extra spacing


class Fonts:
    """Main font configuration class.

    Provides access to all typography settings used in the application.
    """

    FAMILY = FontFamily()
    SIZE = FontSize()
    WEIGHT = FontWeight()
    LINE_HEIGHT = FontLineHeight()

    # Pre-configured font tuples for CustomTkinter
    # Format: (family, size, weight)

    # Headings
    H1 = (FontFamily.heading, FontSize.h1, FontWeight.bold)
    H2 = (FontFamily.heading, FontSize.h2, FontWeight.bold)
    H3 = (FontFamily.heading, FontSize.h3, FontWeight.bold)
    H4 = (FontFamily.heading, FontSize.h4, FontWeight.bold)

    # Body text
    BODY_LARGE = (FontFamily.body, FontSize.body_large, FontWeight.normal)
    BODY = (FontFamily.body, FontSize.body, FontWeight.normal)
    BODY_SMALL = (FontFamily.body, FontSize.body_small, FontWeight.normal)

    # UI Elements
    BUTTON = (FontFamily.ui, FontSize.button, FontWeight.bold)
    INPUT = (FontFamily.ui, FontSize.input, FontWeight.normal)
    LABEL = (FontFamily.ui, FontSize.label, FontWeight.normal)

    # Statistics display
    STAT_LARGE = (FontFamily.mono, FontSize.stat_large, FontWeight.bold)
    STAT_MEDIUM = (FontFamily.mono, FontSize.stat_medium, FontWeight.bold)
    STAT_SMALL = (FontFamily.mono, FontSize.stat_small, FontWeight.bold)

    # Code
    CODE = (FontFamily.mono, FontSize.code, FontWeight.normal)
    CODE_BLOCK = (FontFamily.mono, FontSize.code_block, FontWeight.normal)

    @classmethod
    def get_font(cls, size: int = 12, weight: str = "normal", family: str = None) -> Tuple:
        """Get a custom font tuple.

        Args:
            size: Font size in points
            weight: Font weight ("normal", "bold", "italic")
            family: Font family name (defaults to body font)

        Returns:
            Font tuple for CustomTkinter: (family, size, weight)
        """
        if family is None:
            family = cls.FAMILY.body
        return (family, size, weight)

    @classmethod
    def get_heading(cls, level: int = 1) -> Tuple:
        """Get heading font by level.

        Args:
            level: Heading level (1-4)

        Returns:
            Font tuple for the heading
        """
        return {
            1: cls.H1,
            2: cls.H2,
            3: cls.H3,
            4: cls.H4,
        }.get(level, cls.H4)

    @classmethod
    def get_stat_font(cls, size: str = "medium") -> Tuple:
        """Get statistics display font.

        Args:
            size: Size category (large, medium, small)

        Returns:
            Font tuple for stat display
        """
        return {
            "large": cls.STAT_LARGE,
            "medium": cls.STAT_MEDIUM,
            "small": cls.STAT_SMALL,
        }.get(size, cls.STAT_MEDIUM)


class Typography:
    """Typography utilities and configurations.

    Provides helper methods for consistent typography
    throughout the application.
    """

    # Font configurations for different UI elements
    NAVIGATION = Fonts.BUTTON
    STATUS_BAR = Fonts.BODY_SMALL
    CARD_TITLE = Fonts.H4
    CARD_VALUE = Fonts.STAT_MEDIUM
    CARD_LABEL = Fonts.BODY_SMALL

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
    "FontFamily",
    "FontSize",
    "FontWeight",
    "FontLineHeight",
    "Typography",
]
