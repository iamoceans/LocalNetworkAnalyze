"""
iOS-style Card component for Local Network Analyzer.

Provides cards following iOS design guidelines with
proper corner radius, background colors, and subtle borders.
"""

import logging
from typing import Optional, Any

from src.core.logger import get_logger
logger = get_logger(__name__)

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

import tkinter as tk
from tkinter import ttk

from src.gui.theme.colors import Colors, ThemeMode, iOSShapes, iOSSpacing, iOSCardConfig
from src.gui.theme.typography import Fonts


class iOSCard(ctk.CTkFrame):
    """iOS-style card component.

    Features:
    - 12pt corner radius (iOS large corner)
    - Subtle border (0.5pt separator color)
    - Card background color
    - Optional hover effect

    Example:
        card = iOSCard(parent)
        content.pack()
        card.pack()
    """

    def __init__(
        self,
        master: Any,
        width: int = 200,
        height: int = 200,
        corner_radius: Optional[int] = None,
        border_width: Optional[int] = None,
        bg_color: Optional[str] = None,
        hover: bool = False,
        **kwargs
    ):
        """Initialize iOS card.

        Args:
            master: Parent widget
            width: Card width
            height: Card height
            corner_radius: Border radius (defaults to iOS spec)
            border_width: Border width (defaults to iOS spec)
            bg_color: Card background (auto from theme)
            hover: Enable hover effect
            **kwargs: Additional arguments passed to CTkFrame
        """
        self._hover_enabled = hover
        self._original_bg_color = None
        self._border_color = Colors.THEME.separator

        # Set defaults from iOS theme
        if corner_radius is None:
            corner_radius = iOSShapes.corner_large
        if border_width is None:
            border_width = 1
        if bg_color is None:
            bg_color = Colors.get_card_color()

        self._original_bg_color = bg_color

        super().__init__(
            master,
            width=width,
            height=height,
            corner_radius=corner_radius,
            border_width=border_width,
            border_color=self._border_color,
            fg_color=bg_color,
            **kwargs
        )

        # Apply hover effect if enabled
        if hover:
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)

    def _on_enter(self, event) -> None:
        """Handle mouse enter for hover effect.

        Args:
            event: Mouse event
        """
        if self._hover_enabled and self._original_bg_color:
            # Lighten for hover (simulated iOS lift effect)
            lighter_color = self._adjust_brightness(self._original_bg_color, 0.1)
            self.configure(fg_color=lighter_color)

    def _on_leave(self, event) -> None:
        """Handle mouse leave for hover effect.

        Args:
            event: Mouse event
        """
        if self._hover_enabled and self._original_bg_color:
            self.configure(fg_color=self._original_bg_color)

    def _adjust_brightness(self, hex_color: str, factor: float) -> str:
        """Adjust brightness of a hex color.

        Args:
            hex_color: Hex color string (e.g., "#RRGGBB")
            factor: Brightness adjustment factor (-1 to 1)

        Returns:
            Adjusted hex color string
        """
        if hex_color.startswith("#"):
            hex_color = hex_color[1:]

        if len(hex_color) != 6:
            return hex_color

        try:
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16)

            r = max(0, min(255, int(r * (1 + factor))))
            g = max(0, min(255, int(g * (1 + factor))))
            b = max(0, min(255, int(b * (1 + factor))))

            return f"#{r:02x}{g:02x}{b:02x}"
        except (ValueError, IndexError):
            return hex_color


class iOSLabel(ctk.CTkLabel):
    """iOS-styled label component.

    Provides labels with iOS colors and typography.
    """

    def __init__(
        self,
        master: Any,
        text: str = "",
        corner_radius: Optional[int] = None,
        fg_color: Optional[str] = None,
        text_color: Optional[str] = None,
        font: Optional[Any] = None,
        **kwargs
    ):
        """Initialize iOS label.

        Args:
            master: Parent widget
            text: Label text
            corner_radius: Border radius
            fg_color: Background color
            text_color: Text color
            font: Font tuple
            **kwargs: Additional arguments
        """
        # Set defaults from theme
        if corner_radius is None:
            corner_radius = iOSShapes.corner_small
        if fg_color is None:
            fg_color = Colors.get_card_color()
        if text_color is None:
            text_color = Colors.get_text_color()
        if font is None:
            font = Fonts.BODY

        super().__init__(
            master,
            text=text,
            corner_radius=corner_radius,
            fg_color=fg_color,
            text_color=text_color,
            font=font,
            **kwargs
        )


# Maintain old names for backward compatibility
GlassFrame = iOSCard
GlassLabel = iOSLabel


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSCard(ttk.Frame):
        """Fallback card for standard tkinter."""

        def __init__(
            self,
            master: Any,
            width: int = 200,
            height: int = 200,
            corner_radius: Optional[int] = None,
            border_width: Optional[int] = None,
            bg_color: Optional[str] = None,
            hover: bool = False,
            **kwargs
        ):
            style = ttk.Style()
            style.configure(
                "iOS.TFrame",
                background=bg_color or Colors.get_card_color(),
                relief="flat",
                borderwidth=border_width or 1,
            )
            super().__init__(master, style="iOS.TFrame", width=width, height=height, **kwargs)

            if hover:
                self.bind("<Enter>", self._on_enter)
                self.bind("<Leave>", self._on_leave)

        def _on_enter(self, event):
            # Hover effect not easily supported in ttk
            pass

        def _on_leave(self, event):
            pass

    class TkiOSLabel(ttk.Label):
        """Fallback label for standard tkinter."""

        def __init__(
            self,
            master: Any,
            text: str = "",
            corner_radius: Optional[int] = None,
            fg_color: Optional[str] = None,
            text_color: Optional[str] = None,
            font: Optional[Any] = None,
            **kwargs
        ):
            super().__init__(
                master,
                text=text,
                background=fg_color or Colors.get_card_color(),
                foreground=text_color or Colors.get_text_color(),
                font=font or Fonts.BODY,
                **kwargs
            )

    GlassFrame = TkiOSCard
    GlassLabel = TkiOSLabel


__all__ = [
    "iOSCard",
    "iOSLabel",
    "GlassFrame",  # Legacy alias
    "GlassLabel",  # Legacy alias
]
