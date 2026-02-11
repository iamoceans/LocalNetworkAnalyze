"""
Glassmorphism frame component for Local Network Analyzer.

Provides a frosted glass effect with configurable blur,
transparency, and subtle borders.
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

from src.gui.theme.colors import Colors, GlassConfig


class GlassFrame(ctk.CTkFrame):
    """A frame with glassmorphism visual effect.

    Features:
    - Semi-transparent background
    - Subtle border
    - Rounded corners
    - Configurable blur effect (simulated via transparency)
    - Optional neon glow

    Example:
        frame = GlassFrame(parent, glow="green")
        frame.pack(fill="both", expand=True)
    """

    def __init__(
        self,
        master: Any,
        width: int = 200,
        height: int = 200,
        corner_radius: Optional[int] = None,
        border_width: Optional[int] = None,
        bg_color: Optional[str] = None,
        fg_color: Optional[str] = None,
        glow: str = "none",  # none, green, red, cyan, yellow, orange
        hover: bool = False,
        **kwargs
    ):
        """Initialize glass frame.

        Args:
            master: Parent widget
            width: Frame width
            height: Frame height
            corner_radius: Border radius (defaults to theme)
            border_width: Border width (defaults to theme)
            bg_color: Background color (defaults to transparent)
            fg_color: Foreground color (auto-generated glass effect)
            glow: Glow effect (none, green, red, cyan, yellow, orange)
            hover: Enable hover effect
            **kwargs: Additional arguments passed to CTkFrame
        """
        self._glow = glow
        self._hover_enabled = hover
        self._original_fg_color = None
        self._border_color = "#1A202C"

        # Set defaults from theme
        if corner_radius is None:
            corner_radius = Colors.GLASS.border_radius
        if border_width is None:
            border_width = Colors.GLASS.border_width
        if bg_color is None:
            bg_color = "transparent"
        if fg_color is None:
            fg_color = self._get_glass_color()

        self._original_fg_color = fg_color

        super().__init__(
            master,
            width=width,
            height=height,
            corner_radius=corner_radius,
            border_width=border_width,
            bg_color=bg_color,
            fg_color=fg_color,
            **kwargs
        )

        # Apply border color
        self._configure_border()

        # Apply hover effect if enabled
        if hover:
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)

    def _get_glass_color(self) -> str:
        """Get glass effect foreground color.

        Returns:
            Color string for glass effect
        """
        return Colors.GLASS.bg_color

    def _configure_border(self) -> None:
        """Configure the border color based on glow setting."""
        # Note: Border colors with glow are not directly applied in CustomTkinter
        # as it doesn't support dynamic border coloring. The glow effect
        # is simulated through the overall design theme.
        if self._glow == "none":
            border_color = Colors.GLASS.border_color
        elif self._glow == "green":
            border_color = Colors.NEON.neon_green_dim
        elif self._glow == "red":
            border_color = Colors.NEON.neon_red_dim
        elif self._glow == "cyan":
            border_color = Colors.NEON.neon_cyan_dim
        elif self._glow == "yellow":
            border_color = Colors.NEON.neon_yellow_dim
        elif self._glow == "orange":
            border_color = Colors.NEON.neon_orange_dim
        else:
            border_color = Colors.GLASS.border_color

        # For CustomTkinter, border color is handled at initialization
        # and cannot be changed dynamically. The glow effect is visual only.
        try:
            # Store the border color for potential future use
            self._border_color = border_color
        except Exception as e:
            logger.debug(f"Failed to configure border color: {e}")

    def _on_enter(self, event) -> None:
        """Handle mouse enter for hover effect.

        Args:
            event: Mouse event
        """
        if self._hover_enabled and self._original_fg_color:
            # Lighten the glass effect
            lighter_color = self._adjust_brightness(self._original_fg_color, 0.1)
            self.configure(fg_color=lighter_color)

    def _on_leave(self, event) -> None:
        """Handle mouse leave for hover effect.

        Args:
            event: Mouse event
        """
        if self._hover_enabled and self._original_fg_color:
            self.configure(fg_color=self._original_fg_color)

    def _adjust_brightness(self, hex_color: str, factor: float) -> str:
        """Adjust brightness of a hex color.

        Args:
            hex_color: Hex color string (e.g., "#RRGGBB" or "rgba(...)")
            factor: Brightness adjustment factor (-1 to 1)

        Returns:
            Adjusted hex color string
        """
        # Handle rgba colors
        if hex_color.startswith("rgba"):
            return hex_color  # Can't easily adjust rgba

        # Handle hex colors
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

    def set_glow(self, glow: str) -> None:
        """Change the glow effect.

        Args:
            glow: Glow type (none, green, red, cyan, yellow, orange)
        """
        self._glow = glow
        self._configure_border()


class GlassLabel(ctk.CTkLabel):
    """A label with glassmorphism background.

    Provides a lightweight alternative to full glass frames
    for simple label elements.
    """

    def __init__(
        self,
        master: Any,
        text: str = "",
        corner_radius: Optional[int] = None,
        **kwargs
    ):
        """Initialize glass label.

        Args:
            master: Parent widget
            text: Label text
            corner_radius: Border radius
            **kwargs: Additional arguments passed to CTkLabel
        """
        if corner_radius is None:
            corner_radius = 8

        # Set glass-like colors
        fg_color = kwargs.pop("fg_color", Colors.GLASS.bg_color)
        text_color = kwargs.pop("text_color", Colors.THEME.text_primary)

        super().__init__(
            master,
            text=text,
            corner_radius=corner_radius,
            fg_color=fg_color,
            text_color=text_color,
            **kwargs
        )


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkGlassFrame(ttk.Frame):
        """Fallback glass frame for standard tkinter."""

        def __init__(
            self,
            master: Any,
            glow: str = "none",
            hover: bool = False,
            **kwargs
        ):
            style = ttk.Style()
            style.configure(
                "Glass.TFrame",
                background=Colors.THEME.bg_card,
                relief="flat",
                borderwidth=1,
            )
            super().__init__(master, style="Glass.TFrame", **kwargs)
            self._glow = glow
            self._hover_enabled = hover

    GlassFrame = TkGlassFrame
    GlassLabel = ttk.Label


__all__ = [
    "GlassFrame",
    "GlassLabel",
]
