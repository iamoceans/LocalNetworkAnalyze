"""
iOS-style button component for Local Network Analyzer.

Provides buttons following iOS design guidelines with
proper corner radius, colors, and touch targets.
"""

import logging
from typing import Optional, Any, Callable
from enum import Enum

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

from src.gui.theme.colors import Colors, ThemeMode, iOSShapes, iOSSpacing
from src.gui.theme.typography import Fonts


class iOSButtonStyle(Enum):
    """iOS button style variants."""

    FILLED = "filled"       # Solid color background
    TINTED = "tinted"     # Light color background
    PLAIN = "plain"         # Text only, no background


class iOSButtonSize(Enum):
    """iOS button size variants."""

    LARGE = "large"         # 50pt height
    MEDIUM = "medium"       # 44pt height (standard iOS)
    SMALL = "small"         # 36pt height
    MINI = "mini"          # 28pt height


class iOSButton(ctk.CTkButton):
    """iOS-style button component.

    Features:
    - 44pt minimum touch target (medium)
    - 10pt corner radius (medium)
    - System blue or semantic colors
    - Proper font weight (semibold)
    - Filled, tinted, and plain variants
    - Disabled state support

    Example:
        btn = iOSButton(parent, text="Start", style="filled")
        btn.pack()
    """

    # Size configurations
    SIZE_CONFIG = {
        iOSButtonSize.LARGE: {"height": 50, "font": Fonts.BUTTON},
        iOSButtonSize.MEDIUM: {"height": 44, "font": Fonts.BUTTON},
        iOSButtonSize.SMALL: {"height": 36, "font": Fonts.CALLOUT},
        iOSButtonSize.MINI: {"height": 28, "font": Fonts.CAPTION1},
    }

    # Style configurations
    STYLE_COLORS = {
        iOSButtonStyle.FILLED: {
            "blue": {
                "fg": Colors.THEME.system_blue,
                "text": Colors.THEME.text_primary,
            },
            "green": {
                "fg": Colors.THEME.system_green,
                "text": Colors.THEME.text_primary,
            },
            "red": {
                "fg": Colors.THEME.system_red,
                "text": Colors.THEME.text_primary,
            },
            "gray": {
                "fg": Colors.THEME.system_gray,
                "text": Colors.THEME.text_primary,
            },
        },
        iOSButtonStyle.TINTED: {
            "blue": {
                "fg": Colors.THEME.info_bg,
                "text": Colors.THEME.info,
            },
            "green": {
                "fg": Colors.THEME.success_bg,
                "text": Colors.THEME.success,
            },
            "red": {
                "fg": Colors.THEME.error_bg,
                "text": Colors.THEME.error,
            },
        },
        iOSButtonStyle.PLAIN: {
            "blue": {
                "fg": Colors.THEME.bg_secondary,
                "text": Colors.THEME.system_blue,
            },
            "green": {
                "fg": Colors.THEME.bg_secondary,
                "text": Colors.THEME.system_green,
            },
            "red": {
                "fg": Colors.THEME.bg_secondary,
                "text": Colors.THEME.system_red,
            },
        },
    }

    def __init__(
        self,
        master: Any,
        text: str = "",
        style: str = "filled",
        color: str = "blue",
        size: str = "medium",
        width: Optional[int] = None,
        icon: Optional[str] = None,
        command: Optional[Callable[[], None]] = None,
        enabled: bool = True,
        corner_radius: Optional[int] = None,
        **kwargs
    ):
        """Initialize iOS button.

        Args:
            master: Parent widget
            text: Button text
            style: Button style (filled, tinted, plain)
            color: Button color (blue, green, red, gray)
            size: Button size (large, medium, small, mini)
            width: Button width (auto for medium/small/mini)
            icon: Optional icon/emoji to prepend
            command: Click callback
            enabled: Whether button is enabled
            corner_radius: Border radius (defaults to theme)
            **kwargs: Additional arguments passed to CTkButton
        """
        # Initialize attributes that CTkButton.destroy() expects
        # This prevents AttributeError if initialization fails midway
        self._font = None

        self._style = style
        self._color = color
        self._size = size
        self._icon = icon
        self._enabled = enabled

        # Get size config
        size_enum = iOSButtonSize(size)
        size_config = self.SIZE_CONFIG.get(size_enum, self.SIZE_CONFIG[iOSButtonSize.MEDIUM])

        # Get corner radius
        if corner_radius is None:
            corner_radius = iOSShapes.corner_medium

        # Get style colors
        style_enum = iOSButtonStyle(style)
        style_colors = self.STYLE_COLORS.get(style_enum, self.STYLE_COLORS[iOSButtonStyle.FILLED])
        color_config = style_colors.get(color, self.STYLE_COLORS[iOSButtonStyle.FILLED]["blue"])

        # Prepare text with icon
        display_text = text
        if icon and text:
            display_text = f"{icon} {text}"
        elif icon and not text:
            display_text = icon

        # Determine width
        if width is None:
            width = 120 if size_enum == iOSButtonSize.LARGE else (100 if size_enum == iOSButtonSize.MEDIUM else 80)

        super().__init__(
            master,
            text=display_text,
            width=width,
            height=size_config["height"],
            corner_radius=corner_radius,
            font=size_config["font"],
            fg_color=color_config["fg"] if enabled else Colors.THEME.disabled,
            hover_color=color_config["fg"] if enabled else Colors.THEME.disabled,
            text_color=color_config["text"] if enabled else Colors.THEME.inactive,
            state="normal" if enabled else "disabled",
            command=command if enabled else None,
            border_width=0,
            **kwargs
        )

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable button.

        Args:
            enabled: True to enable, False to disable
        """
        self._enabled = enabled

        style_enum = iOSButtonStyle(self._style)
        style_colors = self.STYLE_COLORS.get(style_enum, self.STYLE_COLORS[iOSButtonStyle.FILLED])
        color_config = style_colors.get(self._color, self.STYLE_COLORS[iOSButtonStyle.FILLED]["blue"])

        self.configure(
            fg_color=color_config["fg"] if enabled else Colors.THEME.disabled,
            hover_color=color_config["fg"] if enabled else Colors.THEME.disabled,
            text_color=color_config["text"] if enabled else Colors.THEME.inactive,
            state="normal" if enabled else "disabled",
        )

    def is_enabled(self) -> bool:
        """Check if button is enabled.

        Returns:
            True if enabled, False otherwise
        """
        return self._enabled

    def set_style(self, style: str, color: str = None) -> None:
        """Change button style.

        Args:
            style: New style (filled, tinted, plain)
            color: New color (blue, green, red, gray)
        """
        self._style = style
        if color:
            self._color = color

        self._update_colors()

    def _update_colors(self) -> None:
        """Update button colors based on current style and color."""
        style_enum = iOSButtonStyle(self._style)
        style_colors = self.STYLE_COLORS.get(style_enum, self.STYLE_COLORS[iOSButtonStyle.FILLED])
        color_config = style_colors.get(self._color, self.STYLE_COLORS[iOSButtonStyle.FILLED]["blue"])

        self.configure(
            fg_color=color_config["fg"] if self._enabled else Colors.THEME.disabled,
            hover_color=color_config["fg"] if self._enabled else Colors.THEME.disabled,
            text_color=color_config["text"] if self._enabled else Colors.THEME.inactive,
        )


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSButton(ttk.Button):
        """Fallback iOS button for standard tkinter."""

        def __init__(
            self,
            master: Any,
            text: str = "",
            style: str = "filled",
            color: str = "blue",
            command=None,
            **kwargs
        ):
            # Map styles to ttk
            style_map = {
                ("filled", "blue"): "iOS.TButton",
                ("filled", "red"): "iOS.Red.TButton",
                ("plain", "blue"): "iOS.Plain.TButton",
            }
            style_name = style_map.get((style, color), "iOS.TButton")

            super().__init__(master, text=text, style=style_name, command=command, **kwargs)

        def set_enabled(self, enabled: bool):
            self.configure(state="normal" if enabled else "disabled")

        def is_enabled(self) -> bool:
            return self.cget("state") == "normal"

    iOSButton = TkiOSButton


__all__ = [
    "iOSButton",
    "iOSButtonStyle",
    "iOSButtonSize",
]
