"""
Neon button component for Local Network Analyzer.

Provides buttons with glowing neon effects in various colors.
"""

import logging
from typing import Optional, Any, Callable, Dict, Tuple, List

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

from src.gui.theme.colors import Colors, NeonColors
from src.gui.theme.typography import Fonts


class NeonButton(ctk.CTkButton):
    """A button with neon glow effect.

    Features:
    - Medium intensity glow (not overwhelming)
    - Color options: green, red, cyan, yellow, orange
    - Hover animation
    - State-aware styling (normal, hover, pressed, disabled)
    - Optional icon support

    Example:
        btn = NeonButton(parent, text="Start", color="green", command=start_func)
        btn.pack()
    """

    # Color presets for different button types
    COLOR_PRESETS: Dict[str, Dict[str, Any]] = {
        "green": {
            "fg": (NeonColors.neon_green, "#00CC33"),
            "hover": (NeonColors.neon_green_dim, NeonColors.neon_green_dim),
            "text": (Colors.THEME.bg_primary, Colors.THEME.bg_primary),
            "glow": NeonColors.neon_green_glow,
        },
        "red": {
            "fg": (NeonColors.neon_red, "#CC2929"),
            "hover": (NeonColors.neon_red_dim, NeonColors.neon_red_dim),
            "text": (Colors.THEME.bg_primary, Colors.THEME.bg_primary),
            "glow": NeonColors.neon_red_glow,
        },
        "cyan": {
            "fg": (NeonColors.neon_cyan, "#00AECC"),
            "hover": (NeonColors.neon_cyan_dim, NeonColors.neon_cyan_dim),
            "text": (Colors.THEME.bg_primary, Colors.THEME.bg_primary),
            "glow": "0 0 12px rgba(0,217,255,0.5), 0 0 24px rgba(0,217,255,0.2)",
        },
        "yellow": {
            "fg": (NeonColors.neon_yellow, "#CCAC00"),
            "hover": (NeonColors.neon_yellow_dim, NeonColors.neon_yellow_dim),
            "text": (Colors.THEME.bg_primary, Colors.THEME.bg_primary),
            "glow": "0 0 12px rgba(255,215,0,0.5), 0 0 24px rgba(255,215,0,0.2)",
        },
        "orange": {
            "fg": (NeonColors.neon_orange, "#B37700"),
            "hover": (NeonColors.neon_orange_dim, NeonColors.neon_orange_dim),
            "text": (Colors.THEME.bg_primary, Colors.THEME.bg_primary),
            "glow": "0 0 12px rgba(255,140,0,0.5), 0 0 24px rgba(255,140,0,0.2)",
        },
        "gray": {
            "fg": (Colors.THEME.bg_hover, Colors.THEME.bg_card),
            "hover": (Colors.THEME.bg_card, Colors.THEME.bg_hover),
            "text": (Colors.THEME.text_primary, Colors.THEME.text_secondary),
            "glow": None,
        },
        "ghost": {
            "fg": ("transparent", "transparent"),
            "hover": (NeonColors.neon_green_dim, NeonColors.neon_green_dim),
            "text": (NeonColors.neon_green, NeonColors.neon_green),
            "glow": None,
        },
    }

    def __init__(
        self,
        master: Any,
        text: str = "",
        color: str = "green",
        width: int = 120,
        height: int = 40,
        icon: Optional[str] = None,
        corner_radius: Optional[int] = None,
        font: Optional[Tuple[str, int, int]] = None,
        command: Optional[Callable[..., None]] = None,
        **kwargs
    ):
        """Initialize neon button.

        Args:
            master: Parent widget
            text: Button text
            color: Color preset (green, red, cyan, yellow, orange, gray, ghost)
            width: Button width
            height: Button height
            icon: Optional icon/emoji to prepend to text
            corner_radius: Border radius (default: 8)
            font: Font tuple (default: theme button font)
            command: Click callback
            **kwargs: Additional arguments passed to CTkButton
        """
        self._color_preset = color
        self._icon = icon

        # Get font from theme if not specified
        if font is None:
            font = Fonts.BUTTON

        # Get corner radius
        if corner_radius is None:
            corner_radius = 8

        # Get color preset
        preset = self.COLOR_PRESETS.get(color, self.COLOR_PRESETS["green"])

        # Prepare text with icon
        display_text = text
        if icon and text:
            display_text = f"{icon} {text}"
        elif icon and not text:
            display_text = icon

        # Extract kwargs that CTkButton accepts
        ctk_kwargs = {}
        for key, value in kwargs.items():
            if key in ["state", "anchor", "compound"]:
                ctk_kwargs[key] = value

        super().__init__(
            master,
            text=display_text,
            width=width,
            height=height,
            corner_radius=corner_radius,
            font=font,
            fg_color=preset["fg"],
            hover_color=preset["hover"],
            text_color=preset["text"],
            command=command,
            border_width=0,
            **ctk_kwargs
        )

        # Store original colors for state changes
        self._original_fg_color = preset["fg"]
        self._original_text_color = preset["text"]
        self._glow_effect = preset.get("glow")

    def set_color(self, color: str) -> None:
        """Change the button color preset.

        Args:
            color: New color preset name
        """
        self._color_preset = color
        preset = self.COLOR_PRESETS.get(color, self.COLOR_PRESETS["green"])

        self.configure(
            fg_color=preset["fg"],
            hover_color=preset["hover"],
            text_color=preset["text"],
        )
        self._glow_effect = preset.get("glow")

    def set_icon(self, icon: Optional[str]) -> None:
        """Change or remove the button icon.

        Args:
            icon: New icon/emoji or None to remove
        """
        self._icon = icon
        current_text = self.cget("text")

        # Remove old icon if present
        for old_icon in [self._icon] if self._icon else []:
            if old_icon and current_text.startswith(old_icon):
                current_text = current_text[len(old_icon):].strip()
                break

        # Add new icon
        if icon:
            self.configure(text=f"{icon} {current_text}")
        else:
            self.configure(text=current_text)

    def pulse(self, active: bool = True) -> None:
        """Enable or disable pulse animation effect.

        Note: This is a placeholder for future animation support.
        Currently, CustomTkinter doesn't support complex animations.

        Args:
            active: Whether to pulse
        """
        # Animation support would require custom Canvas implementation
        # For now, this is a no-op but provides API compatibility
        pass


class NeonToggleButton(ctk.CTkButton):
    """A toggle button with neon glow effect.

    Similar to NeonButton but maintains on/off state
    with different colors for each state.
    """

    def __init__(
        self,
        master: Any,
        text: str = "",
        on_color: str = "green",
        off_color: str = "gray",
        width: int = 120,
        height: int = 40,
        command: Optional[Callable[..., None]] = None,
        **kwargs
    ):
        """Initialize neon toggle button.

        Args:
            master: Parent widget
            text: Button text
            on_color: Color when active
            off_color: Color when inactive
            width: Button width
            height: Button height
            command: Toggle callback
            **kwargs: Additional arguments
        """
        self._is_toggled = False
        self._on_color = on_color
        self._off_color = off_color

        # Get color presets
        on_preset = NeonButton.COLOR_PRESETS.get(on_color, NeonButton.COLOR_PRESETS["green"])
        off_preset = NeonButton.COLOR_PRESETS.get(off_color, NeonButton.COLOR_PRESETS["gray"])

        super().__init__(
            master,
            text=text,
            width=width,
            height=height,
            corner_radius=8,
            font=Fonts.BUTTON,
            fg_color=off_preset["fg"],
            hover_color=off_preset["hover"],
            text_color=off_preset["text"],
            command=lambda: self._toggle(command),
            border_width=0,
            **kwargs
        )

        self._on_fg = on_preset["fg"]
        self._off_fg = off_preset["fg"]
        self._on_hover = on_preset["hover"]
        self._off_hover = off_preset["hover"]
        self._on_text = on_preset["text"]
        self._off_text = off_preset["text"]

    def _toggle(self, user_command: Optional[Callable[..., None]]) -> None:
        """Toggle button state.

        Args:
            user_command: User-provided callback
        """
        self._is_toggled = not self._is_toggled

        if self._is_toggled:
            self.configure(
                fg_color=self._on_fg,
                hover_color=self._on_hover,
                text_color=self._on_text,
            )
        else:
            self.configure(
                fg_color=self._off_fg,
                hover_color=self._off_hover,
                text_color=self._off_text,
            )

        if user_command:
            user_command(self._is_toggled)

    @property
    def is_toggled(self) -> bool:
        """Get current toggle state.

        Returns:
            True if toggled on, False otherwise
        """
        return self._is_toggled

    def set_toggled(self, state: bool) -> None:
        """Set toggle state programmatically.

        Args:
            state: True for on, False for off
        """
        if self._is_toggled != state:
            self._toggle(None)


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkNeonButton(ttk.Button):
        """Fallback neon button for standard tkinter."""

        def __init__(
            self,
            master: Any,
            text: str = "",
            color: str = "green",
            command: Optional[Callable[..., None]] = None,
            **kwargs
        ):
            style = ttk.Style()

            # Map color presets to ttk styles
            color_map = {
                "green": "green",
                "red": "red",
                "gray": "gray",
            }
            style_name = color_map.get(color, "green") + ".TButton"

            super().__init__(
                master,
                text=text,
                style=style_name,
                command=command,
                **kwargs
            )

        def set_color(self, color: str) -> None:
            pass  # Not easily supported in ttk

    NeonButton = TkNeonButton
    NeonToggleButton = ttk.Button  # Use standard button


__all__ = [
    "NeonButton",
    "NeonToggleButton",
]
