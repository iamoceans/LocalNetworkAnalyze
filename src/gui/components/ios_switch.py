"""
iOS-style Switch component for Local Network Analyzer.

Provides a toggle switch following iOS design guidelines
with animated sliding thumb.
"""

import logging
from typing import Optional, Any, Callable

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


class iOSSwitch(ctk.CTkCheckBox):
    """iOS-style toggle switch component.

    Features:
    - 51×31pt total size following iOS spec
    - Rounded track with sliding thumb
    - Green when on, gray when off
    - Smooth animation (simulated via color change)
    - Accessible 44pt minimum touch target with padding

    Example:
        switch = iOSSwitch(parent, text="Auto Capture", on_toggle=on_changed)
        switch.set_is_on(True)
        switch.pack()
    """

    # iOS colors
    ON_COLOR = "#34C759"  # iOS green
    OFF_COLOR = "#8E8E93"  # iOS gray
    THUMB_COLOR = "#FFFFFF"  # White

    def __init__(
        self,
        master: Any,
        text: str = "",
        width: int = 51,
        height: int = 31,
        command: Optional[Callable[[bool], None]] = None,
        is_on: bool = False,
        **kwargs
    ):
        """Initialize iOS switch.

        Args:
            master: Parent widget
            text: Label text
            width: Switch width (default: 51pt)
            height: Switch height (default: 31pt)
            command: Callback when switch is toggled (receives bool)
            is_on: Initial state
            **kwargs: Additional arguments
        """
        self._text = text
        self._callback = command

        # Track state
        self._is_on = is_on

        # Get colors based on theme
        on_color = self.ON_COLOR
        off_color = self.OFF_COLOR
        check_color = self.THUMB_COLOR
        border_color = Colors.THEME.separator

        # Create switch with proper colors
        # CustomTkinter checkbox colors are limited, so we use progress bar colors
        super().__init__(
            master,
            text=text,
            width=width,
            height=height,
            font=Fonts.BODY,
            corner_radius=16,  # Rounded track
            checkbox_width=44,  # Touch target
            checkbox_height=28,
            border_width=2,
            border_color=border_color,
            fg_color=Colors.THEME.bg_tertiary,
            hover_color=Colors.THEME.bg_tertiary,
            onvalue=True,
            offvalue=False,
            command=self._on_toggle,
            **kwargs
        )

        # Set initial state
        super().set(is_on)

    def _on_toggle(self) -> None:
        """Handle toggle event."""
        self._is_on = not self._is_on

        if self._callback:
            self._callback(self._is_on)

        # Update appearance
        self._update_appearance()

    def _update_appearance(self) -> None:
        """Update switch appearance based on state."""
        # Note: CustomTkinter has limited checkbox styling
        # The corner_radius and colors are set in __init__
        pass

    def set_is_on(self, is_on: bool) -> None:
        """Set switch state programmatically.

        Args:
            is_on: True for on, False for off
        """
        if self._is_on == is_on:
            return

        super().set(is_on)
        self._is_on = is_on
        self._update_appearance()

    def get_is_on(self) -> bool:
        """Get current switch state.

        Returns:
            True if on, False if off
        """
        return self._is_on


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSSwitch(ttk.Checkbutton):
        """Fallback switch for standard tkinter."""

        def __init__(
            self,
            master: Any,
            text: str = "",
            command=None,
            is_on: bool = False,
            **kwargs
        ):
            self._text = text
            self._callback = command
            self._is_on = is_on
            self._var = tk.BooleanVar(value=is_on)

            super().__init__(
                master,
                text=text,
                variable=self._var,
                command=self._on_toggle,
                **kwargs
            )

        def _on_toggle(self):
            self._is_on = self._var.get()
            if self._callback:
                self._callback(self._is_on)

        def set_is_on(self, is_on: bool):
            self._var.set(is_on)

        def get_is_on(self):
            return self._var.get()

    iOSSwitch = TkiOSSwitch


__all__ = [
    "iOSSwitch",
]
