"""
iOS-style Progress component for Local Network Analyzer.

Provides progress indicators following iOS design guidelines
including activity indicators and progress bars.
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

from src.gui.theme.colors import Colors, ThemeMode, iOSShapes, iOSSpacing
from src.gui.theme.typography import Fonts


class iOSActivitySpinner(ctk.CTkFrame):
    """iOS-style activity spinner.

    Features:
    - 20×20pt rotating indicator (small)
    - 37×37pt rotating indicator (medium)
    - Gray spinner following iOS design
    - Simulated rotation (pulsing opacity)

    Example:
        spinner = iOSActivitySpinner(parent, size="medium")
        spinner.start()
        spinner.pack()
    """

    def __init__(
        self,
        master: Any,
        size: str = "medium",
        **kwargs
    ):
        """Initialize activity spinner.

        Args:
            master: Parent widget
            size: Spinner size (small, medium, large)
            **kwargs: Additional arguments
        """
        self._size = size
        self._is_animating = False

        # Size configurations
        size_config = {
            "small": (20, 2),
            "medium": (37, 3),
            "large": (50, 4),
        }
        self._spinner_size, self._line_width = size_config.get(size, size_config["medium"])

        super().__init__(
            master,
            width=self._spinner_size + self._line_width * 2,
            height=self._spinner_size + self._line_width * 2,
            corner_radius=0,
            fg_color=Colors.get_card_color(),
            border_width=0,
            **kwargs
        )

        # Create spinner
        self._spinner = ctk.CTkLabel(
            self,
            text="○",
            font=("", self._spinner_size),
            text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
        )
        self._spinner.place(relx=0.5, rely=0.5, anchor="center")

    def start(self) -> None:
        """Start spinner animation."""
        self._is_animating = True
        self._animate()

    def stop(self) -> None:
        """Stop spinner animation."""
        self._is_animating = False
        try:
            if hasattr(self, '_animation_id'):
                self.after_cancel(self._animation_id)
        except Exception:
            pass

    def _animate(self) -> None:
        """Animate spinner (simulated with pulsing)."""
        if not self._is_animating:
            return

        # Simulate rotation by changing opacity (text color brightness)
        states = [
            Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
            Colors.THEME.inactive,
        ]
        state = states[0] if not hasattr(self, '_anim_state') else getattr(self, '_anim_state', 0)
        next_state = states[1] if state == states[0] else states[0]

        self._spinner.configure(text_color=next_state)
        self._anim_state = state

        # Schedule next frame
        self._animation_id = self.after(500, self._animate)


class iOSProgressBar(ctk.CTkFrame):
    """iOS-style progress bar.

    Features:
    - 4pt height following iOS spec
    - Rounded track and fill
    - Blue fill color
    - Optional percentage label

    Example:
        bar = iOSProgressBar(parent, value=0.5)
        bar.pack()
        bar.set_value(0.75)  # Update to 75%
    """

    def __init__(
        self,
        master: Any,
        value: float = 0.0,
        height: int = 4,
        show_percentage: bool = False,
        **kwargs
    ):
        """Initialize progress bar.

        Args:
            master: Parent widget
            value: Initial value (0.0 to 1.0)
            height: Bar height (default: 4pt)
            show_percentage: Show percentage label
            **kwargs: Additional arguments
        """
        self._value = value
        self._show_percentage = show_percentage

        # Background colors
        track_color = Colors.THEME.bg_secondary if ThemeMode.is_dark() else Colors.THEME.light_bg_secondary

        super().__init__(
            master,
            height=height,
            corner_radius=2,
            fg_color=track_color,
            **kwargs
        )

        # Build layout
        self._build_layout()

    def _build_layout(self) -> None:
        """Build progress bar layout."""
        self._container = ctk.CTkFrame(self, fg_color=Colors.get_card_color())
        self._container.pack(fill="both", expand=True, padx=iOSSpacing.lg, pady=iOSSpacing.md)

    def _update_fill(self) -> None:
        """Update fill bar based on current value."""
        if not hasattr(self, '_fill_bar'):
            self._create_fill_bar()
            return

        # Calculate width based on value
        container_width = self._container.winfo_width()
        fill_width = int(container_width * self._value) - (iOSSpacing.lg * 2)

        self._fill_bar.configure(width=fill_width)

    def _create_fill_bar(self) -> None:
        """Create the fill bar widget."""
        self._fill_bar = ctk.CTkFrame(
            self._container,
            height=4,
            corner_radius=2,
            fg_color=Colors.THEME.system_blue,
        )
        self._fill_bar.pack(side="left", anchor="w")

        # Percentage label
        if self._show_percentage:
            self._percentage_label = ctk.CTkLabel(
                self._container,
                text=f"{int(self._value * 100)}%",
                font=Fonts.CAPTION1,
                text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
            )
            self._percentage_label.pack(side="right", padx=(iOSSpacing.sm, 0))

    def set_value(self, value: float) -> None:
        """Set progress value.

        Args:
            value: New value (0.0 to 1.0)
        """
        self._value = max(0.0, min(1.0, value))
        self._update_fill()

        # Update percentage label
        if self._show_percentage and hasattr(self, '_percentage_label'):
            self._percentage_label.configure(text=f"{int(self._value * 100)}%")

    def get_value(self) -> float:
        """Get current progress value.

        Returns:
            Current value (0.0 to 1.0)
        """
        return self._value


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSActivitySpinner(ttk.Label):
        """Fallback spinner for standard tkinter."""

        def __init__(self, master: Any, size: str = "medium", **kwargs):
            super().__init__(master, text="...", **kwargs)
            self._size = size

        def start(self):
            pass  # Animation not supported in fallback

        def stop(self):
            pass

    class TkiOSProgressBar(ttk.Progressbar):
        """Fallback progress bar for standard tkinter."""

        def __init__(self, master: Any, value=0.0, **kwargs):
            super().__init__(master, value=value, **kwargs)
            self._value = value

        def set_value(self, value: float):
            self._value = value
            self.configure(value=value)

        def get_value(self):
            return self._value

    iOSActivitySpinner = TkiOSActivitySpinner
    iOSProgressBar = TkiOSProgressBar


__all__ = [
    "iOSActivitySpinner",
    "iOSProgressBar",
]
