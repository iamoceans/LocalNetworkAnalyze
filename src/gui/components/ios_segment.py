"""
iOS-style Segmented Control component for Local Network Analyzer.

Provides a segmented control following iOS design guidelines
for mutually exclusive options.
"""

import logging
from typing import Optional, Any, List, Callable

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


class iOSSegment(ctk.CTkFrame):
    """iOS-style segmented control.

    Features:
    - 32pt height following iOS spec
    - 8pt corner radius
    - Segmented appearance with separators
    - Active segment with blue highlight
    - Minimum 2 segments, recommended 2-4

    Example:
        segment = iOSSegment(parent)
        segment.add_option("day", "Day")
        segment.add_option("week", "Week")
        segment.add_option("month", "Month")
        segment.set_selected("week")
        segment.pack()
    """

    def __init__(
        self,
        master: Any,
        height: int = 32,
        corner_radius: int = 8,
        command: Optional[Callable[[str], None]] = None,
        **kwargs
    ):
        """Initialize iOS segmented control.

        Args:
            master: Parent widget
            height: Control height (default: 32pt)
            corner_radius: Corner radius (default: 8pt)
            command: Callback when selection changes (receives option key)
            **kwargs: Additional arguments passed to CTkFrame
        """
        self._segment_options: List[dict] = []
        self._selected_key: Optional[str] = None
        self._command = command
        self._segment_widgets: dict = {}

        # Background colors
        bg_color = Colors.THEME.bg_card if ThemeMode.is_dark() else Colors.THEME.light_bg_card
        border_color = Colors.THEME.border_default if ThemeMode.is_dark() else Colors.THEME.border_default

        super().__init__(
            master,
            height=height,
            corner_radius=corner_radius,
            fg_color=bg_color,
            border_width=1,
            border_color=border_color,
            **kwargs
        )

        self._build_layout()

    def _build_layout(self) -> None:
        """Build segmented control layout."""
        # Container for segments
        self._container = ctk.CTkFrame(self, fg_color=Colors.get_card_color())
        self._container.pack(fill="both", expand=True, padx=2, pady=2)

    def add_option(self, key: str, label: str, icon: Optional[str] = None) -> None:
        """Add an option to the segmented control.

        Args:
            key: Unique identifier for this option
            label: Display label
            icon: Optional icon/emoji
        """
        if len(self._segment_options) >= 5:
            logger.warning("iOS Segmented Control supports maximum 5 segments")
            return

        option = {"key": key, "label": label, "icon": icon}
        self._segment_options.append(option)

        # Create segment widget
        self._create_segment_widget(option)

    def clear(self) -> None:
        """Clear all options from the segmented control."""
        # Destroy all segment widgets
        for key, widget in list(self._segment_widgets.items()):
            try:
                widget.destroy()
            except Exception:
                pass
        self._segment_widgets.clear()

        # Clear options list
        self._segment_options.clear()
        self._selected_key = None

    def _create_segment_widget(self, option: dict) -> None:
        """Create widget for a single segment.

        Args:
            option: Option dict with key, label, icon
        """
        # Segment button
        is_selected = self._selected_key == option["key"]
        fg_color = Colors.THEME.system_blue if is_selected else Colors.THEME.bg_tertiary
        if ThemeMode.is_light():
            text_color = Colors.THEME.text_primary if is_selected else Colors.THEME.light_text_secondary
        else:
            text_color = Colors.THEME.text_primary if is_selected else Colors.THEME.text_secondary

        segment = ctk.CTkButton(
            self._container,
            text=option.get("icon", option["label"]),
            font=Fonts.CALLOUT,
            fg_color=fg_color,
            hover_color=Colors.THEME.bg_hover if not is_selected else Colors.THEME.system_blue,
            text_color=text_color,
            border_width=0,
            corner_radius=0,
            height=28,
            command=lambda: self._select_option(option["key"]),
        )
        segment.pack(side="left", expand=True, fill="both", padx=0)

        # Store reference
        self._segment_widgets[option["key"]] = segment

        # Add separator if not last
        if len(self._segment_options) > 1:
            separator = ctk.CTkLabel(
                self._container,
                text="|",
                font=("", 12),
                text_color=Colors.THEME.separator,
            )
            separator.pack(side="left", padx=(0, 4))

    def _select_option(self, key: str) -> None:
        """Handle option selection.

        Args:
            key: Selected option key
        """
        if self._selected_key == key:
            return

        # Update old selection
        if self._selected_key:
            self._update_segment_appearance(self._selected_key, False)

        # Set new selection
        self._selected_key = key
        self._update_segment_appearance(key, True)

        # Call command
        if self._command:
            self._command(key)

    def _update_segment_appearance(self, key: str, is_selected: bool) -> None:
        """Update visual appearance of a segment.

        Args:
            key: Option key
            is_selected: Whether this segment is selected
        """
        if key not in self._segment_widgets:
            return

        widget = self._segment_widgets[key]

        # Update colors
        if is_selected:
            widget.configure(
                fg_color=Colors.THEME.system_blue,
                text_color=Colors.THEME.text_primary,
            )
        else:
            widget.configure(
                fg_color=Colors.THEME.bg_tertiary,
                text_color=Colors.THEME.light_text_secondary if ThemeMode.is_light() else Colors.THEME.text_secondary,
            )

    def set_selected(self, key: str) -> None:
        """Set selected option programmatically.

        Args:
            key: Option key to select
        """
        if key not in [opt["key"] for opt in self._segment_options]:
            logger.warning(f"Unknown option key: {key}")
            return

        self._select_option(key)

    def get_selected(self) -> Optional[str]:
        """Get currently selected option key.

        Returns:
            Selected key or None
        """
        return self._selected_key

    def get_options(self) -> List[str]:
        """Get all option keys.

        Returns:
            List of option keys
        """
        return [opt["key"] for opt in self._segment_options]


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSSegment(ttk.Frame):
        """Fallback segmented control for standard tkinter."""

        def __init__(self, master: Any, command=None, **kwargs):
            super().__init__(master, **kwargs)
            self._segment_options = []
            self._selected_key = None
            self._command = command

        def add_option(self, key: str, label: str, icon=None):
            if len(self._segment_options) >= 5:
                return

            option = {"key": key, "label": label, "icon": icon}
            self._segment_options.append(option)

            # Create button
            var = tk.StringVar()
            btn = ttk.Radiobutton(
                self,
                text=label,
                variable=var,
                value=key,
                command=lambda: self._select_option(key),
            )
            btn.pack(side="left", padx=2)

            return None

        def _select_option(self, key: str):
            if self._selected_key == key:
                return

            self._selected_key = key
            if self._command:
                self._command(key)

        def set_selected(self, key: str):
            if key not in [opt["key"] for opt in self._segment_options]:
                return
            self._select_option(key)

        def get_selected(self):
            return self._selected_key

        def get_options(self):
            return [opt["key"] for opt in self._segment_options]

    iOSSegment = TkiOSSegment


__all__ = [
    "iOSSegment",
]
