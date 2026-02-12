"""
iOS-style Modal component for Local Network Analyzer.

Provides modal presentations following iOS design guidelines
with sheet style and centered modal styles.
"""

import logging
from typing import Optional, Any, List, Callable
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


class iOSModalStyle(Enum):
    """iOS modal presentation styles."""

    SHEET = "sheet"         # Bottom sheet (iOS default for most forms)
    CENTER = "center"       # Centered modal (alerts, confirmations)
    FULL = "full"          # Full screen modal


class iOSModal(ctk.CTkToplevel):
    """iOS-style modal presentation.

    Features:
    - Sheet style (slides from bottom) or centered modal
    - 12-14pt corner radius
    - Dimmed background overlay
    - Swipe to dismiss (simulated with close button)
    - Support for title, message, and custom content
    - Action buttons at bottom

    Example:
        modal = iOSModal(parent, style="sheet", title="Confirm Action")
        modal.add_action("Cancel", "cancel")
        modal.add_action("Confirm", "confirm", primary=True)
        modal.show()
    """

    def __init__(
        self,
        master: Any,
        title: str = "",
        message: str = "",
        style: str = "center",
        width: int = 400,
        height: Optional[int] = None,
        on_dismiss: Optional[Callable[[], None]] = None,
        **kwargs
    ):
        """Initialize iOS modal.

        Args:
            master: Parent window
            title: Modal title
            message: Optional message/body text
            style: Presentation style (sheet, center, full)
            width: Modal width
            height: Modal height (auto if None)
            on_dismiss: Callback when modal is dismissed
            **kwargs: Additional arguments
        """
        self._title = title
        self._message = message
        self._style = style
        self._on_dismiss = on_dismiss
        self._actions: List[dict] = []
        self._action_widgets: List[Any] = []
        self._is_visible = False

        # Get dimensions based on style
        if height is None:
            height = 300 if style == iOSModalStyle.CENTER else 400

        # Background colors
        bg_color = Colors.THEME.bg_card if ThemeMode.is_dark() else Colors.THEME.light_bg_card
        title_color = Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary

        # Create toplevel
        super().__init__(
            fg_color=bg_color,
            corner_radius=iOSShapes.corner_xlarge,
            border_width=1,
            border_color=Colors.THEME.separator,
            **kwargs
        )

        # Set size
        self.geometry(f"{width}x{height}")

        # Make modal stay on top
        self.attributes('-topmost', True)
        self.grab_set()

        # Build content
        self._build_content()

    def _build_content(self) -> None:
        """Build modal content."""
        # Main container
        container = ctk.CTkFrame(self, fg_color=Colors.get_card_color())
        container.pack(fill="both", expand=True, padx=iOSSpacing.lg, pady=iOSSpacing.lg)

        # Title
        if self._title:
            title = ctk.CTkLabel(
                container,
                text=self._title,
                font=Fonts.TITLE3,
                text_color=Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary,
            )
            title.pack(pady=(0, iOSSpacing.md))

        # Message
        if self._message:
            msg = ctk.CTkLabel(
                container,
                text=self._message,
                font=Fonts.BODY,
                text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
                wraplength=350,
            )
            msg.pack(pady=iOSSpacing.md)

        # Action buttons container (will be added if actions are added)
        self._action_container = ctk.CTkFrame(container, fg_color=Colors.get_card_color())
        self._action_container.pack(side="bottom", fill="x", pady=(iOSSpacing.xl, 0))

    def add_action(
        self,
        text: str,
        key: str,
        primary: bool = False,
        destructive: bool = False,
        callback: Optional[Callable[[], None]] = None,
    ) -> None:
        """Add an action button to the modal.

        Args:
            text: Button text
            key: Unique identifier for this action
            primary: Whether this is the primary action (bold, blue)
            destructive: Whether this is a destructive action (red)
            callback: Button callback
        """
        action = {
            "text": text,
            "key": key,
            "primary": primary,
            "destructive": destructive,
            "callback": callback,
        }
        self._actions.append(action)

        # Create button widget
        self._create_action_button(action)

    def _create_action_button(self, action: dict) -> None:
        """Create widget for an action button.

        Args:
            action: Action dict
        """
        # Determine colors
        if action.get("destructive"):
            fg_color = Colors.THEME.error
            text_color = Colors.THEME.error_bg
        elif action.get("primary"):
            fg_color = Colors.THEME.system_blue
            text_color = Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary
        else:
            fg_color = Colors.THEME.bg_secondary if ThemeMode.is_dark() else Colors.THEME.light_bg_secondary
            text_color = Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary

        # Create button
        btn = ctk.CTkButton(
            self._action_container,
            text=action["text"],
            font=Fonts.BUTTON if action.get("primary") else Fonts.BODY,
            fg_color=fg_color,
            hover_color=fg_color,
            text_color=text_color,
            height=44,
            corner_radius=iOSShapes.corner_medium,
            border_width=0,
            command=lambda: self._on_action(action["key"]),
        )
        btn.pack(side="left", expand=True, padx=iOSSpacing.xs)

        self._action_widgets.append(btn)

    def _on_action(self, key: str) -> None:
        """Handle action button click.

        Args:
            key: Action key
        """
        # Find action
        action = next((a for a in self._actions if a["key"] == key), None)
        if action and action.get("callback"):
            action["callback"]()

        # Dismiss modal
        self.dismiss()

    def show(self) -> None:
        """Show the modal."""
        if self._is_visible:
            return

        self._is_visible = True
        self.deiconify()

    def dismiss(self) -> None:
        """Dismiss the modal."""
        if not self._is_visible:
            return

        self._is_visible = False
        self.grab_release()
        self.withdraw()

        # Call dismiss callback
        if self._on_dismiss:
            self._on_dismiss()

    def is_visible(self) -> bool:
        """Check if modal is currently visible.

        Returns:
            True if visible, False otherwise
        """
        return self._is_visible


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSModal(tk.Toplevel):
        """Fallback modal for standard tkinter."""

        def __init__(self, master: Any, title: str = "", style: str = "center", **kwargs):
            super().__init__(master, **kwargs)
            self._title = title
            self._style = style
            self._actions = []
            self._is_visible = False

            # Configure window
            self.title(title)
            self.geometry("400x300")
            self.transient(master)
            self.grab_set()

        def add_action(self, text: str, key: str, primary=False, destructive=False, callback=None):
            action = {"text": text, "key": key, "primary": primary, "destructive": destructive, "callback": callback}
            self._actions.append(action)

            # Create button
            btn = ttk.Button(self, text=text, command=lambda: self._on_action(key))
            btn.pack(side="left", padx=5, pady=5)
            self._action_widgets.append(btn)

        def _on_action(self, key: str):
            action = next((a for a in self._actions if a["key"] == key), None)
            if action and action.get("callback"):
                action["callback"]()
            self.destroy()

        def show(self):
            if not self._is_visible:
                self._is_visible = True
                self.deiconify()

        def dismiss(self):
            if self._is_visible:
                self._is_visible = False
                self.grab_release()
                self.withdraw()

        def is_visible(self):
            return self._is_visible

    iOSModal = TkiOSModal


__all__ = [
    "iOSModal",
    "iOSModalStyle",
]
