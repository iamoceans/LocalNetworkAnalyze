"""
iOS-style Tab Bar component for Local Network Analyzer.

Provides bottom navigation following iOS design guidelines
with icons, labels, and active state indicators.
"""

import logging
from typing import Optional, Any, Dict, List, Callable
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


class TabItem:
    """Represents a single tab in the TabBar.

    Contains icon, label, callback, and visual properties.
    """

    def __init__(
        self,
        name: str,
        icon: str,
        label: str,
        callback: Optional[Callable[[], None]] = None,
        badge: Optional[str] = None,
    ):
        """Initialize tab item.

        Args:
            name: Unique identifier for this tab
            icon: Icon/emoji to display
            label: Tab label text
            callback: Function to call when tab is selected
            badge: Optional badge text (e.g., notification count)
        """
        self.name = name
        self.icon = icon
        self.label = label
        self.callback = callback
        self.badge = badge


class iOSTabBar(ctk.CTkFrame):
    """iOS-style side tab bar navigation.

    Features:
    - 80pt width for vertical layout
    - 24×24pt icons
    - Active state with blue highlight
    - Optional badge support
    - Maximum 5 tabs
    - Frosted glass effect background
    - Vertical orientation for left sidebar

    Example:
        tabbar = iOSTabBar(parent)
        tabbar.add_tab("dashboard", "📊", "Dashboard", on_dashboard)
        tabbar.add_tab("capture", "📡", "Capture", on_capture)
        tabbar.pack(side="left", fill="y")
    """

    def __init__(
        self,
        master: Any,
        width: int = 80,
        corner_radius: int = 0,
        **kwargs
    ):
        """Initialize iOS tab bar.

        Args:
            master: Parent widget
            height: Tab bar height (default: 65pt)
            corner_radius: Corner radius (default: 0 for iOS style)
            **kwargs: Additional arguments passed to CTkFrame
        """
        self._tabs: List[TabItem] = []
        self._active_tab: Optional[str] = None
        self._tab_widgets: Dict[str, Any] = {}
        self._badge_labels: Dict[str, Any] = {}

        # Background color based on theme
        bg_color = Colors.THEME.bg_secondary if ThemeMode.is_dark() else Colors.THEME.light_bg_secondary
        border_color = Colors.THEME.separator

        super().__init__(
            master,
            width=width,
            corner_radius=corner_radius,
            fg_color=bg_color,
            border_width=1,
            border_color=border_color,
            **kwargs
        )

        self._build_layout()

    def _build_layout(self) -> None:
        """Build tab bar layout (vertical for sidebar)."""
        # Container for tab items - vertical layout
        self._tab_container = ctk.CTkFrame(self, fg_color=Colors.get_card_color())
        self._tab_container.pack(fill="both", expand=True, padx=8, pady=8)

    def add_tab(
        self,
        name: str,
        icon: str,
        label: str,
        callback: Optional[Callable[[], None]] = None,
        badge: Optional[str] = None,
    ) -> TabItem:
        """Add a tab to the tab bar.

        Args:
            name: Unique identifier for this tab
            icon: Icon/emoji to display
            label: Tab label text
            callback: Function to call when tab is selected
            badge: Optional badge text

        Returns:
            The created TabItem
        """
        if len(self._tabs) >= 5:
            logger.warning("iOS TabBar supports maximum 5 tabs")
            return None

        tab = TabItem(name=name, icon=icon, label=label, callback=callback, badge=badge)
        self._tabs.append(tab)

        # Create tab widget
        self._create_tab_widget(tab)

        return tab

    def _create_tab_widget(self, tab: TabItem) -> None:
        """Create widget for a single tab (vertical layout for sidebar).

        Args:
            tab: TabItem to create widget for
        """
        # Tab container
        tab_container = ctk.CTkFrame(
            self._tab_container,
            fg_color=Colors.get_bg_color(),
        )
        tab_container.pack(side="top", fill="x", pady=2)

        # Tab button (touch target: min 44×44pt)
        tab_button = ctk.CTkButton(
            tab_container,
            text="",
            width=64,
            height=60,
            fg_color=Colors.get_bg_color(),
            hover_color=Colors.THEME.bg_hover,
            text_color=Colors.get_bg_color(),
            border_width=0,
            corner_radius=12,
            command=lambda: self._select_tab(tab.name),
        )
        tab_button.pack(expand=True, padx=4)
        tab_button.pack_propagate(False)

        # Icon and label container
        content_frame = ctk.CTkFrame(tab_button, fg_color=Colors.get_card_color())
        content_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Icon
        icon_label = ctk.CTkLabel(
            content_frame,
            text=tab.icon,
            font=("Segoe UI Emoji", 24),
            text_color=self._get_tab_color(tab.name, active=False),
        )
        icon_label.pack(side="top", pady=(0, 4))

        # Label (below icon for vertical layout)
        label_font = ctk.CTkFont(size=9, weight="normal")
        text_label = ctk.CTkLabel(
            content_frame,
            text=tab.label,
            font=label_font,
            text_color=self._get_tab_color(tab.name, active=False),
        )
        text_label.pack(side="top", pady=(0, 0))

        # Bind click events to all widgets so clicks pass through to button
        click_callback = lambda e: self._select_tab(tab.name)
        content_frame.bind("<Button-1>", click_callback)
        icon_label.bind("<Button-1>", click_callback)
        text_label.bind("<Button-1>", click_callback)

        # Store references
        self._tab_widgets[tab.name] = {
            "container": tab_container,
            "button": tab_button,
            "icon": icon_label,
            "label": text_label,
        }

        # Initial active state
        if self._active_tab is None and len(self._tabs) == 1:
            self._active_tab = tab.name
            self._update_tab_appearance(tab.name, True)

        # Add badge if provided
        if tab.badge:
            self._add_badge(tab.name, tab.badge)

    def _add_badge(self, tab_name: str, badge_text: str) -> None:
        """Add notification badge to tab (top-right corner for vertical layout).

        Args:
            tab_name: Tab identifier
            badge_text: Badge text (usually number)
        """
        if tab_name not in self._tab_widgets:
            return

        widgets = self._tab_widgets[tab_name]
        icon = widgets["icon"]

        # Create badge
        badge = ctk.CTkLabel(
            icon,
            text=badge_text,
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary,
            fg_color=Colors.THEME.error,
            corner_radius=9,
            width=18,
            height=18,
        )
        badge.place(relx=1.0, rely=0.0, anchor="ne")

        self._badge_labels[tab_name] = badge

    def _get_tab_color(self, tab_name: str, active: bool) -> str:
        """Get color for tab icon/label.

        Args:
            tab_name: Tab identifier
            active: Whether tab is active

        Returns:
            Color string
        """
        if active:
            return Colors.THEME.system_blue
        return Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary

    def _select_tab(self, tab_name: str) -> None:
        """Handle tab selection.

        Args:
            tab_name: Name of selected tab
        """
        if self._active_tab == tab_name:
            return

        # Update old active tab
        if self._active_tab:
            self._update_tab_appearance(self._active_tab, False)

        # Set new active tab
        self._active_tab = tab_name
        self._update_tab_appearance(tab_name, True)

        # Call callback
        tab = next((t for t in self._tabs if t.name == tab_name), None)
        if tab and tab.callback:
            tab.callback()

    def _update_tab_appearance(self, tab_name: str, is_active: bool) -> None:
        """Update visual appearance of a tab.

        Args:
            tab_name: Tab identifier
            is_active: Whether tab is active
        """
        if tab_name not in self._tab_widgets:
            return

        widgets = self._tab_widgets[tab_name]
        color = self._get_tab_color(tab_name, is_active)

        # Update icon and label colors
        widgets["icon"].configure(text_color=color)
        widgets["label"].configure(text_color=color)

    def set_active_tab(self, tab_name: str) -> None:
        """Set active tab programmatically.

        Args:
            tab_name: Name of tab to make active
        """
        if tab_name not in [t.name for t in self._tabs]:
            logger.warning(f"Unknown tab: {tab_name}")
            return

        self._select_tab(tab_name)

    def get_active_tab(self) -> Optional[str]:
        """Get currently active tab name.

        Returns:
            Active tab name or None
        """
        return self._active_tab

    def set_badge(self, tab_name: str, badge: Optional[str]) -> None:
        """Update or remove badge for a tab.

        Args:
            tab_name: Tab identifier
            badge: New badge text (None to remove)
        """
        # Remove existing badge
        if tab_name in self._badge_labels:
            try:
                self._badge_labels[tab_name].destroy()
                del self._badge_labels[tab_name]
            except Exception:
                pass

        # Add new badge
        if badge:
            self._add_badge(tab_name, badge)

    def clear_badges(self) -> None:
        """Remove all badges."""
        for badge_label in self._badge_labels.values():
            try:
                badge_label.destroy()
            except Exception:
                pass
        self._badge_labels.clear()

    def get_tabs(self) -> List[TabItem]:
        """Get all tabs.

        Returns:
            List of TabItem objects
        """
        return self._tabs.copy()


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkTabBar(ttk.Frame):
        """Fallback tab bar for standard tkinter (vertical sidebar layout)."""

        def __init__(self, master: Any, width: int = 80, **kwargs):
            super().__init__(master, width=width, **kwargs)
            self._tabs = []
            self._active_tab = None

        def add_tab(self, name: str, icon: str, label: str, callback=None, badge=None):
            if len(self._tabs) >= 5:
                return

            tab = TabItem(name=name, icon=icon, label=label, callback=callback, badge=badge)
            self._tabs.append(tab)

            # Create button (vertical layout)
            btn = ttk.Button(
                self,
                text=f"{icon}\n{label}",
                command=lambda: self._select_tab(name),
            )
            btn.pack(side="top", fill="x", padx=5, pady=5)

            return tab

        def _select_tab(self, tab_name: str):
            if self._active_tab == tab_name:
                return

            self._active_tab = tab_name
            tab = next((t for t in self._tabs if t.name == tab_name), None)
            if tab and tab.callback:
                tab.callback()

        def set_active_tab(self, tab_name: str):
            if tab_name not in [t.name for t in self._tabs]:
                return
            self._select_tab(tab_name)

        def get_active_tab(self):
            return self._active_tab

        def set_badge(self, tab_name: str, badge=None):
            pass  # Not implemented in fallback

        def clear_badges(self):
            pass

        def get_tabs(self):
            return self._tabs.copy()

    iOSTabBar = TkTabBar


__all__ = [
    "TabItem",
    "iOSTabBar",
]
