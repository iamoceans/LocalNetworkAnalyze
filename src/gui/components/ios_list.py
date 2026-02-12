"""
iOS-style List component for Local Network Analyzer.

Provides a list view following iOS design guidelines
with proper separators, row height, and selection styling.
"""

import logging
from typing import Optional, Any, List, Dict, Callable, Tuple
from datetime import datetime

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


class iOSListItem:
    """Represents a single item in an iOS list view."""

    def __init__(
        self,
        title: str,
        subtitle: Optional[str] = None,
        value: Optional[str] = None,
        icon: Optional[str] = None,
        accessory: Optional[str] = None,  # chevron, switch, etc.
        data: Any = None,  # Arbitrary user data
    ):
        """Initialize list item.

        Args:
            title: Primary text
            subtitle: Optional secondary text
            value: Optional right-aligned value (e.g., date, count)
            icon: Optional icon/emoji
            accessory: Optional accessory indicator (">", switch, etc.)
            data: Arbitrary user data associated with item
        """
        self.title = title
        self.subtitle = subtitle
        self.value = value
        self.icon = icon
        self.accessory = accessory
        self.data = data


class iOSList(ctk.CTkScrollableFrame):
    """iOS-style list view component.

    Features:
    - 44pt row height following iOS spec
    - Thin separators between items
    - Optional section headers
    - Multi-line items with subtitle support
    - Tap to select callback
    - Accessory indicators (chevron, detail text, etc.)

    Example:
        list = iOSList(parent)
        list.add_item("Item 1", subtitle="Details", icon="📄")
        list.add_item("Item 2", value="Off", accessory=">")
        list.pack()
    """

    ROW_HEIGHT = 44
    SEPARATOR_HEIGHT = 0.5

    def __init__(
        self,
        master: Any,
        height: Optional[int] = None,
        corner_radius: int = 12,
        on_select: Optional[Callable[[Any], None]] = None,
        **kwargs
    ):
        """Initialize iOS list view.

        Args:
            master: Parent widget
            height: List height (None for auto, defaults to 200)
            corner_radius: Corner radius
            on_select: Callback when item is selected (receives item data)
            **kwargs: Additional arguments
        """
        self._items: List[iOSListItem] = []
        self._on_select = on_select
        self._item_widgets: List[Any] = []
        self._section_separators: List[Any] = []

        # Background color
        bg_color = Colors.THEME.bg_card if ThemeMode.is_dark() else Colors.THEME.light_bg_card
        border_color = Colors.THEME.separator

        # Default height if not specified
        if height is None:
            height = 200

        # Initialize scrollable frame
        super().__init__(
            master,
            height=height,
            corner_radius=corner_radius,
            fg_color=bg_color,
            border_width=1,
            border_color=border_color,
            label_text="",
            **kwargs
        )

    def add_item(
        self,
        title: str,
        subtitle: Optional[str] = None,
        value: Optional[str] = None,
        icon: Optional[str] = None,
        accessory: Optional[str] = None,
        section: Optional[str] = None,
        data: Any = None,
    ) -> None:
        """Add an item to the list.

        Args:
            title: Primary text
            subtitle: Optional secondary text
            value: Optional right-aligned value
            icon: Optional icon/emoji
            accessory: Optional accessory indicator
            section: Optional section header (creates section separator)
            data: Arbitrary user data
        """
        # Add section if specified
        if section:
            self._add_section(section)

        # Create item
        item = iOSListItem(
            title=title,
            subtitle=subtitle,
            value=value,
            icon=icon,
            accessory=accessory,
            data=data,
        )
        self._items.append(item)

        # Create widget
        self._create_item_widget(item)

    def _add_section(self, title: str) -> None:
        """Add a section header separator.

        Args:
            title: Section title
        """
        # Section header label
        section = ctk.CTkLabel(
            self._widget_frame,
            text=title.upper(),
            font=Fonts.CAPTION1,
            text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
            anchor="w",
        )
        section.pack(fill="x", padx=iOSSpacing.lg, pady=(iOSSpacing.sm, iOSSpacing.xs))

        self._section_separators.append(section)

    def _create_item_widget(self, item: iOSListItem) -> None:
        """Create widget for a single list item.

        Args:
            item: iOSListItem
        """
        # Item container (touch target)
        container = ctk.CTkFrame(
            self._widget_frame,
            height=self.ROW_HEIGHT,
            fg_color=Colors.get_card_color(),
            cursor="hand2" if self._on_select else "",
        )
        container.pack(fill="x", padx=0)

        # Bind click
        if self._on_select:
            container.bind("<Button-1>", lambda e: self._on_item_clicked(item, e))

        # Content frame
        content = ctk.CTkFrame(container, fg_color=Colors.get_card_color())
        content.pack(fill="both", expand=True, padx=iOSSpacing.lg, pady=0)

        # Left side: icon + title + subtitle
        left = ctk.CTkFrame(content, fg_color=Colors.get_card_color())
        left.pack(side="left", fill="both", expand=True)

        # Icon
        if item.icon:
            icon = ctk.CTkLabel(
                left,
                text=item.icon,
                font=("Segoe UI Emoji", 18),
            )
            icon.pack(side="left", padx=(0, iOSSpacing.sm))

        # Title and subtitle
        text_frame = ctk.CTkFrame(left, fg_color=Colors.get_card_color())
        text_frame.pack(side="left", fill="both", expand=True)

        # Title
        title_color = Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary
        title = ctk.CTkLabel(
            text_frame,
            text=item.title,
            font=Fonts.BODY,
            text_color=title_color,
            anchor="w",
        )
        title.pack(side="top", fill="x")

        # Subtitle
        if item.subtitle:
            subtitle_color = Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary
            subtitle = ctk.CTkLabel(
                text_frame,
                text=item.subtitle,
                font=Fonts.SUBHEADLINE,
                text_color=subtitle_color,
                anchor="w",
            )
            subtitle.pack(side="top", fill="x")

        # Right side: value + accessory
        right = ctk.CTkFrame(content, fg_color=Colors.get_card_color())
        right.pack(side="right", padx=(iOSSpacing.md, 0))

        # Value
        if item.value:
            value_label = ctk.CTkLabel(
                right,
                text=item.value,
                font=Fonts.CALLOUT,
                text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
            )
            value_label.pack(side="left", padx=(0, iOSSpacing.xs))

        # Accessory
        if item.accessory:
            accessory_label = ctk.CTkLabel(
                right,
                text=item.accessory,
                font=Fonts.BODY,
                text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
            )
            accessory_label.pack(side="left", padx=(iOSSpacing.xs, 0))

        # Separator
        if len(self._items) > 1:
            separator = ctk.CTkFrame(
                self._widget_frame,
                height=1,
                fg_color=Colors.THEME.separator,
            )
            separator.pack(fill="x", side="bottom")

        self._item_widgets.append(container)

    def _on_item_clicked(self, item: iOSListItem, event: Any) -> None:
        """Handle item click.

        Args:
            item: The clicked item
            event: Mouse event
        """
        if self._on_select:
            self._on_select(item.data or item)

    def get_items(self) -> List[iOSListItem]:
        """Get all items.

        Returns:
            List of iOSListItem objects
        """
        return self._items.copy()

    def clear(self) -> None:
        """Clear all items."""
        self._items.clear()
        self._item_widgets.clear()
        self._section_separators.clear()

        # Clear widget frame
        for widget in self._widget_frame.winfo_children():
            try:
                widget.destroy()
            except Exception:
                pass


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkiOSList(ttk.Frame):
        """Fallback list view for standard tkinter."""

        def __init__(self, master: Any, on_select=None, **kwargs):
            super().__init__(master, **kwargs)
            self._items = []
            self._on_select = on_select

        def add_item(self, title: str, subtitle=None, value=None, icon=None, accessory=None, section=None, data=None):
            item = iOSListItem(title=title, subtitle=subtitle, value=value, icon=icon, accessory=accessory, data=data)
            self._items.append(item)

            # Add section if needed
            if section:
                ttk.Label(self, text=section.upper(), font=("Arial", 8)).pack(fill="x", padx=10, pady=(5, 2))

            # Create item
            text = title
            if subtitle:
                text = f"{title}\n{subtitle}"
            if icon:
                text = f"{icon} {text}"
            if value:
                text = f"{text}    {value}"
            if accessory:
                text = f"{text}    {accessory}"

            lbl = ttk.Label(self, text=text)
            lbl.pack(fill="x", padx=15, pady=2)

            if self._on_select:
                lbl.bind("<Button-1>", lambda e: self._on_select(data or item))

        def get_items(self):
            return self._items.copy()

        def clear(self):
            self._items.clear()
            for widget in self.winfo_children():
                widget.destroy()

    iOSList = TkiOSList


__all__ = [
    "iOSListItem",
    "iOSList",
]
