"""
Stat card component for Local Network Analyzer.

Provides a glassmorphism-styled card for displaying
statistics with icon, label, value, and optional trend indicator.
"""

import logging
from typing import Optional, Any, Dict, List, Tuple

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

from src.gui.theme.colors import Colors
from src.gui.theme.typography import Fonts
from src.gui.components.glass_frame import GlassFrame


class StatCard(GlassFrame):
    """A glass-styled card for displaying statistics.

    Features:
    - Glassmorphism background
    - Icon + Label + Value layout
    - Optional neon border glow
    - Optional trend indicator
    - Hover animation
    - Compact or spacious layout

    Example:
        card = StatCard(
            parent,
            icon="📦",
            label="Total Packets",
            value="1,234,567",
            color="green"
        )
        card.pack()
    """

    def __init__(
        self,
        master: Any,
        icon: str = "",
        label: str = "",
        value: str = "--",
        color: str = "none",
        trend: Optional[str] = None,  # "+5.2%", "-2.1%", etc.
        size: str = "medium",  # small, medium, large
        compact: bool = False,
        **kwargs
    ):
        """Initialize stat card.

        Args:
            master: Parent widget
            icon: Icon/emoji to display
            label: Label text
            value: Value to display
            color: Glow color (none, green, red, cyan, yellow, orange)
            trend: Optional trend indicator
            size: Card size (small, medium, large)
            compact: Use compact layout (label and value on same line)
            **kwargs: Additional arguments passed to GlassFrame
        """
        self._icon = icon
        self._label_text = label
        self._value_text = value
        self._trend_text = trend
        self._size = size
        self._compact = compact

        # Size configurations
        self._size_config: Dict[str, Dict[str, Any]] = {
            "small": {
                "icon_size": 14,
                "label_font": Fonts.BODY_SMALL,
                "value_font": Fonts.STAT_SMALL,
                "padding": 10,
                "height": 60,
            },
            "medium": {
                "icon_size": 18,
                "label_font": Fonts.BODY_SMALL,
                "value_font": Fonts.STAT_MEDIUM,
                "padding": 15,
                "height": 80,
            },
            "large": {
                "icon_size": 24,
                "label_font": Fonts.BODY,
                "value_font": Fonts.STAT_LARGE,
                "padding": 20,
                "height": 100,
            },
        }

        config = self._size_config.get(size, self._size_config["medium"])

        # Initialize with glass effect
        super().__init__(
            master,
            glow=color,
            hover=True,
            height=config["height"],
            **kwargs
        )

        # Build card content
        self._build_content(config)

    def _build_content(self, config: Dict[str, Any]) -> None:
        """Build card content layout.

        Args:
            config: Size configuration dict
        """
        padding = config["padding"]

        if self._compact:
            self._build_compact_layout(config)
        else:
            self._build_standard_layout(config)

    def _build_standard_layout(self, config: Dict[str, Any]) -> None:
        """Build standard vertical layout.

        Args:
            config: Size configuration dict
        """
        padding = config["padding"]

        # Create header section
        self._create_header_section(padding, config)

        # Create value display section
        value_frame = self._create_value_frame(padding)
        self._create_value_label(value_frame, config)

        # Add trend if present
        if self._trend_text:
            self._add_trend_indicator(value_frame)

    def _create_header_section(self, padding: int, config: Dict[str, Any]) -> ctk.CTkFrame:
        """Create the header section with icon and label.

        Args:
            padding: Padding value
            config: Size configuration dict

        Returns:
            The header frame widget
        """
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=padding, pady=(padding, padding // 2))

        self._add_icon_to_frame(header_frame, config, side="left", padx=(0, 8))
        self._add_label_to_frame(header_frame, config, side="left")

        return header_frame

    def _create_value_frame(self, padding: int) -> ctk.CTkFrame:
        """Create the value display frame.

        Args:
            padding: Padding value

        Returns:
            The value frame widget
        """
        value_frame = ctk.CTkFrame(self, fg_color="transparent")
        value_frame.pack(fill="x", padx=padding, pady=(0, padding))
        return value_frame

    def _create_value_label(self, parent: ctk.CTkFrame, config: Dict[str, Any]) -> None:
        """Create and pack the value label.

        Args:
            parent: Parent frame
            config: Size configuration dict
        """
        self._value_label = ctk.CTkLabel(
            parent,
            text=self._value_text,
            font=config["value_font"],
            text_color=Colors.THEME.text_primary,
        )
        self._value_label.pack(side="left")

    def _add_icon_to_frame(self, frame: ctk.CTkFrame, config: Dict[str, Any], side: str = "left", padx: Tuple[int, int] = (0, 8)) -> None:
        """Add icon to a frame if icon exists.

        Args:
            frame: Parent frame
            config: Size configuration dict
            side: Pack side
            padx: Padding x
        """
        if self._icon:
            icon_label = ctk.CTkLabel(
                frame,
                text=self._icon,
                font=("Segoe UI Emoji", config["icon_size"]),
            )
            icon_label.pack(side=side, padx=padx)

    def _add_label_to_frame(self, frame: ctk.CTkFrame, config: Dict[str, Any], side: str = "left") -> None:
        """Add label to a frame if label text exists.

        Args:
            frame: Parent frame
            config: Size configuration dict
            side: Pack side
        """
        if self._label_text:
            label = ctk.CTkLabel(
                frame,
                text=self._label_text,
                font=config["label_font"],
                text_color=Colors.THEME.text_secondary,
            )
            label.pack(side=side)

    def _build_compact_layout(self, config: Dict[str, Any]) -> None:
        """Build compact horizontal layout.

        Args:
            config: Size configuration dict
        """
        padding = config["padding"]

        # Main horizontal container
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=padding, pady=padding)

        # Create left side (icon + label)
        left_frame = self._create_compact_left_side(main_frame, config)

        # Create right side (value + trend)
        right_frame = self._create_compact_right_side(main_frame, config)

    def _create_compact_left_side(self, parent: ctk.CTkFrame, config: Dict[str, Any]) -> ctk.CTkFrame:
        """Create the left side of compact layout (icon + label).

        Args:
            parent: Parent frame
            config: Size configuration dict

        Returns:
            The left frame widget
        """
        left_frame = ctk.CTkFrame(parent, fg_color="transparent")
        left_frame.pack(side="left")

        self._add_icon_to_frame(left_frame, config, side="left", padx=(0, 8))
        self._add_label_to_frame(left_frame, config, side="left")

        return left_frame

    def _create_compact_right_side(self, parent: ctk.CTkFrame, config: Dict[str, Any]) -> ctk.CTkFrame:
        """Create the right side of compact layout (value + trend).

        Args:
            parent: Parent frame
            config: Size configuration dict

        Returns:
            The right frame widget
        """
        right_frame = ctk.CTkFrame(parent, fg_color="transparent")
        right_frame.pack(side="right")

        self._create_value_label(right_frame, config)

        if self._trend_text:
            self._add_trend_indicator(right_frame)

        return right_frame

    def _add_trend_indicator(self, parent: ctk.CTkFrame) -> None:
        """Add trend indicator to the card.

        Args:
            parent: Parent frame for the indicator
        """
        if not self._trend_text:
            return

        # Determine color based on trend
        trend_color = self._get_trend_color()

        trend_label = ctk.CTkLabel(
            parent,
            text=self._trend_text,
            font=Fonts.BODY_SMALL,
            text_color=trend_color,
        )
        trend_label.pack(side="left", padx=(8, 0))

    def _get_trend_color(self) -> str:
        """Get trend indicator color.

        Returns:
            Color string for the trend
        """
        if self._trend_text:
            if self._trend_text.startswith("+"):
                return Colors.STATUS.success
            elif self._trend_text.startswith("-"):
                return Colors.STATUS.error
        return Colors.THEME.text_secondary

    def update_value(self, value: str, trend: Optional[str] = None) -> None:
        """Update the displayed value.

        Args:
            value: New value to display
            trend: Optional new trend indicator
        """
        self._value_text = value
        self._value_label.configure(text=value)

        if trend is not None:
            self._trend_text = trend
            # Rebuild to update trend indicator
            # Note: This is inefficient, would be better to update existing widget
            # but keeping it simple for now

    def set_color(self, color: str) -> None:
        """Change the card glow color.

        Args:
            color: New glow color (none, green, red, cyan, yellow, orange)
        """
        super().set_glow(color)


class StatGrid(ctk.CTkFrame):
    """A grid layout for multiple stat cards.

    Provides automatic grid layout with configurable
    columns and responsive wrapping.
    """

    def __init__(
        self,
        master: Any,
        columns: int = 3,
        spacing: int = 10,
        **kwargs
    ):
        """Initialize stat grid.

        Args:
            master: Parent widget
            columns: Number of columns in grid
            spacing: Spacing between cards
            **kwargs: Additional arguments passed to CTkFrame
        """
        super().__init__(master, fg_color="transparent", **kwargs)
        self._columns = columns
        self._spacing = spacing
        self._cards: List[StatCard] = []

    def add_card(
        self,
        icon: str = "",
        label: str = "",
        value: str = "--",
        color: str = "none",
        trend: Optional[str] = None,
        size: str = "medium",
        compact: bool = False,
    ) -> StatCard:
        """Add a stat card to the grid.

        Args:
            icon: Card icon
            label: Card label
            value: Card value
            color: Card glow color
            trend: Trend indicator
            size: Card size
            compact: Use compact layout

        Returns:
            The created StatCard instance
        """
        row = len(self._cards) // self._columns
        col = len(self._cards) % self._columns

        card = StatCard(
            self,
            icon=icon,
            label=label,
            value=value,
            color=color,
            trend=trend,
            size=size,
            compact=compact,
        )
        card.grid(
            row=row,
            column=col,
            padx=self._spacing // 2,
            pady=self._spacing // 2,
            sticky="nsew"
        )

        # Configure grid weights
        self.grid_rowconfigure(row, weight=1)
        self.grid_columnconfigure(col, weight=1)

        self._cards.append(card)
        return card

    def clear(self) -> None:
        """Remove all cards from the grid."""
        for card in self._cards:
            card.destroy()
        self._cards.clear()

    def get_cards(self) -> List[StatCard]:
        """Get all cards in the grid.

        Returns:
            List of StatCard instances
        """
        return self._cards.copy()


# Fallback for standard tkinter
if not CUSTOMTKINTER_AVAILABLE:
    class TkStatCard(ttk.LabelFrame):
        """Fallback stat card for standard tkinter."""

        def __init__(
            self,
            master: Any,
            icon: str = "",
            label: str = "",
            value: str = "--",
            color: str = "none",
            trend: Optional[str] = None,
            **kwargs
        ):
            super().__init__(master, text=label, **kwargs)

            self._value_label = ttk.Label(self, text=value, font=("Arial", 14, "bold"))
            self._value_label.pack(padx=10, pady=5)

            if trend:
                ttk.Label(self, text=trend).pack()

        def update_value(self, value: str, trend: Optional[str] = None) -> None:
            self._value_label.configure(text=value)

        def set_color(self, color: str) -> None:
            pass  # Not easily supported in ttk

    class TkStatGrid(ttk.Frame):
        """Fallback stat grid for standard tkinter."""

        def __init__(self, master: Any, columns: int = 3, **kwargs):
            super().__init__(master, **kwargs)
            self._columns = columns
            self._cards = []

        def add_card(self, **kwargs) -> TkStatCard:
            row = len(self._cards) // self._columns
            col = len(self._cards) % self._columns

            card = TkStatCard(self, **kwargs)
            card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

            self.grid_rowconfigure(row, weight=1)
            self.grid_columnconfigure(col, weight=1)

            self._cards.append(card)
            return card

        def clear(self) -> None:
            for card in self._cards:
                card.destroy()
            self._cards.clear()

        def get_cards(self) -> List[StatCard]:
            return self._cards.copy()

    StatCard = TkStatCard
    StatGrid = TkStatGrid


__all__ = [
    "StatCard",
    "StatGrid",
]
