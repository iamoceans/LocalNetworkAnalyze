"""
Packet capture panel with iOS styling.

Provides controls for starting/stopping packet capture,
selecting interfaces, setting filters, and viewing captured packets.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

from src.core.logger import get_logger
from src.core.exceptions import CaptureError
from src.capture.base import PacketCapture, PacketInfo
from src.storage import DatabaseManager
from src.capture import create_capture as create_packet_capture
from src.analysis import AnalysisEngine
from src.detection import DetectionEngine

# Import iOS theme system
from src.gui.theme.colors import Colors, ThemeMode, iOSSpacing, iOSShapes
from src.gui.theme.typography import Fonts
from src.gui.components import PacketTree
from src.gui.components.ios_button import iOSButton
from src.gui.components.ios_list import iOSList, iOSListItem
from src.gui.components.ios_switch import iOSSwitch
from src.gui.components.ios_segment import iOSSegment
from src.gui.state import CaptureState


class TrafficAggregator:
    """Aggregates traffic statistics by destination."""

    def __init__(self, max_entries: int = 30):
        """Initialize traffic aggregator.

        Args:
            max_entries: Maximum number of entries to track
        """
        self._max_entries = max_entries
        self._stats: Dict[str, Dict[str, Any]] = {}
        self._cached_top: Optional[list] = None  # Cache for top destinations
        self._lock = threading.Lock()
        self._logger = get_logger(__name__)

    def add_packet(self, packet: PacketInfo) -> None:
        """Add packet to aggregation.

        Args:
            packet: Captured packet
        """
        with self._lock:
            port = packet.dst_port or 0
            key = f"{packet.dst_ip}:{port}"
            stats = self._stats.get(key)

            if not stats:
                stats = {
                    'total_bytes': 0,
                    'packet_count': 0,
                    'last_seen': None,
                    'host': None,
                    'urls': set(),
                }

            stats['total_bytes'] += packet.length
            stats['packet_count'] += 1
            stats['last_seen'] = packet.timestamp

            if packet.host:
                stats['host'] = packet.host

            if packet.url:
                stats['urls'].add(packet.url)

            self._stats[key] = stats

    def get_top_destinations(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Get top destinations by traffic.

        Args:
            limit: Maximum number of results

        Returns:
            List of destination statistics sorted by traffic
        """
        with self._lock:
            results = []
            for key, stats in sorted(
                self._stats.items(),
                key=lambda x: x[1].get('total_bytes', 0),
                reverse=True
            ):
                # Parse key to extract IP and port
                # Key format is "ip:port"
                key_parts = key.split(':')
                dst_ip = key_parts[0] if len(key_parts) > 0 else ''
                # Port 0 means the original port was None (from `packet.dst_port or 0`)
                dst_port = int(key_parts[1]) if len(key_parts) > 1 and key_parts[1] != '0' else None

                results.append({
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'total_bytes': stats['total_bytes'],
                    'packet_count': stats['packet_count'],
                    'last_seen': stats['last_seen'],
                    'host': stats.get('host'),
                    'url': next(iter(stats.get('urls', set()))) if stats.get('urls') else None,
                })
            # Cache the results
            self._cached_top = results[:limit]
            return self._cached_top

    def get_stats_snapshot(self) -> Dict[str, int]:
        """Get a snapshot of current statistics for change detection.

        Returns:
            Dictionary with top destinations and their traffic
        """
        with self._lock:
            snapshot = {}
            for key, stats in self._stats.items():
                snapshot[key] = stats['total_bytes']
            return snapshot

    def clear(self) -> None:
        """Clear all statistics."""
        with self._lock:
            self._stats.clear()
            self._cached_top = None


class CapturePanel:
    """Packet capture panel with iOS styling.

    Provides interface for:
    - Starting/stopping packet capture
    - Selecting network interfaces
    - Setting capture filters
    - Viewing captured packets in real-time

    Features:
    - iOS-style buttons with proper touch targets
    - iOS List for captured packets
    - Clean, modern interface
    - Semantic colors for status indicators
    """

    def __init__(
        self,
        parent,
        capture: Optional[PacketCapture] = None,
        analysis: Optional[AnalysisEngine] = None,
        detection: Optional[DetectionEngine] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        """Initialize capture panel.

        Args:
            parent: Parent widget
            capture: Packet capture engine
            analysis: Analysis engine
            detection: Detection engine
            database: Database manager
        """
        self._parent = parent
        self._capture = capture
        self._analysis = analysis
        self._detection = detection
        self._database = database
        self._logger = get_logger(__name__)

        # State management
        self._state = CaptureState()

        # Traffic aggregator (Top30 destinations)
        self._traffic_aggregator = TrafficAggregator(max_entries=100)

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._control_bar: Optional[Any] = None
        self._packet_tree: Optional[PacketTree] = None
        self._interface_segment: Optional[Any] = None
        self._filter_frame: Optional[tk.Frame] = None
        self._auto_scroll_var: Optional[ctk.StringVar] = None

        self._logger.info("iOS-style Capture panel initialized")

    def build(self) -> tk.Frame:
        """Build capture panel UI with iOS styling.

        Returns:
            Capture panel frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color=Colors.get_card_color())
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)

        # Create sections
        self._create_header()
        self._create_control_panel()
        self._create_filter_panel()
        self._create_packet_display()

        # Register packet callback with capture engine
        if self._capture:
            self._capture.add_callback(self._on_packet_captured)

        # Start periodic display updates
        self._start_display_updates()

        self._logger.info("iOS-style Capture panel UI built")
        return self._frame

    def _on_packet_captured(self, packet: "PacketInfo") -> None:
        """Handle captured packet callback.

        Args:
            packet: Captured packet info
        """
        self._traffic_aggregator.add_packet(packet)

    def _start_display_updates(self) -> None:
        """Start periodic display updates."""
        if self._frame:
            self._update_display_periodically()

    def _update_display_periodically(self) -> None:
        """Update display periodically."""
        try:
            if self._state.is_capturing:
                self._update_packet_list()
        except Exception as e:
            self._logger.error(f"Error in periodic update: {e}")

        # Schedule next update
        if self._frame:
            self._frame.after(1000, self._update_display_periodically)

    def _create_header(self) -> None:
        """Create iOS-style header."""
        if CUSTOMTKINTER_AVAILABLE:
            header = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color(), height=50)
            header.pack(fill="x", pady=(0, iOSSpacing.md))

            # Title
            title = ctk.CTkLabel(
                header,
                text="Packet Capture",
                font=Fonts.TITLE2,
                text_color=Colors.get_text_color(),
            )
            title.pack(side="left", padx=iOSSpacing.lg)

            # Status indicator
            self._status_label = ctk.CTkLabel(
                header,
                text="",
                font=("", 14),
                text_color=Colors.THEME.success if self._state.is_capturing else Colors.THEME.inactive,
            )
            self._status_label.pack(side="left", padx=(iOSSpacing.sm, 0))

            # Update time
            update_time = ctk.StringVar(
                value=datetime.now().strftime("%H:%M:%S")
            )
            update_label = ctk.CTkLabel(
                header,
                textvariable=update_time,
                font=Fonts.CAPTION1,
                text_color=Colors.get_text_secondary(),
            )
            update_label.pack(side="right", padx=iOSSpacing.lg)

    def _create_control_panel(self) -> None:
        """Create iOS-style control panel with buttons."""
        if not CUSTOMTKINTER_AVAILABLE:
            control_frame = ttk.Frame(self._frame)
            control_frame.pack(fill="x", pady=(0, iOSSpacing.md))
            return

        control_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        control_frame.pack(fill="x", pady=(0, iOSSpacing.md))

        # Button container - horizontal layout
        btn_container = ctk.CTkFrame(control_frame, fg_color=Colors.get_card_color())
        btn_container.pack(side="left", padx=iOSSpacing.md)

        # Start/Stop button with iOS styling
        self._start_stop_btn = iOSButton(
            btn_container,
            text="Start" if not self._state.is_capturing else "Stop",
            color="green",
            size="medium",
            command=self._toggle_capture,
        )
        self._start_stop_btn.pack(side="left", padx=iOSSpacing.xs)

        # Refresh button
        self._refresh_btn = iOSButton(
            btn_container,
            text="Refresh",
            style="plain",
            size="medium",
            command=self._refresh_interfaces,
        )
        self._refresh_btn.pack(side="left", padx=iOSSpacing.xs)

        # Clear button
        self._clear_btn = iOSButton(
            btn_container,
            text="Clear",
            style="plain",
            size="medium",
            command=self._clear_packets,
        )
        self._clear_btn.pack(side="left", padx=iOSSpacing.xs)

        # Save button
        self._save_btn = iOSButton(
            btn_container,
            text="Save",
            style="plain",
            size="medium",
            command=self._save_packets,
        )
        self._save_btn.pack(side="left", padx=iOSSpacing.xs)

    def _create_filter_panel(self) -> None:
        """Create filter panel with interface selector and options."""
        if not CUSTOMTKINTER_AVAILABLE:
            filter_frame = ttk.Frame(self._frame)
            filter_frame.pack(fill="x", pady=(0, iOSSpacing.md))
            return

        filter_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        filter_frame.pack(fill="x", pady=(iOSSpacing.sm))

        # Interface selector (iOS Segmented Control)
        interface_label = ctk.CTkLabel(
            filter_frame,
            text="Interface",
            font=Fonts.CAPTION1,
            text_color=Colors.get_text_secondary(),
        )
        interface_label.pack(padx=(iOSSpacing.md, 0))

        self._interface_segment = iOSSegment(
            filter_frame,
            command=lambda v: self._select_interface(v),
        )

        # Add interface options (populated dynamically)
        # Will be populated when _refresh_interfaces is called

        self._interface_segment.pack(fill="x", padx=iOSSpacing.md, pady=(iOSSpacing.xs, 0))

    def _create_packet_display(self) -> None:
        """Create packet display with iOS List."""
        if not CUSTOMTKINTER_AVAILABLE:
            packet_frame = ttk.LabelFrame(self._frame, text="Captured Packets")
            packet_frame.pack(fill="both", expand=True, pady=(0, iOSSpacing.md))
        else:
            packet_frame = ctk.CTkFrame(self._frame, corner_radius=iOSShapes.corner_large, fg_color=Colors.get_card_color())
            packet_frame.pack(fill="both", expand=True, pady=iOSSpacing.md)

        # Header with refresh button
        header = ctk.CTkFrame(packet_frame, fg_color=Colors.get_card_color(), height=36)
        header.pack(fill="x", padx=iOSSpacing.lg, pady=(iOSSpacing.md, 0))

        title = ctk.CTkLabel(
            header,
            text="Top 30 Destinations",
            font=Fonts.HEADLINE,
            text_color=Colors.get_text_color(),
            anchor="w",
        )
        title.pack(side="left", padx=iOSSpacing.lg)

        refresh = ctk.CTkButton(
            header,
            text="Refresh",
            font=Fonts.CAPTION1,
            fg_color=Colors.THEME.bg_hover,
            text_color=Colors.get_text_secondary(),
            hover_color=Colors.THEME.bg_tertiary,
            border_width=0,
            width=60,
            height=28,
            corner_radius=8,
            command=self._refresh_display,
        )
        refresh.pack(side="right", padx=iOSSpacing.md)

        # Scrollable packet list using iOS List component
        self._packet_list = iOSList(
            packet_frame,
            on_select=self._on_packet_select,
        )

        # Packet tree (legacy, embedded in iOS List)
        # For now, we'll create a simple label frame for display
        self._display_frame = ctk.CTkFrame(packet_frame, fg_color=Colors.get_card_color())
        self._display_frame.pack(fill="both", expand=True, padx=iOSSpacing.lg, pady=iOSSpacing.sm)

        no_packets_label = ctk.CTkLabel(
            self._display_frame,
            text="No packets captured",
            font=Fonts.BODY,
            text_color=Colors.get_text_secondary(),
        )
        # Will be packed when content is available

    def _refresh_interfaces(self) -> None:
        """Refresh network interface list."""
        if not self._capture:
            return

        try:
            interfaces = self._capture.get_interfaces()
            if not interfaces:
                interfaces = ["Any"]

            # Clear segment options if initialized
            if self._interface_segment:
                self._interface_segment.clear()

                # Add interface options
                for iface in interfaces:
                    self._interface_segment.add_option(iface, iface)

            # Auto-select first interface
            if interfaces:
                self._select_interface(interfaces[0])

            self._logger.info(f"Refreshed {len(interfaces)} interfaces")

        except Exception as e:
            self._logger.error(f"Error refreshing interfaces: {e}")

    def _select_interface(self, interface: str) -> None:
        """Select capture interface.

        Args:
            interface: Interface name or IP
        """
        if not self._capture:
            return

        try:
            self._capture.set_interface(interface)
            self._state.set_interface(interface)
            self._logger.info(f"Selected interface: {interface}")
        except Exception as e:
            self._logger.error(f"Error selecting interface: {e}")

    def _toggle_capture(self) -> None:
        """Toggle packet capture on/off."""
        if not self._capture:
            return

        if self._state.is_capturing:
            self._capture.stop_capture()
            self._state.set_idle()
        else:
            self._capture.start_capture()
            self._state.set_capturing()
            self._logger.info("Capture started")

        self._update_status_indicator()

    def _refresh_display(self) -> None:
        """Refresh packet display."""
        # Clear display frame
        for widget in self._display_frame.winfo_children():
            widget.destroy()

        # Show loading state
        loading_label = ctk.CTkLabel(
            self._display_frame,
            text="Loading...",
            font=Fonts.BODY,
            text_color=Colors.get_text_secondary(),
        )
        loading_label.pack(padx=iOSSpacing.xl, pady=iOSSpacing.xl)

        # Update display with current data
        self._frame.after(100, self._update_packet_list)

    def _update_packet_list(self) -> None:
        """Update packet list with top destinations."""
        if not self._display_frame:
            return

        try:
            top_destinations = self._traffic_aggregator.get_top_destinations(limit=30)

            # Clear loading label
            for widget in self._display_frame.winfo_children():
                widget.destroy()

            if not top_destinations:
                no_packets_label = ctk.CTkLabel(
                    self._display_frame,
                    text="No packets captured",
                    font=Fonts.BODY,
                    text_color=Colors.get_text_secondary(),
                )
                no_packets_label.pack(padx=iOSSpacing.xl, pady=iOSSpacing.xl)
                return

            # Add each destination as an item
            for dest in top_destinations:
                ip = dest.get('dst_ip', 'Unknown')
                port = dest.get('dst_port', 0)
                bytes_count = dest.get('total_bytes', 0)
                packet_count = dest.get('packet_count', 0)
                last_seen = dest.get('last_seen')

                # Format values
                bytes_str = self._format_bytes(bytes_count)
                packets_str = f"{packet_count:,}"

                # Format last seen time
                if last_seen:
                    if isinstance(last_seen, datetime):
                        time_str = last_seen.strftime("%H:%M")
                    else:
                        time_str = str(last_seen)
                else:
                    time_str = "Never"

                # Create list item
                item_label = f"{ip}:{port}"

                # Add to iOS List
                self._packet_list.add_item(
                    title=item_label,
                    subtitle=f"{bytes_str} • {packets_str} packets",
                    value=time_str,
                    icon="",
                )

        except Exception as e:
            self._logger.error(f"Error updating packet list: {e}")

    def _format_bytes(self, count: int) -> str:
        """Format byte count to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if count < 1024:
                return f"{count} {unit}"
            count /= 1024.0
        return f"{count:.1f} GB"

    def _on_packet_select(self, item_data: Any) -> None:
        """Handle packet selection from list.

        Args:
            item_data: Selected item data
        """
        self._logger.info(f"Selected packet: {item_data}")

    def _clear_packets(self) -> None:
        """Clear captured packets."""
        if not self._capture:
            return

        try:
            self._capture.clear_packets()
            self._traffic_aggregator.clear()
            self._refresh_display()
            self._logger.info("Cleared captured packets")
        except Exception as e:
            self._logger.error(f"Error clearing packets: {e}")

    def _save_packets(self) -> None:
        """Save captured packets to database."""
        if not self._capture or not self._database:
            return

        try:
            packets = self._capture.get_packets()
            if not packets:
                messagebox.showinfo(
                    "No Packets",
                    "No packets to save."
                )
                return

            saved = self._database.save_packets(packets)
            if saved:
                count = len(packets)
                messagebox.showinfo(
                    "Saved",
                    f"Successfully saved {count} packets to database."
                )
            else:
                messagebox.showerror(
                    "Error",
                    "Failed to save packets to database."
                )

        except Exception as e:
            self._logger.error(f"Error saving packets: {e}")
            messagebox.showerror("Error", f"Failed to save packets: {e}")

    def _update_status_indicator(self) -> None:
        """Update capture status indicator."""
        if hasattr(self, '_status_label'):
            color = Colors.THEME.success if self._state.is_capturing else Colors.THEME.inactive
            self._status_label.configure(text_color=color)

    def refresh_display(self) -> None:
        """Refresh the packet display with current capture state."""
        self._refresh_display()

    def update_capture_status(self, is_capturing: bool) -> None:
        """Update capture status from external source."""
        self._state.set_capturing() if is_capturing else self._state.set_idle()
        self._update_status_indicator()

        if hasattr(self, '_start_stop_btn'):
            btn = self._start_stop_btn
            # Update button text and color without destroying
            btn_text = "Stop" if is_capturing else "Start"
            btn.configure(text=btn_text)

    def destroy(self) -> None:
        """Clean up panel resources."""
        if hasattr(self, '_frame') and self._frame:
            self._frame.destroy()

        self._logger.info("iOS-style Capture panel destroyed")


def create_capture_panel(
    parent,
    capture: Optional[PacketCapture] = None,
    analysis: Optional[AnalysisEngine] = None,
    detection: Optional[DetectionEngine] = None,
    database: Optional[DatabaseManager] = None,
) -> CapturePanel:
    """Create capture panel instance.

    Args:
        parent: Parent widget
        capture: Packet capture engine
        analysis: Analysis engine
        detection: Detection engine
        database: Database manager

    Returns:
        CapturePanel instance
    """
    return CapturePanel(
        parent=parent,
        capture=capture,
        analysis=analysis,
        detection=detection,
        database=database,
    )


__all__ = [
    "CapturePanel",
    "create_capture_panel",
]
