"""
Packet capture panel with cyber-security styling.

Provides controls for starting/stopping packet capture,
selecting interfaces, setting filters, and viewing captured packets.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading
from collections import defaultdict

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False

from src.core.logger import get_logger
from src.core.exceptions import CaptureError
from src.capture.base import PacketCapture, PacketInfo
from src.storage import DatabaseManager
from src.capture import create_capture as create_packet_capture

from src.analysis import AnalysisEngine
from src.detection import DetectionEngine

# Import components
from src.gui.components import PacketTree, ControlBar
from src.gui.state import CaptureState

# Import theme system
from src.gui.theme.colors import Colors, NeonColors
from src.gui.theme.typography import Fonts
from src.gui.components import NeonButton, GlassFrame


class TrafficAggregator:
    """Aggregates traffic statistics by destination."""

    def __init__(self, max_entries: int = 30):
        """Initialize traffic aggregator.

        Args:
            max_entries: Maximum number of entries to track
        """
        self._max_entries = max_entries
        self._stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'total_bytes': 0,
            'packet_count': 0,
            'last_seen': None,
            'host': None,
            'urls': set(),
        })
        self._lock = threading.Lock()
        self._logger = get_logger(__name__)
        self._cached_top: Optional[List[Dict[str, Any]]] = None
        self._cache_version = 0  # Incremented when data changes

    def add_packet(self, packet: PacketInfo) -> None:
        """Add packet to aggregation.

        Args:
            packet: Captured packet
        """
        with self._lock:
            # Create key from dst_ip and dst_port
            port = packet.dst_port or 0
            key = f"{packet.dst_ip}:{port}"

            stats = self._stats[key]
            stats['total_bytes'] += packet.length
            stats['packet_count'] += 1
            stats['last_seen'] = packet.timestamp
            stats['dst_ip'] = packet.dst_ip
            stats['dst_port'] = packet.dst_port

            # Track host/URL if available
            if packet.host:
                stats['host'] = packet.host
            if packet.url:
                # Only keep last URL to save memory
                stats['urls'] = {packet.url}

            # Invalidate cache
            self._cache_version += 1

    def get_top_destinations(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Get top destinations by traffic.

        Args:
            limit: Maximum number of results

        Returns:
            List of destination statistics sorted by traffic
        """
        with self._lock:
            # Check if we can use cached result
            if self._cached_top is not None and len(self._cached_top) >= limit:
                return self._cached_top[:limit]

            # Build results
            results = []
            for key, stats in self._stats.items():
                result = {
                    'dst_ip': stats['dst_ip'],
                    'dst_port': stats['dst_port'],
                    'total_bytes': stats['total_bytes'],
                    'packet_count': stats['packet_count'],
                    'last_seen': stats['last_seen'],
                    'host': stats.get('host'),
                    'url': next(iter(stats['urls'])) if stats['urls'] else None,
                }
                results.append(result)

            # Sort by total_bytes descending
            results.sort(key=lambda x: x['total_bytes'], reverse=True)

            # Cache top 100 for faster access
            self._cached_top = results[:100]

            return results[:limit]

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
            self._cache_version += 1


class CapturePanel:
    """Panel for packet capture control and display.

    Provides interface for:
    - Starting/stopping capture
    - Interface selection
    - Capture filters
    - Real-time packet display
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
        self._original_capture: Optional[PacketCapture] = None

        # Traffic aggregator (Top30)
        self._traffic_aggregator = TrafficAggregator(max_entries=100)
        self._top_count = 30

        # For change detection
        self._last_snapshot: Dict[str, int] = {}
        self._last_top_keys: tuple = ()  # Cached tuple of top destination keys

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._control_bar: Optional[ControlBar] = None
        self._packet_tree: Optional[PacketTree] = None

        # Update timer
        self._update_timer: Optional[threading.Timer] = None
        self._is_updating = False
        self._update_interval = 2000  # 2 seconds for better performance

        self._logger.info("Capture panel initialized")

    def build(self) -> tk.Frame:
        """Build capture panel UI.

        Returns:
            Capture panel frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color="transparent")
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Configure grid layout
        self._frame.grid_rowconfigure(0, weight=0)  # Header
        self._frame.grid_rowconfigure(1, weight=0)  # Controls
        self._frame.grid_rowconfigure(2, weight=1)  # Packets (expandable)

        # Create sections
        self._create_header()
        self._create_control_panel()
        self._create_packet_display()

        self._logger.info("Capture panel UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create panel header with neon styling."""
        if not CUSTOMTKINTER_AVAILABLE:
            header = ttk.Frame(self._frame)
            header.pack(fill="x", pady=(0, 10))

            ttk.Label(
                header,
                text="Packet Capture",
                font=("Fira Code", 16, "bold"),
            ).pack(side="left")
            return

        # CustomTkinter header with neon styling
        header = ctk.CTkFrame(self._frame, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))

        title = ctk.CTkLabel(
            header,
            text="📡 Packet Capture",
            font=("Fira Code", 20, "bold"),
            text_color=Colors.NEON.neon_green,
        )
        title.pack(side="left", padx=5)

        # Status indicator
        self._status_indicator = ctk.CTkLabel(
            header,
            text="●",
            font=("Fira Code", 16),
            text_color=Colors.THEME.text_muted,
        )
        self._status_indicator.pack(side="left", padx=(15, 5))

    def _create_control_panel(self) -> None:
        """Create control panel using ControlBar component."""
        self._control_bar = ControlBar(self._frame)
        control_frame = self._control_bar.create(self._frame)

        # Wire up callbacks
        self._control_bar.set_refresh_callback(self._refresh_interfaces)
        self._control_bar.set_start_callback(self.start_capture)
        self._control_bar.set_stop_callback(self.stop_capture)
        self._control_bar.set_clear_callback(self.clear_packets)
        self._control_bar.set_save_callback(self.save_packets)

        # Load interfaces
        self._refresh_interfaces()

    def _create_packet_display(self) -> None:
        """Create packet display using PacketTree component."""
        if not CUSTOMTKINTER_AVAILABLE:
            packet_frame = ttk.LabelFrame(self._frame, text="Top 30 Traffic Destinations")
            packet_frame.pack(fill="both", expand=True)

            # Add refresh button
            btn_frame = ttk.Frame(packet_frame)
            btn_frame.pack(fill="x", padx=5, pady=(0, 5))
            ttk.Button(btn_frame, text="Refresh", command=self._refresh_display).pack(side="right")

            # Create packet tree component
            self._packet_tree = PacketTree(self._frame, self._top_count)
            self._packet_tree.create(packet_frame)
            self._packet_tree.bind_select(self._on_packet_select)
        else:
            # Create outer container frame
            outer_frame = ctk.CTkFrame(self._frame, fg_color="transparent")
            outer_frame.pack(fill="both", expand=True, pady=(12, 0))

            # Header frame with title and refresh button
            header_frame = ctk.CTkFrame(outer_frame, fg_color="transparent")
            header_frame.pack(fill="x", padx=15, pady=(10, 8))

            # Add title
            title = ctk.CTkLabel(
                header_frame,
                text="Top 30 Traffic Destinations",
                font=Fonts.H4,
                text_color=Colors.THEME.text_primary,
                anchor="w",
            )
            title.pack(side="left")

            # Add refresh button
            refresh_btn = ctk.CTkButton(
                header_frame,
                text="Refresh",
                width=80,
                command=self._refresh_display,
                font=ctk.CTkFont(size=11),
            )
            refresh_btn.pack(side="right")

            # Inner frame for treeview (using standard ttk frame)
            inner_frame = ttk.Frame(outer_frame)
            inner_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

            # Create packet tree component
            self._packet_tree = PacketTree(self._frame, self._top_count)
            self._packet_tree.create(inner_frame)
            self._packet_tree.bind_select(self._on_packet_select)

    def _refresh_interfaces(self) -> None:
        """Refresh available network interfaces."""
        try:
            # Try to get interfaces from the capture object
            if self._capture:
                # Check if get_interfaces is a static method or instance method
                if hasattr(self._capture, 'get_interfaces'):
                    interfaces_data = self._capture.get_interfaces()
                else:
                    # Import and use static method directly
                    from src.capture.scapy_capture import ScapyCapture
                    interfaces_data = ScapyCapture.get_interfaces()
            else:
                # No capture object, use static method
                from src.capture.scapy_capture import ScapyCapture
                interfaces_data = ScapyCapture.get_interfaces()

            if interfaces_data:
                self._control_bar.set_interface_options(interfaces_data)
                self._logger.info(f"Loaded {len(interfaces_data)} interfaces")
            else:
                self._logger.warning("No interfaces found")
        except Exception as e:
            self._logger.error(f"Error refreshing interfaces: {e}")
            # Show error to user
            self._control_bar.update_status(f"Error loading interfaces: {e}")

    def start_capture(self) -> None:
        """Start packet capture."""
        try:
            # Get interface from control bar
            selection = self._control_bar.get_selected_interface()
            if not selection:
                self._control_bar.update_status("Please select an interface")
                return

            # Get filter from control bar
            capture_filter = self._control_bar.get_filter()

            # Get monitor mode setting
            monitor_mode = self._control_bar.get_monitor_mode()

            # Warn about monitor mode requirements
            if monitor_mode:
                self._logger.info("Monitor Mode requested - requires Npcap with 802.11 support")
                self._control_bar.update_status("Starting with Monitor Mode...")

            # Store original capture
            if not hasattr(self, '_original_capture'):
                self._original_capture = self._capture

            # Create new capture with specified interface, filter and monitor mode
            self._capture = create_packet_capture(
                backend="scapy",
                interface=selection,
                filter=capture_filter,
                monitor_mode=monitor_mode,
            )

            # Wire up callbacks
            self._capture.add_callback(self._on_packet_captured)
            if self._analysis:
                self._capture.add_callback(self._analysis.update)
            if self._detection:
                self._capture.add_callback(self._detection.process)

            # Start capture
            self._capture.start_capture()

            # Save state (displayed_packets is no longer used with aggregation)
            self._state.save(
                capture=self._capture,
                selected_interface=selection,
                capture_filter=capture_filter,
                displayed_packets=[],  # Not tracking individual packets
                is_capturing=True,
            )

            # Update UI
            self._control_bar.set_capturing_state(True)
            self._control_bar.update_status(f"Capturing on {selection}")
            self._start_updates()

            # Save state to main window for panel switching
            self._save_state_to_main_window()

            self._logger.info(f"Capture started on {selection}")

        except CaptureError as e:
            self._logger.error(f"Capture error: {e}")
            msg = str(e)

            # Check if this is a monitor mode related error
            if "802.11" in msg or "monitor mode" in msg.lower():
                # Suggest using promiscuous mode instead
                self._show_monitor_mode_fallback_error(e)
            else:
                # Build detailed error message
                error_details = []
                if hasattr(e, 'details') and e.details:
                    if "suggestion" in e.details:
                        error_details.append(f"\n\nSolution:\n{e.details['suggestion']}")
                    if "troubleshooting" in e.details:
                        error_details.append(f"\n\nTroubleshooting:\n{e.details['troubleshooting']}")
                    if "additional_suggestions" in e.details:
                        for suggestion in e.details['additional_suggestions']:
                            error_details.append(f"\n- {suggestion}")

                full_error = msg + "".join(error_details)
                self._show_error_message("Capture Error", full_error)

            self._control_bar.update_status(msg + " - See details")
            self._control_bar.set_capturing_state(False)

        except Exception as e:
            self._logger.error(f"Error starting capture: {e}")
            self._show_error_message("Unexpected Error", f"An unexpected error occurred:\n\n{e}")
            self._control_bar.update_status(f"Error: {e}")
            self._control_bar.set_capturing_state(False)

    def stop_capture(self) -> None:
        """Stop packet capture."""
        try:
            if self._capture and self._state.is_capturing:
                self._capture.stop_capture()

            # Clear state
            self._state.clear()

            # Update UI
            self._control_bar.set_capturing_state(False)
            self._control_bar.update_status("Capture stopped")
            self._stop_updates()

            # Clear saved state from main window
            self._clear_state_from_main_window()

            self._logger.info("Capture stopped")

        except Exception as e:
            self._logger.error(f"Error stopping capture: {e}")
            self._control_bar.update_status(f"Error: {e}")

    def clear_packets(self) -> None:
        """Clear displayed packets and traffic statistics."""
        self._traffic_aggregator.clear()
        if self._packet_tree:
            self._packet_tree.clear()
        # Reset change detection cache
        self._last_snapshot = {}
        self._last_top_keys = ()
        self._update_packet_count()
        self._logger.info("Traffic statistics cleared")

    def save_packets(self) -> None:
        """Save captured packets to database."""
        if not self._database:
            self._control_bar.update_status("No database available")
            return

        try:
            from src.storage import create_packet_repository

            packet_repo = create_packet_repository(self._database)

            # Save all aggregated traffic as individual packets
            # This creates a snapshot of current traffic statistics
            top_destinations = self._traffic_aggregator.get_top_destinations(1000)
            saved = 0
            for dest in top_destinations:
                # Create a summary packet for each destination
                packet = PacketInfo(
                    timestamp=dest.get('last_seen', datetime.now()),
                    src_ip="",  # Not tracked in aggregator
                    dst_ip=dest.get('dst_ip', ''),
                    src_port=None,
                    dst_port=dest.get('dst_port'),
                    protocol="TCP",  # Most common for HTTP/HTTPS
                    length=dest.get('total_bytes', 0),
                    raw_data=b"",
                )

                # Add URL/host to raw data storage for reference
                if dest.get('host'):
                    # Store as metadata since PacketInfo doesn't have a metadata field
                    pass

                packet_repo.save(packet)
                saved += 1

            self._control_bar.update_status(f"Saved {saved} traffic entries to database")
            self._logger.info(f"Saved {saved} traffic entries")

        except Exception as e:
            self._logger.error(f"Error saving traffic data: {e}")
            self._control_bar.update_status(f"Error: {e}")

    def _on_packet_captured(self, packet: PacketInfo) -> None:
        """Handle captured packet callback.

        Args:
            packet: Captured packet info
        """
        try:
            # Add to traffic aggregator
            self._traffic_aggregator.add_packet(packet)
        except Exception as e:
            self._logger.error(f"Error adding packet to aggregator: {e}")

    def _start_updates(self) -> None:
        """Start periodic UI updates."""
        if not self._is_updating:
            self._is_updating = True
            self._schedule_update()

    def _stop_updates(self) -> None:
        """Stop periodic UI updates."""
        self._is_updating = False
        if self._update_timer:
            if self._frame:
                try:
                    self._frame.after_cancel(self._update_timer)
                except Exception:
                    pass
            self._update_timer = None

    def _schedule_update(self) -> None:
        """Schedule next UI update."""
        if self._is_updating and self._frame:
            self._update_timer = self._frame.after(
                self._update_interval,
                self._update_packet_display,
            )

    def _update_packet_display(self) -> None:
        """Update packet display from traffic aggregator with change detection."""
        try:
            # Get current snapshot for change detection
            current_snapshot = self._traffic_aggregator.get_stats_snapshot()

            # Check if anything changed
            if current_snapshot == self._last_snapshot:
                # No changes, just schedule next update
                self._schedule_update()
                return

            # Get top destinations from aggregator
            top_destinations = self._traffic_aggregator.get_top_destinations(self._top_count)

            # Get current top keys for comparison
            current_top_keys = tuple(f"{d['dst_ip']}:{d['dst_port'] or 0}" for d in top_destinations)

            # Update display
            if self._packet_tree:
                # Check if we need full refresh or incremental update
                if current_top_keys != self._last_top_keys:
                    # Full refresh when top destinations changed
                    self._packet_tree.clear()
                    for dest in top_destinations:
                        self._add_destination_to_display(dest)
                else:
                    # Incremental update - only update values
                    self._incremental_update_display(top_destinations)

            # Update cache
            self._last_snapshot = current_snapshot
            self._last_top_keys = current_top_keys

            # Update packet count (total unique destinations)
            self._update_packet_count()

            # Schedule next update
            self._schedule_update()

        except Exception as e:
            self._logger.error(f"Error updating packet display: {e}")

    def _incremental_update_display(self, top_destinations: List[Dict[str, Any]]) -> None:
        """Update display incrementally without full rebuild.

        Args:
            top_destinations: Current top destinations
        """
        if not self._packet_tree or not self._packet_tree.widget:
            return

        tree = self._packet_tree.widget

        # Get all current items
        items = tree.get_children()

        # Update each item in place
        for i, dest in enumerate(top_destinations):
            if i < len(items):
                # Update existing item
                item_id = items[i]
                values = self._format_destination_values(dest)
                tree.item(item_id, values=values)
            else:
                # Add new item
                self._add_destination_to_display(dest)

        # Remove excess items
        for i in range(len(top_destinations), len(items)):
            tree.delete(items[i])

    def _add_destination_to_display(self, dest: Dict[str, Any]) -> None:
        """Add destination to display.

        Args:
            dest: Destination statistics dict
        """
        if not self._packet_tree:
            return

        # Create display dict matching the expected format
        dest_data = {
            "dst_ip": dest.get('dst_ip', ''),
            "dst_port": dest.get('dst_port'),
            "url": dest.get('url'),
            "host": dest.get('host'),
            "length": dest.get('total_bytes', 0),
            "timestamp": dest.get('last_seen', datetime.now()).isoformat() if dest.get('last_seen') else datetime.now().isoformat(),
        }

        self._packet_tree.add_packet(dest_data)

    def _format_destination_values(self, dest: Dict[str, Any]) -> tuple:
        """Format destination data for treeview values.

        Args:
            dest: Destination statistics dict

        Returns:
            Tuple of values matching tree columns
        """
        # Format 请求地址 - destination IP:port
        dst_ip = dest.get('dst_ip', '')
        dst_port = dest.get('dst_port')
        request_address = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

        # Format 访问URL - host/url if available
        url_display = self._format_url_display(
            dest.get('url'),
            dest.get('host'),
            dest.get('dst_port')
        )

        # Format 访问端口 - destination port
        port_display = str(dst_port) if dst_port else ""

        # Format 流量size - formatted bytes
        size_display = self._format_bytes(dest.get('total_bytes', 0))

        # Format 最近访问时间 - timestamp
        timestamp = dest.get('last_seen')
        if timestamp:
            if isinstance(timestamp, datetime):
                time_str = timestamp.strftime("%H:%M:%S")
            else:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M:%S")
                except (ValueError, TypeError):
                    time_str = str(timestamp)[:8]
        else:
            time_str = ""

        return (request_address, url_display, port_display, size_display, time_str)

    def _format_url_display(self, url: Optional[str], host: Optional[str], dst_port: Optional[int]) -> str:
        """Format URL/Host for display.

        Args:
            url: Full URL
            host: Host header value or SNI hostname for HTTPS
            dst_port: Destination port

        Returns:
            Formatted URL display string
        """
        if url:
            url_display = url
            if len(url_display) > 40:
                url_display = url_display[:37] + "..."
            return url_display
        elif host:
            return host
        elif dst_port == 443:
            return "(encrypted/no SNI)"
        elif dst_port == 80:
            return "(no host)"
        return ""

    def _format_bytes(self, size: int) -> str:
        """Format bytes into human-readable format.

        Args:
            size: Size in bytes

        Returns:
            Formatted size string (B, KB, MB, GB, TB)
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                if unit == 'B':
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def _refresh_display(self) -> None:
        """Refresh the display with current traffic statistics (force full refresh)."""
        try:
            # Reset cache to force full refresh
            self._last_snapshot = {}
            self._last_top_keys = ()

            top_destinations = self._traffic_aggregator.get_top_destinations(self._top_count)

            if self._packet_tree:
                self._packet_tree.clear()
                for dest in top_destinations:
                    self._add_destination_to_display(dest)

            # Update cache
            current_snapshot = self._traffic_aggregator.get_stats_snapshot()
            self._last_snapshot = current_snapshot
            self._last_top_keys = tuple(f"{d['dst_ip']}:{d['dst_port'] or 0}" for d in top_destinations)

            self._update_packet_count()
            self._logger.info("Display refreshed")
        except Exception as e:
            self._logger.error(f"Error refreshing display: {e}")

    def _update_packet_count(self) -> None:
        """Update traffic statistics display."""
        if self._packet_tree and self._control_bar:
            count = len(self._traffic_aggregator.get_top_destinations(1000))
            self._control_bar.update_packet_count(count)

    def _show_error_message(self, title: str, message: str) -> None:
        """Show error message in a messagebox.

        Args:
            title: Dialog title
            message: Error message to display
        """
        try:
            messagebox.showerror(title, message, parent=self._frame)
        except Exception:
            # Fallback if messagebox fails
            self._logger.error(f"{title}: {message}")

    def _show_monitor_mode_fallback_error(self, error: CaptureError) -> None:
        """Show error message with monitor mode fallback suggestion.

        Args:
            error: The capture error
        """
        msg = """WiFi Monitor Mode requires Npcap with 802.11 support enabled.

To use Monitor Mode, you need to reinstall Npcap with the following option:
☑ 'Support raw 802.11 traffic (and monitor mode) for wireless adapters'

Download Npcap from: https://npcap.com/

---
ALTERNATIVE: Use Promiscuous Mode

You can still capture network traffic without Monitor Mode:
1. Uncheck 'Monitor Mode' checkbox
2. Click Start

This will capture all traffic on your local network segment (including traffic
from other devices on the same WiFi network in many cases).
"""

        try:
            result = messagebox.askyesno(
                "Monitor Mode Not Available",
                msg + "\n\nUncheck Monitor Mode and try again?",
                icon="question",
                parent=self._frame
            )
            if result:
                # Uncheck monitor mode and retry
                if self._control_bar and hasattr(self._control_bar, '_monitor_mode_var'):
                    self._control_bar._monitor_mode_var.set(False)
                    # Retry start capture without monitor mode
                    self.start_capture()
        except Exception:
            self._logger.error(f"Monitor mode error: {error}")
            # Fallback to regular error message
            self._show_error_message("Capture Error", str(error))

    def _on_packet_select(self, event) -> None:
        """Handle packet selection in treeview.

        Args:
            event: Selection event
        """
        # Could show packet details in a popup or side panel
        pass

    def _get_main_window(self):
        """Get the main window instance by traversing up the widget hierarchy.

        Returns:
            MainWindow instance or None
        """
        try:
            current = self._parent
            while current:
                if hasattr(current, '_active_capture_state'):
                    return current
                current = current.master if hasattr(current, 'master') else None
        except Exception:
            pass
        return None

    def _save_state_to_main_window(self) -> None:
        """Save current capture state to main window."""
        main_window = self._get_main_window()
        if main_window:
            state_dict = self._state.to_dict()
            if state_dict:
                main_window._active_capture_state = state_dict
                self._logger.debug("Saved capture state to main window")

    def _clear_state_from_main_window(self) -> None:
        """Clear capture state from main window."""
        main_window = self._get_main_window()
        if main_window and hasattr(main_window, '_active_capture_state'):
            main_window._active_capture_state = None
            self._logger.debug("Cleared capture state from main window")

    def save_capture_state(self) -> Optional[Dict[str, Any]]:
        """Save current capture state for restoration later.

        Returns:
            Dictionary with capture state, or None if not capturing
        """
        return self._state.to_dict()

    def restore_capture_state(self, state: Dict[str, Any]) -> None:
        """Restore capture state from previous panel instance.

        Args:
            state: Previously saved capture state
        """
        if not self._state.restore_from_dict(state):
            return

        try:
            # Restore filter value in UI
            if self._state.capture_filter:
                self._control_bar.set_filter(self._state.capture_filter)

            # Note: Traffic aggregator state is not restored since it's memory-only
            # The capture will start accumulating new statistics

            # Re-wire callbacks
            if self._state.capture:
                self._state.capture.add_callback(self._on_packet_captured)
                if self._analysis:
                    self._state.capture.add_callback(self._analysis.update)
                if self._detection:
                    self._state.capture.add_callback(self._detection.process)

            # Update UI state
            self._control_bar.set_capturing_state(True)
            self._control_bar.update_status(f"Capturing on {self._state.selected_interface}")
            self._start_updates()

            self._logger.info(f"Restored capture state for {self._state.selected_interface}")

        except Exception as e:
            self._logger.error(f"Error restoring capture state: {e}")

    def destroy(self) -> None:
        """Clean up capture panel resources."""
        self._stop_updates()

        # Stop capture if running
        if self._state.is_capturing:
            self.stop_capture()

        if self._frame:
            self._frame.destroy()

        self._logger.info("Capture panel destroyed")


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
    "TrafficAggregator",
    "CapturePanel",
    "create_capture_panel",
]
