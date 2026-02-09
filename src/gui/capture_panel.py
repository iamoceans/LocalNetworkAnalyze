"""
Packet capture panel.

Provides controls for starting/stopping packet capture,
selecting interfaces, setting filters, and viewing captured packets.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading
import queue

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

        # UI state
        self._is_capturing = False
        self._selected_interface = None
        self._capture_filter = ""
        self._interface_map: Dict[str, str] = {}

        # Packet display queue (thread-safe)
        self._packet_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._displayed_packets: List[Dict[str, Any]] = []
        self._max_display_packets = 100

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._control_frame: Optional[tk.Frame] = None
        self._packet_frame: Optional[tk.Frame] = None

        # Control widgets
        self._interface_var: Optional[ctk.StringVar] = None
        self._filter_var: Optional[ctk.StringVar] = None
        self._start_button: Optional[ctk.CTkButton] = None
        self._stop_button: Optional[ctk.CTkButton] = None
        self._save_button: Optional[ctk.CTkButton] = None
        self._clear_button: Optional[ctk.CTkButton] = None

        # Status variables
        self._packet_count_var: Optional[ctk.StringVar] = None
        self._status_var: Optional[ctk.StringVar] = None

        # Update timer
        self._update_timer: Optional[threading.Timer] = None
        self._is_updating = False

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
        
        # Ensure minimum size for control frame visibility
        self._frame.grid_rowconfigure(0, weight=0) # Header
        self._frame.grid_rowconfigure(1, weight=0) # Controls
        self._frame.grid_rowconfigure(2, weight=1) # Packets (expandable)

        # Create sections
        self._create_header()
        self._create_control_panel()
        self._create_packet_display()

        self._logger.info("Capture panel UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create panel header."""
        if not CUSTOMTKINTER_AVAILABLE:
            header = ttk.Frame(self._frame)
            header.pack(fill="x", pady=(0, 10))

            ttk.Label(
                header,
                text="Packet Capture",
                font=("Arial", 16, "bold"),
            ).pack(side="left")
            return

        # CustomTkinter header
        title = ctk.CTkLabel(
            self._frame,
            text="Packet Capture",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.pack(pady=(0, 10))

    def _create_control_panel(self) -> None:
        """Create control panel for capture settings."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._control_frame = ttk.LabelFrame(self._frame, text="Capture Controls")
            self._control_frame.pack(fill="x", pady=(0, 10))

            # Interface selection
            intf_frame = ttk.Frame(self._control_frame)
            intf_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(intf_frame, text="Interface:").pack(side="left")

            self._interface_var = tk.StringVar()
            self._interface_combo = ttk.Combobox(intf_frame, textvariable=self._interface_var, state="readonly")
            self._interface_combo.pack(side="left", padx=5)

            # Filter
            filter_frame = ttk.Frame(self._control_frame)
            filter_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(filter_frame, text="Filter:").pack(side="left")
            self._filter_var = tk.StringVar()
            ttk.Entry(filter_frame, textvariable=self._filter_var).pack(side="left", fill="x", expand=True, padx=5)

            # Buttons
            btn_frame = ttk.Frame(self._control_frame)
            btn_frame.pack(fill="x", padx=5, pady=5)

            self._start_button = ttk.Button(btn_frame, text="Start", command=self.start_capture)
            self._start_button.pack(side="left", padx=2)

            self._stop_button = ttk.Button(btn_frame, text="Stop", command=self.stop_capture, state="disabled")
            self._stop_button.pack(side="left", padx=2)

            self._clear_button = ttk.Button(btn_frame, text="Clear", command=self.clear_packets)
            self._clear_button.pack(side="left", padx=2)

            self._save_button = ttk.Button(btn_frame, text="Save", command=self.save_packets)
            self._save_button.pack(side="left", padx=2)

            # Status
            status_frame = ttk.Frame(self._control_frame)
            status_frame.pack(fill="x", padx=5, pady=5)

            self._packet_count_var = tk.StringVar(value="Packets: 0")
            ttk.Label(status_frame, textvariable=self._packet_count_var).pack(side="left")

            self._status_var = tk.StringVar(value="Ready")
            ttk.Label(status_frame, textvariable=self._status_var).pack(side="right")
            return

        # CustomTkinter control panel
        self._control_frame = ctk.CTkFrame(self._frame)
        self._control_frame.pack(fill="x", pady=(0, 10))

        # Title
        title = ctk.CTkLabel(
            self._control_frame,
            text="Capture Settings",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Interface selection
        intf_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        intf_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            intf_frame,
            text="Interface:",
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=5)

        self._interface_var = ctk.StringVar()
        self._interface_combo = ctk.CTkComboBox(
            intf_frame,
            width=200,
            values=[],
            command=lambda v: self._interface_var.set(v),
        )
        # Manually set variable logic since 'variable' param is not supported in this CTk version
        self._interface_var.trace_add("write", lambda *args: self._interface_combo.set(self._interface_var.get()))
        self._interface_combo.pack(side="left", padx=5)

        # Refresh button
        refresh_btn = ctk.CTkButton(
            intf_frame,
            text="Refresh",
            width=80,
            command=self._refresh_interfaces,
        )
        refresh_btn.pack(side="left", padx=5)

        # Filter
        filter_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        filter_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            filter_frame,
            text="Filter (BPF):",
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=5)

        self._filter_var = ctk.StringVar(value="")
        filter_entry = ctk.CTkEntry(
            filter_frame,
            textvariable=self._filter_var,
            placeholder_text="e.g., tcp port 80",
        )
        filter_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Control buttons
        btn_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=5)

        self._start_button = ctk.CTkButton(
            btn_frame,
            text="▶ Start Capture",
            width=120,
            command=self.start_capture,
            fg_color=("green", "darkgreen"),
        )
        self._start_button.pack(side="left", padx=5)

        self._stop_button = ctk.CTkButton(
            btn_frame,
            text="⏹ Stop",
            width=120,
            command=self.stop_capture,
            fg_color=("red", "darkred"),
            state="disabled",
        )
        self._stop_button.pack(side="left", padx=5)

        self._clear_button = ctk.CTkButton(
            btn_frame,
            text="Clear",
            width=100,
            command=self.clear_packets,
        )
        self._clear_button.pack(side="left", padx=5)

        self._save_button = ctk.CTkButton(
            btn_frame,
            text="Save",
            width=100,
            command=self.save_packets,
        )
        self._save_button.pack(side="left", padx=5)

        # Status bar
        status_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        status_frame.pack(fill="x", padx=10, pady=(5, 10))

        self._packet_count_var = ctk.StringVar(value="Packets: 0")
        ctk.CTkLabel(
            status_frame,
            textvariable=self._packet_count_var,
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=5)

        self._status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(
            status_frame,
            textvariable=self._status_var,
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(side="right", padx=5)

        # Load interfaces
        self._refresh_interfaces()

    def _create_packet_display(self) -> None:
        """Create packet display area."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._packet_frame = ttk.LabelFrame(self._frame, text="Captured Packets")
            self._packet_frame.pack(fill="both", expand=True)

            # Create treeview with URL column
            columns = ("Time", "Source", "Destination", "Protocol", "URL/Host", "Length")
            self._packet_tree = ttk.Treeview(self._packet_frame, columns=columns, show="headings")

            # Set column widths
            self._packet_tree.column("Time", width=80)
            self._packet_tree.column("Source", width=150)
            self._packet_tree.column("Destination", width=150)
            self._packet_tree.column("Protocol", width=80)
            self._packet_tree.column("URL/Host", width=250)
            self._packet_tree.column("Length", width=80)

            for col in columns:
                self._packet_tree.heading(col, text=col)

            # Scrollbar
            scrollbar = ttk.Scrollbar(self._packet_frame, orient="vertical", command=self._packet_tree.yview)
            self._packet_tree.configure(yscrollcommand=scrollbar.set)

            self._packet_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Bind select event
            self._packet_tree.bind("<<TreeviewSelect>>", self._on_packet_select)
            return

        # CustomTkinter packet display
        self._packet_frame = ctk.CTkFrame(self._frame)
        self._packet_frame.pack(fill="both", expand=True)

        # Title
        title = ctk.CTkLabel(
            self._packet_frame,
            text="Captured Packets",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Note: For CustomTkinter, we'd use a scrollable frame or table widget
        # For simplicity, using standard ttk.Treeview
        tree_frame = ttk.Frame(self._packet_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Time", "Source", "Destination", "Protocol", "URL/Host", "Length")
        self._packet_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        # Set column widths
        self._packet_tree.column("Time", width=80)
        self._packet_tree.column("Source", width=150)
        self._packet_tree.column("Destination", width=150)
        self._packet_tree.column("Protocol", width=80)
        self._packet_tree.column("URL/Host", width=250)
        self._packet_tree.column("Length", width=80)

        for col in columns:
            self._packet_tree.heading(col, text=col)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self._packet_tree.yview)
        self._packet_tree.configure(yscrollcommand=scrollbar.set)

        self._packet_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._packet_tree.bind("<<TreeviewSelect>>", self._on_packet_select)

    def _refresh_interfaces(self) -> None:
        """Refresh available network interfaces."""
        try:
            if self._capture:
                interfaces_data = self._capture.get_interfaces()
                self._interface_map.clear()
                
                display_names = []
                for iface in interfaces_data:
                    # Create user friendly name: "Description (IP)"
                    name = iface["name"]
                    desc = iface.get("description", name)
                    ip = iface.get("address", "")
                    
                    if ip:
                        display_name = f"{desc} ({ip})"
                    else:
                        display_name = desc
                        
                    # Handle duplicate display names or make sure unique
                    if display_name in self._interface_map:
                        display_name = f"{display_name} [{name}]"
                        
                    self._interface_map[display_name] = name
                    display_names.append(display_name)

                if CUSTOMTKINTER_AVAILABLE:
                    self._interface_combo.configure(values=display_names)
                    if display_names:
                        # Try to select the first one if nothing selected
                        if not self._interface_var.get():
                            self._interface_var.set(display_names[0])
                            self._interface_combo.set(display_names[0])
                        # Or if current selection is invalid
                        elif self._interface_var.get() not in display_names:
                             self._interface_var.set(display_names[0])
                             self._interface_combo.set(display_names[0])
                else:
                    self._interface_combo['values'] = display_names
                    if display_names:
                        if not self._interface_var.get():
                            self._interface_var.set(display_names[0])
                        elif self._interface_var.get() not in display_names:
                            self._interface_var.set(display_names[0])

                self._logger.info(f"Loaded {len(display_names)} interfaces")

        except Exception as e:
            self._logger.error(f"Error refreshing interfaces: {e}")

    def start_capture(self) -> None:
        """Start packet capture."""
        try:
            # Get interface
            selection = self._interface_var.get()
            if not selection:
                self._update_status("Please select an interface")
                return

            # Resolve display name to actual interface name
            interface = self._interface_map.get(selection, selection)

            # Get filter
            capture_filter = self._filter_var.get().strip()

            # Create new capture instance with selected interface and filter
            # Store the original capture to restore later if needed
            if not hasattr(self, '_original_capture'):
                self._original_capture = self._capture

            # Create new capture with specified interface and filter
            self._capture = create_packet_capture(
                backend="scapy",
                interface=interface,
                filter=capture_filter,
            )

            # Wire up callbacks
            self._capture.add_callback(self._on_packet_captured)

            # Explicitly wire up analysis and detection engines
            if self._analysis:
                self._capture.add_callback(self._analysis.update)
            if self._detection:
                self._capture.add_callback(self._detection.process)

            # Start capture (no arguments needed, interface and filter are set in __init__)
            self._capture.start_capture()

            self._is_capturing = True
            self._selected_interface = interface
            self._capture_filter = capture_filter

            # Update UI
            if self._start_button:
                self._start_button.configure(state="disabled")
            if self._stop_button:
                self._stop_button.configure(state="normal")

            self._update_status(f"Capturing on {interface}")
            self._start_updates()

            # Save capture state to main window for panel switching
            self._save_state_to_main_window()

            self._logger.info(f"Capture started on {interface}")

        except CaptureError as e:
            self._logger.error(f"Capture error: {e}")
            msg = str(e)

            # Build detailed error message for messagebox
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

            # Show messagebox for important errors
            self._show_error_message("Capture Error", full_error)

            self._update_status(msg + " - See details")

            # Reset UI state
            self._is_capturing = False
            if self._start_button:
                self._start_button.configure(state="normal")
            if self._stop_button:
                self._stop_button.configure(state="disabled")

        except Exception as e:
            self._logger.error(f"Error starting capture: {e}")
            self._show_error_message("Unexpected Error", f"An unexpected error occurred:\n\n{e}")
            self._update_status(f"Error: {e}")

    def stop_capture(self) -> None:
        """Stop packet capture."""
        try:
            if self._capture and self._is_capturing:
                self._capture.stop_capture()

            self._is_capturing = False

            # Update UI
            if self._start_button:
                self._start_button.configure(state="normal")
            if self._stop_button:
                self._stop_button.configure(state="disabled")

            self._update_status("Capture stopped")
            self._stop_updates()

            # Clear saved state from main window
            self._clear_state_from_main_window()

            self._logger.info("Capture stopped")

        except Exception as e:
            self._logger.error(f"Error stopping capture: {e}")
            self._update_status(f"Error: {e}")

    def clear_packets(self) -> None:
        """Clear displayed packets."""
        self._displayed_packets.clear()

        if hasattr(self, '_packet_tree'):
            for item in self._packet_tree.get_children():
                self._packet_tree.delete(item)

        self._update_packet_count()

    def save_packets(self) -> None:
        """Save captured packets to database."""
        if not self._database:
            self._update_status("No database available")
            return

        try:
            # Get packet repository
            from src.storage import create_packet_repository

            packet_repo = create_packet_repository(self._database)

            # Save packets
            saved = 0
            for packet_data in self._displayed_packets:
                # Convert to PacketInfo
                packet = PacketInfo(
                    timestamp=datetime.fromisoformat(packet_data['timestamp']),
                    src_ip=packet_data['src_ip'],
                    dst_ip=packet_data['dst_ip'],
                    src_port=packet_data.get('src_port'),
                    dst_port=packet_data.get('dst_port'),
                    protocol=packet_data['protocol'],
                    length=packet_data['length'],
                )

                packet_repo.save(packet)
                saved += 1

            self._update_status(f"Saved {saved} packets to database")
            self._logger.info(f"Saved {saved} packets")

        except Exception as e:
            self._logger.error(f"Error saving packets: {e}")
            self._update_status(f"Error: {e}")

    def _on_packet_captured(self, packet: PacketInfo) -> None:
        """Handle captured packet callback.

        Args:
            packet: Captured packet info
        """
        try:
            # Add to queue (non-blocking)
            if not self._packet_queue.full():
                self._packet_queue.put_nowait(packet)
        except Exception:
            pass  # Drop packet if queue is full

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
                100,  # 100ms
                self._update_packet_display,
            )

    def _update_packet_display(self) -> None:
        """Update packet display from queue."""
        try:
            # Process all queued packets
            while not self._packet_queue.empty():
                try:
                    packet = self._packet_queue.get_nowait()
                    self._add_packet_to_display(packet)
                except queue.Empty:
                    break

            # Update packet count
            self._update_packet_count()

            # Schedule next update
            self._schedule_update()

        except Exception as e:
            self._logger.error(f"Error updating packet display: {e}")

    def _add_packet_to_display(self, packet: PacketInfo) -> None:
        """Add packet to display.

        Args:
            packet: Packet to add
        """
        # Create display dict
        packet_data = {
            "timestamp": packet.timestamp.isoformat(),
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "protocol": packet.protocol,
            "length": packet.length,
            "url": packet.url,
            "host": packet.host,
        }

        # Add to list
        self._displayed_packets.append(packet_data)

        # Limit list size
        if len(self._displayed_packets) > self._max_display_packets:
            self._displayed_packets.pop(0)

        # Add to treeview
        if hasattr(self, '_packet_tree'):
            time_str = packet.timestamp.strftime("%H:%M:%S")
            src = f"{packet.src_ip}:{packet.src_port}" if packet.src_port else packet.src_ip
            dst = f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else packet.dst_ip

            # Determine URL/Host display
            url_display = ""
            if packet.url:
                # Show full URL
                url_display = packet.url
                # Truncate if too long
                if len(url_display) > 40:
                    url_display = url_display[:37] + "..."
            elif packet.host:
                url_display = packet.host
            elif packet.dst_port in (80, 443):
                url_display = "(encrypted/no host)"

            self._packet_tree.insert("", 0, values=(
                time_str,
                src,
                dst,
                packet.protocol,
                url_display,
                packet.length,
            ))

            # Limit treeview items
            items = self._packet_tree.get_children()
            if len(items) > self._max_display_packets:
                self._packet_tree.delete(items[-1])

    def _update_packet_count(self) -> None:
        """Update packet count display."""
        if self._packet_count_var:
            self._packet_count_var.set(f"Packets: {len(self._displayed_packets)}")

    def _update_status(self, message: str) -> None:
        """Update status display.

        Args:
            message: Status message
        """
        if self._status_var:
            self._status_var.set(message)

    def _show_error_message(self, title: str, message: str) -> None:
        """Show error message in a messagebox.

        Args:
            title: Dialog title
            message: Error message to display
        """
        try:
            messagebox.showerror(title, message, parent=self._frame)
        except Exception:
            # Fallback if messagebox fails (e.g., during early initialization)
            self._logger.error(f"{title}: {message}")

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
            state = self.save_capture_state()
            if state:
                main_window._active_capture_state = state
                self._logger.debug("Saved capture state to main window")

    def _clear_state_from_main_window(self) -> None:
        """Clear capture state from main window."""
        main_window = self._get_main_window()
        if main_window and hasattr(main_window, '_active_capture_state'):
            main_window._active_capture_state = None
            self._logger.debug("Cleared capture state from main window")

    def save_capture_state(self) -> Optional[Dict[str, Any]]:
        """Handle packet selection in treeview.

        Args:
            event: Selection event
        """
        # Could show packet details in a popup or side panel
        pass

    def save_capture_state(self) -> Optional[Dict[str, Any]]:
        """Save current capture state for restoration later.

        Returns:
            Dictionary with capture state, or None if not capturing
        """
        if not self._is_capturing or not self._capture:
            return None

        return {
            'is_capturing': True,
            'capture': self._capture,
            'selected_interface': self._selected_interface,
            'capture_filter': self._capture_filter,
            'displayed_packets': self._displayed_packets.copy(),
        }

    def restore_capture_state(self, state: Dict[str, Any]) -> None:
        """Restore capture state from previous panel instance.

        Args:
            state: Previously saved capture state
        """
        if not state or not state.get('is_capturing'):
            return

        try:
            # Restore the active capture object
            self._capture = state['capture']
            self._is_capturing = True
            self._selected_interface = state.get('selected_interface')
            self._capture_filter = state.get('capture_filter', '')

            # Restore displayed packets
            self._displayed_packets = state.get('displayed_packets', [])

            # Re-wire callbacks
            self._capture.add_callback(self._on_packet_captured)
            if self._analysis:
                self._capture.add_callback(self._analysis.update)
            if self._detection:
                self._capture.add_callback(self._detection.process)

            # Restore filter value in UI
            if self._filter_var and self._capture_filter:
                self._filter_var.set(self._capture_filter)

            # Update UI state
            if self._start_button:
                self._start_button.configure(state="disabled")
            if self._stop_button:
                self._stop_button.configure(state="normal")

            # Update status
            self._update_status(f"Capturing on {self._selected_interface}")

            # Restore packet display
            if hasattr(self, '_packet_tree'):
                # Clear existing items
                for item in self._packet_tree.get_children():
                    self._packet_tree.delete(item)

                # Restore displayed packets
                for packet_data in self._displayed_packets:
                    time_str = packet_data.get('timestamp', '')
                    if isinstance(time_str, str):
                        from datetime import datetime
                        try:
                            dt = datetime.fromisoformat(time_str)
                            time_str = dt.strftime("%H:%M:%S")
                        except:
                            time_str = time_str[:8]

                    src = f"{packet_data['src_ip']}:{packet_data['src_port']}" if packet_data.get('src_port') else packet_data['src_ip']
                    dst = f"{packet_data['dst_ip']}:{packet_data['dst_port']}" if packet_data.get('dst_port') else packet_data['dst_ip']

                    # Determine URL/Host display
                    url_display = ""
                    url = packet_data.get('url')
                    host = packet_data.get('host')
                    if url:
                        url_display = url
                        if len(url_display) > 40:
                            url_display = url_display[:37] + "..."
                    elif host:
                        url_display = host
                    elif packet_data.get('dst_port') in (80, 443):
                        url_display = "(encrypted/no host)"

                    self._packet_tree.insert("", 0, values=(
                        time_str,
                        src,
                        dst,
                        packet_data['protocol'],
                        url_display,
                        packet_data['length'],
                    ))

            self._update_packet_count()
            self._start_updates()

            self._logger.info(f"Restored capture state for {self._selected_interface}")

        except Exception as e:
            self._logger.error(f"Error restoring capture state: {e}")

    def destroy(self) -> None:
        """Clean up capture panel resources."""
        self._stop_updates()

        # Stop capture if running
        if self._is_capturing:
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
    "CapturePanel",
    "create_capture_panel",
]
