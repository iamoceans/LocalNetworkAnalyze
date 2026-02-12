"""
Control bar component for capture panel with neon styling.

Provides interface selection, filter input, action buttons, and status display
with cyber-security theme.
"""

from typing import Optional, Callable, Dict

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False

import tkinter as tk
from tkinter import ttk

# Import theme system
# Import iOS theme system
from src.gui.theme.colors import Colors, ThemeMode, iOSSpacing
from src.gui.theme.typography import Fonts


class ControlBar:
    """Control bar for packet capture operations.

    Manages interface selection, BPF filter input, action buttons,
    and status display.
    """

    def __init__(self, parent: tk.Widget):
        """Initialize control bar.

        Args:
            parent: Parent widget
        """
        self._parent = parent
        self._frame: Optional[tk.Frame] = None
        self._interface_map: Dict[str, str] = {}

        # Variables
        self._interface_var: Optional[tk.StringVar] = None
        self._filter_var: Optional[tk.StringVar] = None
        self._monitor_mode_var: Optional[tk.BooleanVar] = None
        self._packet_count_var: Optional[tk.StringVar] = None
        self._status_var: Optional[tk.StringVar] = None

        # Widgets
        self._interface_combo: Optional[ttk.Combobox] = None
        self._monitor_mode_checkbox: Optional[ttk.Checkbutton] = None
        self._start_button: Optional[ttk.Button] = None
        self._stop_button: Optional[ttk.Button] = None
        self._clear_button: Optional[ttk.Button] = None
        self._save_button: Optional[ttk.Button] = None

        # Callbacks
        self._on_refresh_callback: Optional[Callable] = None
        self._on_start_callback: Optional[Callable] = None
        self._on_stop_callback: Optional[Callable] = None
        self._on_clear_callback: Optional[Callable] = None
        self._on_save_callback: Optional[Callable] = None

    def create(self, parent_frame: tk.Frame) -> tk.Frame:
        """Create the control bar UI.

        Args:
            parent_frame: Frame to contain the control bar

        Returns:
            Created frame widget
        """
        if not CUSTOMTKINTER_AVAILABLE:
            return self._create_tk_control_bar(parent_frame)
        return self._create_ctk_control_bar(parent_frame)

    def _create_tk_control_bar(self, parent_frame: tk.Frame) -> tk.Frame:
        """Create tkinter-style control bar.

        Args:
            parent_frame: Parent frame

        Returns:
            Created frame
        """
        self._frame = ttk.LabelFrame(parent_frame, text="Capture Controls")
        self._frame.pack(fill="x", pady=(0, 10))

        # Interface selection
        intf_frame = ttk.Frame(self._frame)
        intf_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(intf_frame, text="Interface:").pack(side="left")

        self._interface_var = tk.StringVar()
        self._interface_combo = ttk.Combobox(
            intf_frame,
            textvariable=self._interface_var,
            state="readonly"
        )
        self._interface_combo.pack(side="left", padx=5)

        # Filter
        filter_frame = ttk.Frame(self._frame)
        filter_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(filter_frame, text="Filter:").pack(side="left")
        self._filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self._filter_var).pack(
            side="left", fill="x", expand=True, padx=5
        )

        # Monitor mode option
        options_frame = ttk.Frame(self._frame)
        options_frame.pack(fill="x", padx=5, pady=5)
        self._monitor_mode_var = tk.BooleanVar(value=False)
        self._monitor_mode_checkbox = ttk.Checkbutton(
            options_frame,
            text="Monitor Mode (capture all WiFi traffic)",
            variable=self._monitor_mode_var,
        )
        self._monitor_mode_checkbox.pack(side="left")

        # Buttons
        self._create_tk_buttons()

        # Status
        self._create_tk_status_bar()

        return self._frame

    def _create_tk_buttons(self) -> None:
        """Create tkinter-style buttons."""
        btn_frame = ttk.Frame(self._frame)
        btn_frame.pack(fill="x", padx=5, pady=5)

        self._start_button = ttk.Button(
            btn_frame,
            text="Start",
            command=self._on_start
        )
        self._start_button.pack(side="left", padx=2)

        self._stop_button = ttk.Button(
            btn_frame,
            text="Stop",
            command=self._on_stop,
            state="disabled"
        )
        self._stop_button.pack(side="left", padx=2)

        self._clear_button = ttk.Button(
            btn_frame,
            text="Clear",
            command=self._on_clear
        )
        self._clear_button.pack(side="left", padx=2)

        self._save_button = ttk.Button(
            btn_frame,
            text="Save",
            command=self._on_save
        )
        self._save_button.pack(side="left", padx=2)

    def _create_tk_status_bar(self) -> None:
        """Create tkinter-style status bar."""
        status_frame = ttk.Frame(self._frame)
        status_frame.pack(fill="x", padx=5, pady=5)

        self._packet_count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(status_frame, textvariable=self._packet_count_var).pack(side="left")

        self._status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self._status_var).pack(side="right")

    def _create_ctk_control_bar(self, parent_frame: tk.Frame) -> tk.Frame:
        """Create CustomTkinter-style control bar.

        Args:
            parent_frame: Parent frame

        Returns:
            Created frame
        """
        self._frame = ctk.CTkFrame(parent_frame)
        self._frame.pack(fill="x", pady=(0, 10))

        # Title
        title = ctk.CTkLabel(
            self._frame,
            text="Capture Settings",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Interface selection
        self._create_ctk_interface_selector()

        # Filter
        self._create_ctk_filter_entry()

        # Monitor mode option
        self._create_ctk_monitor_mode_option()

        # Buttons
        self._create_ctk_buttons()

        # Status
        self._create_ctk_status_bar()

        return self._frame

    def _create_ctk_interface_selector(self) -> None:
        """Create CustomTkinter interface selector."""
        intf_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
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
        self._interface_var.trace_add(
            "write",
            lambda *args: self._interface_combo.set(self._interface_var.get())
        )
        self._interface_combo.pack(side="left", padx=5)

        refresh_btn = ctk.CTkButton(
            intf_frame,
            text="Refresh",
            width=80,
            command=self._on_refresh
        )
        refresh_btn.pack(side="left", padx=5)

    def _create_ctk_filter_entry(self) -> None:
        """Create CustomTkinter filter entry."""
        filter_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
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

    def _create_ctk_monitor_mode_option(self) -> None:
        """Create CustomTkinter monitor mode option."""
        monitor_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        monitor_frame.pack(fill="x", padx=10, pady=5)

        self._monitor_mode_var = ctk.BooleanVar(value=False)
        monitor_checkbox = ctk.CTkCheckBox(
            monitor_frame,
            text="Monitor Mode (capture all WiFi traffic)",
            variable=self._monitor_mode_var,
            font=ctk.CTkFont(size=11),
            checkbox_width=20,
            checkbox_height=20,
        )
        monitor_checkbox.pack(side="left", padx=5)

    def _create_ctk_buttons(self) -> None:
        """Create CustomTkinter buttons with neon styling."""
        btn_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        btn_frame.pack(fill="x", padx=10, pady=6)

        # Start button with iOS green
        self._start_button = ctk.CTkButton(
            btn_frame,
            text="▶ Start",
            width=110,
            height=38,
            font=("Fira Code", 12, "bold"),
            command=self._on_start,
            fg_color=Colors.THEME.system_green,
            hover_color=Colors.THEME.success_bg,
            text_color=Colors.THEME.bg_primary,
            corner_radius=8,
            border_width=0,
        )
        self._start_button.pack(side="left", padx=4)

        # Stop button with iOS red
        self._stop_button = ctk.CTkButton(
            btn_frame,
            text="⏹ Stop",
            width=100,
            height=38,
            font=("Fira Code", 12, "bold"),
            command=self._on_stop,
            fg_color=Colors.THEME.system_red,
            hover_color=Colors.THEME.error_bg,
            text_color=Colors.THEME.bg_primary,
            corner_radius=8,
            border_width=0,
            state="disabled",
        )
        self._stop_button.pack(side="left", padx=4)

        # Clear button (gray)
        self._clear_button = ctk.CTkButton(
            btn_frame,
            text="Clear",
            width=90,
            height=38,
            font=("Fira Code", 12),
            command=self._on_clear,
            fg_color=Colors.THEME.bg_hover,
            hover_color=Colors.THEME.bg_tertiary,
            text_color=Colors.THEME.text_secondary,
            corner_radius=8,
            border_width=1,
            border_color=Colors.THEME.border_default,
        )
        self._clear_button.pack(side="left", padx=4)

        # Save button (blue)
        self._save_button = ctk.CTkButton(
            btn_frame,
            text="Save",
            width=90,
            height=38,
            font=("Fira Code", 12),
            command=self._on_save,
            fg_color=Colors.THEME.info_bg,
            hover_color=Colors.THEME.bg_tertiary,
            text_color=Colors.THEME.info,
            corner_radius=8,
            border_width=1,
            border_color=Colors.THEME.border_default,
        )
        self._save_button.pack(side="left", padx=4)

    def _create_ctk_status_bar(self) -> None:
        """Create CustomTkinter status bar with neon indicators."""
        status_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        status_frame.pack(fill="x", padx=10, pady=(6, 10))

        self._packet_count_var = ctk.StringVar(value="Packets: 0")
        ctk.CTkLabel(
            status_frame,
            textvariable=self._packet_count_var,
            font=("Fira Code", 11),
            text_color=Colors.THEME.system_green,
        ).pack(side="left", padx=5)

        self._status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(
            status_frame,
            textvariable=self._status_var,
            font=("Fira Code", 11),
            text_color=Colors.THEME.text_secondary,
        ).pack(side="right", padx=5)

    # Callback setters
    def set_refresh_callback(self, callback: Callable) -> None:
        """Set refresh button callback.

        Args:
            callback: Function to call on refresh
        """
        self._on_refresh_callback = callback

    def set_start_callback(self, callback: Callable) -> None:
        """Set start button callback.

        Args:
            callback: Function to call on start
        """
        self._on_start_callback = callback

    def set_stop_callback(self, callback: Callable) -> None:
        """Set stop button callback.

        Args:
            callback: Function to call on stop
        """
        self._on_stop_callback = callback

    def set_clear_callback(self, callback: Callable) -> None:
        """Set clear button callback.

        Args:
            callback: Function to call on clear
        """
        self._on_clear_callback = callback

    def set_save_callback(self, callback: Callable) -> None:
        """Set save button callback.

        Args:
            callback: Function to call on save
        """
        self._on_save_callback = callback

    # Button handlers
    def _on_refresh(self) -> None:
        """Handle refresh button click."""
        if self._on_refresh_callback:
            self._on_refresh_callback()

    def _on_start(self) -> None:
        """Handle start button click."""
        if self._on_start_callback:
            self._on_start_callback()

    def _on_stop(self) -> None:
        """Handle stop button click."""
        if self._on_stop_callback:
            self._on_stop_callback()

    def _on_clear(self) -> None:
        """Handle clear button click."""
        if self._on_clear_callback:
            self._on_clear_callback()

    def _on_save(self) -> None:
        """Handle save button click."""
        if self._on_save_callback:
            self._on_save_callback()

    # Public methods
    def set_interface_options(self, interfaces_data: list) -> None:
        """Set available interface options.

        Args:
            interfaces_data: List of interface dicts with 'name', 'description', 'address'
        """
        self._interface_map.clear()
        display_names = []

        for iface in interfaces_data:
            name = iface["name"]
            desc = iface.get("description", name)
            ip = iface.get("address", "")

            if ip:
                display_name = f"{desc} ({ip})"
            else:
                display_name = desc

            # Handle duplicates
            if display_name in self._interface_map:
                display_name = f"{display_name} [{name}]"

            self._interface_map[display_name] = name
            display_names.append(display_name)

        if CUSTOMTKINTER_AVAILABLE:
            self._interface_combo.configure(values=display_names)
            if display_names and not self._interface_var.get():
                self._interface_var.set(display_names[0])
                self._interface_combo.set(display_names[0])
        else:
            self._interface_combo['values'] = display_names
            if display_names and not self._interface_var.get():
                self._interface_var.set(display_names[0])

    def get_selected_interface(self) -> Optional[str]:
        """Get the selected interface name.

        Returns:
            Interface name or None
        """
        selection = self._interface_var.get() if self._interface_var else None
        if not selection:
            return None
        return self._interface_map.get(selection, selection)

    def get_filter(self) -> str:
        """Get the filter text.

        Returns:
            Filter string
        """
        return self._filter_var.get().strip() if self._filter_var else ""

    def get_monitor_mode(self) -> bool:
        """Get the monitor mode setting.

        Returns:
            True if monitor mode is enabled, False otherwise
        """
        return self._monitor_mode_var.get() if self._monitor_mode_var else False

    def set_filter(self, filter_text: str) -> None:
        """Set the filter text.

        Args:
            filter_text: Filter string to set
        """
        if self._filter_var:
            self._filter_var.set(filter_text)

    def update_status(self, message: str) -> None:
        """Update status display.

        Args:
            message: Status message
        """
        if self._status_var:
            self._status_var.set(message)

    def update_packet_count(self, count: int) -> None:
        """Update packet count display.

        Args:
            count: Number of packets
        """
        if self._packet_count_var:
            self._packet_count_var.set(f"Packets: {count}")

    def set_capturing_state(self, is_capturing: bool) -> None:
        """Enable/disable buttons based on capture state.

        Args:
            is_capturing: True if capturing, False otherwise
        """
        if self._start_button:
            state = "disabled" if is_capturing else "normal"
            self._start_button.configure(state=state)
        if self._stop_button:
            state = "normal" if is_capturing else "disabled"
            self._stop_button.configure(state=state)


__all__ = ["ControlBar"]
