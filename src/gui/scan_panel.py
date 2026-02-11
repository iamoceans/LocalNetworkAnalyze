"""
Network scan panel with neon styling.

Provides controls for network discovery and port scanning,
with real-time results display.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading
import ipaddress

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

from src.core.logger import get_logger
from src.scan import NetworkScannerWrapper as NetworkScanner, create_network_scanner
from src.storage import DatabaseManager

# Import theme system
from src.gui.theme.colors import Colors, NeonColors
from src.gui.theme.typography import Fonts


class ScanPanel:
    """Panel for network scanning operations.

    Provides interface for:
    - Network discovery (ARP/ICMP)
    - Port scanning
    - Results display
    - Saving results to database
    """

    def __init__(
        self,
        parent,
        scanner: Optional[NetworkScanner] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        """Initialize scan panel.

        Args:
            parent: Parent widget
            scanner: Network scanner engine
            database: Database manager
        """
        self._parent = parent
        self._scanner = scanner
        self._database = database
        self._logger = get_logger(__name__)

        # UI state
        self._is_scanning = False
        self._scan_results: List[Dict[str, Any]] = []

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._control_frame: Optional[tk.Frame] = None
        self._results_frame: Optional[tk.Frame] = None

        # Control widgets
        self._scan_type_var: Optional[ctk.StringVar] = None
        self._target_var: Optional[ctk.StringVar] = None
        self._ports_var: Optional[ctk.StringVar] = None
        self._start_button: Optional[ctk.CTkButton] = None
        self._stop_button: Optional[ctk.CTkButton] = None
        self._save_button: Optional[ctk.CTkButton] = None
        self._clear_button: Optional[ctk.CTkButton] = None

        # Status variables
        self._status_var: Optional[ctk.StringVar] = None
        self._progress_var: Optional[ctk.StringVar] = None

        self._logger.info("Scan panel initialized")

    def build(self) -> tk.Frame:
        """Build scan panel UI.

        Returns:
            Scan panel frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color="transparent")
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create sections
        self._create_header()
        self._create_control_panel()
        self._create_results_display()

        self._logger.info("Scan panel UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create panel header with neon styling."""
        if not CUSTOMTKINTER_AVAILABLE:
            header = ttk.Frame(self._frame)
            header.pack(fill="x", pady=(0, 10))

            ttk.Label(
                header,
                text="🔍 Network Scan",
                font=("Fira Code", 16, "bold"),
            ).pack(side="left")
            return

        # CustomTkinter header with neon styling
        title = ctk.CTkLabel(
            self._frame,
            text="🔍 Network Scanner",
            font=("Fira Code", 20, "bold"),
            text_color=Colors.NEON.neon_yellow,
        )
        title.pack(pady=(0, 12))

    def _create_control_panel(self) -> None:
        """Create control panel for scan settings."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._control_frame = ttk.LabelFrame(self._frame, text="Scan Settings")
            self._control_frame.pack(fill="x", pady=(0, 10))

            # Scan type
            type_frame = ttk.Frame(self._control_frame)
            type_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(type_frame, text="Scan Type:").pack(side="left")
            self._scan_type_var = tk.StringVar(value="arp")
            type_combo = ttk.Combobox(
                type_frame,
                textvariable=self._scan_type_var,
                values=["arp", "icmp", "port"],
                state="readonly",
            )
            type_combo.pack(side="left", padx=5)

            # Target
            target_frame = ttk.Frame(self._control_frame)
            target_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(target_frame, text="Target:").pack(side="left")
            self._target_var = tk.StringVar(value="192.168.1.0/24")
            ttk.Entry(target_frame, textvariable=self._target_var).pack(side="left", fill="x", expand=True, padx=5)

            # Ports (for port scan)
            ports_frame = ttk.Frame(self._control_frame)
            ports_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(ports_frame, text="Ports:").pack(side="left")
            self._ports_var = tk.StringVar(value="1-1024")
            ttk.Entry(ports_frame, textvariable=self._ports_var).pack(side="left", fill="x", expand=True, padx=5)

            # Buttons
            btn_frame = ttk.Frame(self._control_frame)
            btn_frame.pack(fill="x", padx=5, pady=5)

            self._start_button = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
            self._start_button.pack(side="left", padx=2)

            self._stop_button = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state="disabled")
            self._stop_button.pack(side="left", padx=2)

            self._clear_button = ttk.Button(btn_frame, text="Clear", command=self.clear_results)
            self._clear_button.pack(side="left", padx=2)

            self._save_button = ttk.Button(btn_frame, text="Save", command=self.save_results)
            self._save_button.pack(side="left", padx=2)

            # Status
            status_frame = ttk.Frame(self._control_frame)
            status_frame.pack(fill="x", padx=5, pady=5)

            self._progress_var = tk.StringVar(value="")
            ttk.Label(status_frame, textvariable=self._progress_var).pack(side="left")

            self._status_var = tk.StringVar(value="Ready")
            ttk.Label(status_frame, textvariable=self._status_var).pack(side="right")
            return

        # CustomTkinter control panel
        self._control_frame = ctk.CTkFrame(self._frame)
        self._control_frame.pack(fill="x", pady=(0, 10))

        # Title
        title = ctk.CTkLabel(
            self._control_frame,
            text="Scan Configuration",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Scan type selection
        type_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        type_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            type_frame,
            text="Scan Type:",
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=5)

        self._scan_type_var = ctk.StringVar(value="arp")
        self._scan_type_combo = ctk.CTkComboBox(
            type_frame,
            values=["arp", "icmp", "port"],
            width=150,
            command=self._on_scan_type_changed,
        )
        self._scan_type_combo.set("arp")
        self._scan_type_combo.pack(side="left", padx=5)

        # Type descriptions
        desc_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        desc_frame.pack(fill="x", padx=10, pady=2)

        self._type_desc_var = ctk.StringVar(value="ARP Scan - Discover hosts on local network")
        ctk.CTkLabel(
            desc_frame,
            textvariable=self._type_desc_var,
            font=ctk.CTkFont(size=10),
            text_color="gray",
        ).pack(side="left", padx=5)

        # Target input
        target_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        target_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            target_frame,
            text="Target:",
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=5)

        self._target_var = ctk.StringVar(value="192.168.1.0/24")
        target_entry = ctk.CTkEntry(
            target_frame,
            variable=self._target_var,
            placeholder_text="IP address or CIDR (e.g., 192.168.1.0/24)",
        )
        target_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Port input (for port scan)
        self._ports_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        self._ports_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            self._ports_frame,
            text="Ports:",
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=5)

        self._ports_var = ctk.StringVar(value="1-1024")
        ports_entry = ctk.CTkEntry(
            self._ports_frame,
            variable=self._ports_var,
            placeholder_text="Port range (e.g., 1-1024) or common ports",
        )
        ports_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Hide ports initially
        self._ports_frame.pack_forget()

        # Bind scan type change
        # self._scan_type_combo.configure(command=self._on_scan_type_changed)

        # Control buttons
        btn_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=5)

        self._start_button = ctk.CTkButton(
            btn_frame,
            text="🔍 Start Scan",
            width=120,
            command=self.start_scan,
            fg_color=("blue", "darkblue"),
        )
        self._start_button.pack(side="left", padx=5)

        self._stop_button = ctk.CTkButton(
            btn_frame,
            text="⏹ Stop",
            width=100,
            command=self.stop_scan,
            fg_color=("red", "darkred"),
            state="disabled",
        )
        self._stop_button.pack(side="left", padx=5)

        self._clear_button = ctk.CTkButton(
            btn_frame,
            text="Clear",
            width=100,
            command=self.clear_results,
        )
        self._clear_button.pack(side="left", padx=5)

        self._save_button = ctk.CTkButton(
            btn_frame,
            text="Save",
            width=100,
            command=self.save_results,
        )
        self._save_button.pack(side="left", padx=5)

        # Status bar
        status_frame = ctk.CTkFrame(self._control_frame, fg_color="transparent")
        status_frame.pack(fill="x", padx=10, pady=(5, 10))

        self._progress_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            status_frame,
            textvariable=self._progress_var,
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=5)

        self._status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(
            status_frame,
            textvariable=self._status_var,
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(side="right", padx=5)

    def _create_results_display(self) -> None:
        """Create results display area."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._results_frame = ttk.LabelFrame(self._frame, text="Scan Results")
            self._results_frame.pack(fill="both", expand=True)

            # Create treeview
            columns = ("IP", "Hostname", "MAC", "Status", "Ports", "Latency")
            self._results_tree = ttk.Treeview(self._results_frame, columns=columns, show="headings")

            for col in columns:
                self._results_tree.heading(col, text=col)
                if col == "IP":
                    self._results_tree.column(col, width=140)
                elif col == "Ports":
                    self._results_tree.column(col, width=200)
                elif col == "Hostname":
                    self._results_tree.column(col, width=150)
                else:
                    self._results_tree.column(col, width=100)

            # Scrollbar
            scrollbar = ttk.Scrollbar(self._results_frame, orient="vertical", command=self._results_tree.yview)
            self._results_tree.configure(yscrollcommand=scrollbar.set)

            self._results_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            return

        # CustomTkinter results display
        self._results_frame = ctk.CTkFrame(self._frame)
        self._results_frame.pack(fill="both", expand=True)

        # Title
        title = ctk.CTkLabel(
            self._results_frame,
            text="Discovered Devices",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Use ttk.Treeview
        tree_frame = ttk.Frame(self._results_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("IP", "Hostname", "MAC", "Status", "Ports", "Latency")
        self._results_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        for col in columns:
            self._results_tree.heading(col, text=col)
            if col == "IP":
                self._results_tree.column(col, width=140)
            elif col == "Ports":
                self._results_tree.column(col, width=200)
            elif col == "Hostname":
                self._results_tree.column(col, width=150)
            else:
                self._results_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self._results_tree.yview)
        self._results_tree.configure(yscrollcommand=scrollbar.set)

        self._results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _on_scan_type_changed(self, value: str) -> None:
        """Handle scan type change.

        Args:
            value: New scan type value
        """
        # Update the variable to keep it in sync
        self._scan_type_var.set(value)
        
        descriptions = {
            "arp": "ARP Scan - Discover hosts on local network",
            "icmp": "ICMP Scan - Ping sweep to find alive hosts",
            "port": "Port Scan - Check open ports on target host",
        }

        self._type_desc_var.set(descriptions.get(value, ""))

        # Show/hide ports input
        if value == "port":
            self._ports_frame.pack(fill="x", padx=10, pady=5, after=self._target_var.master.master.master)
        else:
            self._ports_frame.pack_forget()

    def start_scan(self) -> None:
        """Start network scan."""
        try:
            if not self._scanner:
                self._update_status("No scanner available")
                return

            # Get scan parameters
            scan_type = self._scan_type_var.get()
            target = self._target_var.get().strip()

            if not target:
                self._update_status("Please enter a target")
                return

            # Validate target
            try:
                if "/" in target:
                    ipaddress.ip_network(target, strict=False)
                else:
                    ipaddress.ip_address(target)
            except ValueError:
                self._update_status("Invalid target address")
                return

            # Get ports for port scan
            ports = None
            if scan_type == "port":
                ports_str = self._ports_var.get().strip()
                if not ports_str:
                    self._update_status("Please enter port range")
                    return
                ports = self._parse_ports(ports_str)

            # Clear previous results
            self.clear_results()

            # Start scan in thread
            self._is_scanning = True
            thread = threading.Thread(
                target=self._run_scan,
                args=(scan_type, target, ports),
                daemon=True,
            )
            thread.start()

            # Update UI
            if self._start_button:
                self._start_button.configure(state="disabled")
            if self._stop_button:
                self._stop_button.configure(state="normal")

            self._update_status(f"Scanning {target}...")

        except Exception as e:
            self._logger.error(f"Error starting scan: {e}")
            self._update_status(f"Error: {e}")

    def stop_scan(self) -> None:
        """Stop network scan."""
        try:
            if self._scanner:
                self._scanner.stop_scan()

            self._is_scanning = False

            # Update UI
            if self._start_button:
                self._start_button.configure(state="normal")
            if self._stop_button:
                self._stop_button.configure(state="disabled")

            self._update_status("Scan stopped")

        except Exception as e:
            self._logger.error(f"Error stopping scan: {e}")
            self._update_status(f"Error: {e}")

    def clear_results(self) -> None:
        """Clear scan results."""
        self._scan_results.clear()

        if hasattr(self, '_results_tree'):
            for item in self._results_tree.get_children():
                self._results_tree.delete(item)

    def _save_scan_results(self, results: List[Any]) -> None:
        """Save scan results to database (internal helper)."""
        try:
            from src.storage import ScanResultOrm
            import uuid

            with self._database.get_session() as session:
                for result in results:
                    # Handle both dict and object
                    if hasattr(result, 'to_dict'):
                        r_dict = result.to_dict()
                    else:
                        r_dict = result
                        
                    scan_result = ScanResultOrm(
                        scan_id=str(uuid.uuid4()),
                        scan_type=self._scan_type_var.get(),
                        target_ip=r_dict.get("ip", ""),
                        target_hostname=r_dict.get("hostname"),
                        mac_address=r_dict.get("mac"),
                        is_alive=r_dict.get("is_alive") or r_dict.get("alive", False),
                        response_time=r_dict.get("response_time") or r_dict.get("latency"),
                        open_ports=str(r_dict.get("ports", [])),
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                    )
                    session.add(scan_result)
        except Exception as e:
            self._logger.error(f"Error auto-saving scan results: {e}")

    def save_results(self) -> None:
        """Save scan results to database."""
        if not self._database:
            self._update_status("No database available")
            return

        try:
            from src.storage import ScanResultOrm
            from src.storage.models import Base
            import uuid

            saved = 0

            with self._database.get_session() as session:
                for result in self._scan_results:
                    scan_result = ScanResultOrm(
                        scan_id=str(uuid.uuid4()),
                        scan_type=result.get("scan_type", "unknown"),
                        target_ip=result.get("ip", ""),
                        target_hostname=result.get("hostname"),
                        mac_address=result.get("mac"),
                        is_alive=result.get("alive") or result.get("is_alive", False),
                        response_time=result.get("response_time") or result.get("latency"),
                        open_ports=str(result.get("ports", [])),
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                    )

                    session.add(scan_result)
                    saved += 1

            self._update_status(f"Saved {saved} results to database")
            self._logger.info(f"Saved {saved} scan results")

        except Exception as e:
            self._logger.error(f"Error saving results: {e}")
            self._update_status(f"Error: {e}")

    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parse port specification.

        Args:
            ports_str: Port string (e.g., "1-1024", "80,443,8080")

        Returns:
            List of port numbers
        """
        ports = []

        try:
            if "-" in ports_str:
                # Port range
                start, end = ports_str.split("-", 1)
                ports = list(range(int(start), int(end) + 1))
            else:
                # Comma-separated ports
                ports = [int(p.strip()) for p in ports_str.split(",")]
        except ValueError:
            # Common ports
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 8080]
            ports = common_ports

        return ports

    def _run_scan(self, scan_type: str, target: str, ports: Optional[List[int]]) -> None:
        """Run scan in background thread.

        Args:
            scan_type: Type of scan
            target: Target address
            ports: List of ports for port scan
        """
        try:
            results = []

            if scan_type == "arp":
                results = self._scanner.arp_scan(target)
            elif scan_type == "icmp":
                results = self._scanner.icmp_scan(target)
            elif scan_type == "port":
                if not ports:
                    ports = list(range(1, 1025))
                results = self._scanner.port_scan(target, ports)

            # Process results
            # The previous approach of modifying the list in place was problematic
            # Create a fresh list of dicts for processing
            processed_results = []
            
            for result in results:
                # Convert ScanResult object to dictionary
                if hasattr(result, 'to_dict'):
                    r_dict = result.to_dict()
                else:
                    r_dict = result
                
                # Add to UI - SCHEDULE ON MAIN THREAD
                if hasattr(self._frame, 'after'):
                    self._frame.after(0, lambda r=r_dict: self._add_result(r))
                    
                processed_results.append(r_dict)
            
            # Save results to database automatically
            if self._database and processed_results:
                self._save_scan_results(processed_results)

            # Update UI from main thread
            if hasattr(self._frame, 'after'):
                self._frame.after(0, lambda: self._update_status(f"Scan complete - {len(results)} hosts found"))

        except Exception as e:
            self._logger.error(f"Error running scan: {e}")
            err_msg = str(e)
            if hasattr(self._frame, 'after'):
                self._frame.after(0, lambda: self._update_status(f"Error: {err_msg}"))

        finally:
            self._is_scanning = False
            if hasattr(self._frame, 'after'):
                self._frame.after(0, self._on_scan_complete)

    def _add_result(self, result: Dict[str, Any]) -> None:
        """Add scan result to display.

        Args:
            result: Scan result dict
        """
        # Store result
        result["scan_type"] = self._scan_type_var.get()
        self._scan_results.append(result)

        # Add to treeview
        if hasattr(self, '_results_tree'):
            ip = result.get("ip", "")
            hostname = result.get("hostname", "N/A")
            mac = result.get("mac", "N/A")
            status = "Alive" if result.get("alive") or result.get("is_alive") else "Down"
            ports = ", ".join(map(str, result.get("ports", [])))
            
            # Handle response_time/latency
            resp_time = result.get("response_time") or result.get("latency")
            latency = f"{resp_time:.1f}ms" if resp_time is not None else "N/A"

            self._results_tree.insert("", 0, values=(ip, hostname, mac, status, ports, latency))

    def _on_scan_complete(self) -> None:
        """Handle scan completion."""
        if self._start_button:
            self._start_button.configure(state="normal")
        if self._stop_button:
            self._stop_button.configure(state="disabled")

    def _update_status(self, message: str) -> None:
        """Update status display.

        Args:
            message: Status message
        """
        if self._status_var:
            self._status_var.set(message)

    def destroy(self) -> None:
        """Clean up scan panel resources."""
        # Stop scan if running
        if self._is_scanning:
            self.stop_scan()

        if self._frame:
            self._frame.destroy()

        self._logger.info("Scan panel destroyed")


def create_scan_panel(
    parent,
    scanner: Optional[NetworkScanner] = None,
    database: Optional[DatabaseManager] = None,
) -> ScanPanel:
    """Create scan panel instance.

    Args:
        parent: Parent widget
        scanner: Network scanner engine
        database: Database manager

    Returns:
        ScanPanel instance
    """
    # Always ensure a scanner is available
    if scanner is None:
        scanner = create_network_scanner()

    return ScanPanel(
        parent=parent,
        scanner=scanner,
        database=database,
    )


__all__ = [
    "ScanPanel",
    "create_scan_panel",
]
