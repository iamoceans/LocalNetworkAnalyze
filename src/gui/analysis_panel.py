"""
Analysis panel for traffic data analysis with neon styling.

Provides tools for filtering, searching, and analyzing
captured network traffic data.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

try:
    import customtkinter as ctk
    from customtkinter import CTkFont as ctk_CTkFont
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

from src.core.logger import get_logger
from src.analysis import AnalysisEngine
from src.storage import DatabaseManager, PacketFilter, AlertFilter, create_packet_repository, create_alert_repository

# Import theme system
from src.gui.theme.colors import Colors, NeonColors
from src.gui.theme.typography import Fonts


class AnalysisPanel:
    """Panel for traffic data analysis.

    Provides interface for:
    - Querying packet data with filters
    - Viewing traffic statistics
    - Analyzing protocol distribution
    - Exporting data
    - Top10 traffic dashboard
    """

    def __init__(
        self,
        parent,
        analysis: Optional[AnalysisEngine] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        """Initialize analysis panel.

        Args:
            parent: Parent widget
            analysis: Analysis engine
            database: Database manager
        """
        self._parent = parent
        self._analysis = analysis
        self._database = database
        self._logger = get_logger(__name__)

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._filter_frame: Optional[tk.Frame] = None
        self._results_frame: Optional[tk.Frame] = None
        self._top10_frame: Optional[tk.Frame] = None

        # Filter widgets
        self._start_time_var: Optional[ctk.StringVar] = None
        self._end_time_var: Optional[ctk.StringVar] = None
        self._src_ip_var: Optional[ctk.StringVar] = None
        self._dst_ip_var: Optional[ctk.StringVar] = None
        self._protocol_var: Optional[ctk.StringVar] = None
        self._limit_var: Optional[ctk.StringVar] = None

        # Results
        self._current_results: List[Dict[str, Any]] = []
        self._top10_data: List[Dict[str, Any]] = []

        self._logger.info("Analysis panel initialized")

    def build(self) -> tk.Frame:
        """Build analysis panel UI.

        Returns:
            Analysis panel frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color="transparent")
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create sections
        self._create_header()
        self._create_top10_dashboard()
        self._create_filter_panel()
        self._create_results_display()

        # Initial data load
        self.refresh_top10_dashboard()

        self._logger.info("Analysis panel UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create panel header with neon styling."""
        if not CUSTOMTKINTER_AVAILABLE:
            header = ttk.Frame(self._frame)
            header.pack(fill="x", pady=(0, 10))

            ttk.Label(
                header,
                text="📈 Traffic Analysis",
                font=("Fira Code", 16, "bold"),
            ).pack(side="left")
            return

        # CustomTkinter header with neon styling
        title = ctk.CTkLabel(
            self._frame,
            text="📈 Traffic Analysis",
            font=("Fira Code", 20, "bold"),
            text_color=Colors.NEON.neon_cyan,
        )
        title.pack(pady=(0, 12))

    def _create_top10_dashboard(self) -> None:
        """Create Top10 traffic dashboard section."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._top10_frame = ttk.LabelFrame(self._frame, text="Top 10 Traffic Destinations")
            self._top10_frame.pack(fill="x", pady=(0, 10))

            # Create treeview for Top10
            columns = ("请求地址", "访问URL", "访问端口", "流量size", "最近访问时间")
            self._top10_tree = ttk.Treeview(
                self._top10_frame,
                columns=columns,
                show="headings",
                height=6
            )

            # Configure columns
            self._top10_tree.heading("请求地址", text="请求地址")
            self._top10_tree.column("请求地址", width=150)

            self._top10_tree.heading("访问URL", text="访问URL")
            self._top10_tree.column("访问URL", width=200)

            self._top10_tree.heading("访问端口", text="访问端口")
            self._top10_tree.column("访问端口", width=80)

            self._top10_tree.heading("流量size", text="流量size")
            self._top10_tree.column("流量size", width=100)

            self._top10_tree.heading("最近访问时间", text="最近访问时间")
            self._top10_tree.column("最近访问时间", width=150)

            # Scrollbar
            scrollbar = ttk.Scrollbar(
                self._top10_frame,
                orient="vertical",
                command=self._top10_tree.yview
            )
            self._top10_tree.configure(yscrollcommand=scrollbar.set)

            self._top10_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
            scrollbar.pack(side="right", fill="y")

            # Refresh button
            btn_frame = ttk.Frame(self._top10_frame)
            btn_frame.pack(fill="x", padx=5, pady=(0, 5))
            ttk.Button(btn_frame, text="Refresh", command=self.refresh_top10_dashboard).pack(side="right")
            return

        # CustomTkinter Top10 dashboard
        self._top10_frame = ctk.CTkFrame(self._frame)
        self._top10_frame.pack(fill="x", pady=(0, 10))

        # Header with title and refresh button
        header_frame = ctk.CTkFrame(self._top10_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(10, 5))

        title = ctk.CTkLabel(
            header_frame,
            text="🏆 Top 10 Traffic Destinations",
            font=ctk_CTkFont(family="Fira Code", size=14, weight="bold"),
            text_color=Colors.NEON.neon_cyan,
        )
        title.pack(side="left")

        refresh_btn = ctk.CTkButton(
            header_frame,
            text="Refresh",
            width=80,
            command=self.refresh_top10_dashboard,
            font=ctk_CTkFont(size=11),
        )
        refresh_btn.pack(side="right")

        # Content frame with treeview
        content_frame = ttk.Frame(self._top10_frame)
        content_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Create treeview for Top10
        columns = ("请求地址", "访问URL", "访问端口", "流量size", "最近访问时间")
        self._top10_tree = ttk.Treeview(
            content_frame,
            columns=columns,
            show="headings",
            height=6
        )

        # Configure columns
        self._top10_tree.heading("请求地址", text="请求地址")
        self._top10_tree.column("请求地址", width=150)

        self._top10_tree.heading("访问URL", text="访问URL")
        self._top10_tree.column("访问URL", width=200)

        self._top10_tree.heading("访问端口", text="访问端口")
        self._top10_tree.column("访问端口", width=80, anchor="center")

        self._top10_tree.heading("流量size", text="流量size")
        self._top10_tree.column("流量size", width=100, anchor="e")

        self._top10_tree.heading("最近访问时间", text="最近访问时间")
        self._top10_tree.column("最近访问时间", width=150)

        # Style the treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=Colors.THEME.bg_card,
            foreground=Colors.THEME.text_primary,
            fieldbackground=Colors.THEME.bg_card,
            borderwidth=0,
            rowheight=28,
        )
        style.configure("Treeview.Heading", background=Colors.THEME.bg_hover, foreground=Colors.NEON.neon_cyan)
        style.map("Treeview", background=[("selected", Colors.NEON.neon_green_dim)])

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            content_frame,
            orient="vertical",
            command=self._top10_tree.yview
        )
        self._top10_tree.configure(yscrollcommand=scrollbar.set)

        self._top10_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _create_filter_panel(self) -> None:
        """Create filter panel."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._filter_frame = ttk.LabelFrame(self._frame, text="Query Filters")
            self._filter_frame.pack(fill="x", pady=(0, 10))

            # Time range
            time_frame = ttk.Frame(self._filter_frame)
            time_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(time_frame, text="Start:").pack(side="left")
            self._start_time_var = tk.StringVar(value="")
            ttk.Entry(time_frame, textvariable=self._start_time_var, width=20).pack(side="left", padx=2)

            ttk.Label(time_frame, text="End:").pack(side="left", padx=(10, 0))
            self._end_time_var = tk.StringVar(value="")
            ttk.Entry(time_frame, textvariable=self._end_time_var, width=20).pack(side="left", padx=2)

            # IP addresses
            ip_frame = ttk.Frame(self._filter_frame)
            ip_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(ip_frame, text="Source IP:").pack(side="left")
            self._src_ip_var = tk.StringVar()
            ttk.Entry(ip_frame, textvariable=self._src_ip_var).pack(side="left", fill="x", expand=True, padx=2)

            ttk.Label(ip_frame, text="Dest IP:").pack(side="left", padx=(10, 0))
            self._dst_ip_var = tk.StringVar()
            ttk.Entry(ip_frame, textvariable=self._dst_ip_var).pack(side="left", fill="x", expand=True, padx=2)

            # Protocol and limit
            filter_frame = ttk.Frame(self._filter_frame)
            filter_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(filter_frame, text="Protocol:").pack(side="left")
            self._protocol_var = tk.StringVar()
            ttk.Entry(filter_frame, textvariable=self._protocol_var, width=15).pack(side="left", padx=2)

            ttk.Label(filter_frame, text="Limit:").pack(side="left", padx=(10, 0))
            self._limit_var = tk.StringVar(value="100")
            ttk.Entry(filter_frame, textvariable=self._limit_var, width=10).pack(side="left", padx=2)

            # Buttons
            btn_frame = ttk.Frame(self._filter_frame)
            btn_frame.pack(fill="x", padx=5, pady=5)

            ttk.Button(btn_frame, text="Query", command=self.query_packets).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Clear", command=self.clear_filters).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Export", command=self.export_results).pack(side="left", padx=2)
            return

        # CustomTkinter filter panel
        self._filter_frame = ctk.CTkFrame(self._frame)
        self._filter_frame.pack(fill="x", pady=(0, 10))

        # Title
        title = ctk.CTkLabel(
            self._filter_frame,
            text="Query Filters",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Time range
        time_frame = ctk.CTkFrame(self._filter_frame, fg_color="transparent")
        time_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            time_frame,
            text="Time Range:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=5)

        self._start_time_var = ctk.StringVar(value="")
        start_entry = ctk.CTkEntry(
            time_frame,
            variable=self._start_time_var,
            placeholder_text="Start (YYYY-MM-DD HH:MM:SS)",
            width=200,
        )
        start_entry.pack(side="left", padx=2)

        self._end_time_var = ctk.StringVar(value="")
        end_entry = ctk.CTkEntry(
            time_frame,
            variable=self._end_time_var,
            placeholder_text="End (YYYY-MM-DD HH:MM:SS)",
            width=200,
        )
        end_entry.pack(side="left", padx=2)

        # Quick time buttons
        quick_frame = ctk.CTkFrame(self._filter_frame, fg_color="transparent")
        quick_frame.pack(fill="x", padx=10, pady=2)

        ctk.CTkButton(
            quick_frame,
            text="Last 5 min",
            width=80,
            command=lambda: self._set_time_range(minutes=5),
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            quick_frame,
            text="Last 1 hour",
            width=80,
            command=lambda: self._set_time_range(hours=1),
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            quick_frame,
            text="Last 24 hours",
            width=90,
            command=lambda: self._set_time_range(hours=24),
        ).pack(side="left", padx=2)

        # IP addresses
        ip_frame = ctk.CTkFrame(self._filter_frame, fg_color="transparent")
        ip_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            ip_frame,
            text="Source IP:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=5)

        self._src_ip_var = ctk.StringVar()
        src_entry = ctk.CTkEntry(
            ip_frame,
            variable=self._src_ip_var,
            placeholder_text="e.g., 192.168.1.1",
        )
        src_entry.pack(side="left", fill="x", expand=True, padx=2)

        ctk.CTkLabel(
            ip_frame,
            text="Dest IP:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(10, 0))

        self._dst_ip_var = ctk.StringVar()
        dst_entry = ctk.CTkEntry(
            ip_frame,
            variable=self._dst_ip_var,
            placeholder_text="e.g., 192.168.1.2",
        )
        dst_entry.pack(side="left", fill="x", expand=True, padx=2)

        # Protocol and limit
        filter2_frame = ctk.CTkFrame(self._filter_frame, fg_color="transparent")
        filter2_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            filter2_frame,
            text="Protocol:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=5)

        self._protocol_var = ctk.StringVar()
        ctk.CTkEntry(
            filter2_frame,
            variable=self._protocol_var,
            placeholder_value="TCP, UDP, ICMP, etc.",
            width=150,
        ).pack(side="left", padx=2)

        ctk.CTkLabel(
            filter2_frame,
            text="Limit:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(10, 0))

        self._limit_var = ctk.StringVar(value="100")
        ctk.CTkEntry(
            filter2_frame,
            variable=self._limit_var,
            width=80,
        ).pack(side="left", padx=2)

        # Buttons
        btn_frame = ctk.CTkFrame(self._filter_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        ctk.CTkButton(
            btn_frame,
            text="🔍 Query",
            width=100,
            command=self.query_packets,
            fg_color=("blue", "darkblue"),
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Clear",
            width=100,
            command=self.clear_filters,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="📤 Export",
            width=100,
            command=self.export_results,
        ).pack(side="left", padx=5)

    def _create_results_display(self) -> None:
        """Create results display area."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._results_frame = ttk.LabelFrame(self._frame, text="Query Results")
            self._results_frame.pack(fill="both", expand=True)

            # Create treeview
            columns = ("Time", "Source", "Destination", "Protocol", "Length")
            self._results_tree = ttk.Treeview(self._results_frame, columns=columns, show="headings")

            for col in columns:
                self._results_tree.heading(col, text=col)
                self._results_tree.column(col, width=120)

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
            text="Query Results",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Use ttk.Treeview
        tree_frame = ttk.Frame(self._results_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Time", "Source", "Destination", "Protocol", "Length")
        self._results_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        for col in columns:
            self._results_tree.heading(col, text=col)
            self._results_tree.column(col, width=120)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self._results_tree.yview)
        self._results_tree.configure(yscrollcommand=scrollbar.set)

        self._results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Result count label
        self._count_var = ctk.StringVar(value="Results: 0")
        count_label = ctk.CTkLabel(
            self._results_frame,
            textvariable=self._count_var,
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        count_label.pack(pady=(0, 10))

    def _set_time_range(self, minutes: int = 0, hours: int = 0) -> None:
        """Set time range to recent period.

        Args:
            minutes: Minutes back from now
            hours: Hours back from now
        """
        now = datetime.now()
        start = now - timedelta(minutes=minutes, hours=hours)

        self._end_time_var.set(now.strftime("%Y-%m-%d %H:%M:%S"))
        self._start_time_var.set(start.strftime("%Y-%m-%d %H:%M:%S"))

    def query_packets(self) -> None:
        """Query packets with current filters."""
        if not self._database:
            self._show_error("No database available")
            return

        try:
            # Build filter
            packet_filter = PacketFilter()

            # Parse time range
            if self._start_time_var.get():
                try:
                    packet_filter.start_time = datetime.strptime(
                        self._start_time_var.get(),
                        "%Y-%m-%d %H:%M:%S",
                    )
                except ValueError:
                    pass

            if self._end_time_var.get():
                try:
                    packet_filter.end_time = datetime.strptime(
                        self._end_time_var.get(),
                        "%Y-%m-%d %H:%M:%S",
                    )
                except ValueError:
                    pass

            # Parse IPs
            if self._src_ip_var.get():
                packet_filter.src_ip = self._src_ip_var.get()

            if self._dst_ip_var.get():
                packet_filter.dst_ip = self._dst_ip_var.get()

            # Parse protocol
            if self._protocol_var.get():
                packet_filter.protocol = self._protocol_var.get().upper()

            # Parse limit
            if self._limit_var.get():
                try:
                    packet_filter.limit = int(self._limit_var.get())
                except ValueError:
                    packet_filter.limit = 100

            # Query database
            packet_repo = create_packet_repository(self._database)
            results = packet_repo.find_by_filter(packet_filter)

            self._current_results = results
            self._display_results(results)

        except Exception as e:
            self._logger.error(f"Error querying packets: {e}")
            self._show_error(f"Query error: {e}")

    def clear_filters(self) -> None:
        """Clear all filter fields."""
        self._start_time_var.set("")
        self._end_time_var.set("")
        self._src_ip_var.set("")
        self._dst_ip_var.set("")
        self._protocol_var.set("")
        self._limit_var.set("100")

        self._current_results.clear()

        if hasattr(self, '_results_tree'):
            for item in self._results_tree.get_children():
                self._results_tree.delete(item)

        if hasattr(self, '_count_var'):
            self._count_var.set("Results: 0")

    def export_results(self) -> None:
        """Export current results."""
        if not self._current_results:
            self._show_error("No results to export")
            return

        try:
            # Simple CSV export
            from tkinter import filedialog
            import csv

            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            )

            if filepath:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "timestamp", "src_ip", "dst_ip", "src_port",
                        "dst_port", "protocol", "length",
                    ])
                    writer.writeheader()

                    for result in self._current_results:
                        writer.writerow({
                            "timestamp": result.get("timestamp", ""),
                            "src_ip": result.get("src_ip", ""),
                            "dst_ip": result.get("dst_ip", ""),
                            "src_port": result.get("src_port", ""),
                            "dst_port": result.get("dst_port", ""),
                            "protocol": result.get("protocol", ""),
                            "length": result.get("length", ""),
                        })

                self._show_info(f"Exported {len(self._current_results)} records to {filepath}")

        except Exception as e:
            self._logger.error(f"Error exporting results: {e}")
            self._show_error(f"Export error: {e}")

    def _display_results(self, results: List[Dict[str, Any]]) -> None:
        """Display query results.

        Args:
            results: Query results
        """
        # Clear existing
        if hasattr(self, '_results_tree'):
            for item in self._results_tree.get_children():
                self._results_tree.delete(item)

        # Add results
        for result in results:
            timestamp = result.get("timestamp", "")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M:%S")
                except (ValueError, TypeError):
                    time_str = str(timestamp)
            else:
                time_str = ""

            src = f"{result.get('src_ip', '')}:{result.get('src_port', '')}" if result.get('src_port') else result.get('src_ip', '')
            dst = f"{result.get('dst_ip', '')}:{result.get('dst_port', '')}" if result.get('dst_port') else result.get('dst_ip', '')

            self._results_tree.insert("", 0, values=(
                time_str,
                src,
                dst,
                result.get('protocol', ''),
                result.get('length', 0),
            ))

        # Update count
        if hasattr(self, '_count_var'):
            self._count_var.set(f"Results: {len(results)}")

    def _format_bytes(self, size: int) -> str:
        """Format bytes to human readable string.

        Args:
            size: Size in bytes

        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def refresh_top10_dashboard(self) -> None:
        """Refresh the Top10 traffic dashboard with latest data."""
        if not self._database:
            self._logger.warning("No database available for Top10 dashboard")
            return

        try:
            # Get top destinations from repository
            packet_repo = create_packet_repository(self._database)
            self._top10_data = packet_repo.get_top_destinations(limit=10)

            # Clear existing data
            if hasattr(self, '_top10_tree'):
                for item in self._top10_tree.get_children():
                    self._top10_tree.delete(item)

            # Populate treeview
            for item in self._top10_data:
                dst_ip = item.get('dst_ip', '')
                dst_port = item.get('dst_port', '')
                total_bytes = item.get('total_bytes', 0)
                last_seen = item.get('last_seen', '')

                # Format traffic size
                traffic_size = self._format_bytes(total_bytes)

                # Format last seen time
                if last_seen:
                    try:
                        dt = datetime.fromisoformat(last_seen)
                        last_seen_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, TypeError):
                        last_seen_str = str(last_seen)
                else:
                    last_seen_str = "-"

                # Access URL - use dst_ip as placeholder (could be enhanced with host resolution)
                access_url = dst_ip if dst_ip else "-"

                # Format destination address
                request_addr = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

                # Format port
                port_str = str(dst_port) if dst_port else "-"

                self._top10_tree.insert("", "end", values=(
                    request_addr,
                    access_url,
                    port_str,
                    traffic_size,
                    last_seen_str,
                ))

            self._logger.info(f"Top10 dashboard refreshed with {len(self._top10_data)} entries")

        except Exception as e:
            self._logger.error(f"Error refreshing Top10 dashboard: {e}")
            # Don't show error dialog to avoid spam on auto-refresh

    def _show_error(self, message: str) -> None:
        """Show error message.

        Args:
            message: Error message
        """
        if CUSTOMTKINTER_AVAILABLE:
            ctk.CTkMessageBox(title="Error", message=message)
        else:
            messagebox.showerror("Error", message)

    def _show_info(self, message: str) -> None:
        """Show info message.

        Args:
            message: Info message
        """
        if CUSTOMTKINTER_AVAILABLE:
            ctk.CTkMessageBox(title="Information", message=message)
        else:
            messagebox.showinfo("Information", message)

    def destroy(self) -> None:
        """Clean up analysis panel resources."""
        if self._frame:
            self._frame.destroy()

        self._logger.info("Analysis panel destroyed")


def create_analysis_panel(
    parent,
    analysis: Optional[AnalysisEngine] = None,
    database: Optional[DatabaseManager] = None,
) -> AnalysisPanel:
    """Create analysis panel instance.

    Args:
        parent: Parent widget
        analysis: Analysis engine
        database: Database manager

    Returns:
        AnalysisPanel instance
    """
    return AnalysisPanel(
        parent=parent,
        analysis=analysis,
        database=database,
    )


__all__ = [
    "AnalysisPanel",
    "create_analysis_panel",
]
