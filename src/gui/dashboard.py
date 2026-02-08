"""
Dashboard panel for real-time monitoring.

Provides an at-a-glance view of network activity with live
statistics, charts, and recent alerts.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import threading
import time

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

from src.core.logger import get_logger
from src.capture.base import PacketCapture
from src.analysis import AnalysisEngine
from src.detection import DetectionEngine
from src.storage import DatabaseManager


class DashboardPanel:
    """Real-time monitoring dashboard.

    Displays traffic statistics, bandwidth usage, protocol distribution,
    top connections, and recent alerts.
    """

    def __init__(
        self,
        parent,
        capture: Optional[PacketCapture] = None,
        analysis: Optional[AnalysisEngine] = None,
        detection: Optional[DetectionEngine] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        """Initialize dashboard panel.

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

        # Update timer
        self._update_interval = 1.0  # seconds
        self._update_timer: Optional[threading.Timer] = None
        self._is_updating = False

        # Statistics display variables
        self._total_packets_var: Optional[ctk.StringVar] = None
        self._total_bytes_var: Optional[ctk.StringVar] = None
        self._packet_rate_var: Optional[ctk.StringVar] = None
        self._byte_rate_var: Optional[ctk.StringVar] = None
        self._active_connections_var: Optional[ctk.StringVar] = None
        self._alert_count_var: Optional[ctk.StringVar] = None

        # Previous statistics for rate calculation
        self._prev_packets = 0
        self._prev_bytes = 0
        self._prev_time = datetime.now()

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._stats_frame: Optional[tk.Frame] = None
        self._protocol_frame: Optional[tk.Frame] = None
        self._connections_frame: Optional[tk.Frame] = None
        self._alerts_frame: Optional[tk.Frame] = None

        self._logger.info("Dashboard panel initialized")

    def build(self) -> tk.Frame:
        """Build dashboard UI.

        Returns:
            Dashboard frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color="transparent")
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create sections
        self._create_header()
        self._create_statistics_grid()
        self._create_content_area()

        # Start update timer
        self._start_updates()

        self._logger.info("Dashboard UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create dashboard header."""
        if not CUSTOMTKINTER_AVAILABLE:
            header = ttk.Frame(self._frame)
            header.pack(fill="x", pady=(0, 10))

            ttk.Label(
                header,
                text="Network Dashboard",
                font=("Arial", 18, "bold"),
            ).pack(side="left")

            ttk.Label(
                header,
                text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}",
                font=("Arial", 10),
            ).pack(side="right")
            return

        # CustomTkinter header
        header = ctk.CTkFrame(self._frame, height=50)
        header.pack(fill="x", pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(
            header,
            text="Network Dashboard",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.pack(side="left", padx=20, pady=10)

        self._update_time_var = ctk.StringVar(
            value=datetime.now().strftime("%H:%M:%S")
        )
        update_label = ctk.CTkLabel(
            header,
            textvariable=self._update_time_var,
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        update_label.pack(side="right", padx=20, pady=10)

    def _create_statistics_grid(self) -> None:
        """Create statistics summary grid."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._stats_frame = ttk.LabelFrame(self._frame, text="Statistics")
            self._stats_frame.pack(fill="x", pady=(0, 10))

            grid = ttk.Frame(self._stats_frame)
            grid.pack(fill="both", expand=True, padx=5, pady=5)

            # Create 6 stat cards
            for i, label in enumerate([
                "Total Packets", "Total Bytes", "Packet Rate",
                "Byte Rate", "Active Connections", "Recent Alerts"
            ]):
                card = ttk.Frame(grid, relief="ridge", borderwidth=1)
                card.grid(row=i//3, column=i%3, padx=5, pady=5, sticky="nsew")

                ttk.Label(card, text=label, font=("Arial", 9)).pack(pady=2)

                value_var = tk.StringVar(value="--")
                ttk.Label(
                    card,
                    textvariable=value_var,
                    font=("Arial", 14, "bold"),
                ).pack(pady=2)

                # Store reference
                if i == 0:
                    self._total_packets_var = value_var
                elif i == 1:
                    self._total_bytes_var = value_var
                elif i == 2:
                    self._packet_rate_var = value_var
                elif i == 3:
                    self._byte_rate_var = value_var
                elif i == 4:
                    self._active_connections_var = value_var
                elif i == 5:
                    self._alert_count_var = value_var

            # Configure grid weights
            for i in range(3):
                grid.columnconfigure(i, weight=1)
            return

        # CustomTkinter statistics
        self._stats_frame = ctk.CTkFrame(self._frame)
        self._stats_frame.pack(fill="x", pady=(0, 10))

        # Title
        title = ctk.CTkLabel(
            self._stats_frame,
            text="Traffic Statistics",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Stats grid
        grid = ctk.CTkFrame(self._stats_frame, fg_color="transparent")
        grid.pack(fill="x", padx=10, pady=10)

        # Create stat cards
        stats = [
            ("Total Packets", "📦", self._get_total_packets),
            ("Total Bytes", "💾", self._get_total_bytes),
            ("Packet Rate", "📊", self._get_packet_rate),
            ("Byte Rate", "⚡", self._get_byte_rate),
            ("Active Connections", "🔗", self._get_active_connections),
            ("Recent Alerts", "⚠️", self._get_alert_count),
        ]

        for i, (label, icon, _) in enumerate(stats):
            card = ctk.CTkFrame(grid, corner_radius=8)
            card.grid(row=i//3, column=i%3, padx=5, pady=5, sticky="nsew")

            # Icon and label
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=(8, 2))

            ctk.CTkLabel(
                header,
                text=icon,
                font=ctk.CTkFont(size=16),
            ).pack(side="left")

            ctk.CTkLabel(
                header,
                text=label,
                font=ctk.CTkFont(size=11),
                text_color="gray",
            ).pack(side="left", padx=5)

            # Value
            value_var = ctk.StringVar(value="--")
            ctk.CTkLabel(
                card,
                textvariable=value_var,
                font=ctk.CTkFont(size=20, weight="bold"),
            ).pack(pady=(0, 8))

            # Store reference
            if i == 0:
                self._total_packets_var = value_var
            elif i == 1:
                self._total_bytes_var = value_var
            elif i == 2:
                self._packet_rate_var = value_var
            elif i == 3:
                self._byte_rate_var = value_var
            elif i == 4:
                self._active_connections_var = value_var
            elif i == 5:
                self._alert_count_var = value_var

        # Configure grid weights
        for i in range(3):
            grid.columnconfigure(i, weight=1)

    def _create_content_area(self) -> None:
        """Create main content area with panels."""
        if not CUSTOMTKINTER_AVAILABLE:
            content = ttk.Frame(self._frame)
            content.pack(fill="both", expand=True)

            # Left column - Protocol and Connections
            left = ttk.Frame(content)
            left.pack(side="left", fill="both", expand=True, padx=(0, 5))

            self._protocol_frame = ttk.LabelFrame(left, text="Protocol Distribution")
            self._protocol_frame.pack(fill="both", expand=True, pady=(0, 5))

            self._connections_frame = ttk.LabelFrame(left, text="Top Connections")
            self._connections_frame.pack(fill="both", expand=True)

            # Right column - Alerts
            right = ttk.Frame(content)
            right.pack(side="right", fill="both", expand=True, padx=(5, 0))

            self._alerts_frame = ttk.LabelFrame(right, text="Recent Alerts")
            self._alerts_frame.pack(fill="both", expand=True)
            return

        # CustomTkinter content
        content = ctk.CTkFrame(self._frame, fg_color="transparent")
        content.pack(fill="both", expand=True)

        # Left column
        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self._protocol_frame = ctk.CTkFrame(left)
        self._protocol_frame.pack(fill="both", expand=True, pady=(0, 5))

        self._connections_frame = ctk.CTkFrame(left)
        self._connections_frame.pack(fill="both", expand=True)

        # Right column
        right = ctk.CTkFrame(content, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self._alerts_frame = ctk.CTkFrame(right)
        self._alerts_frame.pack(fill="both", expand=True)

        # Add titles
        self._add_frame_title(self._protocol_frame, "Protocol Distribution")
        self._add_frame_title(self._connections_frame, "Top Connections")
        self._add_frame_title(self._alerts_frame, "Recent Alerts")

    def _add_frame_title(self, frame: tk.Frame, title: str) -> None:
        """Add title to frame."""
        label = ctk.CTkLabel(
            frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        label.pack(pady=(10, 5))

    def _start_updates(self) -> None:
        """Start periodic updates."""
        if not self._is_updating:
            self._is_updating = True
            self._schedule_update()

    def _stop_updates(self) -> None:
        """Stop periodic updates."""
        self._is_updating = False
        if self._update_timer:
            self._update_timer.cancel()
            self._update_timer = None

    def _schedule_update(self) -> None:
        """Schedule next update."""
        if self._is_updating:
            self._update_timer = threading.Timer(
                self._update_interval,
                self._update_display,
            )
            self._update_timer.daemon = True
            self._update_timer.start()

    def _update_display(self) -> None:
        """Update dashboard display with latest data."""
        try:
            # Update statistics
            if self._total_packets_var:
                self._total_packets_var.set(self._get_total_packets())
            if self._total_bytes_var:
                self._total_bytes_var.set(self._get_total_bytes())
            if self._packet_rate_var:
                self._packet_rate_var.set(self._get_packet_rate())
            if self._byte_rate_var:
                self._byte_rate_var.set(self._get_byte_rate())
            if self._active_connections_var:
                self._active_connections_var.set(self._get_active_connections())
            if self._alert_count_var:
                self._alert_count_var.set(self._get_alert_count())

            # Update timestamp
            if hasattr(self, '_update_time_var'):
                self._update_time_var.set(datetime.now().strftime("%H:%M:%S"))

            # Update content panels
            self._update_protocol_panel()
            self._update_connections_panel()
            self._update_alerts_panel()

        except Exception as e:
            self._logger.error(f"Error updating dashboard: {e}")

        # Schedule next update
        self._schedule_update()

    def _get_total_packets(self) -> str:
        """Get total packet count."""
        try:
            if self._analysis:
                stats = self._analysis.get_statistics()
                total = stats.get("total_packets", 0)
                self._prev_packets = total
                return f"{total:,}"
        except Exception:
            pass
        return "--"

    def _get_total_bytes(self) -> str:
        """Get total bytes formatted."""
        try:
            if self._analysis:
                stats = self._analysis.get_statistics()
                total = stats.get("total_bytes", 0)
                self._prev_bytes = total
                return self._format_bytes(total)
        except Exception:
            pass
        return "--"

    def _get_packet_rate(self) -> str:
        """Get packet rate (packets/sec)."""
        try:
            if self._analysis:
                stats = self._analysis.get_statistics()
                rate = stats.get("packets_per_second", 0)
                return f"{rate:.1f} pps"
        except Exception:
            pass
        return "-- pps"

    def _get_byte_rate(self) -> str:
        """Get byte rate (bytes/sec)."""
        try:
            if self._analysis:
                stats = self._analysis.get_statistics()
                bps = stats.get("bytes_per_second", 0)
                return f"{self._format_bytes(bps)}/s"
        except Exception:
            pass
        return "-- B/s"

    def _get_active_connections(self) -> str:
        """Get active connection count."""
        try:
            if self._analysis:
                stats = self._analysis.get_statistics()
                count = stats.get("active_connections", 0)
                return str(count)
        except Exception:
            pass
        return "--"

    def _get_alert_count(self) -> str:
        """Get recent alert count."""
        try:
            if self._detection:
                # Get alerts from last hour
                since = datetime.now() - timedelta(hours=1)
                count = self._detection.get_alert_count(since=since)
                return str(count)
        except Exception:
            pass
        return "--"

    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes to human readable.

        Args:
            bytes_count: Number of bytes

        Returns:
            Formatted string (e.g., "1.5 MB")
        """
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"

    def _update_protocol_panel(self) -> None:
        """Update protocol distribution panel."""
        if not self._protocol_frame:
            return

        try:
            # Clear existing content (except title)
            for widget in self._protocol_frame.winfo_children():
                if widget.winfo_class() not in ["CTkLabel", "Label"]:
                    widget.destroy()

            if self._analysis:
                stats = self._analysis.get_statistics()
                protocol_stats = stats.get("protocol_stats", {})

                # Display protocol distribution
                for protocol, count in protocol_stats.items():
                    self._add_protocol_item(protocol, count)

        except Exception as e:
            self._logger.error(f"Error updating protocol panel: {e}")

    def _add_protocol_item(self, protocol: str, count: int) -> None:
        """Add protocol item to display.

        Args:
            protocol: Protocol name
            count: Packet count
        """
        if not CUSTOMTKINTER_AVAILABLE:
            frame = ttk.Frame(self._protocol_frame)
            frame.pack(fill="x", padx=5, pady=2)

            ttk.Label(frame, text=protocol).pack(side="left")
            ttk.Label(frame, text=str(count)).pack(side="right")
            return

        # CustomTkinter protocol item
        item = ctk.CTkFrame(self._protocol_frame, height=30)
        item.pack(fill="x", padx=10, pady=3)
        item.pack_propagate(False)

        ctk.CTkLabel(
            item,
            text=protocol,
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=10)

        ctk.CTkLabel(
            item,
            text=f"{count:,}",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(side="right", padx=10)

    def _update_connections_panel(self) -> None:
        """Update top connections panel."""
        if not self._connections_frame:
            return

        try:
            # Clear existing content
            for widget in self._connections_frame.winfo_children():
                if widget.winfo_class() not in ["CTkLabel", "Label"]:
                    widget.destroy()

            if self._analysis:
                stats = self._analysis.get_statistics()
                top_connections = stats.get("top_connections", [])[:5]

                for conn in top_connections:
                    self._add_connection_item(conn)

        except Exception as e:
            self._logger.error(f"Error updating connections panel: {e}")

    def _add_connection_item(self, conn: Dict[str, Any]) -> None:
        """Add connection item to display.

        Args:
            conn: Connection info dict
        """
        if not CUSTOMTKINTER_AVAILABLE:
            frame = ttk.Frame(self._connections_frame)
            frame.pack(fill="x", padx=5, pady=2)

            src = f"{conn.get('src_ip', '')}:{conn.get('src_port', '')}"
            dst = f"{conn.get('dst_ip', '')}:{conn.get('dst_port', '')}"
            protocol = conn.get('protocol', '')

            ttk.Label(frame, text=f"{src} → {dst}", font=("Arial", 8)).pack(side="left")
            ttk.Label(frame, text=protocol).pack(side="right")
            return

        # CustomTkinter connection item
        item = ctk.CTkFrame(self._connections_frame, height=35)
        item.pack(fill="x", padx=10, pady=3)
        item.pack_propagate(False)

        src = f"{conn.get('src_ip', '')}:{conn.get('src_port', '')}"
        dst = f"{conn.get('dst_ip', '')}:{conn.get('dst_port', '')}"
        protocol = conn.get('protocol', '')

        ctk.CTkLabel(
            item,
            text=f"{src} → {dst}",
            font=ctk.CTkFont(size=10),
        ).pack(side="left", padx=10)

        ctk.CTkLabel(
            item,
            text=protocol,
            font=ctk.CTkFont(size=10),
            text_color="gray",
        ).pack(side="right", padx=10)

    def _update_alerts_panel(self) -> None:
        """Update recent alerts panel."""
        if not self._alerts_frame:
            return

        try:
            # Clear existing content
            for widget in self._alerts_frame.winfo_children():
                if widget.winfo_class() not in ["CTkLabel", "Label"]:
                    widget.destroy()

            if self._detection:
                # Get recent alerts
                alerts = self._detection.get_recent_alerts(limit=5)

                if not alerts:
                    self._add_no_alerts_message()
                else:
                    for alert in alerts:
                        self._add_alert_item(alert)

        except Exception as e:
            self._logger.error(f"Error updating alerts panel: {e}")

    def _add_no_alerts_message(self) -> None:
        """Add no alerts message."""
        if not CUSTOMTKINTER_AVAILABLE:
            ttk.Label(
                self._alerts_frame,
                text="No recent alerts",
                font=("Arial", 10, "italic"),
            ).pack(padx=10, pady=10)
            return

        ctk.CTkLabel(
            self._alerts_frame,
            text="No recent alerts",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(pady=20)

    def _add_alert_item(self, alert: Dict[str, Any]) -> None:
        """Add alert item to display.

        Args:
            alert: Alert info dict
        """
        if not CUSTOMTKINTER_AVAILABLE:
            frame = ttk.Frame(self._alerts_frame)
            frame.pack(fill="x", padx=5, pady=2)

            title = alert.get('title', 'Unknown Alert')
            severity = alert.get('severity', 'unknown')
            timestamp = alert.get('timestamp', datetime.now())

            if isinstance(timestamp, datetime):
                time_str = timestamp.strftime("%H:%M:%S")
            else:
                time_str = str(timestamp)

            ttk.Label(frame, text=title, font=("Arial", 9)).pack(side="left")
            ttk.Label(frame, text=f"{severity} ({time_str})", font=("Arial", 8)).pack(side="right")
            return

        # CustomTkinter alert item
        item = ctk.CTkFrame(self._alerts_frame, height=40)
        item.pack(fill="x", padx=10, pady=3)
        item.pack_propagate(False)

        title = alert.get('title', 'Unknown Alert')
        severity = alert.get('severity', 'unknown')
        timestamp = alert.get('timestamp', datetime.now())

        if isinstance(timestamp, datetime):
            time_str = timestamp.strftime("%H:%M:%S")
        else:
            time_str = str(timestamp)

        # Color based on severity
        severity_colors = {
            "critical": "#ff4757",
            "high": "#ff6b81",
            "medium": "#ffa502",
            "low": "#7bed9f",
        }
        color = severity_colors.get(severity.lower(), "gray")

        ctk.CTkLabel(
            item,
            text=title,
            font=ctk.CTkFont(size=11),
            anchor="w",
        ).pack(side="left", padx=10, fill="x", expand=True)

        ctk.CTkLabel(
            item,
            text=f"{severity.upper()}",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=color,
        ).pack(side="right", padx=5)

    def destroy(self) -> None:
        """Clean up dashboard resources."""
        self._stop_updates()

        if self._frame:
            self._frame.destroy()

        self._logger.info("Dashboard destroyed")


def create_dashboard(
    parent,
    capture: Optional[PacketCapture] = None,
    analysis: Optional[AnalysisEngine] = None,
    detection: Optional[DetectionEngine] = None,
    database: Optional[DatabaseManager] = None,
) -> DashboardPanel:
    """Create dashboard panel instance.

    Args:
        parent: Parent widget
        capture: Packet capture engine
        analysis: Analysis engine
        detection: Detection engine
        database: Database manager

    Returns:
        DashboardPanel instance
    """
    return DashboardPanel(
        parent=parent,
        capture=capture,
        analysis=analysis,
        detection=detection,
        database=database,
    )


__all__ = [
    "DashboardPanel",
    "create_dashboard",
]
