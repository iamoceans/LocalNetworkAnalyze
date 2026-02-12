"""
Dashboard panel for real-time monitoring.

Provides an at-a-glance view of network activity with live
statistics, charts, and recent alerts with iOS styling.
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

# Import iOS theme system
from src.gui.theme.colors import Colors, ThemeMode, iOSSpacing, iOSShapes
from src.gui.theme.typography import Fonts
from src.gui.components import StatCard, StatGrid


class DashboardPanel:
    """Real-time monitoring dashboard with iOS styling.

    Displays traffic statistics, bandwidth usage, protocol distribution,
    top connections, and recent alerts.

    Features:
    - iOS-style stat cards with semantic colors
    - Clean, modern interface
    - 44pt touch targets
    - iOS color scheme (dark/light mode support)
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
        self._stat_cards: List[StatCard] = []
        self._protocol_frame: Optional[tk.Frame] = None
        self._connections_frame: Optional[tk.Frame] = None
        self._alerts_frame: Optional[tk.Frame] = None

        self._logger.info("Dashboard panel initialized (iOS style)")

    def build(self) -> tk.Frame:
        """Build dashboard UI with iOS styling.

        Returns:
            Dashboard frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color=Colors.get_card_color())
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)

        # Create sections
        self._create_header()
        self._create_statistics_grid()
        self._create_content_area()

        # Start update timer
        self._start_updates()

        self._logger.info("iOS-style Dashboard UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create iOS-style header."""
        if CUSTOMTKINTER_AVAILABLE:
            header = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color(), height=50)
            header.pack(fill="x", pady=(0, iOSSpacing.md))

            # Title
            title = ctk.CTkLabel(
                header,
                text="Dashboard",
                font=Fonts.TITLE2,
                text_color=Colors.get_text_color(),
            )
            title.pack(side="left", padx=iOSSpacing.lg)

            # Update time
            self._update_time_var = ctk.StringVar(
                value=datetime.now().strftime("%H:%M:%S")
            )
            update_label = ctk.CTkLabel(
                header,
                textvariable=self._update_time_var,
                font=Fonts.CAPTION1,
                text_color=Colors.get_text_secondary(),
            )
            update_label.pack(side="right", padx=iOSSpacing.lg)

    def _create_statistics_grid(self) -> None:
        """Create statistics summary grid with iOS stat cards."""
        if CUSTOMTKINTER_AVAILABLE:
            self._stats_frame = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        else:
            self._stats_frame = ttk.LabelFrame(self._frame, text="Statistics")

        self._stats_frame.pack(fill="x", pady=(0, iOSSpacing.md))

        if CUSTOMTKINTER_AVAILABLE:
            grid = ctk.CTkFrame(self._stats_frame, fg_color=Colors.get_card_color())
        else:
            grid = ttk.Frame(self._stats_frame)

        grid.pack(fill="both", expand=True, padx=iOSSpacing.lg, pady=iOSSpacing.lg)

        # Define stat configurations
        stats_config = [
            {
                "icon": "📦",
                "label": "Total Packets",
                "color": "none",
                "getter": self._get_total_packets,
                "var_ref": "_total_packets_var",
            },
            {
                "icon": "💾",
                "label": "Total Bytes",
                "color": "none",
                "getter": self._get_total_bytes,
                "var_ref": "_total_bytes_var",
            },
            {
                "icon": "📊",
                "label": "Packet Rate",
                "color": "green",
                "getter": self._get_packet_rate,
                "var_ref": "_packet_rate_var",
            },
            {
                "icon": "⚡",
                "label": "Byte Rate",
                "color": "cyan",
                "getter": self._get_byte_rate,
                "var_ref": "_byte_rate_var",
            },
            {
                "icon": "🔗",
                "label": "Active Connections",
                "color": "none",
                "getter": self._get_active_connections,
                "var_ref": "_active_connections_var",
            },
            {
                "icon": "⚠️",
                "label": "Recent Alerts",
                "color": "red",
                "getter": self._get_alert_count,
                "var_ref": "_alert_count_var",
            },
        ]

        # Create iOS-style stat cards
        self._stat_cards = []  # Initialize list before adding cards
        for i, config in enumerate(stats_config):
            card = StatCard(
                grid,
                icon=config["icon"],
                label=config["label"],
                value="--",
                color=config["color"],
                size="medium",
                compact=True,
            )
            card.grid(row=i // 2, column=i % 2, padx=iOSSpacing.sm, pady=iOSSpacing.sm, sticky="nsew")

            # Store reference to both list and named attribute
            self._stat_cards.append(card)
            setattr(self, config["var_ref"], card)

        # Configure grid weights
        for i in range(2):
            grid.grid_rowconfigure(i, weight=1)
            grid.grid_columnconfigure(i, weight=1)

    def _create_content_area(self) -> None:
        """Create main content area with iOS panels."""
        if CUSTOMTKINTER_AVAILABLE:
            content = ctk.CTkFrame(self._frame, corner_radius=0, fg_color=Colors.get_card_color())
        else:
            content = ttk.Frame(self._frame)

        content.pack(fill="both", expand=True, padx=0, pady=(iOSSpacing.md, 0))

        # Left column - Protocol and Connections
        left = ctk.CTkFrame(content, fg_color=Colors.get_card_color())
        left.pack(side="left", fill="both", expand=True, padx=(0, iOSSpacing.md))

        self._protocol_frame = ctk.CTkFrame(
            left,
            corner_radius=iOSShapes.corner_large,
            fg_color=Colors.get_card_color(),
            border_width=1,
            border_color=Colors.THEME.separator,
        )
        self._protocol_frame.pack(fill="both", expand=True, pady=(0, iOSSpacing.md))

        protocol_title = ctk.CTkLabel(
            self._protocol_frame,
            text="Protocol Distribution",
            font=Fonts.HEADLINE,
            text_color=Colors.get_text_color(),
        )
        protocol_title.pack(padx=iOSSpacing.lg, pady=(iOSSpacing.md, iOSSpacing.xs))

        self._connections_frame = ctk.CTkFrame(
            left,
            corner_radius=iOSShapes.corner_large,
            fg_color=Colors.get_card_color(),
            border_width=1,
            border_color=Colors.THEME.separator,
        )
        self._connections_frame.pack(fill="both", expand=True, pady=(0, iOSSpacing.md))

        connections_title = ctk.CTkLabel(
            self._connections_frame,
            text="Top Connections",
            font=Fonts.HEADLINE,
            text_color=Colors.get_text_color(),
        )
        connections_title.pack(padx=iOSSpacing.lg, pady=(iOSSpacing.md, iOSSpacing.xs))

        # Right column - Alerts
        right = ctk.CTkFrame(content, fg_color=Colors.get_card_color())
        right.pack(side="right", fill="both", expand=True, padx=(iOSSpacing.md, 0))

        self._alerts_frame = ctk.CTkFrame(
            right,
            corner_radius=iOSShapes.corner_large,
            fg_color=Colors.get_card_color(),
            border_width=1,
            border_color=Colors.THEME.separator,
        )
        self._alerts_frame.pack(fill="both", expand=True, pady=(0, iOSSpacing.md))

        alerts_title = ctk.CTkLabel(
            self._alerts_frame,
            text="Recent Alerts",
            font=Fonts.HEADLINE,
            text_color=Colors.get_text_color(),
        )
        alerts_title.pack(padx=iOSSpacing.lg, pady=(iOSSpacing.md, iOSSpacing.xs))

    def _start_updates(self) -> None:
        """Start periodic updates."""
        if not self._is_updating:
            self._is_updating = True
            self._schedule_update()

    def _stop_updates(self) -> None:
        """Stop periodic updates."""
        self._is_updating = False
        if self._update_timer:
            if self._frame:
                try:
                    self._frame.after_cancel(self._update_timer)
                except Exception:
                    pass
            self._update_timer = None

    def _schedule_update(self) -> None:
        """Schedule next update."""
        if self._is_updating and self._frame:
            self._update_timer = self._frame.after(
                int(self._update_interval * 1000),
                self._update_display,
            )

    def _update_display(self) -> None:
        """Update dashboard display with latest data."""
        try:
            # Update stat cards
            total_packets = self._get_total_packets()
            total_bytes = self._get_total_bytes()
            packet_rate = self._get_packet_rate()
            byte_rate = self._get_byte_rate()
            active_connections = self._get_active_connections()
            alert_count = self._get_alert_count()

            # Update iOS StatCard components
            if self._stat_cards:
                self._stat_cards[0].update_value(total_packets)
                self._stat_cards[1].update_value(total_bytes)
                self._stat_cards[2].update_value(packet_rate)
                self._stat_cards[3].update_value(byte_rate)
                self._stat_cards[4].update_value(active_connections)
                self._stat_cards[5].update_value(alert_count)

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
                return f"{bytes_count:.0f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"

    def _update_protocol_panel(self) -> None:
        """Update protocol distribution panel."""
        if not self._protocol_frame:
            return

        try:
            # Clear existing content
            for widget in self._protocol_frame.winfo_children():
                if widget.winfo_class() not in ["CTkLabel"]:
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
        """Add protocol item to display."""
        if CUSTOMTKINTER_AVAILABLE:
            item = ctk.CTkFrame(self._protocol_frame, height=35, fg_color=Colors.get_card_color())
            item.pack(fill="x", padx=iOSSpacing.md, pady=2)

            protocol_label = ctk.CTkLabel(
                item,
                text=protocol,
                font=Fonts.BODY,
                text_color=Colors.get_text_color(),
            )
            protocol_label.pack(side="left", padx=iOSSpacing.md)

            count_label = ctk.CTkLabel(
                item,
                text=f"{count:,}",
                font=Fonts.STAT_MEDIUM,
                text_color=Colors.get_text_color(),
            )
            count_label.pack(side="right", padx=iOSSpacing.md)

    def _update_connections_panel(self) -> None:
        """Update top connections panel."""
        if not self._connections_frame:
            return

        try:
            # Clear existing content
            for widget in self._connections_frame.winfo_children():
                if widget.winfo_class() not in ["CTkLabel"]:
                    widget.destroy()

            if self._analysis:
                stats = self._analysis.get_statistics()
                top_connections = stats.get("top_connections", [])[:5]

                for conn in top_connections:
                    self._add_connection_item(conn)

        except Exception as e:
            self._logger.error(f"Error updating connections panel: {e}")

    def _add_connection_item(self, conn: Dict[str, Any]) -> None:
        """Add connection item to display."""
        if CUSTOMTKINTER_AVAILABLE:
            item = ctk.CTkFrame(self._connections_frame, height=35, fg_color=Colors.get_card_color())
            item.pack(fill="x", padx=iOSSpacing.md, pady=2)

            src = f"{conn.get('src_ip', '')}:{conn.get('src_port', '')}"
            dst = f"{conn.get('dst_ip', '')}:{conn.get('dst_port', '')}"
            protocol = conn.get('protocol', '')

            flow_label = ctk.CTkLabel(
                item,
                text=f"{src} → {dst}",
                font=Fonts.BODY,
                text_color=Colors.get_text_color(),
            )
            flow_label.pack(side="left", padx=iOSSpacing.md)

            protocol_label = ctk.CTkLabel(
                item,
                text=protocol,
                font=Fonts.CALLOUT,
                text_color=Colors.get_text_secondary(),
            )
            protocol_label.pack(side="right", padx=iOSSpacing.md)

    def _update_alerts_panel(self) -> None:
        """Update recent alerts panel."""
        if not self._alerts_frame:
            return

        try:
            # Clear existing content
            for widget in self._alerts_frame.winfo_children():
                if widget.winfo_class() not in ["CTkLabel"]:
                    widget.destroy()

            if self._detection:
                alerts = self._detection.get_recent_alerts(limit=5)

                if not alerts:
                    no_alert_msg = ctk.CTkLabel(
                        self._alerts_frame,
                        text="No recent alerts",
                        font=Fonts.BODY,
                        text_color=Colors.get_text_secondary(),
                    )
                    no_alert_msg.pack(padx=iOSSpacing.lg, pady=iOSSpacing.xl)
                else:
                    for alert in alerts:
                        self._add_alert_item(alert)

        except Exception as e:
            self._logger.error(f"Error updating alerts panel: {e}")

    def _add_alert_item(self, alert: Dict[str, Any]) -> None:
        """Add alert item to display."""
        if CUSTOMTKINTER_AVAILABLE:
            item = ctk.CTkFrame(self._alerts_frame, height=40, fg_color=Colors.get_card_color())
            item.pack(fill="x", padx=iOSSpacing.md, pady=2)

            # Severity-based color
            severity = alert.get('severity', 'unknown')
            severity_colors = {
                "critical": Colors.THEME.critical,
                "high": Colors.THEME.high,
                "medium": Colors.THEME.medium,
                "low": Colors.THEME.low,
            }
            bg_color = severity_colors.get(severity, Colors.THEME.low_bg)

            title = alert.get('title', 'Unknown Alert')
            timestamp = alert.get('timestamp', datetime.now())

            if isinstance(timestamp, datetime):
                time_str = timestamp.strftime("%H:%M")
            else:
                time_str = str(timestamp)

            title_label = ctk.CTkLabel(
                item,
                text=title,
                font=Fonts.BODY,
                text_color=Colors.get_text_color(),
                anchor="w",
            )
            title_label.pack(side="left", padx=iOSSpacing.md, fill="x")

            severity_label = ctk.CTkLabel(
                item,
                text=f"{severity.upper()}",
                font=Fonts.CAPTION1,
                text_color=bg_color,
                fg_color="white" if ThemeMode.is_dark() else Colors.THEME.light_text_primary,
                corner_radius=4,
            )
            severity_label.pack(side="right", padx=iOSSpacing.md)

            time_label = ctk.CTkLabel(
                item,
                text=time_str,
                font=Fonts.CAPTION1,
                text_color=Colors.get_text_secondary(),
            )
            time_label.pack(side="right", padx=iOSSpacing.md)

    def destroy(self) -> None:
        """Clean up dashboard resources."""
        self._stop_updates()

        if self._frame:
            self._frame.destroy()

        self._logger.info("iOS-style Dashboard destroyed")


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
