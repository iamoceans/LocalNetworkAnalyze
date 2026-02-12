"""
Alert panel for security alerts display with neon severity styling.

Provides tools for viewing, filtering, and managing
security detection alerts with color-coded severity levels.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

from src.core.logger import get_logger
from src.detection import DetectionEngine
from src.storage import DatabaseManager, AlertFilter, create_alert_repository

# Import theme system
# Import iOS theme system
from src.gui.theme.colors import Colors, ThemeMode, iOSSpacing
from src.gui.theme.typography import Fonts
from src.gui.components.ios_list import iOSList, iOSListItem
from src.gui.components.ios_button import iOSButton
from src.gui.components.ios_modal import iOSModal
from src.gui.components.ios_switch import iOSSwitch
from src.gui.components.ios_segment import iOSSegment
from src.gui.components.ios_progress import iOSActivitySpinner, iOSProgressBar


class AlertPanel:
    """Panel for security alerts display.

    Provides interface for:
    - Viewing detection alerts
    - Filtering by severity/type
    - Acknowledging alerts
    - Adding notes to alerts
    - Exporting alerts
    """

    def __init__(
        self,
        parent,
        detection: Optional[DetectionEngine] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        """Initialize alert panel.

        Args:
            parent: Parent widget
            detection: Detection engine
            database: Database manager
        """
        self._parent = parent
        self._detection = detection
        self._database = database
        self._logger = get_logger(__name__)

        # UI components
        self._frame: Optional[tk.Frame] = None
        self._filter_frame: Optional[tk.Frame] = None
        self._alerts_frame: Optional[tk.Frame] = None
        self._detail_frame: Optional[tk.Frame] = None

        # Filter widgets
        self._severity_var: Optional[ctk.StringVar] = None
        self._detection_type_var: Optional[ctk.StringVar] = None
        self._start_time_var: Optional[ctk.StringVar] = None
        self._end_time_var: Optional[ctk.StringVar] = None
        self._acknowledged_var: Optional[ctk.BooleanVar] = None

        # Alert data
        self._current_alerts: List[Dict[str, Any]] = []
        self._selected_alert: Optional[Dict[str, Any]] = None

        self._logger.info("Alert panel initialized")

    def _get_severity_color(self, severity: str) -> str:
        """Get color for alert severity level.

        Args:
            severity: Severity level (critical, high, medium, low)

        Returns:
            Hex color string for the severity
        """
        return Colors.get_severity_color(severity)

    def build(self) -> tk.Frame:
        """Build alert panel UI.

        Returns:
            Alert panel frame widget
        """
        if CUSTOMTKINTER_AVAILABLE:
            self._frame = ctk.CTkFrame(self._parent, fg_color=Colors.get_card_color())
        else:
            self._frame = ttk.Frame(self._parent)

        self._frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)

        # Create sections
        self._create_header()
        self._create_filter_panel()
        self._create_alerts_display()

        self._logger.info("Alert panel UI built")
        return self._frame

    def _create_header(self) -> None:
        """Create panel header with neon styling."""
        if not CUSTOMTKINTER_AVAILABLE:
            header = ttk.Frame(self._frame)
            header.pack(fill="x", pady=(0, 10))

            ttk.Label(
                header,
                text="⚠️ Security Alerts",
                font=("Fira Code", 16, "bold"),
            ).pack(side="left")
            return

        # CustomTkinter header with iOS styling
        title = ctk.CTkLabel(
            self._frame,
            text="⚠️ Security Alerts",
            font=("Fira Code", 20, "bold"),
            text_color=Colors.THEME.system_red,
        )
        title.pack(pady=(0, 12))

    def _create_filter_panel(self) -> None:
        """Create filter panel."""
        if not CUSTOMTKINTER_AVAILABLE:
            self._filter_frame = ttk.LabelFrame(self._frame, text="Filters")
            self._filter_frame.pack(fill="x", pady=(0, 10))

            # Severity
            severity_frame = ttk.Frame(self._filter_frame)
            severity_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(severity_frame, text="Severity:").pack(side="left")
            self._severity_var = tk.StringVar(value="all")
            severity_combo = ttk.Combobox(
                severity_frame,
                textvariable=self._severity_var,
                values=["all", "critical", "high", "medium", "low"],
                state="readonly",
                width=10,
            )
            severity_combo.pack(side="left", padx=5)

            # Detection type
            type_frame = ttk.Frame(self._filter_frame)
            type_frame.pack(fill="x", padx=5, pady=5)

            ttk.Label(type_frame, text="Type:").pack(side="left")
            self._detection_type_var = tk.StringVar(value="all")
            type_combo = ttk.Combobox(
                type_frame,
                textvariable=self._detection_type_var,
                values=["all", "port_scan", "dos", "malware", "anomaly"],
                state="readonly",
                width=15,
            )
            type_combo.pack(side="left", padx=5)

            # Acknowledged
            self._acknowledged_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                self._filter_frame,
                text="Show acknowledged only",
                variable=self._acknowledged_var,
            ).pack(padx=5, pady=5)

            # Buttons
            btn_frame = ttk.Frame(self._filter_frame)
            btn_frame.pack(fill="x", padx=5, pady=5)

            ttk.Button(btn_frame, text="Filter", command=self.filter_alerts).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Clear", command=self.clear_filters).pack(side="left", padx=2)
            ttk.Button(btn_frame, text="Export", command=self.export_alerts).pack(side="left", padx=2)
            return

        # CustomTkinter filter panel
        self._filter_frame = ctk.CTkFrame(self._frame)
        self._filter_frame.pack(fill="x", pady=(0, 10))

        # Title
        title = ctk.CTkLabel(
            self._filter_frame,
            text="Alert Filters",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Filters row
        filter_row = ctk.CTkFrame(self._filter_frame, fg_color=Colors.get_card_color())
        filter_row.pack(fill="x", padx=10, pady=5)

        # Severity
        ctk.CTkLabel(
            filter_row,
            text="Severity:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=5)

        self._severity_var = ctk.StringVar(value="all")
        severity_combo = ctk.CTkComboBox(
            filter_row,
            variable=self._severity_var,
            values=["all", "critical", "high", "medium", "low"],
            width=100,
        )
        severity_combo.pack(side="left", padx=2)

        # Detection type
        ctk.CTkLabel(
            filter_row,
            text="Type:",
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(10, 0))

        self._detection_type_var = ctk.StringVar(value="all")
        type_combo = ctk.CTkComboBox(
            filter_row,
            variable=self._detection_type_var,
            values=["all", "port_scan", "dos", "malware", "anomaly"],
            width=120,
        )
        type_combo.pack(side="left", padx=2)

        # Acknowledged
        self._acknowledged_var = tk.BooleanVar(value=False)
        acknowledged_check = ctk.CTkCheckBox(
            filter_row,
            text="Acknowledged only",
            variable=self._acknowledged_var,
        )
        acknowledged_check.pack(side="left", padx=(10, 0))

        # Buttons
        btn_frame = ctk.CTkFrame(self._filter_frame, fg_color=Colors.get_card_color())
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        ctk.CTkButton(
            btn_frame,
            text="🔍 Filter",
            width=100,
            command=self.filter_alerts,
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
            command=self.export_alerts,
        ).pack(side="left", padx=5)

    def _create_alerts_display(self) -> None:
        """Create alerts display area."""
        if not CUSTOMTKINTER_AVAILABLE:
            # Split into alerts list and detail view
            paned = ttk.PanedWindow(self._frame, orient="horizontal")
            paned.pack(fill="both", expand=True)

            # Alerts list
            self._alerts_frame = ttk.LabelFrame(paned, text="Alerts")
            paned.add(self._alerts_frame, weight=1)

            columns = ("Time", "Severity", "Type", "Title")
            self._alerts_tree = ttk.Treeview(self._alerts_frame, columns=columns, show="headings")

            for col in columns:
                self._alerts_tree.heading(col, text=col)
                if col == "Title":
                    self._alerts_tree.column(col, width=200)
                else:
                    self._alerts_tree.column(col, width=100)

            scrollbar = ttk.Scrollbar(self._alerts_frame, orient="vertical", command=self._alerts_tree.yview)
            self._alerts_tree.configure(yscrollcommand=scrollbar.set)

            self._alerts_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            self._alerts_tree.bind("<<TreeviewSelect>>", self._on_alert_select)

            # Detail view
            self._detail_frame = ttk.LabelFrame(paned, text="Alert Details")
            paned.add(self._detail_frame, weight=1)

            self._detail_text = tk.Text(self._detail_frame, wrap="word", state="disabled")
            detail_scroll = ttk.Scrollbar(self._detail_frame, orient="vertical", command=self._detail_text.yview)
            self._detail_text.configure(yscrollcommand=detail_scroll.set)

            self._detail_text.pack(side="left", fill="both", expand=True)
            detail_scroll.pack(side="right", fill="y")
            return

        # CustomTkinter alerts display
        content = ctk.CTkFrame(self._frame, fg_color=Colors.get_card_color())
        content.pack(fill="both", expand=True)

        # Alerts list (left)
        self._alerts_frame = ctk.CTkFrame(content)
        self._alerts_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        title = ctk.CTkLabel(
            self._alerts_frame,
            text="Alert List",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        title.pack(pady=(10, 5))

        # Use ttk.Treeview for alerts
        tree_frame = ttk.Frame(self._alerts_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Time", "Severity", "Type", "Title")
        self._alerts_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        for col in columns:
            self._alerts_tree.heading(col, text=col)
            if col == "Title":
                self._alerts_tree.column(col, width=200)
            else:
                self._alerts_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self._alerts_tree.yview)
        self._alerts_tree.configure(yscrollcommand=scrollbar.set)

        self._alerts_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._alerts_tree.bind("<<TreeviewSelect>>", self._on_alert_select)

        # Detail view (right)
        self._detail_frame = ctk.CTkFrame(content)
        self._detail_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

        detail_title = ctk.CTkLabel(
            self._detail_frame,
            text="Alert Details",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        detail_title.pack(pady=(10, 5))

        self._detail_text = ctk.CTkTextbox(self._detail_frame)
        self._detail_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Action buttons
        action_frame = ctk.CTkFrame(self._detail_frame, fg_color=Colors.get_card_color())
        action_frame.pack(fill="x", padx=10, pady=(0, 10))

        self._acknowledge_btn = ctk.CTkButton(
            action_frame,
            text="Acknowledge",
            command=self.acknowledge_alert,
        )
        self._acknowledge_btn.pack(side="left", padx=5)

        self._add_note_btn = ctk.CTkButton(
            action_frame,
            text="Add Note",
            command=self.add_note,
        )
        self._add_note_btn.pack(side="left", padx=5)

    def filter_alerts(self) -> None:
        """Filter alerts based on current filters."""
        if not self._database:
            return

        try:
            # Build filter
            alert_filter = AlertFilter()

            # Severity
            severity = self._severity_var.get()
            if severity != "all":
                alert_filter.severity = severity

            # Detection type
            det_type = self._detection_type_var.get()
            if det_type != "all":
                alert_filter.detection_type = det_type

            # Acknowledged
            if self._acknowledged_var.get():
                alert_filter.acknowledged = True

            # Time range (last 24 hours by default)
            if not self._start_time_var.get() and not self._end_time_var.get():
                alert_filter.start_time = datetime.now() - timedelta(hours=24)
            else:
                if self._start_time_var.get():
                    try:
                        alert_filter.start_time = datetime.strptime(
                            self._start_time_var.get(),
                            "%Y-%m-%d %H:%M:%S",
                        )
                    except ValueError:
                        pass

                if self._end_time_var.get():
                    try:
                        alert_filter.end_time = datetime.strptime(
                            self._end_time_var.get(),
                            "%Y-%m-%d %H:%M:%S",
                        )
                    except ValueError:
                        pass

            # Query database
            alert_repo = create_alert_repository(self._database)
            results = alert_repo.find_by_filter(alert_filter)

            self._current_alerts = results
            self._display_alerts(results)

        except Exception as e:
            self._logger.error(f"Error filtering alerts: {e}")

    def clear_filters(self) -> None:
        """Clear all filters."""
        self._severity_var.set("all")
        self._detection_type_var.set("all")
        self._acknowledged_var.set(False)

        self._current_alerts.clear()

        if hasattr(self, '_alerts_tree'):
            for item in self._alerts_tree.get_children():
                self._alerts_tree.delete(item)

        self._clear_detail_view()

    def export_alerts(self) -> None:
        """Export filtered alerts."""
        if not self._current_alerts:
            self._show_error("No alerts to export")
            return

        try:
            from tkinter import filedialog
            import csv

            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            )

            if filepath:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "timestamp", "detection_type", "severity", "title",
                        "description", "source_ip", "destination_ip",
                        "confidence", "acknowledged",
                    ])
                    writer.writeheader()

                    for alert in self._current_alerts:
                        writer.writerow({
                            "timestamp": alert.get("timestamp", ""),
                            "detection_type": alert.get("detection_type", ""),
                            "severity": alert.get("severity", ""),
                            "title": alert.get("title", ""),
                            "description": alert.get("description", ""),
                            "source_ip": alert.get("source_ip", ""),
                            "destination_ip": alert.get("destination_ip", ""),
                            "confidence": alert.get("confidence", 0),
                            "acknowledged": alert.get("acknowledged", False),
                        })

                self._show_info(f"Exported {len(self._current_alerts)} alerts")

        except Exception as e:
            self._logger.error(f"Error exporting alerts: {e}")
            self._show_error(f"Export error: {e}")

    def _display_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Display alerts in treeview.

        Args:
            alerts: Alert list
        """
        # Clear existing
        if hasattr(self, '_alerts_tree'):
            for item in self._alerts_tree.get_children():
                self._alerts_tree.delete(item)

        # Add alerts
        for alert in alerts:
            timestamp = alert.get("timestamp", "")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M:%S")
                except (ValueError, TypeError):
                    time_str = str(timestamp)[:19]
            else:
                time_str = ""

            severity = alert.get("severity", "").upper()
            alert_type = alert.get("detection_type", "unknown")
            title = alert.get("title", "No title")

            self._alerts_tree.insert("", 0, values=(time_str, severity, alert_type, title))

    def _on_alert_select(self, event) -> None:
        """Handle alert selection.

        Args:
            event: Selection event
        """
        if not hasattr(self, '_alerts_tree'):
            return

        selection = self._alerts_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self._alerts_tree.item(item, "values")

        # Find corresponding alert
        time_str = values[0]
        severity = values[1].lower()
        alert_type = values[2]
        title = values[3]

        for alert in self._current_alerts:
            if (alert.get("title") == title and
                alert.get("severity").lower() == severity and
                alert.get("detection_type") == alert_type):
                self._selected_alert = alert
                self._display_alert_detail(alert)
                break

    def _display_alert_detail(self, alert: Dict[str, Any]) -> None:
        """Display alert details.

        Args:
            alert: Alert dict
        """
        detail_text = f"""Title: {alert.get('title', 'N/A')}
Type: {alert.get('detection_type', 'N/A')}
Severity: {alert.get('severity', 'N/A').upper()}
Confidence: {alert.get('confidence', 0):.2f}

Timestamp: {alert.get('timestamp', 'N/A')}
Source IP: {alert.get('source_ip', 'N/A')}
Destination IP: {alert.get('destination_ip', 'N/A')}
Source Port: {alert.get('source_port', 'N/A')}
Destination Port: {alert.get('destination_port', 'N/A')}

Description:
{alert.get('description', 'No description')}

Evidence:
{alert.get('evidence', 'No evidence')}

Acknowledged: {'Yes' if alert.get('acknowledged') else 'No'}

Notes:
{alert.get('notes', 'No notes')}
"""

        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", detail_text)

        # Update acknowledge button
        if alert.get("acknowledged"):
            if CUSTOMTKINTER_AVAILABLE:
                self._acknowledge_btn.configure(state="disabled")
        else:
            if CUSTOMTKINTER_AVAILABLE:
                self._acknowledge_btn.configure(state="normal")

    def _clear_detail_view(self) -> None:
        """Clear detail view."""
        self._selected_alert = None

        if hasattr(self, '_detail_text'):
            self._detail_text.delete("1.0", "end")
            self._detail_text.insert("1.0", "Select an alert to view details")

    def acknowledge_alert(self) -> None:
        """Acknowledge selected alert."""
        if not self._selected_alert or not self._database:
            return

        try:
            from src.storage import AlertOrm

            alert_id = self._selected_alert.get("id")

            with self._database.get_session() as session:
                alert = session.query(AlertOrm).filter_by(id=alert_id).first()
                if alert:
                    alert.acknowledged = True
                    session.commit()

                    # Update local copy
                    self._selected_alert["acknowledged"] = True

                    # Refresh display
                    self._display_alert_detail(self._selected_alert)

        except Exception as e:
            self._logger.error(f"Error acknowledging alert: {e}")

    def add_note(self) -> None:
        """Add note to selected alert."""
        if not self._selected_alert or not self._database:
            return

        # Simple note input dialog
        note = self._show_input_dialog("Add Note", "Enter note:")

        if note:
            try:
                from src.storage import AlertOrm

                alert_id = self._selected_alert.get("id")

                with self._database.get_session() as session:
                    alert = session.query(AlertOrm).filter_by(id=alert_id).first()
                    if alert:
                        existing_notes = alert.notes or ""
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        alert.notes = f"{existing_notes}\n[{timestamp}] {note}\n"
                        session.commit()

                        # Update local copy
                        self._selected_alert["notes"] = alert.notes

                        # Refresh display
                        self._display_alert_detail(self._selected_alert)

            except Exception as e:
                self._logger.error(f"Error adding note: {e}")

    def _show_error(self, message: str) -> None:
        """Show error message.

        Args:
            message: Error message
        """
        # Always use standard messagebox - CTkMessageBox doesn't exist
        messagebox.showerror("Error", message)

    def _show_info(self, message: str) -> None:
        """Show info message.

        Args:
            message: Info message
        """
        # Always use standard messagebox - CTkMessageBox doesn't exist
        messagebox.showinfo("Information", message)

    def _show_input_dialog(self, title: str, prompt: str) -> str:
        """Show input dialog.

        Args:
            title: Dialog title
            prompt: Input prompt

        Returns:
            User input string
        """
        if CUSTOMTKINTER_AVAILABLE:
            # CustomTkinter doesn't have a built-in input dialog
            # Use simpledialog from tkinter
            from tkinter import simpledialog
            return simpledialog.askstring(title, prompt)
        else:
            from tkinter import simpledialog
            return simpledialog.askstring(title, prompt)

    def destroy(self) -> None:
        """Clean up alert panel resources."""
        if self._frame:
            self._frame.destroy()

        self._logger.info("Alert panel destroyed")


def create_alert_panel(
    parent,
    detection: Optional[DetectionEngine] = None,
    database: Optional[DatabaseManager] = None,
) -> AlertPanel:
    """Create alert panel instance.

    Args:
        parent: Parent widget
        detection: Detection engine
        database: Database manager

    Returns:
        AlertPanel instance
    """
    return AlertPanel(
        parent=parent,
        detection=detection,
        database=database,
    )


__all__ = [
    "AlertPanel",
    "create_alert_panel",
]
