"""
Main application window.

Provides the primary GUI framework for the network analyzer
with iOS-style design and bottom TabBar navigation.
"""

import tkinter as tk
from tkinter import ttk
import os
from typing import Optional, Callable, Dict, Any
from datetime import datetime
import threading
import time

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    import tkinter as ctk

from src.core.logger import get_logger
from src.core.config import GuiConfig
from src.core.language_manager import LanguageManager
from src.capture import PacketCapture, create_capture as create_packet_capture
from src.analysis import AnalysisEngine, create_analysis_engine
from src.detection import DetectionEngine, create_detection_engine
from src.storage import DatabaseManager, get_database_manager

# Import iOS theme system
from src.gui.theme.colors import Colors, ThemeMode, iOSSpacing, iOSShapes
from src.gui.theme.typography import Fonts

# Import panels
from src.gui.dashboard import create_dashboard
from src.gui.capture_panel import create_capture_panel
from src.gui.scan_panel import create_scan_panel
from src.gui.analysis_panel import create_analysis_panel
from src.gui.alert_panel import create_alert_panel

# Import iOS components
from src.gui.components.tab_bar import iOSTabBar
from src.gui.components.ios_button import iOSButton


class MainWindow:
    """Main application window with iOS-style design.

    Features:
    - Left sidebar TabBar navigation
    - iOS color scheme
    - Clean, modern interface
    - 80pt sidebar width
    """

    # Tab definitions
    TABS = [
        {"key": "dashboard", "icon": "📊", "label": "Dashboard", "panel": "dashboard"},
        {"key": "capture", "icon": "📡", "label": "Capture", "panel": "capture"},
        {"key": "scan", "icon": "🔍", "label": "Scan", "panel": "scan"},
        {"key": "analysis", "icon": "📈", "label": "Analysis", "panel": "analysis"},
        {"key": "alerts", "icon": "⚠️", "label": "Alerts", "panel": "alerts"},
    ]

    def __init__(
        self,
        config: Optional[GuiConfig] = None,
        lang_manager: Optional[LanguageManager] = None,
    ) -> None:
        """Initialize main window.

        Args:
            config: GUI configuration
            lang_manager: Language manager for translations
        """
        self._config = config or GuiConfig()
        self._lang = lang_manager
        self._logger = get_logger(__name__)

        # Initialize engines
        self._capture: Optional[PacketCapture] = None
        self._analysis: Optional[AnalysisEngine] = None
        self._detection: Optional[DetectionEngine] = None
        self._database: Optional[DatabaseManager] = None

        # Create main window
        self._root = self._create_window()

        # UI components
        self._header_frame: Optional[tk.Frame] = None
        self._content_frame: Optional[tk.Frame] = None
        self._tab_bar: Optional[iOSTabBar] = None
        self._current_frame: Optional[tk.Frame] = None

        # Status bar
        self._status_var: Optional[ctk.StringVar] = None
        self._packet_count_var: Optional[ctk.StringVar] = None
        self._alert_count_var: Optional[ctk.StringVar] = None
        self._alert_label: Optional[Any] = None

        # Current panel
        self._current_panel = None
        self._current_tab = "dashboard"

        # Tab callbacks
        self._tab_callbacks = {
            "dashboard": lambda: self._show_dashboard(),
            "capture": lambda: self._show_capture(),
            "scan": lambda: self._show_scan(),
            "analysis": lambda: self._show_analysis(),
            "alerts": lambda: self._show_alerts(),
        }

        # Application state
        self._is_capturing = False
        self._is_scanning = False

        self._logger.info("Main window initialized")

    def _create_window(self) -> tk.Tk:
        """Create main window with iOS dark theme.

        Returns:
            Main window instance
        """
        if CUSTOMTKINTER_AVAILABLE:
            root = ctk.CTk()
            root.title("Local Network Analyzer")
            root.geometry(f"{self._config.window_width}x{self._config.window_height}")

            # Apply iOS dark theme
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("dark-blue")

            # Configure window background
            root.configure(fg_color=Colors.THEME.bg_primary)

            return root
        else:
            # Fallback to standard tkinter
            root = tk.Tk()
            root.title("Local Network Analyzer")
            root.geometry(f"{self._config.window_width}x{self._config.window_height}")
            root.configure(bg=Colors.THEME.bg_primary)

            # Configure basic styling
            style = ttk.Style()
            style.theme_use("clam")
            style.configure(".", background=Colors.THEME.bg_primary)
            style.configure("TFrame", background=Colors.THEME.bg_card)
            style.configure("TButton", background=Colors.THEME.bg_hover, foreground=Colors.THEME.text_primary)
            style.configure("TLabel", background=Colors.THEME.bg_primary, foreground=Colors.THEME.text_primary)

            return root

    def setup_ui(self) -> None:
        """Setup user interface with iOS-style layout.

        Creates:
        - Left sidebar TabBar (80pt width)
        - Main content area
        - Status bar (at bottom)
        """
        # Create main iOS layout (includes grid configuration)
        self._create_ios_layout()

        # Create status bar
        self._create_status_bar()

        # Show initial panel
        self._show_dashboard()

        self._logger.info("iOS-style UI setup completed")

    def _create_ios_layout(self) -> None:
        """Create iOS-style layout with left sidebar, content, and status bar.

        Layout structure:
        ┌─────────────────────────────────────────────┐
        │ ┌──────┐  Content Area                   │
        │ │      │  (Current Panel)                 │
        │ │ Tab │                                  │
        │ │ Bar │                                  │
        │ │      │                                  │
        │ └──────┘                                  │
        │ ┌──────────────────────────────────────┐   │
        │ │ Status Bar                          │   │
        │ └──────────────────────────────────────┘   │
        └─────────────────────────────────────────────┘
        """
        # Configure root grid for left sidebar layout
        self._root.grid_rowconfigure(0, weight=1)
        self._root.grid_columnconfigure(0, weight=0)  # Sidebar fixed width
        self._root.grid_columnconfigure(1, weight=1)  # Content expands

        # Tab bar frame (left sidebar)
        self._tab_bar = iOSTabBar(self._root)
        self._tab_bar.grid(row=0, column=0, sticky="ns", padx=0, pady=0)

        # Content frame (main area for panels)
        self._content_frame = ctk.CTkFrame(self._root, corner_radius=0, fg_color=Colors.get_card_color())
        self._content_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self._content_frame.grid_rowconfigure(0, weight=1)  # Content panel expands
        self._content_frame.grid_rowconfigure(1, weight=0)  # Status bar fixed height
        self._content_frame.grid_columnconfigure(0, weight=1)

        # Status bar frame container (at the bottom of content area)
        self._status_frame = ctk.CTkFrame(self._content_frame, fg_color=Colors.get_card_color())
        self._status_frame.grid(row=1, column=0, sticky="ew")

    def _create_header(self) -> None:
        """Create iOS-style header bar.

        Could contain:
        - Large title (for current view)
        - Back button
        - Action buttons
        """
        # Get translations or use defaults
        def t(key: str, default: str) -> str:
            if self._lang:
                return self._lang.t(key)
            return default

        # Title based on current tab
        tab_info = next((tab for tab in self.TABS if tab["key"] == self._current_tab), None)
        if tab_info:
            title = t(f"navigation.{tab_info['key']}", tab_info["label"])
        else:
            title = t("app.name", "Network Analyzer")

        # Create header content
        # Left: optional back button (not shown on root dashboard)
        # Center: title
        # Right: optional actions (theme toggle, etc.)

        title_label = ctk.CTkLabel(
            self._header_frame,
            text=title,
            font=Fonts.TITLE2,
            text_color=Colors.THEME.text_primary if ThemeMode.is_dark() else Colors.THEME.light_text_primary,
            anchor="w",
        )
        title_label.pack(side="left", padx=iOSSpacing.lg, expand=True, fill="x")

        # Optional: Add theme toggle button
        theme_btn = iOSButton(
            self._header_frame,
            text="◐",
            size="small",
            style="plain",
            command=self._toggle_theme,
        )
        theme_btn.pack(side="right", padx=iOSSpacing.md)

    def _create_status_bar(self) -> None:
        """Create iOS-style status bar at bottom of content area."""
        if CUSTOMTKINTER_AVAILABLE:
            # Status bar frame
            status_frame = ctk.CTkFrame(
                self._status_frame,
                height=32,
                corner_radius=iOSShapes.corner_small,
                fg_color=Colors.THEME.bg_secondary if ThemeMode.is_dark() else Colors.THEME.light_bg_secondary,
                border_width=1,
                border_color=Colors.THEME.separator,
            )
            status_frame.pack(fill="x", padx=iOSSpacing.lg, pady=(iOSSpacing.md, iOSSpacing.sm))

            # Status variables
            self._status_var = ctk.StringVar(value="Ready")
            self._packet_count_var = ctk.StringVar(value="Packets: 0")
            self._alert_count_var = ctk.StringVar(value="Alerts: 0")

            # Status label
            status_label = ctk.CTkLabel(
                status_frame,
                textvariable=self._status_var,
                font=Fonts.CAPTION1,
                text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
                anchor="w",
            )
            status_label.pack(side="left", padx=iOSSpacing.md)

            # Packet count
            packet_label = ctk.CTkLabel(
                status_frame,
                textvariable=self._packet_count_var,
                font=Fonts.CAPTION1,
                text_color=Colors.THEME.system_green,
                anchor="e",
            )
            packet_label.pack(side="right", padx=iOSSpacing.md)

            # Alert count
            self._alert_label = ctk.CTkLabel(
                status_frame,
                textvariable=self._alert_count_var,
                font=Fonts.CAPTION1,
                text_color=Colors.THEME.text_secondary if ThemeMode.is_dark() else Colors.THEME.light_text_secondary,
                anchor="e",
            )
            self._alert_label.pack(side="right", padx=(iOSSpacing.xs, iOSSpacing.md))

            # Separator
            separator = ctk.CTkLabel(
                status_frame,
                text="|",
                font=Fonts.CAPTION1,
                text_color=Colors.THEME.separator,
            )
            separator.pack(side="right", padx=iOSSpacing.xs)

        else:
            # Standard tkinter status bar
            status_frame = ttk.Frame(self._status_frame)
            status_frame.pack(side="bottom", fill="x")

            self._status_var = tk.StringVar(value="Ready")
            self._packet_count_var = tk.StringVar(value="Packets: 0")
            self._alert_count_var = tk.StringVar(value="Alerts: 0")

            ttk.Label(status_frame, textvariable=self._status_var).pack(side="left", padx=10)
            ttk.Label(status_frame, textvariable=self._packet_count_var).pack(side="right", padx=10)
            ttk.Label(status_frame, textvariable=self._alert_count_var).pack(side="right", padx=10)

    def _setup_tab_bar(self) -> None:
        """Setup the left sidebar TabBar with all tabs."""
        # Add all tabs to the tab bar
        for tab in self.TABS:
            self._tab_bar.add_tab(
                name=tab["key"],
                icon=tab["icon"],
                label=tab["label"],
                callback=self._tab_callbacks[tab["key"]],
            )

        # Set initial active tab
        self._tab_bar.set_active_tab(self._current_tab)

    def _show_panel_by_key(self, panel_key: str) -> None:
        """Show a panel by its tab key.

        Args:
            panel_key: The tab key (dashboard, capture, scan, analysis, alerts)
        """
        # Update tab bar active state
        self._current_tab = panel_key
        self._tab_bar.set_active_tab(panel_key)

        # Clear content frame
        self._clear_content_frame()

        # Get tab info
        tab_info = next((tab for tab in self.TABS if tab["key"] == panel_key), None)
        if not tab_info:
            self._logger.warning(f"Unknown panel key: {panel_key}")
            return

        # Create and show panel
        if panel_key == "dashboard":
            self._show_dashboard()
        elif panel_key == "capture":
            self._show_capture()
        elif panel_key == "scan":
            self._show_scan()
        elif panel_key == "analysis":
            self._show_analysis()
        elif panel_key == "alerts":
            self._show_alerts()

        # Update status
        self._update_status(f"{tab_info['label']} loaded")

    def _clear_content_frame(self) -> None:
        """Clear panel widgets from content frame (preserves status bar)."""
        # Clean up current panel
        if self._current_panel and hasattr(self._current_panel, 'destroy'):
            try:
                self._current_panel.destroy()
            except Exception as e:
                self._logger.warning(f"Error destroying panel: {e}")

        self._current_panel = None

        # Clear only panel widgets from row 0 (preserve status bar in row 1)
        try:
            widgets = self._content_frame.winfo_children()
            for widget in widgets:
                # Skip status bar frame
                if widget == self._status_frame:
                    continue
                # Check if widget is in row 0 (panel area)
                try:
                    grid_info = widget.grid_info()
                    if grid_info and int(grid_info.get('row', 1)) == 0:
                        widget.destroy()
                except Exception:
                    # If no grid info, try to destroy anyway (but skip status_frame)
                    if widget != self._status_frame:
                        try:
                            widget.destroy()
                        except Exception as e:
                            self._logger.debug(f"Error destroying widget: {e}")
        except Exception as e:
            self._logger.warning(f"Error clearing content frame: {e}")

    def _show_dashboard(self) -> None:
        """Show dashboard panel."""
        self._clear_content_frame()

        try:
            self._current_panel = create_dashboard(
                parent=self._content_frame,
                capture=self._capture,
                analysis=self._analysis,
                detection=self._detection,
                database=self._database,
            )

            # Build dashboard UI
            self._current_panel.build()

            self._update_status("Dashboard loaded")

        except Exception as e:
            self._logger.error(f"Error loading dashboard: {e}")
            self._update_status("Error loading dashboard")

    def _show_capture(self) -> None:
        """Show capture panel."""
        self._clear_content_frame()

        try:
            self._current_panel = create_capture_panel(
                parent=self._content_frame,
                capture=self._capture,
                analysis=self._analysis,
                detection=self._detection,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Capture loaded")

        except Exception as e:
            self._logger.error(f"Error loading capture panel: {e}")
            self._update_status("Error loading capture panel")

    def _show_scan(self) -> None:
        """Show scan panel."""
        self._clear_content_frame()

        try:
            from src.scan import create_network_scanner

            # Always create a new scanner instance
            scanner = create_network_scanner()

            self._current_panel = create_scan_panel(
                parent=self._content_frame,
                scanner=scanner,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Scan loaded")

        except Exception as e:
            self._logger.error(f"Error loading scan panel: {e}")
            self._update_status("Error loading scan panel")

    def _show_analysis(self) -> None:
        """Show analysis panel."""
        self._clear_content_frame()

        try:
            self._current_panel = create_analysis_panel(
                parent=self._content_frame,
                analysis=self._analysis,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Analysis loaded")

        except Exception as e:
            self._logger.error(f"Error loading analysis panel: {e}")
            self._update_status("Error loading analysis panel")

    def _show_alerts(self) -> None:
        """Show alerts panel."""
        self._clear_content_frame()

        try:
            self._current_panel = create_alert_panel(
                parent=self._content_frame,
                detection=self._detection,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Alerts loaded")

        except Exception as e:
            self._logger.error(f"Error loading alerts panel: {e}")
            self._update_status("Error loading alerts panel")

    def _update_status(self, message: str) -> None:
        """Update status bar message.

        Args:
            message: Status message
        """
        if self._status_var:
            self._status_var.set(message)

    def update_packet_count(self, count: int) -> None:
        """Update packet count display.

        Args:
            count: Packet count
        """
        if self._packet_count_var:
            self._packet_count_var.set(f"Packets: {count:,}")

    def update_alert_count(self, count: int) -> None:
        """Update alert count display.

        Args:
            count: Alert count
        """
        if self._alert_count_var:
            self._alert_count_var.set(f"Alerts: {count:,}")
            # Update badge on tab bar
            if count > 0:
                self._tab_bar.set_badge("alerts", str(count) if count > 99 else "99+")
            else:
                self._tab_bar.set_badge("alerts", None)

    def _toggle_theme(self) -> None:
        """Toggle between light and dark theme."""
        ThemeMode.toggle()
        # Recreate window to apply new theme
        self._logger.info(f"Theme toggled to {ThemeMode.get_mode()}")
        # In a real implementation, you might want to update all widget colors

    def set_engines(
        self,
        capture: Optional[PacketCapture] = None,
        analysis: Optional[AnalysisEngine] = None,
        detection: Optional[DetectionEngine] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        """Set engine instances.

        Args:
            capture: Packet capture engine
            analysis: Analysis engine
            detection: Detection engine
            database: Database manager
        """
        self._capture = capture
        self._analysis = analysis
        self._detection = detection
        self._database = database

        self._logger.info("Engines configured")

    def run(self) -> None:
        """Run main application loop."""
        try:
            self._logger.info("Starting main window")

            # Setup UI first
            self.setup_ui()

            # Setup tab bar after UI is created
            self._setup_tab_bar()

            # Start mainloop
            self._root.mainloop()

        except Exception as e:
            self._logger.error(f"Error running main window: {e}")
            raise

    def quit(self) -> None:
        """Quit application.

        Stops capture, closes database, and destroys window.
        """
        self._logger.info("Quitting application")

        # Clean up current panel
        if self._current_panel and hasattr(self._current_panel, 'destroy'):
            try:
                self._current_panel.destroy()
            except Exception:
                pass

        # Stop capture if running
        if self._capture and self._is_capturing:
            try:
                self._capture.stop_capture()
            except Exception:
                pass

        # Close database connection
        if self._database:
            try:
                self._database.disconnect()
            except Exception:
                pass

        # Destroy window
        if self._root:
            self._root.destroy()

    def get_root(self) -> Any:
        """Get root window.

        Returns:
            Root window instance
        """
        return self._root

    def get_config(self) -> GuiConfig:
        """Get GUI configuration.

        Returns:
            GUI configuration
        """
        return self._config


def create_main_window(
    config: Optional[GuiConfig] = None,
    lang_manager: Optional[LanguageManager] = None,
) -> MainWindow:
    """Create main window instance.

    Args:
        config: Optional GUI configuration
        lang_manager: Optional language manager for translations

    Returns:
        MainWindow instance
    """
    return MainWindow(config, lang_manager)


__all__ = [
    "MainWindow",
    "create_main_window",
]
