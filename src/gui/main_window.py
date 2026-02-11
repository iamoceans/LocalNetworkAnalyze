"""
Main application window.

Provides the primary GUI framework for the network analyzer.
"""

import tkinter as tk
from tkinter import ttk
import os
from typing import Optional, Callable, Dict, Any
from datetime import datetime
import threading

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False
    # Fall back to standard tkinter
    import tkinter as ctk

from src.core.logger import get_logger
from src.core.config import GuiConfig
from src.core.language_manager import LanguageManager
from src.capture import PacketCapture, create_capture as create_packet_capture
from src.analysis import AnalysisEngine, create_analysis_engine
from src.detection import DetectionEngine, create_detection_engine
from src.storage import DatabaseManager, get_database_manager
from src.gui.dashboard import create_dashboard
from src.gui.capture_panel import create_capture_panel
from src.gui.scan_panel import create_scan_panel
from src.gui.analysis_panel import create_analysis_panel
from src.gui.alert_panel import create_alert_panel

# Import new theme system
from src.gui.theme.colors import Colors, NeonColors
from src.gui.theme.typography import Fonts, Typography
from src.gui.components import GlassFrame, NeonButton


class MainWindow:
    """Main application window.

    Coordinates all GUI components and manages the application lifecycle.
    """

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

        # Initialize engines (will be created later)
        self._capture: Optional[PacketCapture] = None
        self._analysis: Optional[AnalysisEngine] = None
        self._detection: Optional[DetectionEngine] = None
        self._database: Optional[DatabaseManager] = None

        # Create main window
        self._root = self._create_window()

        # UI components (will be created in subclasses)
        self._current_frame: Optional[tk.Frame] = None
        self._navigation_frame: Optional[tk.Frame] = None
        self._content_frame: Optional[tk.Frame] = None

        # Status bar
        self._status_var: Optional[ctk.StringVar] = None
        self._packet_count_var: Optional[ctk.StringVar] = None
        self._alert_count_var: Optional[ctk.StringVar] = None

        # Current panel (for cleanup)
        self._current_panel = None

        # Application state
        self._is_capturing = False
        self._is_scanning = False

        self._logger.info("Main window initialized")

    def _create_window(self) -> tk.Tk:
        """Create main window with cyber-security dark theme.

        Returns:
            Main window instance
        """
        if CUSTOMTKINTER_AVAILABLE:
            root = ctk.CTk()
            root.title("Local Network Analyzer")
            root.geometry(f"{self._config.window_width}x{self._config.window_height}")

            # Apply cyber-security dark theme
            ctk.set_appearance_mode("Dark")

            # Use dark theme as base
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

            # Apply dark colors
            style.configure(".", background=Colors.THEME.bg_primary)
            style.configure("TFrame", background=Colors.THEME.bg_primary)
            style.configure("TLabelframe", background=Colors.THEME.bg_card, bordercolor=Colors.THEME.border_default)
            style.configure("TLabelframe.Label", background=Colors.THEME.bg_card, foreground=Colors.THEME.text_primary)
            style.configure("TButton", background=Colors.THEME.bg_hover, foreground=Colors.THEME.text_primary, borderwidth=0)
            style.configure("TLabel", background=Colors.THEME.bg_primary, foreground=Colors.THEME.text_primary)
            style.map("TButton", background=[("active", Colors.NEON.neon_green_dim)])

            return root

    def setup_ui(self) -> None:
        """Setup user interface components.

        This method should be called after initialization
        to build all UI components.
        """
        # Create main layout
        self._create_main_layout()

        # Create status bar
        self._create_status_bar()

        # Create initial content frame
        self._show_default_content()

        self._logger.info("UI setup completed")

    def _create_main_layout(self) -> None:
        """Create main window layout with glassmorphism sidebar.

        Creates navigation frame on the left and content frame on the right.
        """
        if CUSTOMTKINTER_AVAILABLE:
            # Grid layout for main window
            self._root.grid_rowconfigure(0, weight=1)
            self._root.grid_columnconfigure(1, weight=1)

            # Navigation frame (sidebar) with glass effect
            self._navigation_frame = ctk.CTkFrame(
                self._root,
                width=240,
                corner_radius=16,
                fg_color=Colors.THEME.bg_card,
                border_width=1,
                border_color=Colors.THEME.border_default,
            )
            self._navigation_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
            self._navigation_frame.grid_rowconfigure(5, weight=1)

            # Content frame (main area) - transparent
            self._content_frame = ctk.CTkFrame(
                self._root,
                corner_radius=16,
                fg_color="transparent"
            )
            self._content_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 20), pady=20)
            self._content_frame.grid_rowconfigure(0, weight=1)
            self._content_frame.grid_columnconfigure(0, weight=1)

            # Create navigation buttons
            self._create_navigation()

        else:
            # Standard tkinter layout
            self._navigation_frame = ttk.Frame(self._root, width=200, relief="ridge", borderwidth=1)
            self._navigation_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

            self._content_frame = ttk.Frame(self._root)
            self._content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Create navigation buttons
            self._create_navigation()

    def _create_navigation(self) -> None:
        """Create navigation buttons in sidebar."""
        # Get translations or use defaults
        def t(key: str, default: str) -> str:
            if self._lang:
                return self._lang.t(key)
            return default

        if not CUSTOMTKINTER_AVAILABLE:
            # Standard tkinter navigation
            nav_items = [
                ("navigation.dashboard", "Dashboard", lambda: self._show_dashboard()),
                ("navigation.capture", "Capture", lambda: self._show_capture()),
                ("navigation.scan", "Scan", lambda: self._show_scan()),
                ("navigation.analysis", "Analysis", lambda: self._show_analysis()),
                ("navigation.alerts", "Alerts", lambda: self._show_alerts()),
            ]

            for key, default, callback in nav_items:
                label = t(key, default)
                btn = ttk.Button(
                    self._navigation_frame,
                    text=label,
                    command=callback,
                )
                btn.pack(fill=tk.X, padx=5, pady=5)

            # Language selector
            self._add_language_selector_tk()

            # Add quit button
            quit_label = t("navigation.exit", "Exit")
            quit_btn = ttk.Button(
                self._navigation_frame,
                text=quit_label,
                command=self.quit,
            )
            quit_btn.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

            return

        # CustomTkinter navigation with neon styling
        nav_buttons = [
            {
                "key": "navigation.dashboard",
                "default": "Dashboard",
                "icon": "📊",
                "command": self._show_dashboard,
            },
            {
                "key": "navigation.capture",
                "default": "Capture",
                "icon": "📡",
                "command": self._show_capture,
            },
            {
                "key": "navigation.scan",
                "default": "Scan",
                "icon": "🔍",
                "command": self._show_scan,
            },
            {
                "key": "navigation.analysis",
                "default": "Analysis",
                "icon": "📈",
                "command": self._show_analysis,
            },
            {
                "key": "navigation.alerts",
                "default": "Alerts",
                "icon": "⚠️",
                "command": self._show_alerts,
            },
        ]

        # Add title/logo to sidebar
        title_label = ctk.CTkLabel(
            self._navigation_frame,
            text="🔍 Network",
            font=("Fira Code", 18, "bold"),
            text_color=Colors.NEON.neon_green,
        )
        title_label.pack(pady=(15, 10))

        # Navigation buttons with ghost/neon style
        for btn_config in nav_buttons:
            text = t(btn_config["key"], btn_config["default"])
            btn = ctk.CTkButton(
                self._navigation_frame,
                text=f"{text}  {btn_config['icon']}",
                font=("Fira Code", 13),
                height=42,
                fg_color="transparent",
                text_color=Colors.THEME.text_secondary,
                hover_color=Colors.NEON.neon_green_dim,
                anchor="w",
                corner_radius=8,
                command=btn_config["command"],
                border_width=0,
            )
            btn.pack(fill=tk.X, padx=12, pady=4)

        # Add language selector
        self._add_language_selector_ctk()

        # Add spacer before exit button
        ctk.CTkLabel(self._navigation_frame, text="").pack(pady=15)

        # Exit button with red accent
        exit_label = t("navigation.exit", "Exit")
        exit_btn = ctk.CTkButton(
            self._navigation_frame,
            text=f"{exit_label}  🚪",
            font=("Fira Code", 13),
            height=42,
            fg_color="transparent",
            text_color=Colors.NEON.neon_red,
            hover_color=Colors.NEON.neon_red_dim,
            anchor="w",
            corner_radius=8,
            command=self.quit,
            border_width=0,
        )
        exit_btn.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=(0, 15))

    def _create_status_bar(self) -> None:
        """Create status bar at bottom with neon indicators."""
        if CUSTOMTKINTER_AVAILABLE:
            # Status bar frame with glass effect
            status_frame = ctk.CTkFrame(
                self._root,
                height=32,
                fg_color=Colors.THEME.bg_card,
                corner_radius=8,
            )
            status_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 15))

            # Status variables
            self._status_var = ctk.StringVar(value="Ready")
            self._packet_count_var = ctk.StringVar(value="Packets: 0")
            self._alert_count_var = ctk.StringVar(value="Alerts: 0")

            # Status label with Fira Code font
            status_label = ctk.CTkLabel(
                status_frame,
                textvariable=self._status_var,
                anchor="w",
                font=("Fira Code", 11),
                text_color=Colors.THEME.text_secondary,
            )
            status_label.pack(side=tk.LEFT, padx=12)

            # Packet count with neon green accent
            packet_label = ctk.CTkLabel(
                status_frame,
                textvariable=self._packet_count_var,
                font=("Fira Code", 11),
                text_color=Colors.NEON.neon_green,
            )
            packet_label.pack(side=tk.RIGHT, padx=12)

            # Separator
            separator = ctk.CTkLabel(
                status_frame,
                text="|",
                font=("Fira Code", 11),
                text_color=Colors.THEME.border_default,
            )
            separator.pack(side=tk.RIGHT, padx=(0, 12))

            # Alert count with neon red accent (if alerts > 0)
            self._alert_label = ctk.CTkLabel(
                status_frame,
                textvariable=self._alert_count_var,
                font=("Fira Code", 11),
                text_color=Colors.THEME.text_secondary,
            )
            self._alert_label.pack(side=tk.RIGHT, padx=(0, 12))

        else:
            # Standard tkinter status bar
            status_frame = ttk.Frame(self._root)
            status_frame.pack(side=tk.BOTTOM, fill=tk.X)

            self._status_var = tk.StringVar(value="Ready")
            self._packet_count_var = tk.StringVar(value="Packets: 0")
            self._alert_count_var = tk.StringVar(value="Alerts: 0")

            ttk.Label(
                status_frame,
                textvariable=self._status_var,
            ).pack(side=tk.LEFT, padx=10)

            ttk.Label(
                status_frame,
                textvariable=self._packet_count_var,
            ).pack(side=tk.RIGHT, padx=10)

            ttk.Label(
                status_frame,
                textvariable=self._alert_count_var,
            ).pack(side=tk.RIGHT, padx=10)

    def _add_language_selector_tk(self) -> None:
        """Add language selector for standard tkinter."""
        if not self._lang:
            return

        def t(key: str, default: str) -> str:
            return self._lang.t(key, default=default)

        # Language label
        lang_label = ttk.Label(
            self._navigation_frame,
            text=t("navigation.language", "Language") + ":",
        )
        lang_label.pack(pady=(20, 5))

        # Language variable
        current_lang = self._lang.get_language()
        lang_var = tk.StringVar(value=current_lang)

        def on_language_change(*args):
            new_lang = lang_var.get()
            if new_lang != current_lang:
                self._switch_language(new_lang)

        lang_var.trace("w", on_language_change)

        # Language dropdown
        lang_combo = ttk.Combobox(
            self._navigation_frame,
            textvariable=lang_var,
            values=["en", "zh"],
            state="readonly",
            width=18,
        )
        lang_combo.pack(padx=5, pady=5)

    def _add_language_selector_ctk(self) -> None:
        """Add language selector for CustomTkinter."""
        if not self._lang:
            return

        def t(key: str, default: str) -> str:
            return self._lang.t(key, default=default)

        # Language label
        lang_label = ctk.CTkLabel(
            self._navigation_frame,
            text=t("navigation.language", "Language"),
            font=ctk.CTkFont(size=12),
        )
        lang_label.pack(pady=(10, 5))

        # Language variable
        current_lang = self._lang.get_language()

        def on_language_select(choice):
            if choice != current_lang:
                # Extract language code from choice
                lang_code = "en" if "English" in choice else "zh"
                self._switch_language(lang_code)

        # Language options
        lang_options = [
            self._lang.get_language_name("en"),
            self._lang.get_language_name("zh"),
        ]

        # Get display name for current language
        current_display = self._lang.get_language_name(current_lang)

        lang_combo = ctk.CTkOptionMenu(
            self._navigation_frame,
            values=lang_options,
            command=on_language_select,
        )
        lang_combo.set(current_display)
        lang_combo.pack(padx=10, pady=5)

    def _switch_language(self, lang: str) -> None:
        """Switch application language.

        Args:
            lang: New language code ("en" or "zh")
        """
        if not self._lang:
            return

        def t(key: str, default: str) -> str:
            return self._lang.t(key, default=default)

        # Get display name for confirmation
        lang_name = self._lang.get_language_name(lang)

        # Simple confirmation using message box
        import tkinter.messagebox as messagebox
        confirm = messagebox.askyesno(
            t("language.switch_confirm", "Switch Language?").replace("{lang}", lang_name),
            t("language.switch_confirm", "Switch to {lang}?").replace("{lang}", lang_name),
        )

        if confirm:
            try:
                self._lang.set_language(lang)
                # Restart application to apply changes
                self._logger.info(f"Language switched to {lang}, restarting...")
                self._restart_application()
            except ValueError as e:
                messagebox.showerror("Error", str(e))

    def _restart_application(self) -> None:
        """Restart the application to apply language changes."""
        # Store current state
        # Then restart by destroying and recreating the window
        # For now, just destroy and let the main loop handle it
        self._root.destroy()

    def _show_default_content(self) -> None:
        """Show default welcome content."""
        if not CUSTOMTKINTER_AVAILABLE:
            label = ttk.Label(
                self._content_frame,
                text="Local Network Analyzer\n\nSelect a module from the sidebar to begin.",
                font=("Arial", 16),
            )
            label.pack(expand=True)
            return

        # CustomTkinter welcome content with neon styling
        welcome_frame = ctk.CTkFrame(self._content_frame, fg_color="transparent")
        welcome_frame.pack(expand=True, fill="both", padx=20, pady=20)

        # Main title with neon effect
        title_label = ctk.CTkLabel(
            welcome_frame,
            text="Local Network Analyzer",
            font=("Fira Code", 36, "bold"),
            text_color=Colors.NEON.neon_green,
        )
        title_label.pack(pady=(40, 10))

        # Subtitle
        subtitle_label = ctk.CTkLabel(
            welcome_frame,
            text="Monitor and analyze your local network traffic",
            font=("Fira Sans", 16),
            text_color=Colors.THEME.text_secondary,
        )
        subtitle_label.pack(pady=(0, 30))

        # Info message
        info_label = ctk.CTkLabel(
            welcome_frame,
            text="Select a module from the sidebar to begin",
            font=("Fira Code", 13),
            text_color=Colors.THEME.text_muted,
        )
        info_label.pack(pady=(0, 40))

        # Features in glass cards
        features_frame = ctk.CTkFrame(welcome_frame, fg_color="transparent")
        features_frame.pack(pady=20)

        features = [
            ("📡", "Real-time Packet Capture", "Capture and monitor network packets in real-time"),
            ("🔍", "Network Scanning", "Discover devices and services on your network"),
            ("📈", "Traffic Analysis", "Analyze network patterns and protocols"),
            ("⚠️", "Anomaly Detection", "Detect suspicious activities and threats"),
        ]

        for i, (icon, title, desc) in enumerate(features):
            # Create glass-style card for each feature
            card = ctk.CTkFrame(
                features_frame,
                corner_radius=12,
                fg_color=Colors.GLASS.bg_color,
                border_width=1,
                border_color=Colors.THEME.border_default,
            )
            card.pack(fill="x", pady=8, padx=(50, 50))

            # Icon and title
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=15, pady=(12, 6))

            ctk.CTkLabel(
                header,
                text=icon,
                font=("Segoe UI Emoji", 18),
            ).pack(side="left", padx=(0, 10))

            ctk.CTkLabel(
                header,
                text=title,
                font=("Fira Code", 13, "bold"),
                text_color=Colors.THEME.text_primary,
            ).pack(side="left")

            # Description
            ctk.CTkLabel(
                card,
                text=desc,
                font=("Fira Sans", 11),
                text_color=Colors.THEME.text_secondary,
                anchor="w",
            ).pack(fill="x", padx=15, pady=(0, 12))

    def _show_dashboard(self) -> None:
        """Show dashboard panel."""
        self._clear_content_frame()

        try:
            # Create dashboard
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
        """Show packet capture panel."""
        self._clear_content_frame()

        try:
            # Create capture panel
            panel = create_capture_panel(
                parent=self._content_frame,
                capture=self._capture,
                analysis=self._analysis,
                detection=self._detection,
                database=self._database,
            )

            # Build panel UI
            panel.build()

            # Restore capture state if one is running
            # Check if there's an active capture from a previous panel instance
            if hasattr(self, '_active_capture_state') and self._active_capture_state:
                panel.restore_capture_state(self._active_capture_state)

            # Save reference to current panel for state restoration
            self._current_panel = panel

            self._update_status("Capture panel loaded")

        except Exception as e:
            self._logger.error(f"Error loading capture panel: {e}")
            self._update_status("Error loading capture panel")

    def _show_scan(self) -> None:
        """Show network scan panel."""
        self._clear_content_frame()

        try:
            # Create scan panel
            from src.scan import create_network_scanner

            # Always create a new scanner instance if not provided
            # We don't need to check for capture engine, as scanner is independent
            scanner = create_network_scanner()

            self._current_panel = create_scan_panel(
                parent=self._content_frame,
                scanner=scanner,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Scan panel loaded")

        except Exception as e:
            self._logger.error(f"Error loading scan panel: {e}")
            self._update_status("Error loading scan panel")

    def _show_analysis(self) -> None:
        """Show analysis panel."""
        self._clear_content_frame()

        try:
            # Create analysis panel
            self._current_panel = create_analysis_panel(
                parent=self._content_frame,
                analysis=self._analysis,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Analysis panel loaded")

        except Exception as e:
            self._logger.error(f"Error loading analysis panel: {e}")
            self._update_status("Error loading analysis panel")

    def _show_alerts(self) -> None:
        """Show alerts panel."""
        self._clear_content_frame()

        try:
            # Create alert panel
            self._current_panel = create_alert_panel(
                parent=self._content_frame,
                detection=self._detection,
                database=self._database,
            )

            # Build panel UI
            self._current_panel.build()

            self._update_status("Alerts panel loaded")

        except Exception as e:
            self._logger.error(f"Error loading alert panel: {e}")
            self._update_status("Error loading alert panel")

    def _clear_content_frame(self) -> None:
        """Clear all widgets from content frame."""
        # Clean up current panel if it has a destroy method
        if self._current_panel and hasattr(self._current_panel, 'destroy'):
            try:
                self._current_panel.destroy()
            except Exception as e:
                self._logger.warning(f"Error destroying panel: {e}")
                # Continue even if destroy fails

        self._current_panel = None

        # Clear all widgets from content frame
        # Use a more robust approach to handle CustomTkinter widgets
        try:
            widgets = self._content_frame.winfo_children()
            for widget in widgets:
                try:
                    widget.destroy()
                except Exception as e:
                    # Log but continue with other widgets
                    self._logger.debug(f"Error destroying widget: {e}")
        except Exception as e:
            self._logger.warning(f"Error clearing content frame: {e}")

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
        """Run the main application loop."""
        try:
            self._logger.info("Starting main window")

            # Setup UI first
            self.setup_ui()

            # Start mainloop
            self._root.mainloop()

        except Exception as e:
            self._logger.error(f"Error running main window: {e}")
            raise

    def quit(self) -> None:
        """Quit the application.

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
