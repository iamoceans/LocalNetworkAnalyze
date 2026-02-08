"""
GUI module for network analyzer.

Provides main window and various functional panels
for monitoring and controlling network analysis.
"""

from .main_window import (
    MainWindow,
    create_main_window,
)

from .dashboard import (
    DashboardPanel,
    create_dashboard,
)

from .capture_panel import (
    CapturePanel,
    create_capture_panel,
)

from .scan_panel import (
    ScanPanel,
    create_scan_panel,
)

from .analysis_panel import (
    AnalysisPanel,
    create_analysis_panel,
)

from .alert_panel import (
    AlertPanel,
    create_alert_panel,
)

__all__ = [
    # Main Window
    "MainWindow",
    "create_main_window",
    # Dashboard
    "DashboardPanel",
    "create_dashboard",
    # Capture Panel
    "CapturePanel",
    "create_capture_panel",
    # Scan Panel
    "ScanPanel",
    "create_scan_panel",
    # Analysis Panel
    "AnalysisPanel",
    "create_analysis_panel",
    # Alert Panel
    "AlertPanel",
    "create_alert_panel",
]
