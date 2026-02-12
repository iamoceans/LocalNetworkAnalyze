"""
GUI components package for Local Network Analyzer.

Provides reusable UI components for panels with
iOS-themed styling.
"""

# Core components
from .packet_tree import PacketTree
from .control_bar import ControlBar

# iOS-style components
from .tab_bar import TabItem, iOSTabBar
from .ios_button import iOSButton, iOSButtonStyle, iOSButtonSize
from .ios_segment import iOSSegment
from .ios_switch import iOSSwitch
from .ios_modal import iOSModal, iOSModalStyle
from .ios_list import iOSListItem, iOSList
from .ios_progress import iOSActivitySpinner, iOSProgressBar
# Note: Use iOSActivitySpinner and iOSProgressBar when importing from ios_progress

# Legacy components (maintained for backward compatibility)
from .glass_frame import GlassFrame, GlassLabel
from .neon_button import NeonButton, NeonToggleButton
from .stat_card import StatCard, StatGrid

__all__ = [
    # Core
    "PacketTree",
    "ControlBar",

    # iOS components
    "TabItem",
    "iOSTabBar",
    "iOSButton",
    "iOSButtonStyle",
    "iOSButtonSize",
    "iOSSegment",
    "iOSSwitch",
    "iOSModal",
    "iOSModalStyle",
    "iOSListItem",
    "iOSList",
    "iOSActivitySpinner",
    "iOSProgressBar",
    "Note: Use iOSActivitySpinner and iOSProgressBar when importing from ios_progress",

    # Legacy
    "GlassFrame",
    "GlassLabel",
    "NeonButton",
    "NeonToggleButton",
    "StatCard",
    "StatGrid",
]
