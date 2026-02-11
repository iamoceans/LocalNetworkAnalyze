"""
Capture state management.

Handles saving and restoring capture panel state for panel switching.
"""

from typing import Optional, Dict, Any, List
from src.capture.base import PacketCapture


class CaptureState:
    """Manages capture panel state.

    Provides methods to save and restore capture state,
    allowing users to switch between panels without losing
    active capture sessions.
    """

    def __init__(self) -> None:
        """Initialize capture state manager."""
        self._capture: Optional[PacketCapture] = None
        self._selected_interface: Optional[str] = None
        self._capture_filter: str = ""
        self._displayed_packets: List[Dict[str, Any]] = []
        self._is_capturing: bool = False

    def save(
        self,
        capture: Optional[PacketCapture],
        selected_interface: Optional[str],
        capture_filter: str,
        displayed_packets: List[Dict[str, Any]],
        is_capturing: bool,
    ) -> None:
        """Save current capture state.

        Args:
            capture: Active capture instance
            selected_interface: Selected interface name
            capture_filter: BPF filter string
            displayed_packets: List of displayed packet data
            is_capturing: Whether capture is active
        """
        self._capture = capture
        self._selected_interface = selected_interface
        self._capture_filter = capture_filter
        self._displayed_packets = displayed_packets.copy()
        self._is_capturing = is_capturing

    def to_dict(self) -> Optional[Dict[str, Any]]:
        """Export state to dictionary.

        Returns:
            Dictionary with state data, or None if not capturing
        """
        if not self._is_capturing or not self._capture:
            return None

        return {
            'is_capturing': True,
            'capture': self._capture,
            'selected_interface': self._selected_interface,
            'capture_filter': self._capture_filter,
            'displayed_packets': self._displayed_packets.copy(),
        }

    def restore_from_dict(self, state: Dict[str, Any]) -> bool:
        """Restore state from dictionary.

        Args:
            state: Previously saved state dictionary

        Returns:
            True if state was restored, False otherwise
        """
        if not state or not state.get('is_capturing'):
            return False

        self._capture = state['capture']
        self._is_capturing = True
        self._selected_interface = state.get('selected_interface')
        self._capture_filter = state.get('capture_filter', '')
        self._displayed_packets = state.get('displayed_packets', [])
        return True

    def clear(self) -> None:
        """Clear all state."""
        self._capture = None
        self._selected_interface = None
        self._capture_filter = ""
        self._displayed_packets.clear()
        self._is_capturing = False

    @property
    def capture(self) -> Optional[PacketCapture]:
        """Get the capture instance."""
        return self._capture

    @property
    def selected_interface(self) -> Optional[str]:
        """Get the selected interface."""
        return self._selected_interface

    @property
    def capture_filter(self) -> str:
        """Get the capture filter."""
        return self._capture_filter

    @property
    def displayed_packets(self) -> List[Dict[str, Any]]:
        """Get the displayed packets list."""
        return self._displayed_packets.copy()

    @property
    def is_capturing(self) -> bool:
        """Check if capture is active."""
        return self._is_capturing and self._capture is not None


__all__ = ["CaptureState"]
