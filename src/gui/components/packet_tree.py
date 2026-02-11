"""
Packet tree display component.

Provides a reusable Treeview component for displaying captured packets.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False

import tkinter as tk
from tkinter import ttk


class PacketTree:
    """Treeview component for displaying captured packets.

    Provides methods for adding, clearing, and formatting packet data.
    """

    # Column configuration - matching Top10 dashboard format
    COLUMNS = ("请求地址", "访问URL", "访问端口", "流量size", "最近访问时间")
    COLUMN_WIDTHS = {
        "请求地址": 150,
        "访问URL": 200,
        "访问端口": 80,
        "流量size": 100,
        "最近访问时间": 120,
    }

    def __init__(self, parent: tk.Widget, max_packets: int = 100):
        """Initialize packet tree.

        Args:
            parent: Parent widget
            max_packets: Maximum number of packets to display
        """
        self._parent = parent
        self._max_packets = max_packets
        self._tree: Optional[ttk.Treeview] = None
        self._displayed_packets: List[Dict[str, Any]] = []

    def create(self, parent_frame: tk.Widget) -> None:
        """Create the treeview widget with scrollbars.

        Args:
            parent_frame: Frame to contain the treeview
        """
        # Create container for treeview and scrollbars
        container = tk.Frame(parent_frame)
        container.pack(fill="both", expand=True)

        if not CUSTOMTKINTER_AVAILABLE:
            self._tree = ttk.Treeview(container, columns=self.COLUMNS, show="headings")
        else:
            # For CustomTkinter, use standard ttk.Treeview in a frame
            self._tree = ttk.Treeview(container, columns=self.COLUMNS, show="headings")

        # Configure columns with stretchable widths
        for col in self.COLUMNS:
            stretch = col not in ("访问端口", "流量size", "最近访问时间")  # Only 请求地址 and 访问URL stretch
            self._tree.column(col, width=self.COLUMN_WIDTHS.get(col, 100), stretch=stretch)
            self._tree.heading(col, text=col)

        # Add vertical scrollbar
        v_scrollbar = ttk.Scrollbar(container, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=v_scrollbar.set)

        # Add horizontal scrollbar
        h_scrollbar = ttk.Scrollbar(container, orient="horizontal", command=self._tree.xview)
        self._tree.configure(xscrollcommand=h_scrollbar.set)

        # Pack widgets
        self._tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        # Configure grid weights
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

    def add_packet(self, packet_info: Dict[str, Any]) -> None:
        """Add a packet to the display.

        Args:
            packet_info: Dictionary with packet data (timestamp, src_ip, dst_ip, etc.)
        """
        if not self._tree:
            return

        # Format timestamp
        timestamp = packet_info.get('timestamp', '')
        if isinstance(timestamp, datetime):
            time_str = timestamp.strftime("%H:%M:%S")
        elif isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%H:%M:%S")
            except (ValueError, TypeError):
                time_str = str(timestamp)[:8]
        else:
            time_str = str(timestamp)

        # Format 请求地址 - destination IP:port
        dst_ip = packet_info.get('dst_ip', '')
        dst_port = packet_info.get('dst_port')
        request_address = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

        # Format 访问URL - host/url if available
        url_display = self._format_url_display(
            packet_info.get('url'),
            packet_info.get('host'),
            packet_info.get('dst_port')
        )

        # Format 访问端口 - destination port
        port_display = str(dst_port) if dst_port else ""

        # Format 流量size - formatted bytes
        size_display = self._format_bytes(packet_info.get('length', 0))

        # Insert into treeview
        self._tree.insert("", 0, values=(
            request_address,
            url_display,
            port_display,
            size_display,
            time_str,
        ))

        # Add to displayed list
        self._displayed_packets.append(packet_info)

        # Limit size
        items = self._tree.get_children()
        if len(items) > self._max_packets:
            self._tree.delete(items[-1])

        if len(self._displayed_packets) > self._max_packets:
            self._displayed_packets.pop(0)

    def clear(self) -> None:
        """Clear all packets from display."""
        if self._tree:
            for item in self._tree.get_children():
                self._tree.delete(item)
        self._displayed_packets.clear()

    def get_displayed_packets(self) -> List[Dict[str, Any]]:
        """Get list of displayed packets.

        Returns:
            List of packet dictionaries
        """
        return self._displayed_packets.copy()

    def set_displayed_packets(self, packets: List[Dict[str, Any]]) -> None:
        """Set the displayed packets (for state restoration).

        Args:
            packets: List of packet dictionaries to display
        """
        self.clear()
        for packet in packets:
            self.add_packet(packet)

    def bind_select(self, callback) -> None:
        """Bind selection event callback.

        Args:
            callback: Function to call when item is selected
        """
        if self._tree:
            self._tree.bind("<<TreeviewSelect>>", callback)

    def _format_endpoint(self, ip: str, port: Optional[int]) -> str:
        """Format endpoint as IP:Port or just IP.

        Args:
            ip: IP address
            port: Port number (optional)

        Returns:
            Formatted endpoint string
        """
        return f"{ip}:{port}" if port else ip

    def _format_bytes(self, size: int) -> str:
        """Format bytes into human-readable format.

        Args:
            size: Size in bytes

        Returns:
            Formatted size string (B, KB, MB, GB, TB)
        """
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        for unit in units:
            if size < 1024.0:
                if unit == 'B':
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def _format_url_display(self, url: Optional[str], host: Optional[str], dst_port: Optional[int]) -> str:
        """Format URL/Host for display.

        Args:
            url: Full URL
            host: Host header value or SNI hostname for HTTPS
            dst_port: Destination port

        Returns:
            Formatted URL display string
        """
        if url:
            # Show full URL, truncated if too long
            url_display = url
            if len(url_display) > 40:
                url_display = url_display[:37] + "..."
            return url_display
        elif host:
            # Show hostname (from HTTP Host header or TLS SNI)
            return host
        elif dst_port == 443:
            # HTTPS with no SNI
            return "(encrypted/no SNI)"
        elif dst_port == 80:
            # HTTP with no Host header
            return "(no host)"
        return ""

    @property
    def widget(self) -> Optional[ttk.Treeview]:
        """Get the underlying treeview widget.

        Returns:
            Treeview widget or None if not created
        """
        return self._tree


__all__ = ["PacketTree"]
