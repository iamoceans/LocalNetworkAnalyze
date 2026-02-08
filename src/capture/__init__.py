"""
Packet capture module.

Provides functionality for capturing network packets with multiple
backend implementations.
"""

from typing import Optional

from .base import (
    PacketCapture,
    PacketInfo,
    CaptureState,
    CaptureCallback,
    validate_interface,
    validate_bpf_filter,
)
from .scapy_capture import (
    ScapyCapture,
    create_scapy_capture,
)

__all__ = [
    # Abstract base
    "PacketCapture",
    "PacketInfo",
    "CaptureState",
    "CaptureCallback",
    # Implementations
    "ScapyCapture",
    # Factory functions
    "create_capture",
    # Utilities
    "validate_interface",
    "validate_bpf_filter",
    "get_available_interfaces",
]


def create_capture(
    backend: str = "scapy",
    interface: str = "",
    filter: str = "",
    buffer_size: int = 1000,
    promiscuous: bool = True,
    timeout: Optional[int] = None,
    **kwargs,
) -> PacketCapture:
    """Create a packet capture instance.

    Factory function that creates the appropriate capture implementation
    based on the specified backend.

    Args:
        backend: Capture backend to use ("scapy", "pcapy")
        interface: Network interface name (empty for default)
        filter: BPF filter string for packet filtering
        buffer_size: Maximum packets to buffer
        promiscuous: Enable promiscuous mode
        timeout: Capture timeout in seconds (None = no timeout)
        **kwargs: Additional backend-specific arguments

    Returns:
        Configured PacketCapture instance

    Raises:
        ValueError: If backend is not supported

    Example:
        >>> # Create with default backend
        >>> capture = create_capture()
        >>>
        >>> # Create with specific interface
        >>> capture = create_capture(interface="eth0")
        >>>
        >>> # Create with filter
        >>> capture = create_capture(filter="tcp port 80")
    """
    if backend == "scapy":
        return ScapyCapture(
            interface=interface,
            filter=filter,
            buffer_size=buffer_size,
            promiscuous=promiscuous,
            timeout=timeout,
        )
    else:
        raise ValueError(
            f"Unsupported capture backend: {backend}",
        )


def get_available_interfaces() -> list[dict]:
    """Get list of available network interfaces.

    Returns a list of dictionaries containing interface information
    including name, IP address, and description.

    Returns:
        List of interface information dictionaries

    Example:
        >>> interfaces = get_available_interfaces()
        >>> for iface in interfaces:
        ...     print(f"{iface['name']}: {iface['address']}")
    """
    return ScapyCapture.get_interfaces()


def find_default_interface() -> Optional[str]:
    """Find the default network interface.

    Attempts to find a suitable default interface by looking for
    the first non-loopback interface with an IP address.

    Returns:
        Interface name or None if not found

    Example:
        >>> iface = find_default_interface()
        >>> if iface:
        ...     print(f"Default interface: {iface}")
    """
    interfaces = get_available_interfaces()

    # Look for first interface with an IP address
    for iface_info in interfaces:
        if iface_info["address"] and iface_info["address"] != "0.0.0.0":
            return iface_info["name"]

    # Fallback to first interface
    if interfaces:
        return interfaces[0]["name"]

    return None
