"""
Network utility functions.

Provides helpers for network interface identification and routing.
"""

import socket
import psutil
import subprocess
import logging
from typing import Optional, Tuple

from src.core.logger import get_logger
logger = get_logger(__name__)

def get_active_wifi_interface() -> Optional[Tuple[str, str]]:
    """
    Get the active internet-facing Wi-Fi interface.
    
    This function attempts to determine which network interface is currently
    routing internet traffic and verifies if it's a Wi-Fi interface.
    
    Returns:
        Tuple of (interface_name, ip_address) if found, else None.
        interface_name is the system name (e.g., "Wi-Fi").
    """
    # 1. Determine the local IP used for internet access
    # Connect to a public DNS (8.8.8.8) to let the OS routing table decide the source IP
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # We don't actually send data, just connecting to determine routing
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except OSError as e:
        logger.warning(f"Failed to determine local IP via socket connection: {e}")
        return None

    if not local_ip:
        return None

    # 2. Find the interface name matching this IP
    target_iface_name = None
    for iface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.address == local_ip:
                target_iface_name = iface_name
                break
        if target_iface_name:
            break

    if not target_iface_name:
        return None

    # 3. Verify if it is a Wi-Fi interface
    # On Windows, we can use netsh to list wireless interfaces
    is_wifi = False
    
    # Heuristic 1: Check name keywords
    wifi_keywords = ['wi-fi', 'wlan', 'wireless', '无线']
    if any(k in target_iface_name.lower() for k in wifi_keywords):
        is_wifi = True
        
    # Heuristic 2: Use system commands for stricter verification (Windows only)
    if not is_wifi:
        try:
            # 使用列表参数避免shell=True的安全风险
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=False,
                stderr=subprocess.STDOUT
            )
            output = result.stdout.decode('gbk', errors='ignore')

            # If the interface name appears in netsh wlan output, it's a Wi-Fi interface
            if target_iface_name in output:
                is_wifi = True
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
            logger.debug(f"Failed to verify Wi-Fi interface via netsh: {e}")

    if is_wifi:
        return target_iface_name, local_ip
        
    return None
