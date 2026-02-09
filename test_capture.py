"""
Quick test script to verify packet capture functionality.

Run this script with administrator privileges to test if
Npcap is properly installed and packet capture works.
"""

import sys
import time
from scapy.all import sniff, conf
from src.capture.scapy_capture import ScapyCapture


def test_environment():
    """Test the capture environment."""
    print("=" * 60)
    print("Network Capture Environment Test")
    print("=" * 60)
    print()

    # Check environment
    result = ScapyCapture.check_capture_environment()

    print("Environment Check Results:")
    print(f"  Administrator Privileges: {'✓ Yes' if result['is_admin'] else '✗ No'}")
    print(f"  Npcap Installed:          {'✓ Yes' if result['npcap_installed'] else '✗ No'}")
    print(f"  Npcap Service Running:    {'✓ Yes' if result['npcap_service_running'] else '✗ No'}")
    print()

    if result['issues']:
        print("Issues Found:")
        for issue in result['issues']:
            print(f"  ✗ {issue}")
        print()

    if result['suggestions']:
        print("Suggested Solutions:")
        for suggestion in result['suggestions']:
            print(f"  → {suggestion}")
        print()

    # Check Scapy configuration
    print("Scapy Configuration:")
    print(f"  Use PCAP:     {conf.use_pcap}")
    print(f"  Default iface: {conf.iface}")
    print()

    # List available interfaces
    print("Available Network Interfaces:")
    try:
        interfaces = ScapyCapture.get_interfaces()
        if interfaces:
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface.get('description', iface['name'])}")
                print(f"     Name:    {iface['name']}")
                print(f"     Address: {iface.get('address', 'N/A')}")
                print()
        else:
            print("  No interfaces found!")
    except Exception as e:
        print(f"  Error getting interfaces: {e}")
    print()

    return result['is_admin'] and result['npcap_installed']


def test_capture_short():
    """Test packet capture for 5 seconds."""
    print("=" * 60)
    print("Packet Capture Test (5 seconds)")
    print("=" * 60)
    print()
    print("Starting capture test... (Generating some network activity will help)")
    print("Try opening a web browser or pinging a website.")
    print()

    packet_count = 0

    def packet_callback(packet):
        nonlocal packet_count
        packet_count += 1
        from datetime import datetime
        timestamp = datetime.fromtimestamp(float(packet.time))
        print(f"  [{timestamp.strftime('%H:%M:%S')}] Packet #{packet_count}: {packet.summary()}")

    try:
        # Capture for 5 seconds
        sniff(timeout=5, prn=packet_callback, store=False)
    except Exception as e:
        print(f"Capture failed: {e}")
        return False

    print()
    print(f"Total packets captured: {packet_count}")

    if packet_count > 0:
        print("✓ Packet capture is working!")
    else:
        print("⚠ No packets captured. This might be normal if there's no network activity.")
        print("  Try running the test while opening a website or running: ping google.com")

    return packet_count > 0


def main():
    """Main test function."""
    print()

    # Test environment first
    env_ok = test_environment()

    if not env_ok:
        print("=" * 60)
        print("ENVIRONMENT TEST FAILED")
        print("=" * 60)
        print()
        print("Please fix the issues above before running the capture test.")
        print()
        print("Most common fix:")
        print("  → Right-click this script and select 'Run as Administrator'")
        print()
        input("Press Enter to exit...")
        sys.exit(1)

    # Ask user if they want to run capture test
    print("=" * 60)
    response = input("Run packet capture test? (y/n): ").strip().lower()

    if response == 'y':
        print()
        test_capture_short()

    print()
    print("=" * 60)
    print("Test Complete")
    print("=" * 60)
    print()
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()
