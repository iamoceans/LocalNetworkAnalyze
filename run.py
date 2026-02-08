"""
Local Network Analyzer - Startup Script

This script provides convenient entry points for running the network analyzer
in different modes.
"""

import sys
import os
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def main():
    """Main entry point for startup script."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Local Network Analyzer - Monitor and analyze network traffic",
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Start GUI application (default)",
    )

    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run in headless mode (no GUI)",
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture from",
    )

    parser.add_argument(
        "-d", "--duration",
        type=int,
        help="Capture duration in seconds (headless mode only)",
    )

    parser.add_argument(
        "--scan",
        choices=["arp", "icmp", "port"],
        help="Run network scan",
    )

    parser.add_argument(
        "--target",
        help="Target for network scan (IP or CIDR)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Import and run main application
    from src.main import main as app_main

    # Convert args to sys.argv format
    sys.argv = ["network_analyzer"]

    if args.gui:
        sys.argv.append("--theme")
        sys.argv.append("system")

    if args.headless:
        sys.argv.append("--headless")

    if args.interface:
        sys.argv.extend(["--interface", args.interface])

    if args.duration:
        sys.argv.extend(["--duration", str(args.duration)])

    if args.scan:
        sys.argv.extend(["--scan", args.scan])

    if args.target:
        sys.argv.extend(["--target", args.target])

    if args.debug:
        sys.argv.append("--debug")

    app_main()


if __name__ == "__main__":
    main()
