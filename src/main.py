"""
Main entry point for Local Network Analyzer.

This module provides the main application initialization
and command-line interface.
"""

import sys
import logging
import argparse
from pathlib import Path
from typing import Optional

from src.core.logger import get_logger, setup_logging
from src.core.config import GuiConfig, CaptureConfig, LogConfig, AppConfig
from src.core.language_manager import create_language_manager
from src.capture import create_capture as create_packet_capture
from src.analysis import create_analysis_engine
from src.detection import create_detection_engine
from src.storage import get_database_manager, DatabaseConfig, init_database
from src.gui import create_main_window


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Local Network Analyzer - Monitor and analyze network traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default settings
  python -m src.main

  # Start with specific network interface
  python -m src.main --interface eth0

  # Start with custom database
  python -m src.main --database /path/to/database.db

  # Enable debug logging
  python -m src.main --debug

  # Run headless (no GUI) with capture
  python -m src.main --headless --interface eth0 --duration 60
        """,
    )

    # Interface options
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture from",
        default=None,
    )

    # Capture options
    parser.add_argument(
        "-f", "--filter",
        help="BPF filter for packet capture",
        default=None,
    )

    parser.add_argument(
        "-d", "--duration",
        type=int,
        help="Capture duration in seconds (headless mode only)",
        default=None,
    )

    # Database options
    parser.add_argument(
        "--database",
        help="Path to database file",
        default=None,
    )

    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialize database and exit",
    )

    # GUI options
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without GUI",
    )

    parser.add_argument(
        "--theme",
        choices=["light", "dark", "system"],
        help="GUI theme",
        default="system",
    )

    parser.add_argument(
        "--language",
        choices=["en", "zh"],
        help="Interface language (en=English, zh=Chinese)",
        default=None,
    )

    # Logging options
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    parser.add_argument(
        "--log-file",
        help="Log file path",
        default=None,
    )

    # Scan options (for headless mode)
    parser.add_argument(
        "--scan",
        choices=["arp", "icmp", "port"],
        help="Run network scan and exit",
        default=None,
    )

    parser.add_argument(
        "--target",
        help="Target for network scan (IP or CIDR)",
        default=None,
    )

    parser.add_argument(
        "--ports",
        help="Ports for port scan (e.g., 1-1024, 80,443,8080)",
        default=None,
    )

    return parser.parse_args()


def setup_application(args: argparse.Namespace) -> None:
    """Setup application configuration.

    Args:
        args: Command-line arguments
    """
    # Setup logging
    log_level_str = "DEBUG" if args.debug else "INFO"
    log_path = Path(args.log_file) if args.log_file else Path("logs/app.log")
    log_config = LogConfig(level=log_level_str, path=log_path)
    setup_logging(log_config)

    logger = get_logger(__name__)
    logger.info("Local Network Analyzer starting...")
    logger.debug(f"Arguments: {args}")


def initialize_components(args: argparse.Namespace):
    """Initialize application components.

    Args:
        args: Command-line arguments

    Returns:
        Tuple of (capture, analysis, detection, database)
    """
    logger = get_logger(__name__)

    # Initialize database
    db_config = DatabaseConfig(db_path=args.database) if args.database else DatabaseConfig()
    database = get_database_manager(db_config)
    database.connect()

    logger.info(f"Database initialized: {db_config.db_path}")

    # Initialize analysis engine
    analysis = create_analysis_engine()
    logger.info("Analysis engine initialized")

    # Initialize detection engine
    detection = create_detection_engine()
    logger.info("Detection engine initialized")

    # Initialize packet capture
    capture = None
    if args.interface:
        capture = create_packet_capture(backend="scapy")
        logger.info(f"Packet capture initialized (interface: {args.interface})")
    else:
        # Create with default backend (can be configured later in GUI)
        capture = create_packet_capture(backend="scapy")
        logger.info("Packet capture initialized")

    return capture, analysis, detection, database


def run_headless_capture(args, capture, analysis, detection, database):
    """Run headless capture mode.

    Args:
        args: Command-line arguments
        capture: Packet capture engine
        analysis: Analysis engine
        detection: Detection engine
        database: Database manager
    """
    logger = get_logger(__name__)

    if not args.interface:
        logger.error("No interface specified for headless capture")
        sys.exit(1)

    if not args.duration:
        logger.error("No duration specified for headless capture")
        sys.exit(1)

    # Setup packet processing
    from src.capture.base import PacketInfo
    from src.storage import create_packet_repository
    import time

    packet_repo = create_packet_repository(database.get_session)

    packets_captured = 0
    alerts_generated = 0

    def packet_callback(packet: PacketInfo):
        nonlocal packets_captured
        packets_captured += 1

        # Process through analysis
        analysis.update(packet)

        # Save to database
        packet_repo.save(packet)

        # Check for detection alerts
        detection.process_packet(packet)

    def alert_callback(alert):
        nonlocal alerts_generated
        alerts_generated += 1
        logger.warning(f"Alert: {alert.title} - {alert.description}")

    # Wire up callbacks
    capture.add_callback(packet_callback)
    detection.add_callback(alert_callback)

    # Start capture
    logger.info(f"Starting capture on {args.interface} for {args.duration} seconds...")

    try:
        capture.start_capture(
            interface=args.interface,
            filter=args.filter or "",
        )

        # Wait for duration
        time.sleep(args.duration)

    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")

    finally:
        capture.stop_capture()

    # Print summary
    stats = analysis.get_statistics()
    logger.info("Capture summary:")
    logger.info(f"  Packets captured: {packets_captured}")
    logger.info(f"  Total bytes: {stats['total_bytes']:,}")
    logger.info(f"  Alerts generated: {alerts_generated}")
    logger.info(f"  Active connections: {len(analysis.get_active_connections())}")


def run_headless_scan(args, database):
    """Run headless network scan.

    Args:
        args: Command-line arguments
        database: Database manager
    """
    logger = get_logger(__name__)

    if not args.target:
        logger.error("No target specified for scan")
        sys.exit(1)

    from src.scan import create_network_scanner
    from src.storage import ScanResultOrm
    import uuid
    from datetime import datetime

    scanner = create_network_scanner()

    try:
        if args.scan == "arp":
            logger.info(f"Starting ARP scan on {args.target}...")
            results = scanner.arp_scan(args.target)
        elif args.scan == "icmp":
            logger.info(f"Starting ICMP scan on {args.target}...")
            results = scanner.icmp_scan(args.target)
        elif args.scan == "port":
            logger.info(f"Starting port scan on {args.target}...")

            # Parse ports
            ports = None
            if args.ports:
                if "-" in args.ports:
                    start, end = args.ports.split("-", 1)
                    ports = list(range(int(start), int(end) + 1))
                else:
                    ports = [int(p.strip()) for p in args.ports.split(",")]
            else:
                ports = list(range(1, 1025))

            results = scanner.port_scan(args.target, ports)
        else:
            logger.error(f"Unknown scan type: {args.scan}")
            sys.exit(1)

        # Print results
        logger.info(f"Scan complete - {len(results)} hosts found")

        for result in results:
            status = "Alive" if result.get("alive") else "Down"
            logger.info(f"  {result.get('ip')}: {status}")

            if result.get("hostname"):
                logger.info(f"    Hostname: {result['hostname']}")

            if result.get("mac"):
                logger.info(f"    MAC: {result['mac']}")

            if result.get("ports"):
                logger.info(f"    Open ports: {result['ports']}")

            if result.get("latency"):
                logger.info(f"    Latency: {result['latency']:.2f}ms")

        # Save to database
        with database.get_session() as session:
            for result in results:
                scan_result = ScanResultOrm(
                    scan_id=str(uuid.uuid4()),
                    scan_type=args.scan,
                    target_ip=result.get("ip", ""),
                    target_hostname=result.get("hostname"),
                    mac_address=result.get("mac"),
                    is_alive=result.get("alive", False),
                    response_time=result.get("latency"),
                    open_ports=str(result.get("ports", [])),
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                )
                session.add(scan_result)

            session.commit()

        logger.info("Results saved to database")

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


def run_gui(args, capture, analysis, detection, database):
    """Run GUI application.

    Args:
        args: Command-line arguments
        capture: Packet capture engine
        analysis: Analysis engine
        detection: Detection engine
        database: Database manager
    """
    logger = get_logger(__name__)

    # Create GUI configuration
    gui_config = GuiConfig(
        theme=args.theme,
        language=args.language or "en",
    )

    # Create full app config for language manager
    config_path = Path("config/app_config.json")
    app_config = AppConfig()

    # Try to load existing config, create default if not exists
    if config_path.exists():
        try:
            app_config = AppConfig.from_file(config_path)
            # Override language if specified via CLI
            if args.language:
                app_config = app_config.with_language(args.language)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}, using defaults")
    else:
        # Apply CLI language setting to default config
        if args.language:
            app_config = app_config.with_language(args.language)

    # Initialize language manager
    lang_manager = create_language_manager(
        config=app_config.gui,
        config_path=config_path,
        app_config=app_config,
    )

    # Create main window with language manager
    main_window = create_main_window(
        config=app_config.gui,
        lang_manager=lang_manager,
    )

    # Set engines
    main_window.set_engines(
        capture=capture,
        analysis=analysis,
        detection=detection,
        database=database,
    )

    logger.info("Starting GUI application...")

    try:
        # Run main loop
        main_window.run()

    except Exception as e:
        logger.error(f"GUI error: {e}")
        raise

    finally:
        logger.info("Application shutdown")


def main():
    """Main entry point."""
    # Parse arguments
    args = parse_arguments()

    # Setup application
    setup_application(args)

    logger = get_logger(__name__)

    # Initialize database only if requested
    if args.init_db:
        db_config = DatabaseConfig(db_path=args.database) if args.database else DatabaseConfig()
        database = get_database_manager(db_config)
        database.connect()
        logger.info("Database initialized")
        database.disconnect()
        sys.exit(0)

    # Run scan if requested
    if args.scan:
        db_config = DatabaseConfig(db_path=args.database) if args.database else DatabaseConfig()
        database = get_database_manager(db_config)
        database.connect()

        try:
            run_headless_scan(args, database)
        finally:
            database.disconnect()

        sys.exit(0)

    # Initialize components
    capture, analysis, detection, database = initialize_components(args)

    try:
        # Run appropriate mode
        if args.headless:
            run_headless_capture(args, capture, analysis, detection, database)
        else:
            run_gui(args, capture, analysis, detection, database)

    except Exception as e:
        logger.exception(f"Application error: {e}")
        sys.exit(1)

    finally:
        # Cleanup
        if database:
            try:
                database.disconnect()
            except Exception:
                pass

    logger.info("Application exited successfully")


if __name__ == "__main__":
    main()
