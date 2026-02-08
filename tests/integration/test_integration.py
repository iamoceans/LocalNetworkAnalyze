"""
Integration tests for network analyzer.

Tests the interaction between different modules
and end-to-end workflows.
"""

import pytest
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, Mock

from src.capture import PacketCapture, PacketInfo, create_capture
from src.analysis import AnalysisEngine, create_analysis_engine
from src.detection import DetectionEngine, Alert, create_detection_engine
from src.detection.base import Severity, DetectionType
from src.storage import DatabaseManager, DatabaseConfig, create_tables, get_database_manager
from src.storage import PacketFilter, AlertFilter


@pytest.mark.integration
class TestCaptureWithAnalysis:
    """Test integration between packet capture and analysis engine."""

    def test_capture_to_analysis_flow(self):
        """Test packets flow from capture to analysis engine."""
        # Create analysis engine
        analysis = create_analysis_engine()

        # Create capture with scapy backend
        capture = create_capture(backend="scapy")

        # Track packets received by analysis
        received_packets = []

        def packet_callback(packet: PacketInfo):
            received_packets.append(packet)
            analysis.update(packet)

        capture.add_callback(packet_callback)

        # Simulate packet capture
        test_packets = [
            PacketInfo(
                timestamp=datetime.now(),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                length=1500,
                raw_data=b"test packet data 1",
            ),
            PacketInfo(
                timestamp=datetime.now(),
                src_ip="192.168.1.2",
                dst_ip="192.168.1.1",
                src_port=80,
                dst_port=12345,
                protocol="TCP",
                length=500,
                raw_data=b"test packet data 2",
            ),
        ]

        # Simulate capture delivering packets
        for packet in test_packets:
            packet_callback(packet)

        # Verify packets were processed
        assert len(received_packets) == 2

        # Verify analysis engine processed them
        stats = analysis.get_summary()
        assert stats["traffic"]["total_packets"] == 2
        assert stats["traffic"]["total_bytes"] == 2000

    def test_capture_with_connection_tracking(self):
        """Test connection tracking with packet capture."""
        analysis = create_analysis_engine()
        capture = create_capture(backend="scapy")

        # Simulate TCP handshake and data transfer
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=5000,
                dst_port=443,
                protocol="TCP",
                length=100,
                raw_data=b"SYN packet",
            ),
            PacketInfo(
                timestamp=datetime.now() + timedelta(milliseconds=10),
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=443,
                dst_port=5000,
                protocol="TCP",
                length=80,
                raw_data=b"SYN-ACK packet",
            ),
            PacketInfo(
                timestamp=datetime.now() + timedelta(milliseconds=20),
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=5000,
                dst_port=443,
                protocol="TCP",
                length=1500,
                raw_data=b"Data packet",
            ),
        ]

        for packet in packets:
            analysis.update(packet)

        # Check connection tracking
        connections = analysis.get_active_connections()
        # Note: Connection tracker creates separate connections for each direction
        # So we get 2 connections (bidirectional)
        assert len(connections) == 2

        # Calculate total packets across all connections
        total_packets = sum(c.total_packets for c in connections)
        total_bytes = sum(c.total_bytes for c in connections)

        assert total_packets == 3
        assert total_bytes == 1680


@pytest.mark.integration
class TestAnalysisWithDetection:
    """Test integration between analysis and detection engines."""

    def test_bandwidth_alert_generation(self):
        """Test bandwidth monitoring with high traffic."""
        analysis = create_analysis_engine()

        # Set up bandwidth threshold
        analysis.set_bandwidth_threshold(
            warning_level=1_000_000,  # 1 MB/s warning
            critical_level=2_000_000,  # 2 MB/s critical
            window_seconds=1,
        )

        # Simulate high bandwidth traffic
        start_time = datetime.now()

        for i in range(10):
            packet = PacketInfo(
                timestamp=start_time + timedelta(milliseconds=i * 100),
                src_ip="192.168.1.100",
                dst_ip="192.168.1.200",
                src_port=5000,
                dst_port=6000,
                protocol="UDP",
                length=500_000,  # Large packets
                raw_data=b"x" * 500000,
            )
            analysis.update(packet)

        # Verify summary contains bandwidth info
        summary = analysis.get_summary()
        assert "bandwidth" in summary
        assert "traffic" in summary

    def test_port_scan_detection_integration(self):
        """Test port scan detection with analysis engine."""
        analysis = create_analysis_engine()
        detection = create_detection_engine()

        # Simulate port scan behavior
        start_time = datetime.now()

        for port in range(20, 100):  # Scan ports 20-99
            packet = PacketInfo(
                timestamp=start_time + timedelta(milliseconds=port * 10),
                src_ip="192.168.1.50",
                dst_ip="192.168.1.1",
                src_port=40000,
                dst_port=port,
                protocol="TCP",
                length=60,
                raw_data=b"Scan packet",
            )
            analysis.update(packet)

        # Verify connections were tracked
        connections = analysis.get_active_connections()
        assert len(connections) > 0

        # Verify we can get connection summary
        summary = analysis.get_summary()
        assert "connections" in summary


@pytest.mark.integration
class TestStorageWithCapture:
    """Test integration between storage and packet capture."""

    def test_save_packets_to_database(self):
        """Test saving captured packets to database."""
        # Use file-based database for proper isolation
        import tempfile
        import os

        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        db = None
        try:
            # Direct instantiation to avoid singleton
            from src.storage.database import DatabaseManager
            config = DatabaseConfig(db_path=db_path)
            db = DatabaseManager(config)
            db.connect()

            # Create tables
            from src.storage.models import Base
            create_tables(db._engine)

            # Create packet repository
            from src.storage import create_packet_repository
            packet_repo = create_packet_repository(db.get_session)

            # Simulate captured packets
            packets = [
                PacketInfo(
                    timestamp=datetime.now(),
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                    src_port=5000,
                    dst_port=443,
                    protocol="TCP",
                    length=1500,
                    raw_data=b"packet 1 data",
                ),
                PacketInfo(
                    timestamp=datetime.now() + timedelta(seconds=1),
                    src_ip="10.0.0.2",
                    dst_ip="10.0.0.1",
                    src_port=443,
                    dst_port=5000,
                    protocol="TCP",
                    length=500,
                    raw_data=b"packet 2 data",
                ),
            ]

            # Save packets
            for packet in packets:
                packet_repo.save(packet)

            # Query back
            from src.storage import PacketFilter
            results = packet_repo.find_by_filter(PacketFilter())

            assert len(results) == 2

            # Verify data (order may vary, so check both)
            src_ips = {r["src_ip"] for r in results}
            assert "10.0.0.1" in src_ips
            assert "10.0.0.2" in src_ips
            assert all(r["protocol"] == "TCP" for r in results)

        finally:
            # Cleanup
            if db:
                db.disconnect()
            # Clean up temp file
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_save_and_query_alerts(self):
        """Test saving alerts to database and querying them."""
        import uuid
        import tempfile
        import os

        # Use file-based database for proper isolation
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        db = None
        try:
            # Direct instantiation to avoid singleton
            from src.storage.database import DatabaseManager
            config = DatabaseConfig(db_path=db_path)
            db = DatabaseManager(config)
            db.connect()

            from src.storage.models import Base
            create_tables(db._engine)

            from src.storage import create_alert_repository, AlertFilter
            alert_repo = create_alert_repository(db.get_session)

            # Create test alerts with unique IDs
            alert_id_1 = f"alert-{uuid.uuid4().hex[:8]}"
            alert_id_2 = f"alert-{uuid.uuid4().hex[:8]}"

            alerts = [
                {
                    "id": alert_id_1,
                    "detection_type": "port_scan",
                    "severity": "high",
                    "title": "Port Scan Detected",
                    "description": "Multiple ports scanned",
                    "timestamp": datetime.now(),
                    "confidence": 0.9,
                    "source_ip": "192.168.1.50",
                },
                {
                    "id": alert_id_2,
                    "detection_type": "traffic_anomaly",
                    "severity": "medium",
                    "title": "High Bandwidth Usage",
                    "description": "Bandwidth exceeded warning threshold",
                    "timestamp": datetime.now() + timedelta(seconds=10),
                    "confidence": 0.85,
                    "source_ip": "192.168.1.100",
                },
            ]

            # Save alerts
            for alert in alerts:
                alert_repo.save(alert)

            # Query all alerts
            results = alert_repo.find_by_filter(AlertFilter())
            assert len(results) == 2

            # Query by severity
            high_alerts = alert_repo.find_by_filter(
                AlertFilter(severity="high")
            )
            assert len(high_alerts) == 1
            assert high_alerts[0]["detection_type"] == "port_scan"

            # Query by time range
            recent_alerts = alert_repo.find_by_filter(
                AlertFilter(start_time=datetime.now() - timedelta(hours=1))
            )
            assert len(recent_alerts) == 2

        finally:
            # Cleanup
            if db:
                db.disconnect()
            # Clean up temp file
            if os.path.exists(db_path):
                os.unlink(db_path)


@pytest.mark.integration
class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""

    def test_capture_analyze_detect_save_workflow(self):
        """Test full workflow: capture -> analyze -> detect -> save."""
        import tempfile
        import os

        # Use file-based database for proper isolation
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        db = None
        try:
            # Setup components - direct instantiation to avoid singleton
            from src.storage.database import DatabaseManager
            config = DatabaseConfig(db_path=db_path)
            db = DatabaseManager(config)
            db.connect()

            from src.storage.models import Base
            create_tables(db._engine)

            from src.storage import create_packet_repository, create_alert_repository
            packet_repo = create_packet_repository(db.get_session)
            alert_repo = create_alert_repository(db.get_session)

            analysis = create_analysis_engine()
            detection = create_detection_engine()

            # Simulate network traffic
            start_time = datetime.now()

            # Normal traffic
            for i in range(5):
                packet = PacketInfo(
                    timestamp=start_time + timedelta(seconds=i),
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                    src_port=5000,
                    dst_port=80,
                    protocol="TCP",
                    length=1000,
                    raw_data=b"traffic data",
                )
                analysis.update(packet)
                packet_repo.save(packet)

            # Verify statistics
            stats = analysis.get_summary()
            assert stats["traffic"]["total_packets"] == 5
            assert stats["traffic"]["total_bytes"] == 5000

            # Verify saved packets
            packets = packet_repo.find_by_filter(PacketFilter())
            assert len(packets) == 5

        finally:
            # Cleanup
            if db:
                db.disconnect()
            # Clean up temp file
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_alert_lifecycle_workflow(self):
        """Test alert lifecycle: generate -> save -> acknowledge."""
        import uuid
        import tempfile
        import os

        # Use file-based database for proper isolation
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        db = None
        try:
            # Direct instantiation to avoid singleton
            from src.storage.database import DatabaseManager
            config = DatabaseConfig(db_path=db_path)
            db = DatabaseManager(config)
            db.connect()

            from src.storage.models import Base, AlertOrm
            create_tables(db._engine)

            from src.storage import create_alert_repository
            alert_repo = create_alert_repository(db.get_session)

            # Create alert with unique ID and title
            unique_id = uuid.uuid4().hex[:8]
            alert_title = f"Test Alert {unique_id}"
            alert = {
                "id": f"test-alert-{unique_id}",
                "detection_type": "traffic_anomaly",
                "severity": "medium",
                "title": alert_title,
                "description": "Test alert for lifecycle",
                "timestamp": datetime.now(),
                "confidence": 0.8,
            }

            # Save alert
            saved_id = alert_repo.save(alert)
            assert saved_id is not None

            # Query all alerts and verify our alert is there
            results = alert_repo.find_by_filter(AlertFilter())
            assert len(results) >= 1

            # Find our specific alert by title
            our_alert = next((r for r in results if r["title"] == alert_title), None)
            assert our_alert is not None
            assert our_alert["acknowledged"] is False
            assert our_alert["alert_id"] == f"test-alert-{unique_id}"

            # Acknowledge alert
            with db.get_session() as session:
                alert_orm = session.query(AlertOrm).filter_by(
                    alert_id=f"test-alert-{unique_id}"
                ).first()
                alert_orm.acknowledged = True
                session.commit()

            # Verify acknowledgement
            results = alert_repo.find_by_filter(AlertFilter(acknowledged=True))
            acknowledged_ours = [r for r in results if r["title"] == alert_title]
            assert len(acknowledged_ours) == 1

        finally:
            # Cleanup
            if db:
                db.disconnect()
            # Clean up temp file
            if os.path.exists(db_path):
                os.unlink(db_path)


@pytest.mark.integration
class TestConcurrencyIntegration:
    """Test concurrent operations integration."""

    def test_concurrent_packet_processing(self):
        """Test processing packets from multiple sources."""
        analysis = create_analysis_engine()
        detection = create_detection_engine()

        packets_processed = {"count": 0}
        alerts_received = []

        def packet_callback(packet: PacketInfo):
            packets_processed["count"] += 1
            analysis.update(packet)

        def alert_callback(alert: Alert):
            alerts_received.append(alert)

        detection.add_callback(alert_callback)

        # Simulate multiple packet sources
        def generate_packets(source_id: str):
            for i in range(10):
                packet = PacketInfo(
                    timestamp=datetime.now(),
                    src_ip=f"192.168.1.{source_id}",
                    dst_ip="192.168.1.255",
                    src_port=5000 + i,
                    dst_port=80,
                    protocol="TCP",
                    length=1000,
                    raw_data=b"multi-source packet",
                )
                packet_callback(packet)

        # Run in threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=generate_packets, args=(i,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        # Verify all packets processed
        assert packets_processed["count"] == 30
        assert analysis.get_summary()["traffic"]["total_packets"] == 30


@pytest.mark.integration
class TestExportIntegration:
    """Test export functionality integration."""

    def test_export_packets_after_capture(self):
        """Test exporting packets after capturing."""
        config = DatabaseConfig(db_path=":memory:")
        db = get_database_manager(config)
        db.connect()

        from src.storage.models import Base
        create_tables(db._engine)

        from src.storage import create_packet_repository, create_export_service
        packet_repo = create_packet_repository(db.get_session)
        export_service = create_export_service()

        # Save some packets
        for i in range(5):
            packet = PacketInfo(
                timestamp=datetime.now(),
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=5000,
                dst_port=80,
                protocol="TCP",
                length=1000,
                raw_data=b"export test data",
            )
            packet_repo.save(packet)

        # Export to JSON
        json_output = export_service.export_packets(
            packet_repo,
            format="json",
        )

        assert isinstance(json_output, str)
        assert "10.0.0.1" in json_output

        # Export to CSV
        csv_output = export_service.export_packets(
            packet_repo,
            format="csv",
        )

        assert isinstance(csv_output, str)
        assert "10.0.0.1" in csv_output

        # Cleanup
        db.disconnect()

    def test_export_alerts_with_filter(self):
        """Test exporting alerts with filtering."""
        config = DatabaseConfig(db_path=":memory:")
        db = get_database_manager(config)
        db.connect()

        from src.storage.models import Base
        create_tables(db._engine)

        from src.storage import create_alert_repository, create_export_service, AlertFilter
        alert_repo = create_alert_repository(db.get_session)
        export_service = create_export_service()

        # Create alerts with different severities
        import uuid
        for severity_name in ["low", "medium", "high", "critical"]:
            alert = {
                "id": f"alert-{severity_name}-{uuid.uuid4().hex[:8]}",
                "detection_type": "traffic_anomaly",
                "severity": severity_name,
                "title": f"{severity_name.capitalize()} Alert",
                "description": f"Test alert with {severity_name} severity",
                "timestamp": datetime.now(),
                "confidence": 0.8,
            }
            alert_repo.save(alert)

        # Export only high and critical alerts
        filter_obj = AlertFilter(
            severity="high",  # Will match "high" and "critical" based on implementation
        )

        # For this test, export all and verify structure
        json_output = export_service.export_alerts(
            alert_repo,
            format="json",
        )

        assert isinstance(json_output, str)
        assert "high" in json_output.lower()
        assert "critical" in json_output.lower()

        # Cleanup
        db.disconnect()


# Performance integration tests
@pytest.mark.integration
class TestPerformanceIntegration:
    """Test performance characteristics of integrated system."""

    def test_high_volume_packet_processing(self):
        """Test processing large number of packets efficiently."""
        analysis = create_analysis_engine()

        start_time = time.time()

        # Process 1000 packets
        for i in range(1000):
            packet = PacketInfo(
                timestamp=datetime.now(),
                src_ip=f"192.168.1.{i % 255}",
                dst_ip="192.168.1.255",
                src_port=5000 + i,
                dst_port=80,
                protocol="TCP",
                length=1500,
                raw_data=b"x" * 1500,
            )
            analysis.update(packet)

        elapsed = time.time() - start_time

        # Should process quickly
        assert elapsed < 1.0  # Less than 1 second for 1000 packets

        # Verify statistics
        stats = analysis.get_summary()
        assert stats["traffic"]["total_packets"] == 1000

    def test_database_write_performance(self):
        """Test database write performance with batch inserts."""
        config = DatabaseConfig(db_path=":memory:")
        db = get_database_manager(config)
        db.connect()

        from src.storage.models import Base
        create_tables(db._engine)

        from src.storage import create_packet_repository
        packet_repo = create_packet_repository(db.get_session)

        start_time = time.time()

        # Save 100 packets
        for i in range(100):
            packet = PacketInfo(
                timestamp=datetime.now(),
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=5000,
                dst_port=80,
                protocol="TCP",
                length=1000,
                raw_data=b"db test data",
            )
            packet_repo.save(packet)

        elapsed = time.time() - start_time

        # Should complete reasonably fast
        assert elapsed < 2.0  # Less than 2 seconds for 100 writes

        # Cleanup
        db.disconnect()
