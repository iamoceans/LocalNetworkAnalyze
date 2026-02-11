"""
Unit tests for storage module.
"""

import pytest
import json
import csv
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock

from src.capture.base import PacketInfo
from src.storage import (
    DatabaseConfig,
    PacketFilter,
    AlertFilter,
    ExportConfig,
    CsvExporter,
    JsonExporter,
    ExportService,
    create_export_service,
)


@pytest.mark.unit
class TestDatabaseConfig:
    """Test DatabaseConfig class."""

    def test_default_config(self):
        """Test default configuration."""
        config = DatabaseConfig()

        assert config.db_path == "data/network_analyzer.db"
        assert config.echo_sql is False
        assert config.pool_size == 5

    def test_custom_config(self):
        """Test custom configuration."""
        config = DatabaseConfig(
            db_path="/tmp/test.db",
            echo_sql=True,
            pool_size=10,
        )

        assert config.db_path == "/tmp/test.db"
        assert config.echo_sql is True
        assert config.pool_size == 10

    def test_get_database_url(self):
        """Test getting database URL."""
        config = DatabaseConfig(db_path="data/test.db")

        url = config.get_database_url()

        assert url == "sqlite:///data/test.db"


@pytest.mark.unit
class TestPacketFilter:
    """Test PacketFilter dataclass."""

    def test_default_filter(self):
        """Test default filter."""
        filter = PacketFilter()

        assert filter.start_time is None
        assert filter.end_time is None
        assert filter.src_ip is None
        assert filter.limit is None

    def test_filter_with_params(self):
        """Test filter with parameters."""
        now = datetime.now()
        filter = PacketFilter(
            start_time=now,
            protocol="TCP",
            limit=100,
        )

        assert filter.start_time == now
        assert filter.protocol == "TCP"
        assert filter.limit == 100


@pytest.mark.unit
class TestAlertFilter:
    """Test AlertFilter dataclass."""

    def test_default_filter(self):
        """Test default filter."""
        filter = AlertFilter()

        assert filter.start_time is None
        assert filter.detection_type is None
        assert filter.severity is None

    def test_filter_with_params(self):
        """Test filter with parameters."""
        now = datetime.now()
        filter = AlertFilter(
            start_time=now,
            severity="high",
            acknowledged=False,
        )

        assert filter.start_time == now
        assert filter.severity == "high"
        assert filter.acknowledged is False


@pytest.mark.unit
class TestExportConfig:
    """Test ExportConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = ExportConfig()

        assert config.format == "json"
        assert config.compress is False
        assert config.batch_size == 1000

    def test_custom_config(self):
        """Test custom configuration."""
        config = ExportConfig(
            format="csv",
            batch_size=500,
            output_path="/tmp/export.csv",
        )

        assert config.format == "csv"
        assert config.batch_size == 500
        assert config.output_path == "/tmp/export.csv"


@pytest.mark.unit
class TestCsvExporter:
    """Test CsvExporter class."""

    def test_export_packets_empty(self):
        """Test exporting empty packet list."""
        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        # Mock repository that returns empty list
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        output = exporter.export_packets(repository)

        # Should get CSV string
        assert isinstance(output, str)
        assert "id" in output  # Header row
        assert "timestamp" in output

    def test_export_packets_with_data(self):
        """Test exporting packets with data."""
        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        # Mock repository
        packets = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00",
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.2",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": "TCP",
                "length": 1500,
                "connection_id": "conn-1",
            }
        ]

        repository = MagicMock()
        repository.find_by_filter = Mock(side_effect=[packets, []])

        output = exporter.export_packets(repository)

        assert "192.168.1.1" in output
        assert "192.168.1.2" in output

    def test_export_alerts_empty(self):
        """Test exporting empty alert list."""
        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        output = exporter.export_alerts(repository)

        assert "id" in output
        assert "alert_id" in output

    def test_export_alerts_with_data(self):
        """Test exporting alerts with data."""
        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        # Mock repository
        alerts = [
            {
                "id": 1,
                "alert_id": "alert-1",
                "detection_type": "port_scan",
                "severity": "high",
                "title": "Port Scan Detected",
                "timestamp": "2024-01-01T00:00:00",
                "confidence": 0.9,
                "source_ip": "192.168.1.100",
                "destination_ip": None,
                "acknowledged": False,
            }
        ]

        repository = MagicMock()
        repository.find_by_filter = Mock(side_effect=[alerts, []])

        output = exporter.export_alerts(repository)

        assert "port_scan" in output
        assert "Port Scan Detected" in output


@pytest.mark.unit
class TestJsonExporter:
    """Test JsonExporter class."""

    def test_export_packets_empty(self):
        """Test exporting empty packet list."""
        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        output = exporter.export_packets(repository)

        # Should get JSON array
        assert isinstance(output, str)
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 0

    def test_export_packets_with_data(self):
        """Test exporting packets with data."""
        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        # Mock repository
        packets = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00",
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.2",
                "protocol": "TCP",
                "length": 1500,
            }
        ]

        repository = MagicMock()
        repository.find_by_filter = Mock(side_effect=[packets, []])

        output = exporter.export_packets(repository)

        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["src_ip"] == "192.168.1.1"

    def test_export_alerts_empty(self):
        """Test exporting empty alert list."""
        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        output = exporter.export_alerts(repository)

        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 0

    def test_export_alerts_with_data(self):
        """Test exporting alerts with data."""
        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        # Mock repository
        alerts = [
            {
                "id": 1,
                "alert_id": "alert-1",
                "detection_type": "port_scan",
                "severity": "high",
                "title": "Port Scan Detected",
                "confidence": 0.9,
            }
        ]

        repository = MagicMock()
        repository.find_by_filter = Mock(side_effect=[alerts, []])

        output = exporter.export_alerts(repository)

        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["detection_type"] == "port_scan"


@pytest.mark.unit
class TestExportService:
    """Test ExportService class."""

    def test_init(self):
        """Test initialization."""
        service = ExportService()

        assert service is not None

    def test_export_packets_json(self):
        """Test exporting packets as JSON."""
        service = ExportService()

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_packets(
            repository,
            format="json",
        )

        assert isinstance(result, str)

    def test_export_packets_csv(self):
        """Test exporting packets as CSV."""
        service = ExportService()

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_packets(
            repository,
            format="csv",
        )

        assert isinstance(result, str)

    def test_export_packets_with_filter(self):
        """Test exporting packets with filter."""
        service = ExportService()

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        filter = PacketFilter(protocol="TCP")
        result = service.export_packets(
            repository,
            format="json",
            filter=filter,
        )

        assert isinstance(result, str)

    def test_export_alerts_json(self):
        """Test exporting alerts as JSON."""
        service = ExportService()

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_alerts(
            repository,
            format="json",
        )

        assert isinstance(result, str)

    def test_export_alerts_csv(self):
        """Test exporting alerts as CSV."""
        service = ExportService()

        # Mock repository
        repository = MagicMock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_alerts(
            repository,
            format="csv",
        )

        assert isinstance(result, str)

    def test_export_unsupported_format(self):
        """Test exporting with unsupported format."""
        service = ExportService()

        repository = MagicMock()

        with pytest.raises(ValueError, match="Unsupported export format"):
            service.export_packets(
                repository,
                format="xml",
            )


@pytest.mark.unit
class TestFactoryFunctions:
    """Test factory functions."""

    def test_create_export_service(self):
        """Test export service factory."""
        service = create_export_service()

        assert isinstance(service, ExportService)


@pytest.mark.unit
class TestPacketInfoForStorage:
    """Test PacketInfo compatibility with storage."""

    def test_packet_info_to_dict(self):
        """Test converting PacketInfo to dict for storage."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            length=1500,
            raw_data=b"test data",
        )

        # Should have all necessary fields
        assert packet.timestamp is not None
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.protocol == "TCP"
        assert packet.length == 1500
        assert packet.raw_data == b"test data"


@pytest.mark.unit
class TestSqlPacketRepositoryTopDestinations:
    """Test SqlPacketRepository.get_top_destinations method."""

    def test_get_top_destinations_empty(self):
        """Test getting top destinations from empty repository."""
        from src.storage.repository import SqlPacketRepository

        # Mock session factory
        session_factory = MagicMock()
        session = MagicMock()
        session_factory.return_value.__enter__.return_value = session

        # Mock query to return empty result
        session.query.return_value.group_by.return_value.order_by.return_value.limit.return_value.all.return_value = []

        repo = SqlPacketRepository(session_factory)
        result = repo.get_top_destinations(limit=10)

        assert isinstance(result, list)
        assert len(result) == 0

    def test_get_top_destinations_with_data(self):
        """Test getting top destinations with actual data."""
        from src.storage.repository import SqlPacketRepository

        # Mock session factory
        session_factory = MagicMock()
        session = MagicMock()
        session_factory.return_value.__enter__.return_value = session

        # Create mock result rows
        mock_row = MagicMock()
        mock_row.dst_ip = "93.184.216.34"
        mock_row.dst_port = 443
        mock_row.total_bytes = 15000
        mock_row.last_seen = datetime(2024, 1, 1, 12, 0, 0)
        mock_row.packet_count = 10

        session.query.return_value.group_by.return_value.order_by.return_value.limit.return_value.all.return_value = [
            mock_row
        ]

        repo = SqlPacketRepository(session_factory)
        result = repo.get_top_destinations(limit=10)

        assert len(result) == 1
        assert result[0]['dst_ip'] == "93.184.216.34"
        assert result[0]['dst_port'] == 443
        assert result[0]['total_bytes'] == 15000
        assert result[0]['last_seen'] == "2024-01-01T12:00:00"
        assert result[0]['packet_count'] == 10

    def test_get_top_destinations_multiple_results(self):
        """Test getting top destinations with multiple results."""
        from src.storage.repository import SqlPacketRepository

        # Mock session factory
        session_factory = MagicMock()
        session = MagicMock()
        session_factory.return_value.__enter__.return_value = session

        # Create mock result rows - sorted by total_bytes descending
        mock_rows = []
        for i in range(3):
            row = MagicMock()
            row.dst_ip = f"{i}.1.1.1"
            row.dst_port = 80
            row.total_bytes = (3 - i) * 1000  # 3000, 2000, 1000
            row.last_seen = datetime(2024, 1, 1, 12, i, 0)
            row.packet_count = i + 1
            mock_rows.append(row)

        session.query.return_value.group_by.return_value.order_by.return_value.limit.return_value.all.return_value = mock_rows

        repo = SqlPacketRepository(session_factory)
        result = repo.get_top_destinations(limit=10)

        assert len(result) == 3
        # Check sorted by total_bytes descending
        assert result[0]['total_bytes'] == 3000
        assert result[1]['total_bytes'] == 2000
        assert result[2]['total_bytes'] == 1000

    def test_get_top_destinations_respects_limit(self):
        """Test that limit parameter is respected."""
        from src.storage.repository import SqlPacketRepository

        # Mock session factory
        session_factory = MagicMock()
        session = MagicMock()
        session_factory.return_value.__enter__.return_value = session

        # Create 5 mock rows
        mock_rows = []
        for i in range(5):
            row = MagicMock()
            row.dst_ip = f"{i}.1.1.1"
            row.dst_port = 80
            row.total_bytes = (5 - i) * 1000
            row.last_seen = datetime(2024, 1, 1, 12, 0, 0)
            row.packet_count = 1
            mock_rows.append(row)

        # Configure limit mock
        limit_mock = MagicMock()
        limit_mock.all.return_value = mock_rows

        session.query.return_value.group_by.return_value.order_by.return_value.limit = MagicMock(
            return_value=limit_mock
        )

        repo = SqlPacketRepository(session_factory)

        # Request only top 3
        result = repo.get_top_destinations(limit=3)

        # Verify limit was called with correct value
        session.query.return_value.group_by.return_value.order_by.return_value.limit.assert_called_with(3)

    def test_get_top_destinations_with_null_values(self):
        """Test handling of null total_bytes and last_seen."""
        from src.storage.repository import SqlPacketRepository

        # Mock session factory
        session_factory = MagicMock()
        session = MagicMock()
        session_factory.return_value.__enter__.return_value = session

        # Create mock row with null values
        mock_row = MagicMock()
        mock_row.dst_ip = "1.1.1.1"
        mock_row.dst_port = 80
        mock_row.total_bytes = None
        mock_row.last_seen = None
        mock_row.packet_count = None

        session.query.return_value.group_by.return_value.order_by.return_value.limit.return_value.all.return_value = [
            mock_row
        ]

        repo = SqlPacketRepository(session_factory)
        result = repo.get_top_destinations(limit=10)

        assert len(result) == 1
        assert result[0]['total_bytes'] == 0  # Should default to 0
        assert result[0]['last_seen'] is None
        assert result[0]['packet_count'] == 0  # Should default to 0

    def test_get_top_destinations_handles_exception(self):
        """Test that exceptions are properly wrapped."""
        from src.storage.repository import SqlPacketRepository
        from src.core.exceptions import StorageError

        # Mock session factory that raises exception
        session_factory = MagicMock()
        session_factory.return_value.__enter__.side_effect = Exception("Database error")

        repo = SqlPacketRepository(session_factory)

        with pytest.raises(StorageError, match="Failed to get top destinations"):
            repo.get_top_destinations(limit=10)
