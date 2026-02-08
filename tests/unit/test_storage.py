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
