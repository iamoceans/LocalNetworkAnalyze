"""Tests for src.storage.export_service module."""

import pytest
import json
import csv
from io import StringIO
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from src.storage.export_service import (
    ExportConfig, Exporter, CsvExporter, JsonExporter,
    ExportService, create_export_service
)
from src.storage.repository import PacketFilter, AlertFilter
from src.core.exceptions import StorageError


@pytest.mark.unit
class TestExportConfig:
    """Test ExportConfig dataclass."""

    def test_default_config(self):
        """Test creating default export config."""
        config = ExportConfig()
        assert config.format == "json"
        assert config.compress is False
        assert config.include_raw_data is False
        assert config.batch_size == 1000
        assert config.output_path is None

    def test_custom_config(self):
        """Test creating custom export config."""
        config = ExportConfig(
            format="csv",
            compress=True,
            include_raw_data=True,
            batch_size=500,
            output_path="/tmp/export.csv"
        )
        assert config.format == "csv"
        assert config.compress is True
        assert config.batch_size == 500


@pytest.mark.unit
class TestCsvExporter:
    """Test CsvExporter class."""

    def test_create_exporter(self):
        """Test creating CSV exporter."""
        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)
        assert isinstance(exporter, Exporter)

    @patch('src.storage.export_service.CsvExporter._get_output')
    @patch('src.storage.export_service.CsvExporter._finalize_output')
    def test_export_packets_empty(self, mock_finalize, mock_get_output):
        """Test exporting packets when no packets exist."""
        mock_output = StringIO()
        mock_get_output.return_value = mock_output
        mock_finalize.return_value = "test.csv"

        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        # Mock repository
        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = exporter.export_packets(repository)
        assert result == "test.csv"
        repository.find_by_filter.assert_called()

    @patch('src.storage.export_service.CsvExporter._get_output')
    @patch('src.storage.export_service.CsvExporter._finalize_output')
    def test_export_packets_with_data(self, mock_finalize, mock_get_output):
        """Test exporting packets with data."""
        mock_output = StringIO()
        mock_get_output.return_value = mock_output
        mock_finalize.return_value = "test.csv"

        config = ExportConfig(format="csv", batch_size=100)
        exporter = CsvExporter(config)

        # Mock repository with packets
        repository = Mock()
        repository.find_by_filter = Mock(side_effect=[
            [  # First batch
                {
                    "id": 1,
                    "timestamp": "2024-01-01 12:00:00",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "192.168.1.2",
                    "src_port": 12345,
                    "dst_port": 80,
                    "protocol": "TCP",
                    "length": 1024,
                    "connection_id": "conn-1"
                }
            ],
            []  # Empty second batch to stop iteration
        ])

        result = exporter.export_packets(repository)
        assert result == "test.csv"

    @patch('src.storage.export_service.CsvExporter._get_output')
    def test_export_to_string(self, mock_get_output):
        """Test exporting to string (no file path)."""
        mock_output = StringIO()
        mock_get_output.return_value = mock_output

        config = ExportConfig(format="csv", output_path=None)
        exporter = CsvExporter(config)

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = exporter.export_packets(repository)
        # Should return CSV content string
        assert isinstance(result, str)

    @patch('src.storage.export_service.CsvExporter._get_output')
    @patch('src.storage.export_service.CsvExporter._finalize_output')
    def test_export_alerts(self, mock_finalize, mock_get_output):
        """Test exporting alerts to CSV."""
        mock_output = StringIO()
        mock_get_output.return_value = mock_output
        mock_finalize.return_value = "alerts.csv"

        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        # Mock repository
        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = exporter.export_alerts(repository)
        assert result == "alerts.csv"

    def test_get_output_with_path(self, tmp_path):
        """Test _get_output with file path."""
        output_path = tmp_path / "test.csv"
        config = ExportConfig(format="csv", output_path=str(output_path))
        exporter = CsvExporter(config)

        output = exporter._get_output()
        assert output is not None
        output.close()

    def test_get_output_without_path(self):
        """Test _get_output without file path."""
        config = ExportConfig(format="csv", output_path=None)
        exporter = CsvExporter(config)

        output = exporter._get_output()
        assert isinstance(output, StringIO)

    def test_finalize_output_with_path(self, tmp_path):
        """Test _finalize_output with file path."""
        output_path = tmp_path / "test.csv"
        output_path.write_text("test")

        config = ExportConfig(format="csv", output_path=str(output_path))
        exporter = CsvExporter(config)

        # Create a mock file handle
        mock_file = open(str(output_path), "r")
        result = exporter._finalize_output(mock_file)

        assert result == str(output_path)

    def test_finalize_output_without_path(self):
        """Test _finalize_output without file path."""
        config = ExportConfig(format="csv", output_path=None)
        exporter = CsvExporter(config)

        output = StringIO()
        output.write("test content")
        result = exporter._finalize_output(output)

        assert result == "test content"

    def test_export_error_handling(self):
        """Test error handling during export."""
        config = ExportConfig(format="csv")
        exporter = CsvExporter(config)

        repository = Mock()
        repository.find_by_filter = Mock(side_effect=Exception("DB error"))

        with pytest.raises(StorageError):
            exporter.export_packets(repository)


@pytest.mark.unit
class TestJsonExporter:
    """Test JsonExporter class."""

    def test_create_exporter(self):
        """Test creating JSON exporter."""
        config = ExportConfig(format="json")
        exporter = JsonExporter(config)
        assert isinstance(exporter, Exporter)

    @patch('src.storage.export_service.JsonExporter._get_output')
    @patch('src.storage.export_service.JsonExporter._finalize_output')
    def test_export_packets(self, mock_finalize, mock_get_output):
        """Test exporting packets to JSON."""
        mock_output = StringIO()
        mock_get_output.return_value = mock_output
        mock_finalize.return_value = '{"packets": []}'

        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        repository = Mock()
        repository.find_by_filter = Mock(side_effect=[[], []])

        result = exporter.export_packets(repository)
        assert result is not None

    @patch('src.storage.export_service.JsonExporter._get_output')
    @patch('src.storage.export_service.JsonExporter._finalize_output')
    def test_export_alerts(self, mock_finalize, mock_get_output):
        """Test exporting alerts to JSON."""
        mock_output = StringIO()
        mock_get_output.return_value = mock_output
        mock_finalize.return_value = '{"alerts": []}'

        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        repository = Mock()
        repository.find_by_filter = Mock(side_effect=[[], []])

        result = exporter.export_alerts(repository)
        assert result is not None

    def test_export_with_filter(self):
        """Test exporting with filter applied."""
        config = ExportConfig(format="json")
        exporter = JsonExporter(config)

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        filter_obj = PacketFilter(src_ip="192.168.1.1", limit=100)
        result = exporter.export_packets(repository, filter_obj)

        assert result is not None


@pytest.mark.unit
class TestExportService:
    """Test ExportService class."""

    def test_create_service(self):
        """Test creating export service."""
        service = ExportService()
        assert service is not None

    def test_export_packets_default_format(self):
        """Test exporting packets with default format."""
        service = ExportService()

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_packets(repository)
        assert result is not None

    def test_export_packets_csv_format(self):
        """Test exporting packets in CSV format."""
        service = ExportService()

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_packets(repository, format="csv")
        assert result is not None

    def test_export_packets_to_file(self, tmp_path):
        """Test exporting packets to file."""
        service = ExportService()

        output_path = tmp_path / "export.json"
        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_packets(
            repository,
            format="json",
            output_path=str(output_path)
        )
        assert result is not None

    def test_export_packets_with_filter(self):
        """Test exporting packets with filter."""
        service = ExportService()

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        filter_obj = PacketFilter(
            src_ip="192.168.1.1",
            protocol="TCP",
            limit=100
        )

        result = service.export_packets(
            repository,
            filter=filter_obj
        )
        assert result is not None

    def test_export_alerts(self):
        """Test exporting alerts."""
        service = ExportService()

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_alerts(repository)
        assert result is not None

    def test_export_with_custom_batch_size(self):
        """Test exporting with custom batch size."""
        service = ExportService()

        repository = Mock()
        repository.find_by_filter = Mock(return_value=[])

        result = service.export_packets(
            repository,
            batch_size=500
        )
        assert result is not None

    def test_create_exporter_csv(self):
        """Test creating CSV exporter."""
        service = ExportService()
        config = ExportConfig(format="csv")
        exporter = service._create_exporter(config)
        assert isinstance(exporter, CsvExporter)

    def test_create_exporter_json(self):
        """Test creating JSON exporter."""
        service = ExportService()
        config = ExportConfig(format="json")
        exporter = service._create_exporter(config)
        assert isinstance(exporter, JsonExporter)

    def test_create_exporter_invalid_format(self):
        """Test creating exporter with invalid format."""
        service = ExportService()
        config = ExportConfig(format="xml")

        with pytest.raises(ValueError):
            service._create_exporter(config)

    def test_export_error_propagation(self):
        """Test that export errors are properly wrapped."""
        service = ExportService()

        repository = Mock()
        repository.find_by_filter = Mock(side_effect=Exception("Connection lost"))

        with pytest.raises(StorageError):
            service.export_packets(repository)


@pytest.mark.unit
class TestCreateExportService:
    """Test create_export_service function."""

    def test_create_service(self):
        """Test creating export service instance."""
        service = create_export_service()
        assert isinstance(service, ExportService)


@pytest.mark.unit
class TestExporterAbstract:
    """Test Exporter abstract class."""

    def test_cannot_instantiate(self):
        """Test that Exporter cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Exporter()
