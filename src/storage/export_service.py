"""
Export service for data export functionality.

Supports exporting data to various formats including CSV, JSON,
and PCAP.
"""

import csv
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, TextIO
from io import StringIO, BytesIO

from src.core.logger import get_logger
from src.core.exceptions import StorageError
from .repository import PacketRepository, AlertRepository, PacketFilter, AlertFilter


@dataclass
class ExportConfig:
    """Configuration for data export.

    Attributes:
        format: Export format (csv, json)
        compress: Whether to compress output
        include_raw_data: Whether to include raw packet data
        batch_size: Number of records per batch
        output_path: Output file path
    """
    format: str = "json"
    compress: bool = False
    include_raw_data: bool = False
    batch_size: int = 1000
    output_path: Optional[str] = None


class Exporter(ABC):
    """Abstract base class for data exporters."""

    @abstractmethod
    def export_packets(
        self,
        repository: PacketRepository,
        filter: Optional[PacketFilter] = None,
    ) -> str:
        """Export packets.

        Args:
            repository: Packet repository
            filter: Optional packet filter

        Returns:
            Export result path or data
        """
        pass

    @abstractmethod
    def export_alerts(
        self,
        repository: AlertRepository,
        filter: Optional[AlertFilter] = None,
    ) -> str:
        """Export alerts.

        Args:
            repository: Alert repository
            filter: Optional alert filter

        Returns:
            Export result path or data
        """
        pass


class CsvExporter(Exporter):
    """CSV format exporter."""

    def __init__(self, config: ExportConfig):
        """Initialize CSV exporter.

        Args:
            config: Export configuration
        """
        self._config = config
        logger = get_logger(__name__)
        self._logger = logger

    def export_packets(
        self,
        repository: PacketRepository,
        filter: Optional[PacketFilter] = None,
    ) -> str:
        """Export packets to CSV.

        Args:
            repository: Packet repository
            filter: Optional packet filter

        Returns:
            File path or CSV string
        """
        try:
            output = self._get_output()

            # Define CSV fields
            fieldnames = [
                "id", "timestamp", "src_ip", "dst_ip",
                "src_port", "dst_port", "protocol", "length",
                "connection_id"
            ]

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            # Fetch and write packets in batches
            offset = 0
            while True:
                batch_filter = PacketFilter(
                    start_time=filter.start_time if filter else None,
                    end_time=filter.end_time if filter else None,
                    src_ip=filter.src_ip if filter else None,
                    dst_ip=filter.dst_ip if filter else None,
                    protocol=filter.protocol if filter else None,
                    limit=self._config.batch_size,
                    offset=offset,
                )

                packets = repository.find_by_filter(batch_filter)

                if not packets:
                    break

                for packet in packets:
                    writer.writerow({
                        "id": packet.get("id", ""),
                        "timestamp": packet.get("timestamp", ""),
                        "src_ip": packet.get("src_ip", ""),
                        "dst_ip": packet.get("dst_ip", ""),
                        "src_port": packet.get("src_port", ""),
                        "dst_port": packet.get("dst_port", ""),
                        "protocol": packet.get("protocol", ""),
                        "length": packet.get("length", ""),
                        "connection_id": packet.get("connection_id", ""),
                    })

                offset += len(packets)

            return self._finalize_output(output)

        except Exception as e:
            self._logger.error(f"Failed to export packets to CSV: {e}")
            raise StorageError(f"CSV export failed: {e}") from e

    def export_alerts(
        self,
        repository: AlertRepository,
        filter: Optional[AlertFilter] = None,
    ) -> str:
        """Export alerts to CSV.

        Args:
            repository: Alert repository
            filter: Optional alert filter

        Returns:
            File path or CSV string
        """
        try:
            output = self._get_output()

            # Define CSV fields
            fieldnames = [
                "id", "alert_id", "detection_type", "severity",
                "title", "timestamp", "confidence",
                "source_ip", "destination_ip", "acknowledged"
            ]

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            # Fetch and write alerts in batches
            offset = 0
            while True:
                batch_filter = AlertFilter(
                    start_time=filter.start_time if filter else None,
                    end_time=filter.end_time if filter else None,
                    detection_type=filter.detection_type if filter else None,
                    severity=filter.severity if filter else None,
                    source_ip=filter.source_ip if filter else None,
                    limit=self._config.batch_size,
                    offset=offset,
                )

                alerts = repository.find_by_filter(batch_filter)

                if not alerts:
                    break

                for alert in alerts:
                    writer.writerow({
                        "id": alert.get("id", ""),
                        "alert_id": alert.get("alert_id", ""),
                        "detection_type": alert.get("detection_type", ""),
                        "severity": alert.get("severity", ""),
                        "title": alert.get("title", ""),
                        "timestamp": alert.get("timestamp", ""),
                        "confidence": alert.get("confidence", ""),
                        "source_ip": alert.get("source_ip", ""),
                        "destination_ip": alert.get("destination_ip", ""),
                        "acknowledged": alert.get("acknowledged", ""),
                    })

                offset += len(alerts)

            return self._finalize_output(output)

        except Exception as e:
            self._logger.error(f"Failed to export alerts to CSV: {e}")
            raise StorageError(f"CSV export failed: {e}") from e

    def _get_output(self) -> TextIO:
        """Get output stream.

        Returns:
            Output stream
        """
        if self._config.output_path:
            return open(self._config.output_path, "w", newline="", encoding="utf-8")
        else:
            return StringIO()

    def _finalize_output(self, output: TextIO) -> str:
        """Finalize output.

        Args:
            output: Output stream

        Returns:
            File path or content string
        """
        if self._config.output_path:
            output.close()
            return self._config.output_path
        else:
            content = output.getvalue()
            output.close()
            return content


class JsonExporter(Exporter):
    """JSON format exporter."""

    def __init__(self, config: ExportConfig):
        """Initialize JSON exporter.

        Args:
            config: Export configuration
        """
        self._config = config
        logger = get_logger(__name__)
        self._logger = logger

    def export_packets(
        self,
        repository: PacketRepository,
        filter: Optional[PacketFilter] = None,
    ) -> str:
        """Export packets to JSON.

        Args:
            repository: Packet repository
            filter: Optional packet filter

        Returns:
            File path or JSON string
        """
        try:
            packets = []
            offset = 0

            # Fetch packets in batches
            while True:
                batch_filter = PacketFilter(
                    start_time=filter.start_time if filter else None,
                    end_time=filter.end_time if filter else None,
                    src_ip=filter.src_ip if filter else None,
                    dst_ip=filter.dst_ip if filter else None,
                    protocol=filter.protocol if filter else None,
                    limit=self._config.batch_size,
                    offset=offset,
                )

                batch = repository.find_by_filter(batch_filter)

                if not batch:
                    break

                packets.extend(batch)
                offset += len(batch)

            # Export to JSON
            output = self._get_output()
            json.dump(packets, output, indent=2, default=str)

            return self._finalize_output(output)

        except Exception as e:
            self._logger.error(f"Failed to export packets to JSON: {e}")
            raise StorageError(f"JSON export failed: {e}") from e

    def export_alerts(
        self,
        repository: AlertRepository,
        filter: Optional[AlertFilter] = None,
    ) -> str:
        """Export alerts to JSON.

        Args:
            repository: Alert repository
            filter: Optional alert filter

        Returns:
            File path or JSON string
        """
        try:
            alerts = []
            offset = 0

            # Fetch alerts in batches
            while True:
                batch_filter = AlertFilter(
                    start_time=filter.start_time if filter else None,
                    end_time=filter.end_time if filter else None,
                    detection_type=filter.detection_type if filter else None,
                    severity=filter.severity if filter else None,
                    source_ip=filter.source_ip if filter else None,
                    limit=self._config.batch_size,
                    offset=offset,
                )

                batch = repository.find_by_filter(batch_filter)

                if not batch:
                    break

                alerts.extend(batch)
                offset += len(batch)

            # Export to JSON
            output = self._get_output()
            json.dump(alerts, output, indent=2, default=str)

            return self._finalize_output(output)

        except Exception as e:
            self._logger.error(f"Failed to export alerts to JSON: {e}")
            raise StorageError(f"JSON export failed: {e}") from e

    def _get_output(self) -> TextIO:
        """Get output stream.

        Returns:
            Output stream
        """
        if self._config.output_path:
            return open(self._config.output_path, "w", encoding="utf-8")
        else:
            return StringIO()

    def _finalize_output(self, output: TextIO) -> str:
        """Finalize output.

        Args:
            output: Output stream

        Returns:
            File path or content string
        """
        if self._config.output_path:
            output.close()
            return self._config.output_path
        else:
            content = output.getvalue()
            output.close()
            return content


class ExportService:
    """Service for exporting data in various formats."""

    def __init__(self):
        """Initialize export service."""
        logger = get_logger(__name__)
        self._logger = logger

    def export_packets(
        self,
        repository: PacketRepository,
        format: str = "json",
        output_path: Optional[str] = None,
        filter: Optional[PacketFilter] = None,
        batch_size: int = 1000,
    ) -> str:
        """Export packets to specified format.

        Args:
            repository: Packet repository
            format: Export format (csv, json)
            output_path: Optional output file path
            filter: Optional packet filter
            batch_size: Batch size for fetching

        Returns:
            File path or exported data

        Raises:
            StorageError: If export fails
        """
        config = ExportConfig(
            format=format,
            batch_size=batch_size,
            output_path=output_path,
        )

        exporter = self._create_exporter(config)

        try:
            result = exporter.export_packets(repository, filter)

            self._logger.info(
                f"Exported packets to {format}: "
                f"{output_path or 'in-memory'}"
            )

            return result

        except Exception as e:
            raise StorageError(f"Packet export failed: {e}") from e

    def export_alerts(
        self,
        repository: AlertRepository,
        format: str = "json",
        output_path: Optional[str] = None,
        filter: Optional[AlertFilter] = None,
        batch_size: int = 1000,
    ) -> str:
        """Export alerts to specified format.

        Args:
            repository: Alert repository
            format: Export format (csv, json)
            output_path: Optional output file path
            filter: Optional alert filter
            batch_size: Batch size for fetching

        Returns:
            File path or exported data

        Raises:
            StorageError: If export fails
        """
        config = ExportConfig(
            format=format,
            batch_size=batch_size,
            output_path=output_path,
        )

        exporter = self._create_exporter(config)

        try:
            result = exporter.export_alerts(repository, filter)

            self._logger.info(
                f"Exported alerts to {format}: "
                f"{output_path or 'in-memory'}"
            )

            return result

        except Exception as e:
            raise StorageError(f"Alert export failed: {e}") from e

    def _create_exporter(self, config: ExportConfig) -> Exporter:
        """Create exporter for format.

        Args:
            config: Export configuration

        Returns:
            Exporter instance

        Raises:
            ValueError: If format is not supported
        """
        format_lower = config.format.lower()

        if format_lower == "csv":
            return CsvExporter(config)
        elif format_lower == "json":
            return JsonExporter(config)
        else:
            raise ValueError(f"Unsupported export format: {config.format}")


def create_export_service() -> ExportService:
    """Create export service instance.

    Returns:
        ExportService instance
    """
    return ExportService()


__all__ = [
    "ExportConfig",
    "Exporter",
    "CsvExporter",
    "JsonExporter",
    "ExportService",
    "create_export_service",
]
