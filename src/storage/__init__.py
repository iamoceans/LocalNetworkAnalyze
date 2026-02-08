"""
Storage module for data persistence.

Provides database models, repository pattern implementation,
and export services for network traffic data.
"""

from .models import (
    Base,
    PacketOrm,
    AlertOrm,
    ScanResultOrm,
    ConnectionOrm,
    StatisticsOrm,
    DatabaseConfig,
    create_tables,
    drop_tables,
)

from .database import (
    DatabaseManager,
    get_database_manager,
    init_database,
)

from .repository import (
    PacketRepository,
    AlertRepository,
    ConnectionRepository,
    PacketFilter,
    AlertFilter,
    SqlPacketRepository,
    SqlAlertRepository,
    SqlConnectionRepository,
    create_packet_repository,
    create_alert_repository,
    create_connection_repository,
)

from .export_service import (
    ExportConfig,
    Exporter,
    CsvExporter,
    JsonExporter,
    ExportService,
    create_export_service,
)

__all__ = [
    # Models
    "Base",
    "PacketOrm",
    "AlertOrm",
    "ScanResultOrm",
    "ConnectionOrm",
    "StatisticsOrm",
    "DatabaseConfig",
    "create_tables",
    "drop_tables",
    # Database
    "DatabaseManager",
    "get_database_manager",
    "init_database",
    # Repository
    "PacketRepository",
    "AlertRepository",
    "ConnectionRepository",
    "PacketFilter",
    "AlertFilter",
    "SqlPacketRepository",
    "SqlAlertRepository",
    "SqlConnectionRepository",
    "create_packet_repository",
    "create_alert_repository",
    "create_connection_repository",
    # Export
    "ExportConfig",
    "Exporter",
    "CsvExporter",
    "JsonExporter",
    "ExportService",
    "create_export_service",
]
