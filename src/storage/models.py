"""
Data models for storage layer.

Defines SQLAlchemy ORM models for packet data,
alerts, and scan results.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from enum import Enum

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Float,
    Boolean,
    Text,
    LargeBinary,
    Index,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func

from src.core.logger import get_logger

# Base class for all models
Base = declarative_base()


class PacketOrm(Base):
    """Packet data ORM model.

    Represents a captured network packet in the database.
    """
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)  # Support IPv6
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True, index=True)
    dst_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(16), nullable=False, index=True)
    length = Column(Integer, nullable=False)
    raw_data = Column(LargeBinary, nullable=True)

    # Parsed data fields
    parsed_protocol = Column(String(32), nullable=True)
    parsed_data = Column(Text, nullable=True)  # JSON string

    # Analysis fields
    connection_id = Column(String(64), nullable=True, index=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    # Indexes for common queries
    __table_args__ = (
        Index("idx_packet_timestamp_src", "timestamp", "src_ip"),
        Index("idx_packet_protocol", "protocol"),
        Index("idx_packet_connection", "connection_id"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "parsed_protocol": self.parsed_protocol,
            "parsed_data": self.parsed_data,
            "connection_id": self.connection_id,
            "created_at": self.created_at.isoformat(),
        }


class AlertOrm(Base):
    """Security alert ORM model.

    Represents a security detection alert.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    detection_type = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    confidence = Column(Float, nullable=False)

    # Source/destination info
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    # Evidence and metadata (JSON strings)
    evidence = Column(Text, nullable=True)
    alert_metadata = Column(Text, nullable=True)

    # Alert status
    acknowledged = Column(Boolean, default=False, nullable=False)
    notes = Column(Text, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    # Indexes
    __table_args__ = (
        Index("idx_alert_timestamp_severity", "timestamp", "severity"),
        Index("idx_alert_detection_type", "detection_type"),
        Index("idx_alert_source", "source_ip"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "evidence": self.evidence,
            "alert_metadata": self.alert_metadata,
            "acknowledged": self.acknowledged,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
        }


class ScanResultOrm(Base):
    """Network scan result ORM model.

    Represents results from network scanning operations.
    """
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    scan_type = Column(String(32), nullable=False, index=True)

    # Target information
    target_ip = Column(String(45), nullable=False, index=True)
    target_hostname = Column(String(256), nullable=True)
    mac_address = Column(String(18), nullable=True)

    # Scan results
    is_alive = Column(Boolean, nullable=False, index=True)
    response_time = Column(Float, nullable=True)  # milliseconds
    open_ports = Column(Text, nullable=True)  # JSON array of ports

    # Scan metadata
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)

    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    # Indexes
    __table_args__ = (
        Index("idx_scan_target_type", "target_ip", "scan_type"),
        Index("idx_scan_timestamp", "start_time"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "target_ip": self.target_ip,
            "target_hostname": self.target_hostname,
            "mac_address": self.mac_address,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "open_ports": self.open_ports,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "created_at": self.created_at.isoformat(),
        }


class ConnectionOrm(Base):
    """Network connection ORM model.

    Represents tracked network connections.
    """
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    connection_id = Column(String(64), unique=True, nullable=False, index=True)

    # Connection endpoints
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False)

    # Connection state
    state = Column(String(32), nullable=False)

    # Statistics
    packets_sent = Column(Integer, default=0, nullable=False)
    packets_received = Column(Integer, default=0, nullable=False)
    bytes_sent = Column(Integer, default=0, nullable=False)
    bytes_received = Column(Integer, default=0, nullable=False)

    # Timestamps
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False, index=True)

    # Role identification
    client_ip = Column(String(45), nullable=True)
    server_ip = Column(String(45), nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    # Indexes
    __table_args__ = (
        Index("idx_connection_endpoints", "src_ip", "dst_ip", "protocol"),
        Index("idx_connection_active", "last_seen"),
    )

    @property
    def total_packets(self) -> int:
        """Get total packets in both directions."""
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """Get total bytes in both directions."""
        return self.bytes_sent + self.bytes_received

    def to_dict(self) -> dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "connection_id": self.connection_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "state": self.state,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "created_at": self.created_at.isoformat(),
        }


class StatisticsOrm(Base):
    """Aggregated statistics ORM model.

    Stores periodic traffic statistics snapshots.
    """
    __tablename__ = "statistics"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Timestamp
    timestamp = Column(DateTime, nullable=False, unique=True, index=True)

    # Traffic counters
    total_packets = Column(Integer, nullable=False)
    total_bytes = Column(Integer, nullable=False)

    # Rate data
    packets_per_second = Column(Float, nullable=False)
    bytes_per_second = Column(Float, nullable=False)

    # Protocol distribution (JSON)
    protocol_stats = Column(Text, nullable=True)

    # Connection stats
    active_connections = Column(Integer, default=0)
    established_connections = Column(Integer, default=0)

    # Top talkers and connections (JSON)
    top_connections = Column(Text, nullable=True)
    top_talkers = Column(Text, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    def to_dict(self) -> dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "protocol_stats": self.protocol_stats,
            "active_connections": self.active_connections,
            "established_connections": self.established_connections,
            "top_connections": self.top_connections,
            "top_talkers": self.top_talkers,
            "created_at": self.created_at.isoformat(),
        }


class DatabaseConfig:
    """Database configuration.

    Attributes:
        db_path: Path to SQLite database file
        echo_sql: Whether to echo SQL statements
        pool_size: Connection pool size
        max_overflow: Max overflow for pool
    """
    def __init__(
        self,
        db_path: str = "data/network_analyzer.db",
        echo_sql: bool = False,
        pool_size: int = 5,
        max_overflow: int = 10,
    ):
        """Initialize database configuration.

        Args:
            db_path: Path to database file
            echo_sql: Enable SQL logging
            pool_size: Connection pool size
            max_overflow: Max overflow connections
        """
        self.db_path = db_path
        self.echo_sql = echo_sql
        self.pool_size = pool_size
        self.max_overflow = max_overflow

    def get_database_url(self) -> str:
        """Get SQLAlchemy database URL.

        Returns:
            Database URL string
        """
        # Ensure directory exists
        import os
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        return f"sqlite:///{self.db_path}"


def create_tables(engine) -> None:
    """Create all database tables.

    Args:
        engine: SQLAlchemy engine
    """
    Base.metadata.create_all(engine)

    logger = get_logger(__name__)
    logger.info("Database tables created")


def drop_tables(engine) -> None:
    """Drop all database tables.

    Args:
        engine: SQLAlchemy engine
    """
    Base.metadata.drop_all(engine)

    logger = get_logger(__name__)
    logger.info("Database tables dropped")


__all__ = [
    "Base",
    "PacketOrm",
    "AlertOrm",
    "ScanResultOrm",
    "ConnectionOrm",
    "StatisticsOrm",
    "DatabaseConfig",
    "create_tables",
    "drop_tables",
]
