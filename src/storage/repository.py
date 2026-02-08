"""
Repository pattern implementation for data access.

Provides abstract interfaces and concrete implementations
for database operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
import json

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from src.core.logger import get_logger
from src.core.exceptions import StorageError
from src.capture.base import PacketInfo
from .models import (
    PacketOrm,
    AlertOrm,
    ScanResultOrm,
    ConnectionOrm,
    StatisticsOrm,
)


# =============================================================================
# Data Transfer Objects
# =============================================================================

@dataclass
class PacketFilter:
    """Filter for packet queries.

    Attributes:
        start_time: Start of time range
        end_time: End of time range
        src_ip: Source IP filter
        dst_ip: Destination IP filter
        protocol: Protocol filter
        min_port: Minimum port number
        max_port: Maximum port number
        limit: Maximum results
        offset: Result offset
    """
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    min_port: Optional[int] = None
    max_port: Optional[int] = None
    limit: Optional[int] = None
    offset: int = 0


@dataclass
class AlertFilter:
    """Filter for alert queries.

    Attributes:
        start_time: Start of time range
        end_time: End of time range
        detection_type: Detection type filter
        severity: Severity level filter
        source_ip: Source IP filter
        acknowledged: Acknowledgment status
        limit: Maximum results
        offset: Result offset
    """
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    detection_type: Optional[str] = None
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    acknowledged: Optional[bool] = None
    limit: Optional[int] = None
    offset: int = 0


# =============================================================================
# Abstract Repository Interfaces
# =============================================================================

class PacketRepository(ABC):
    """Abstract packet repository interface."""

    @abstractmethod
    def save(self, packet: PacketInfo) -> str:
        """Save packet to database.

        Args:
            packet: Packet to save

        Returns:
            Packet ID
        """
        pass

    @abstractmethod
    def save_batch(self, packets: List[PacketInfo]) -> List[str]:
        """Save multiple packets.

        Args:
            packets: Packets to save

        Returns:
            List of packet IDs
        """
        pass

    @abstractmethod
    def find_by_id(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Find packet by ID.

        Args:
            packet_id: Packet ID

        Returns:
            Packet data or None
        """
        pass

    @abstractmethod
    def find_by_filter(self, filter: PacketFilter) -> List[Dict[str, Any]]:
        """Find packets matching filter.

        Args:
            filter: Packet filter

        Returns:
            List of packet data
        """
        pass

    @abstractmethod
    def count(self, filter: Optional[PacketFilter] = None) -> int:
        """Count packets.

        Args:
            filter: Optional filter

        Returns:
            Packet count
        """
        pass

    @abstractmethod
    def delete_old(self, days: int) -> int:
        """Delete packets older than specified days.

        Args:
            days: Days to keep

        Returns:
            Number of packets deleted
        """
        pass


class AlertRepository(ABC):
    """Abstract alert repository interface."""

    @abstractmethod
    def save(self, alert: Dict[str, Any]) -> str:
        """Save alert to database.

        Args:
            alert: Alert data

        Returns:
            Alert ID
        """
        pass

    @abstractmethod
    def find_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Find alert by ID.

        Args:
            alert_id: Alert ID

        Returns:
            Alert data or None
        """
        pass

    @abstractmethod
    def find_by_filter(self, filter: AlertFilter) -> List[Dict[str, Any]]:
        """Find alerts matching filter.

        Args:
            filter: Alert filter

        Returns:
            List of alert data
        """
        pass

    @abstractmethod
    def acknowledge(self, alert_id: int, notes: Optional[str] = None) -> bool:
        """Acknowledge alert.

        Args:
            alert_id: Alert ID
            notes: Optional notes

        Returns:
            True if acknowledged
        """
        pass

    @abstractmethod
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics.

        Returns:
            Statistics dictionary
        """
        pass


class ConnectionRepository(ABC):
    """Abstract connection repository interface."""

    @abstractmethod
    def save(self, connection: Dict[str, Any]) -> str:
        """Save connection to database.

        Args:
            connection: Connection data

        Returns:
            Connection ID
        """
        pass

    @abstractmethod
    def update(self, connection_id: str, updates: Dict[str, Any]) -> bool:
        """Update connection.

        Args:
            connection_id: Connection ID
            updates: Fields to update

        Returns:
            True if updated
        """
        pass

    @abstractmethod
    def find_by_id(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """Find connection by ID.

        Args:
            connection_id: Connection ID

        Returns:
            Connection data or None
        """
        pass

    @abstractmethod
    def find_active(self) -> List[Dict[str, Any]]:
        """Find all active connections.

        Returns:
            List of connection data
        """
        pass

    @abstractmethod
    def find_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Find connections for an IP.

        Args:
            ip: IP address

        Returns:
            List of connection data
        """
        pass


# =============================================================================
# Concrete Repository Implementations
# =============================================================================

class SqlPacketRepository(PacketRepository):
    """SQLAlchemy-based packet repository."""

    def __init__(self, session_factory):
        """Initialize repository.

        Args:
            session_factory: Session factory function
        """
        self._session_factory = session_factory
        logger = get_logger(__name__)
        self._logger = logger

    def save(self, packet: PacketInfo) -> str:
        """Save packet to database.

        Args:
            packet: Packet to save

        Returns:
            Packet ID
        """
        try:
            with self._session_factory() as session:
                orm_packet = PacketOrm(
                    timestamp=packet.timestamp,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    length=packet.length,
                    raw_data=packet.raw_data,
                )

                session.add(orm_packet)
                session.commit()
                session.refresh(orm_packet)

                return str(orm_packet.id)

        except Exception as e:
            self._logger.error(f"Failed to save packet: {e}")
            raise StorageError(f"Failed to save packet: {e}") from e

    def save_batch(self, packets: List[PacketInfo]) -> List[str]:
        """Save multiple packets.

        Args:
            packets: Packets to save

        Returns:
            List of packet IDs
        """
        try:
            with self._session_factory() as session:
                orm_packets = [
                    PacketOrm(
                        timestamp=p.timestamp,
                        src_ip=p.src_ip,
                        dst_ip=p.dst_ip,
                        src_port=p.src_port,
                        dst_port=p.dst_port,
                        protocol=p.protocol,
                        length=p.length,
                        raw_data=p.raw_data,
                    )
                    for p in packets
                ]

                session.add_all(orm_packets)
                session.commit()

                # Refresh to get IDs
                for p in orm_packets:
                    session.refresh(p)

                return [str(p.id) for p in orm_packets]

        except Exception as e:
            self._logger.error(f"Failed to save packet batch: {e}")
            raise StorageError(f"Failed to save packet batch: {e}") from e

    def find_by_id(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Find packet by ID.

        Args:
            packet_id: Packet ID

        Returns:
            Packet data or None
        """
        try:
            with self._session_factory() as session:
                packet = session.query(PacketOrm).filter(
                    PacketOrm.id == packet_id
                ).first()

                return packet.to_dict() if packet else None

        except Exception as e:
            self._logger.error(f"Failed to find packet: {e}")
            raise StorageError(f"Failed to find packet: {e}") from e

    def find_by_filter(self, filter: PacketFilter) -> List[Dict[str, Any]]:
        """Find packets matching filter.

        Args:
            filter: Packet filter

        Returns:
            List of packet data
        """
        try:
            with self._session_factory() as session:
                query = session.query(PacketOrm)

                # Apply filters
                if filter.start_time:
                    query = query.filter(PacketOrm.timestamp >= filter.start_time)

                if filter.end_time:
                    query = query.filter(PacketOrm.timestamp <= filter.end_time)

                if filter.src_ip:
                    query = query.filter(PacketOrm.src_ip == filter.src_ip)

                if filter.dst_ip:
                    query = query.filter(PacketOrm.dst_ip == filter.dst_ip)

                if filter.protocol:
                    query = query.filter(PacketOrm.protocol == filter.protocol)

                if filter.min_port:
                    query = query.filter(
                        or_(
                            PacketOrm.src_port >= filter.min_port,
                            PacketOrm.dst_port >= filter.min_port,
                        )
                    )

                if filter.max_port:
                    query = query.filter(
                        or_(
                            PacketOrm.src_port <= filter.max_port,
                            PacketOrm.dst_port <= filter.max_port,
                        )
                    )

                # Order by timestamp descending
                query = query.order_by(desc(PacketOrm.timestamp))

                # Apply limit and offset
                if filter.limit:
                    query = query.limit(filter.limit)
                query = query.offset(filter.offset)

                packets = query.all()
                return [p.to_dict() for p in packets]

        except Exception as e:
            self._logger.error(f"Failed to find packets: {e}")
            raise StorageError(f"Failed to find packets: {e}") from e

    def count(self, filter: Optional[PacketFilter] = None) -> int:
        """Count packets.

        Args:
            filter: Optional filter

        Returns:
            Packet count
        """
        try:
            with self._session_factory() as session:
                query = session.query(func.count(PacketOrm.id))

                if filter:
                    # Apply filters (simplified)
                    if filter.start_time:
                        query = query.filter(PacketOrm.timestamp >= filter.start_time)
                    if filter.end_time:
                        query = query.filter(PacketOrm.timestamp <= filter.end_time)
                    if filter.src_ip:
                        query = query.filter(PacketOrm.src_ip == filter.src_ip)
                    if filter.protocol:
                        query = query.filter(PacketOrm.protocol == filter.protocol)

                return query.scalar() or 0

        except Exception as e:
            self._logger.error(f"Failed to count packets: {e}")
            raise StorageError(f"Failed to count packets: {e}") from e

    def delete_old(self, days: int) -> int:
        """Delete packets older than specified days.

        Args:
            days: Days to keep

        Returns:
            Number of packets deleted
        """
        try:
            cutoff = datetime.now() - timedelta(days=days)

            with self._session_factory() as session:
                count = session.query(PacketOrm).filter(
                    PacketOrm.timestamp < cutoff
                ).delete()
                session.commit()

                return count

        except Exception as e:
            self._logger.error(f"Failed to delete old packets: {e}")
            raise StorageError(f"Failed to delete old packets: {e}") from e


class SqlAlertRepository(AlertRepository):
    """SQLAlchemy-based alert repository."""

    def __init__(self, session_factory):
        """Initialize repository.

        Args:
            session_factory: Session factory function
        """
        self._session_factory = session_factory
        logger = get_logger(__name__)
        self._logger = logger

    def save(self, alert: Dict[str, Any]) -> str:
        """Save alert to database.

        Args:
            alert: Alert data

        Returns:
            Alert ID
        """
        try:
            with self._session_factory() as session:
                orm_alert = AlertOrm(
                    alert_id=alert.get("id", ""),
                    detection_type=alert.get("detection_type", ""),
                    severity=alert.get("severity", ""),
                    title=alert.get("title", ""),
                    description=alert.get("description", ""),
                    timestamp=alert.get("timestamp", datetime.now()),
                    confidence=alert.get("confidence", 0.0),
                    source_ip=alert.get("source_ip"),
                    destination_ip=alert.get("destination_ip"),
                    source_port=alert.get("source_port"),
                    destination_port=alert.get("destination_port"),
                    evidence=json.dumps(alert.get("evidence", {})),
                    metadata=json.dumps(alert.get("metadata", {})),
                )

                session.add(orm_alert)
                session.commit()
                session.refresh(orm_alert)

                return str(orm_alert.id)

        except Exception as e:
            self._logger.error(f"Failed to save alert: {e}")
            raise StorageError(f"Failed to save alert: {e}") from e

    def find_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Find alert by ID.

        Args:
            alert_id: Alert ID

        Returns:
            Alert data or None
        """
        try:
            with self._session_factory() as session:
                alert = session.query(AlertOrm).filter(
                    AlertOrm.id == alert_id
                ).first()

                return alert.to_dict() if alert else None

        except Exception as e:
            self._logger.error(f"Failed to find alert: {e}")
            raise StorageError(f"Failed to find alert: {e}") from e

    def find_by_filter(self, filter: AlertFilter) -> List[Dict[str, Any]]:
        """Find alerts matching filter.

        Args:
            filter: Alert filter

        Returns:
            List of alert data
        """
        try:
            with self._session_factory() as session:
                query = session.query(AlertOrm)

                # Apply filters
                if filter.start_time:
                    query = query.filter(AlertOrm.timestamp >= filter.start_time)

                if filter.end_time:
                    query = query.filter(AlertOrm.timestamp <= filter.end_time)

                if filter.detection_type:
                    query = query.filter(AlertOrm.detection_type == filter.detection_type)

                if filter.severity:
                    query = query.filter(AlertOrm.severity == filter.severity)

                if filter.source_ip:
                    query = query.filter(AlertOrm.source_ip == filter.source_ip)

                if filter.acknowledged is not None:
                    query = query.filter(AlertOrm.acknowledged == filter.acknowledged)

                # Order by timestamp descending
                query = query.order_by(desc(AlertOrm.timestamp))

                # Apply limit and offset
                if filter.limit:
                    query = query.limit(filter.limit)
                query = query.offset(filter.offset)

                alerts = query.all()
                return [a.to_dict() for a in alerts]

        except Exception as e:
            self._logger.error(f"Failed to find alerts: {e}")
            raise StorageError(f"Failed to find alerts: {e}") from e

    def acknowledge(self, alert_id: int, notes: Optional[str] = None) -> bool:
        """Acknowledge alert.

        Args:
            alert_id: Alert ID
            notes: Optional notes

        Returns:
            True if acknowledged
        """
        try:
            with self._session_factory() as session:
                alert = session.query(AlertOrm).filter(
                    AlertOrm.id == alert_id
                ).first()

                if alert:
                    alert.acknowledged = True
                    alert.notes = notes
                    session.commit()
                    return True

                return False

        except Exception as e:
            self._logger.error(f"Failed to acknowledge alert: {e}")
            raise StorageError(f"Failed to acknowledge alert: {e}") from e

    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics.

        Returns:
            Statistics dictionary
        """
        try:
            with self._session_factory() as session:
                total = session.query(func.count(AlertOrm.id)).scalar() or 0

                # Count by severity
                by_severity = {}
                for severity in ["info", "low", "medium", "high", "critical"]:
                    count = session.query(func.count(AlertOrm.id)).filter(
                        AlertOrm.severity == severity
                    ).scalar() or 0
                    by_severity[severity] = count

                # Count by detection type
                by_type = {}
                for row in session.query(
                    AlertOrm.detection_type,
                    func.count(AlertOrm.id)
                ).group_by(AlertOrm.detection_type).all():
                    by_type[row[0]] = row[1]

                # Count unacknowledged
                unacknowledged = session.query(func.count(AlertOrm.id)).filter(
                    AlertOrm.acknowledged == False
                ).scalar() or 0

                return {
                    "total": total,
                    "by_severity": by_severity,
                    "by_type": by_type,
                    "unacknowledged": unacknowledged,
                }

        except Exception as e:
            self._logger.error(f"Failed to get alert statistics: {e}")
            raise StorageError(f"Failed to get alert statistics: {e}") from e


class SqlConnectionRepository(ConnectionRepository):
    """SQLAlchemy-based connection repository."""

    def __init__(self, session_factory):
        """Initialize repository.

        Args:
            session_factory: Session factory function
        """
        self._session_factory = session_factory
        logger = get_logger(__name__)
        self._logger = logger

    def save(self, connection: Dict[str, Any]) -> str:
        """Save connection to database.

        Args:
            connection: Connection data

        Returns:
            Connection ID
        """
        try:
            with self._session_factory() as session:
                orm_conn = ConnectionOrm(
                    connection_id=connection.get("connection_id", ""),
                    src_ip=connection.get("src_ip", ""),
                    dst_ip=connection.get("dst_ip", ""),
                    src_port=connection.get("src_port"),
                    dst_port=connection.get("dst_port"),
                    protocol=connection.get("protocol", ""),
                    state=connection.get("state", "unknown"),
                    packets_sent=connection.get("packets_sent", 0),
                    packets_received=connection.get("packets_received", 0),
                    bytes_sent=connection.get("bytes_sent", 0),
                    bytes_received=connection.get("bytes_received", 0),
                    first_seen=connection.get("first_seen", datetime.now()),
                    last_seen=connection.get("last_seen", datetime.now()),
                    client_ip=connection.get("client_ip"),
                    server_ip=connection.get("server_ip"),
                )

                session.add(orm_conn)
                session.commit()
                session.refresh(orm_conn)

                return str(orm_conn.id)

        except Exception as e:
            self._logger.error(f"Failed to save connection: {e}")
            raise StorageError(f"Failed to save connection: {e}") from e

    def update(self, connection_id: str, updates: Dict[str, Any]) -> bool:
        """Update connection.

        Args:
            connection_id: Connection ID
            updates: Fields to update

        Returns:
            True if updated
        """
        try:
            with self._session_factory() as session:
                conn = session.query(ConnectionOrm).filter(
                    ConnectionOrm.connection_id == connection_id
                ).first()

                if conn:
                    for key, value in updates.items():
                        if hasattr(conn, key):
                            setattr(conn, key, value)

                    session.commit()
                    return True

                return False

        except Exception as e:
            self._logger.error(f"Failed to update connection: {e}")
            raise StorageError(f"Failed to update connection: {e}") from e

    def find_by_id(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """Find connection by ID.

        Args:
            connection_id: Connection ID

        Returns:
            Connection data or None
        """
        try:
            with self._session_factory() as session:
                conn = session.query(ConnectionOrm).filter(
                    ConnectionOrm.connection_id == connection_id
                ).first()

                return conn.to_dict() if conn else None

        except Exception as e:
            self._logger.error(f"Failed to find connection: {e}")
            raise StorageError(f"Failed to find connection: {e}") from e

    def find_active(self) -> List[Dict[str, Any]]:
        """Find all active connections.

        Returns:
            List of connection data
        """
        try:
            with self._session_factory() as session:
                connections = session.query(ConnectionOrm).filter(
                    ConnectionOrm.state.in_(["new", "established"])
                ).order_by(desc(ConnectionOrm.last_seen)).all()

                return [c.to_dict() for c in connections]

        except Exception as e:
            self._logger.error(f"Failed to find active connections: {e}")
            raise StorageError(f"Failed to find active connections: {e}") from e

    def find_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Find connections for an IP.

        Args:
            ip: IP address

        Returns:
            List of connection data
        """
        try:
            with self._session_factory() as session:
                connections = session.query(ConnectionOrm).filter(
                    or_(
                        ConnectionOrm.src_ip == ip,
                        ConnectionOrm.dst_ip == ip,
                    )
                ).order_by(desc(ConnectionOrm.last_seen)).all()

                return [c.to_dict() for c in connections]

        except Exception as e:
            self._logger.error(f"Failed to find connections by IP: {e}")
            raise StorageError(f"Failed to find connections by IP: {e}") from e


def create_packet_repository(session_factory) -> PacketRepository:
    """Create packet repository.

    Args:
        session_factory: Session factory

    Returns:
        PacketRepository instance
    """
    return SqlPacketRepository(session_factory)


def create_alert_repository(session_factory) -> AlertRepository:
    """Create alert repository.

    Args:
        session_factory: Session factory

    Returns:
        AlertRepository instance
    """
    return SqlAlertRepository(session_factory)


def create_connection_repository(session_factory) -> ConnectionRepository:
    """Create connection repository.

    Args:
        session_factory: Session factory

    Returns:
        ConnectionRepository instance
    """
    return SqlConnectionRepository(session_factory)


__all__ = [
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
]
