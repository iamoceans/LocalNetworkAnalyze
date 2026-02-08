"""
Database management layer.

Provides database connection, session management,
and basic database operations.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
import threading

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.exc import SQLAlchemyError

from src.core.logger import get_logger
from src.core.exceptions import StorageError
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


class DatabaseManager:
    """Database connection and session manager.

    Manages SQLite database connections with proper
    connection pooling and session handling.
    """

    _instance: Optional["DatabaseManager"] = None
    _lock = threading.Lock()

    def __new__(cls, config: Optional[DatabaseConfig] = None) -> "DatabaseManager":
        """Singleton pattern for database manager.

        Args:
            config: Database configuration

        Returns:
            DatabaseManager instance
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        config: Optional[DatabaseConfig] = None,
    ) -> None:
        """Initialize database manager.

        Args:
            config: Database configuration
        """
        if self._initialized:
            return

        self._config = config or DatabaseConfig()
        self._engine = None
        self._session_factory = None
        self._connection_count = 0
        self._connection_lock = threading.Lock()

        logger = get_logger(__name__)
        self._logger = logger

        self._initialized = True

    def connect(self, create_schema: bool = True) -> None:
        """Establish database connection.

        Args:
            create_schema: Whether to create tables if they don't exist

        Raises:
            StorageError: If connection fails
        """
        try:
            database_url = self._config.get_database_url()

            # Create engine with SQLite-specific optimizations
            self._engine = create_engine(
                database_url,
                echo=self._config.echo_sql,
                connect_args={
                    "check_same_thread": False,  # Allow multi-threading
                    "timeout": 30,  # 30 second timeout
                },
                poolclass=StaticPool if database_url.startswith("sqlite") else QueuePool,
                pool_pre_ping=True,  # Verify connections before using
            )

            # Set SQLite pragmas for better performance
            if database_url.startswith("sqlite"):
                @event.listens_for(self._engine, "connect")
                def set_sqlite_pragma(dbapi_conn, connection_record):
                    cursor = dbapi_conn.cursor()
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache
                    cursor.execute("PRAGMA temp_store=memory")
                    cursor.close()

            # Create session factory
            self._session_factory = sessionmaker(
                bind=self._engine,
                autocommit=False,
                autoflush=False,
                expire_on_commit=False,
            )

            # Create tables if requested
            if create_schema:
                create_tables(self._engine)

            self._logger.info(
                f"Connected to database: {self._config.db_path}"
            )

        except Exception as e:
            raise StorageError(f"Failed to connect to database: {e}") from e

    def disconnect(self) -> None:
        """Close database connection."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
            self._logger.info("Disconnected from database")

    @contextmanager
    def get_session(self) -> Session:
        """Get a database session context manager.

        Yields:
            Database session

        Example:
            >>> with db_manager.get_session() as session:
            ...     packets = session.query(PacketOrm).all()
        """
        if self._session_factory is None:
            raise StorageError("Database not connected")

        session = self._session_factory()

        try:
            with self._connection_lock:
                self._connection_count += 1

            yield session

            # Commit if no exception
            session.commit()

        except Exception as e:
            # Rollback on error
            session.rollback()
            self._logger.error(f"Session error: {e}")
            raise

        finally:
            session.close()

            with self._connection_lock:
                self._connection_count -= 1

    def execute_sql(self, sql: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Execute raw SQL statement.

        Args:
            sql: SQL statement to execute
            params: Optional parameters

        Raises:
            StorageError: If execution fails
        """
        try:
            with self.get_session() as session:
                session.execute(text(sql), params or {})
                session.commit()
        except Exception as e:
            raise StorageError(f"Failed to execute SQL: {e}") from e

    def get_connection_info(self) -> Dict[str, Any]:
        """Get database connection information.

        Returns:
            Dictionary with connection info
        """
        return {
            "database_path": self._config.db_path,
            "connected": self._engine is not None,
            "active_connections": self._connection_count,
            "echo_sql": self._config.echo_sql,
        }

    def backup_database(self, backup_path: str) -> None:
        """Create backup of database.

        Args:
            backup_path: Path for backup file

        Raises:
            StorageError: If backup fails
        """
        try:
            import shutil
            Path(backup_path).parent.mkdir(parents=True, exist_ok=True)

            # Close existing connections
            was_connected = self._engine is not None
            if was_connected:
                self.disconnect()

            # Copy database file
            shutil.copy2(self._config.db_path, backup_path)

            # Reconnect if was connected
            if was_connected:
                self.connect(create_schema=False)

            self._logger.info(f"Database backed up to: {backup_path}")

        except Exception as e:
            raise StorageError(f"Failed to backup database: {e}") from e

    def restore_database(self, backup_path: str) -> None:
        """Restore database from backup.

        Args:
            backup_path: Path to backup file

        Raises:
            StorageError: If restore fails
        """
        try:
            import shutil

            if not Path(backup_path).exists():
                raise StorageError(f"Backup file not found: {backup_path}")

            # Close existing connections
            if self._engine:
                self.disconnect()

            # Restore backup
            shutil.copy2(backup_path, self._config.db_path)

            # Reconnect
            self.connect(create_schema=False)

            self._logger.info(f"Database restored from: {backup_path}")

        except Exception as e:
            raise StorageError(f"Failed to restore database: {e}") from e

    def vacuum_database(self) -> None:
        """Vacuum database to reclaim space.

        Raises:
            StorageError: If vacuum fails
        """
        try:
            with self.get_session() as session:
                session.execute(text("VACUUM"))
                session.commit()

            self._logger.info("Database vacuumed successfully")

        except Exception as e:
            raise StorageError(f"Failed to vacuum database: {e}") from e

    def get_database_size(self) -> int:
        """Get database file size in bytes.

        Returns:
            Size in bytes
        """
        try:
            return Path(self._config.db_path).stat().st_size
        except Exception:
            return 0

    def get_table_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about database tables.

        Returns:
            Dictionary with table info
        """
        info = {}

        try:
            with self.get_session() as session:
                # Get row counts for each table
                tables = {
                    "packets": PacketOrm,
                    "alerts": AlertOrm,
                    "scan_results": ScanResultOrm,
                    "connections": ConnectionOrm,
                    "statistics": StatisticsOrm,
                }

                for table_name, model in tables.items():
                    count = session.query(model).count()
                    info[table_name] = {"row_count": count}

        except Exception as e:
            self._logger.error(f"Failed to get table info: {e}")

        return info

    def cleanup_old_data(
        self,
        days: int = 30,
        keep_statistics: bool = True,
    ) -> Dict[str, int]:
        """Clean up old data from database.

        Args:
            days: Days of data to keep
            keep_statistics: Whether to keep statistics

        Returns:
            Dictionary with deletion counts

        Raises:
            StorageError: If cleanup fails
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        counts = {}

        try:
            with self.get_session() as session:
                # Clean old packets
                packets_deleted = session.query(PacketOrm).filter(
                    PacketOrm.timestamp < cutoff_date
                ).delete()
                counts["packets"] = packets_deleted

                # Clean old alerts (keep high severity)
                alerts_deleted = session.query(AlertOrm).filter(
                    AlertOrm.timestamp < cutoff_date,
                    AlertOrm.severity.in_(["info", "low", "medium"]),
                ).delete()
                counts["alerts"] = alerts_deleted

                # Clean old scan results
                scans_deleted = session.query(ScanResultOrm).filter(
                    ScanResultOrm.start_time < cutoff_date
                ).delete()
                counts["scan_results"] = scans_deleted

                # Clean old connections (closed)
                connections_deleted = session.query(ConnectionOrm).filter(
                    ConnectionOrm.last_seen < cutoff_date,
                    ConnectionOrm.state.in_(["closed", "timeout"]),
                ).delete()
                counts["connections"] = connections_deleted

                # Clean old statistics if requested
                if not keep_statistics:
                    stats_deleted = session.query(StatisticsOrm).filter(
                        StatisticsOrm.timestamp < cutoff_date
                    ).delete()
                    counts["statistics"] = stats_deleted

                session.commit()

            self._logger.info(
                f"Cleaned up old data: {counts}"
            )

            # Vacuum to reclaim space
            self.vacuum_database()

            return counts

        except Exception as e:
            raise StorageError(f"Failed to cleanup old data: {e}") from e

    def reset_database(self) -> None:
        """Reset database by dropping and recreating tables.

        Raises:
            StorageError: If reset fails
        """
        try:
            if self._engine:
                drop_tables(self._engine)
                create_tables(self._engine)

            self._logger.info("Database reset completed")

        except Exception as e:
            raise StorageError(f"Failed to reset database: {e}") from e

    @classmethod
    def get_instance(cls) -> "DatabaseManager":
        """Get the singleton instance.

        Returns:
            DatabaseManager instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def is_connected(self) -> bool:
        """Check if database is connected.

        Returns:
            True if connected
        """
        return self._engine is not None


def get_database_manager(
    db_path: Optional[str] = None,
    echo_sql: bool = False,
) -> DatabaseManager:
    """Get or create database manager instance.

    Args:
        db_path: Path to database file
        echo_sql: Enable SQL logging

    Returns:
        DatabaseManager instance
    """
    config = DatabaseConfig(db_path=db_path, echo_sql=echo_sql)
    manager = DatabaseManager.get_instance()

    if not manager.is_connected():
        manager.connect()

    return manager


def init_database(
    db_path: str = "data/network_analyzer.db",
    echo_sql: bool = False,
) -> DatabaseManager:
    """Initialize database with schema creation.

    Args:
        db_path: Path to database file
        echo_sql: Enable SQL logging

    Returns:
        Initialized DatabaseManager instance
    """
    config = DatabaseConfig(db_path=db_path, echo_sql=echo_sql)
    manager = DatabaseManager(config)
    manager.connect(create_schema=True)

    return manager


__all__ = [
    "DatabaseManager",
    "get_database_manager",
    "init_database",
]
