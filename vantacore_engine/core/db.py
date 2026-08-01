"""SQLite state manager with Write-Ahead Logging (WAL) mode for forensic scanning."""

import sqlite3
from pathlib import Path
from typing import Optional, Union


class SQLiteWALStateManager:
    """Manages persistent traversal state, node/edge metadata, and deduplication using SQLite in WAL mode."""

    def __init__(self, db_path: Union[str, Path]) -> None:
        """Initialize SQLite WAL database connection and setup tables.

        Args:
            db_path: Path to the SQLite database file.

        Raises:
            RuntimeError: If setting WAL mode fails.

        """
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = sqlite3.connect(str(self.db_path))

        cursor = self._conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        mode = cursor.fetchone()
        if not mode or mode[0].lower() != "wal":
            raise RuntimeError(f"Failed to set WAL journal mode for database: {self.db_path}")

        cursor.execute("PRAGMA synchronous=NORMAL")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS visited_pointers (
                namespace TEXT NOT NULL,
                virtual_address INTEGER NOT NULL,
                PRIMARY KEY (namespace, virtual_address)
            ) WITHOUT ROWID;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS extracted_nodes (
                namespace TEXT NOT NULL,
                virtual_address INTEGER NOT NULL,
                node_type TEXT NOT NULL,
                label TEXT,
                raw_bytes BLOB,
                PRIMARY KEY (namespace, virtual_address)
            ) WITHOUT ROWID;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS extracted_edges (
                source_namespace TEXT NOT NULL,
                source_va INTEGER NOT NULL,
                target_namespace TEXT NOT NULL,
                target_va INTEGER NOT NULL,
                edge_type TEXT NOT NULL,
                offset_in_struct INTEGER,
                PRIMARY KEY (source_namespace, source_va, target_namespace, target_va, edge_type)
            ) WITHOUT ROWID;
            """
        )

        self._conn.commit()

    def mark_visited(self, namespace: str, virtual_address: int) -> None:
        """Mark a virtual address in a given namespace as visited.

        Args:
            namespace: Memory namespace identifier (e.g. CR3 hex or 'GLOBAL_KERNEL').
            virtual_address: Virtual address that was traversed.

        """
        if self._conn is None:
            raise RuntimeError("Database connection is closed.")
        self._conn.execute(
            "INSERT OR IGNORE INTO visited_pointers (namespace, virtual_address) VALUES (?, ?)",
            (namespace, virtual_address),
        )
        self._conn.commit()

    def is_visited(self, namespace: str, virtual_address: int) -> bool:
        """Check if a virtual address in a given namespace has been visited.

        Args:
            namespace: Memory namespace identifier.
            virtual_address: Virtual address to check.

        Returns:
            True if previously visited, False otherwise.

        """
        if self._conn is None:
            raise RuntimeError("Database connection is closed.")
        cursor = self._conn.execute(
            "SELECT 1 FROM visited_pointers WHERE namespace = ? AND virtual_address = ? LIMIT 1",
            (namespace, virtual_address),
        )
        return cursor.fetchone() is not None

    def set_metadata(self, key: str, value: str) -> None:
        """Set a metadata key-value pair for the scan session.

        Args:
            key: Metadata key.
            value: Metadata value.

        """
        if self._conn is None:
            raise RuntimeError("Database connection is closed.")
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_metadata (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve a metadata value by key.

        Args:
            key: Metadata key to look up.

        Returns:
            String value if key exists, or None.

        """
        if self._conn is None:
            raise RuntimeError("Database connection is closed.")
        cursor = self._conn.execute(
            "SELECT value FROM scan_metadata WHERE key = ?",
            (key,),
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def insert_node(
        self,
        namespace: str,
        virtual_address: int,
        node_type: str,
        label: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> None:
        """Insert or replace an extracted node in the database.

        Args:
            namespace: Memory namespace identifier.
            virtual_address: Virtual address of the extracted node.
            node_type: Identifier of the struct or node type.
            label: Human-readable label or name.
            raw_bytes: Optional binary payload of the struct.

        """
        if self._conn is None:
            raise RuntimeError("Database connection is closed.")
        self._conn.execute(
            """
            INSERT OR REPLACE INTO extracted_nodes
            (namespace, virtual_address, node_type, label, raw_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (namespace, virtual_address, node_type, label, raw_bytes),
        )
        self._conn.commit()

    def insert_edge(
        self,
        source_namespace: str,
        source_va: int,
        target_namespace: str,
        target_va: int,
        edge_type: str,
        offset_in_struct: Optional[int] = None,
    ) -> None:
        """Insert or replace an extracted edge in the database.

        Args:
            source_namespace: Memory namespace of source node.
            source_va: Virtual address of source node.
            target_namespace: Memory namespace of target node.
            target_va: Virtual address of target node.
            edge_type: String relationship type.
            offset_in_struct: Byte offset within source structure for pointer.

        """
        if self._conn is None:
            raise RuntimeError("Database connection is closed.")
        self._conn.execute(
            """
            INSERT OR REPLACE INTO extracted_edges
            (source_namespace, source_va, target_namespace, target_va, edge_type, offset_in_struct)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                source_namespace,
                source_va,
                target_namespace,
                target_va,
                edge_type,
                offset_in_struct,
            ),
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "SQLiteWALStateManager":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exit context manager and close connection."""
        self.close()
