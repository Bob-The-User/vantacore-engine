"""Unit tests for SQLite WAL state manager."""

from pathlib import Path
from vantacore_engine.core.db import SQLiteWALStateManager


def test_sqlite_wal_journal_mode(tmp_output_dir: Path) -> None:
    """Verify that SQLite database opens in WAL journal mode."""
    db_file = tmp_output_dir / "test_wal.db"

    with SQLiteWALStateManager(db_file) as db:
        assert db._conn is not None
        cursor = db._conn.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert mode.lower() == "wal"


def test_sqlite_wal_tables_without_rowid(tmp_output_dir: Path) -> None:
    """Verify all 4 required tables exist and specify WITHOUT ROWID."""
    db_file = tmp_output_dir / "test_tables.db"

    expected_tables = {
        "visited_pointers",
        "scan_metadata",
        "extracted_nodes",
        "extracted_edges",
    }

    with SQLiteWALStateManager(db_file) as db:
        assert db._conn is not None
        cursor = db._conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table';"
        )
        rows = cursor.fetchall()
        table_dict = {name: sql for name, sql in rows}

        assert expected_tables.issubset(set(table_dict.keys()))

        for table in expected_tables:
            sql = table_dict[table]
            assert "WITHOUT ROWID" in sql.upper()


def test_visited_pointers_idempotency(tmp_output_dir: Path) -> None:
    """Verify mark_visited and is_visited logic and idempotency."""
    db_file = tmp_output_dir / "test_visited.db"

    with SQLiteWALStateManager(db_file) as db:
        assert not db.is_visited("K", 0x1000)
        db.mark_visited("K", 0x1000)
        assert db.is_visited("K", 0x1000)
        assert not db.is_visited("K", 0x2000)

        # Duplicate mark_visited call should not raise IntegrityError
        db.mark_visited("K", 0x1000)
        assert db.is_visited("K", 0x1000)


def test_scan_metadata(tmp_output_dir: Path) -> None:
    """Verify metadata getter and setter behavior."""
    db_file = tmp_output_dir / "test_meta.db"

    with SQLiteWALStateManager(db_file) as db:
        assert db.get_metadata("nonexistent") is None
        db.set_metadata("key1", "val1")
        assert db.get_metadata("key1") == "val1"


def test_insert_node_and_edge(tmp_output_dir: Path) -> None:
    """Verify inserting node and edge records."""
    db_file = tmp_output_dir / "test_graph.db"

    with SQLiteWALStateManager(db_file) as db:
        db.insert_node("K", 0x1000, "task_struct", label="init", raw_bytes=b"\x00" * 16)
        db.insert_node("K", 0x2000, "task_struct", label="systemd")
        db.insert_edge("K", 0x1000, "K", 0x2000, "tasks_list", offset_in_struct=8)

        assert db._conn is not None
        node_count = db._conn.execute("SELECT count(*) FROM extracted_nodes;").fetchone()[0]
        edge_count = db._conn.execute("SELECT count(*) FROM extracted_edges;").fetchone()[0]

        assert node_count == 2
        assert edge_count == 1


def test_context_manager_closed(tmp_output_dir: Path) -> None:
    """Verify context manager closes the database connection."""
    db_file = tmp_output_dir / "test_cm.db"

    db_instance = SQLiteWALStateManager(db_file)
    with db_instance as db:
        assert db._conn is not None

    assert db_instance._conn is None


def test_closed_connection_raises_error(tmp_output_dir: Path) -> None:
    """Verify that operating on a closed database connection raises RuntimeError."""
    import pytest

    db_file = tmp_output_dir / "test_closed.db"
    db = SQLiteWALStateManager(db_file)
    db.close()

    with pytest.raises(RuntimeError, match="Database connection is closed"):
        db.mark_visited("K", 0x1000)

    with pytest.raises(RuntimeError, match="Database connection is closed"):
        db.is_visited("K", 0x1000)

    with pytest.raises(RuntimeError, match="Database connection is closed"):
        db.set_metadata("k", "v")

    with pytest.raises(RuntimeError, match="Database connection is closed"):
        db.get_metadata("k")

    with pytest.raises(RuntimeError, match="Database connection is closed"):
        db.insert_node("K", 0x1000, "node")

    with pytest.raises(RuntimeError, match="Database connection is closed"):
        db.insert_edge("K", 0x1000, "K", 0x2000, "edge")

