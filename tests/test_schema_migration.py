from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from proxy.database import _audit_ledger_columns, _migrate_audit_ledger

# Esquema anterior a la columna upstream_error y a la restriccion de la cadena
LEGACY_SCHEMA = """
CREATE TABLE audit_ledger (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    request_id VARCHAR(64) NOT NULL,
    timestamp_utc DATETIME NOT NULL,
    app_id VARCHAR(64),
    user_id VARCHAR(128),
    ip_address VARCHAR(45),
    model_requested VARCHAR(128) NOT NULL,
    is_streaming BOOLEAN,
    request_payload JSON NOT NULL,
    response_payload JSON NOT NULL,
    tools_called JSON,
    is_blocked BOOLEAN,
    block_reason TEXT,
    previous_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL,
    archived_to_s3 BOOLEAN
)
"""

INSERT_RECORD = """
INSERT INTO audit_ledger
(request_id, timestamp_utc, app_id, model_requested, is_streaming, request_payload,
 response_payload, is_blocked, previous_hash, record_hash, archived_to_s3)
VALUES (:rid, '2026-01-01 00:00:00', 'test', 'gpt-4o', 0, '{}', '{}', 0, :prev, :rec, 0)
"""


async def build_legacy_database(path, records):
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with engine.begin() as conn:
        await conn.execute(text(LEGACY_SCHEMA))
        for rid, prev, rec in records:
            await conn.execute(text(INSERT_RECORD), {"rid": rid, "prev": prev, "rec": rec})
    return engine


async def index_names(conn):
    result = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_ledger'")
    )
    return {row[0] for row in result}


async def test_migration_adds_column_and_unique_index(tmp_path):
    engine = await build_legacy_database(
        tmp_path / "legacy.db", [("req-1", "0" * 64, "a" * 64)]
    )

    async with engine.begin() as conn:
        columns = await conn.run_sync(_audit_ledger_columns)
        assert "upstream_error" not in columns

        await _migrate_audit_ledger(conn)

        columns = await conn.run_sync(_audit_ledger_columns)
        assert "upstream_error" in columns
        assert "uq_audit_ledger_previous_hash" in await index_names(conn)

    # Repetirla no cambia nada
    async with engine.begin() as conn:
        await _migrate_audit_ledger(conn)
        assert "uq_audit_ledger_previous_hash" in await index_names(conn)

    await engine.dispose()


async def test_migration_survives_an_already_forked_chain(tmp_path, caplog):
    """Una base con la cadena bifurcada arranca igual, con el aviso registrado."""
    engine = await build_legacy_database(
        tmp_path / "forked.db",
        [("req-1", "0" * 64, "a" * 64), ("req-2", "0" * 64, "b" * 64)],
    )

    async with engine.begin() as conn:
        await _migrate_audit_ledger(conn)
        assert "uq_audit_ledger_previous_hash" not in await index_names(conn)

    assert "hashes previos repetidos" in caplog.text
    await engine.dispose()
