import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from proxy.config import settings
from proxy.models import AuditLedger, Base
from proxy.services import audit_worker as worker_module
from proxy.services.audit_worker import AuditLedgerWorker


def make_item(request_id: str) -> dict:
    return {
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc),
        "app_id": "test",
        "user_id": None,
        "ip_address": None,
        "model": "gpt-4o",
        "is_streaming": False,
        "request_payload": {"prompt": request_id},
        "response_payload": {"answer": request_id},
        "tools_called": None,
        "is_blocked": False,
        "block_reason": None,
        "upstream_error": None,
    }


@pytest_asyncio.fixture
async def factory(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ledger.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(worker_module, "async_session_factory", session_factory)
    monkeypatch.setattr(worker_module, "FAILED_DIR", tmp_path / "failed_audit")
    monkeypatch.setattr(settings, "AUDIT_WRITE_MAX_ATTEMPTS", 1)

    yield session_factory
    await engine.dispose()


async def test_records_are_chained(factory):
    worker = AuditLedgerWorker()
    await worker.start()
    await worker.enqueue_log(make_item("req-1"))
    await worker.enqueue_log(make_item("req-2"))
    await worker.queue.join()
    await worker.stop()

    async with factory() as session:
        records = (await session.execute(select(AuditLedger).order_by(AuditLedger.id))).scalars().all()

    assert [r.request_id for r in records] == ["req-1", "req-2"]
    assert records[0].previous_hash == settings.GENESIS_HASH
    assert records[1].previous_hash == records[0].record_hash
    assert worker.failed_count == 0


async def test_rejected_record_lands_in_the_failed_folder(factory, tmp_path):
    worker = AuditLedgerWorker()
    await worker.start()

    broken = make_item("req-roto")
    del broken["model"]  # la escritura falla al construir el registro
    await worker.enqueue_log(broken)
    await worker.queue.join()
    await worker.stop()

    dumps = list((tmp_path / "failed_audit").glob("*.json"))
    assert len(dumps) == 1
    assert worker.failed_count == 1

    payload = json.loads(dumps[0].read_text(encoding="utf-8"))
    assert payload["item"]["request_id"] == "req-roto"
    assert payload["reason"]

    async with factory() as session:
        stored = (await session.execute(select(AuditLedger))).scalars().all()
    assert stored == []


async def test_stop_drains_pending_items(factory):
    worker = AuditLedgerWorker()
    await worker.start()
    for index in range(5):
        await worker.enqueue_log(make_item(f"req-{index}"))
    await worker.stop()

    async with factory() as session:
        total = len((await session.execute(select(AuditLedger))).scalars().all())
    assert total == 5


async def test_forked_chain_is_rejected_by_the_unique_index(tmp_path):
    """Dos apuntes con el mismo eslabon anterior no pueden convivir."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'fork.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    from sqlalchemy.exc import IntegrityError

    async with session_factory() as session:
        session.add(AuditLedger(
            request_id="req-a", timestamp_utc=datetime.now(timezone.utc), app_id="test",
            model_requested="gpt-4o", request_payload={}, response_payload={},
            previous_hash=settings.GENESIS_HASH, record_hash="a" * 64,
        ))
        session.add(AuditLedger(
            request_id="req-b", timestamp_utc=datetime.now(timezone.utc), app_id="test",
            model_requested="gpt-4o", request_payload={}, response_payload={},
            previous_hash=settings.GENESIS_HASH, record_hash="b" * 64,
        ))
        with pytest.raises(IntegrityError):
            await session.commit()

    await engine.dispose()
