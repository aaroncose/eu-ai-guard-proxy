import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import select
from proxy.models import AuditLedger
from proxy.security.crypto_chain import generate_record_hash, normalize_timestamp
from proxy.config import settings
from proxy.database import async_session_factory

class AuditLedgerWorker:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self):
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._process_queue())

    async def stop(self):
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def enqueue_log(self, log_data: Dict[str, Any]):
        await self.queue.put(log_data)

    async def _process_queue(self):
        while True:
            item = await self.queue.get()
            try:
                async with async_session_factory() as session:
                    async with session.begin():
                        stmt = select(AuditLedger.record_hash).order_by(AuditLedger.id.desc()).limit(1)
                        result = await session.execute(stmt)
                        last_hash = result.scalar_one_or_none() or settings.GENESIS_HASH

                        timestamp_str = normalize_timestamp(item["timestamp"])
                        
                        record_hash = generate_record_hash(
                            previous_hash=last_hash,
                            request_id=item["request_id"],
                            timestamp_iso=timestamp_str,
                            model=item["model"],
                            request_payload=item["request_payload"],
                            response_payload=item["response_payload"]
                        )

                        ledger_entry = AuditLedger(
                            request_id=item["request_id"],
                            timestamp_utc=item["timestamp"],
                            app_id=item.get("app_id", "default-app"),
                            user_id=item.get("user_id"),
                            ip_address=item.get("ip_address"),
                            model_requested=item["model"],
                            is_streaming=item.get("is_streaming", False),
                            request_payload=item["request_payload"],
                            response_payload=item["response_payload"],
                            tools_called=item.get("tools_called"),
                            is_blocked=item.get("is_blocked", False),
                            block_reason=item.get("block_reason"),
                            previous_hash=last_hash,
                            record_hash=record_hash
                        )
                        session.add(ledger_entry)
            except Exception as e:
                pass
            finally:
                self.queue.task_done()

audit_worker = AuditLedgerWorker()