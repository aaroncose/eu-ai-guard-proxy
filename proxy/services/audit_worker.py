import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from proxy.config import BASE_DIR, settings
from proxy.database import async_session_factory
from proxy.models import AuditLedger
from proxy.security.crypto_chain import generate_record_hash, normalize_timestamp

logger = logging.getLogger(__name__)

# Buzon de apuntes que la base rechazo. Un registro de auditoria perdido en
# silencio vacia el valor probatorio de todo el ledger, asi que el ultimo
# recurso es dejarlo en disco para reprocesarlo
FAILED_DIR = BASE_DIR / "data" / "failed_audit"


class AuditLedgerWorker:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self.failed_count: int = 0

    @property
    def pending(self) -> int:
        return self.queue.qsize()

    async def start(self):
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._process_queue())

    async def stop(self):
        """Vacia la cola antes de cancelar el consumidor.

        Cancelar sin drenar descarta los apuntes que aun esperan turno.
        """
        if self._worker_task is None:
            return

        try:
            await asyncio.wait_for(self.queue.join(), timeout=settings.AUDIT_DRAIN_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error(
                "La cola de auditoria no se vacio en %.1f s, quedan %d apuntes",
                settings.AUDIT_DRAIN_TIMEOUT,
                self.queue.qsize(),
            )
            self._drain_to_disk()

        self._worker_task.cancel()
        try:
            await self._worker_task
        except asyncio.CancelledError:
            pass
        finally:
            self._worker_task = None

    async def enqueue_log(self, log_data: Dict[str, Any]):
        await self.queue.put(log_data)

    async def _process_queue(self):
        while True:
            item = await self.queue.get()
            try:
                await self._persist_with_retry(item)
            except asyncio.CancelledError:
                self._dump_failed(item, "cancelado durante la escritura")
                raise
            except Exception as exc:
                logger.exception("Apunte de auditoria descartado por la base de datos")
                self._dump_failed(item, str(exc))
            finally:
                self.queue.task_done()

    async def _persist_with_retry(self, item: Dict[str, Any]) -> None:
        attempts = max(1, settings.AUDIT_WRITE_MAX_ATTEMPTS)
        last_error: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            try:
                await self._persist(item)
                return
            except IntegrityError as exc:
                # Otro escritor tomo el mismo eslabon de la cadena. El hash
                # previo se relee en el intento siguiente.
                last_error = exc
                logger.warning(
                    "Colision al encadenar el apunte %s, intento %d de %d",
                    item.get("request_id"),
                    attempt,
                    attempts,
                )
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Fallo al escribir el apunte %s, intento %d de %d: %s",
                    item.get("request_id"),
                    attempt,
                    attempts,
                    exc,
                )

            if attempt < attempts:
                await asyncio.sleep(min(0.1 * (2 ** (attempt - 1)), 2.0))

        raise RuntimeError(f"Escritura del apunte agotada tras {attempts} intentos") from last_error

    async def _persist(self, item: Dict[str, Any]) -> None:
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
                    app_id=item.get("app_id") or "default-app",
                    user_id=item.get("user_id"),
                    ip_address=item.get("ip_address"),
                    model_requested=item["model"],
                    is_streaming=item.get("is_streaming", False),
                    request_payload=item["request_payload"],
                    response_payload=item["response_payload"],
                    tools_called=item.get("tools_called"),
                    is_blocked=item.get("is_blocked", False),
                    block_reason=item.get("block_reason"),
                    upstream_error=item.get("upstream_error"),
                    previous_hash=last_hash,
                    record_hash=record_hash
                )
                session.add(ledger_entry)

    def _dump_failed(self, item: Dict[str, Any], reason: str) -> None:
        """Escribe en disco el apunte que la base rechazo."""
        self.failed_count += 1
        try:
            FAILED_DIR.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            request_id = str(item.get("request_id") or uuid.uuid4().hex)
            path = FAILED_DIR / f"{stamp}_{request_id}.json"
            path.write_text(
                json.dumps({"reason": reason, "item": item}, default=str, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.error("Apunte de auditoria volcado a %s", path)
        except Exception:
            logger.exception("El apunte de auditoria se perdio y tampoco pudo volcarse a disco")

    def _drain_to_disk(self) -> None:
        while True:
            try:
                item = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            self._dump_failed(item, "cola sin vaciar al apagar el servicio")
            self.queue.task_done()


audit_worker = AuditLedgerWorker()
