import hashlib
import json
from datetime import datetime, timezone
from typing import Any, List, Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from proxy.config import settings

def ensure_dict(val: Any) -> Any:
    """Garantiza que si un JSON vino como string desde SQLite, se deserialice a dict antes de hashear."""
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val

def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def normalize_timestamp(ts: Any) -> str:
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return ts
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(ts)

def generate_record_hash(
    previous_hash: str,
    request_id: str,
    timestamp_iso: str,
    model: str,
    request_payload: Any,
    response_payload: Any
) -> str:
    canonical_data = {
        "previous_hash": previous_hash,
        "request_id": request_id,
        "timestamp_iso": normalize_timestamp(timestamp_iso),
        "model": model,
        "request_payload": ensure_dict(request_payload),
        "response_payload": ensure_dict(response_payload)
    }
    return hashlib.sha256(canonical_json(canonical_data).encode("utf-8")).hexdigest()

def compute_merkle_root(hashes: List[str]) -> str:
    """Raiz Merkle del lote, duplicando el ultimo nodo en los niveles impares.

    Trabaja sobre una copia, porque la lista que recibe pertenece a quien
    llama.
    """
    if not hashes:
        return settings.GENESIS_HASH
    current_level = list(hashes)
    while len(current_level) > 1:
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])
        next_level = []
        for i in range(0, len(current_level), 2):
            combined = current_level[i] + current_level[i + 1]
            next_level.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
        current_level = next_level
    return current_level[0]

async def verify_ledger_integrity(session: AsyncSession) -> Tuple[bool, int, Optional[int]]:
    """Recorre la cadena entera y devuelve (integra, total, primer id corrupto).

    El recorrido va por paginas y suelta cada una al terminarla. Cargar el
    ledger completo en memoria deja de ser viable en cuanto crece.
    """
    from proxy.models import AuditLedger

    total = (await session.execute(select(func.count(AuditLedger.id)))).scalar() or 0
    if total == 0:
        return True, 0, None

    page_size = max(1, settings.AUDIT_PAGE_SIZE)
    expected_prev = settings.GENESIS_HASH
    last_id = 0

    # Se piden columnas sueltas en lugar de entidades. Las filas asi devueltas
    # se quedan fuera del mapa de identidad de la sesion, de modo que el
    # recorrido acota su memoria sin alterar los objetos de quien llama
    columns = (
        AuditLedger.id,
        AuditLedger.request_id,
        AuditLedger.timestamp_utc,
        AuditLedger.model_requested,
        AuditLedger.request_payload,
        AuditLedger.response_payload,
        AuditLedger.previous_hash,
        AuditLedger.record_hash,
    )

    while True:
        stmt = (
            select(*columns)
            .where(AuditLedger.id > last_id)
            .order_by(AuditLedger.id.asc())
            .limit(page_size)
        )
        rows = (await session.execute(stmt)).all()
        if not rows:
            return True, total, None

        for row in rows:
            if row.previous_hash != expected_prev:
                return False, total, row.id

            calculated = generate_record_hash(
                previous_hash=row.previous_hash,
                request_id=row.request_id,
                timestamp_iso=normalize_timestamp(row.timestamp_utc),
                model=row.model_requested,
                request_payload=row.request_payload,
                response_payload=row.response_payload
            )
            if calculated != row.record_hash:
                return False, total, row.id

            expected_prev = row.record_hash
            last_id = row.id
