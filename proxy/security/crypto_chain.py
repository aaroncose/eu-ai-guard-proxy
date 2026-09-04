import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
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
    if not hashes:
        return settings.GENESIS_HASH
    current_level = hashes
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
    from proxy.models import AuditLedger
    stmt = select(AuditLedger).order_by(AuditLedger.id.asc())
    result = await session.execute(stmt)
    records = result.scalars().all()
    
    if not records:
        return True, 0, None
        
    expected_prev = settings.GENESIS_HASH
    for rec in records:
        if rec.previous_hash != expected_prev:
            return False, len(records), rec.id
            
        calculated = generate_record_hash(
            previous_hash=rec.previous_hash,
            request_id=rec.request_id,
            timestamp_iso=normalize_timestamp(rec.timestamp_utc),
            model=rec.model_requested,
            request_payload=rec.request_payload,
            response_payload=rec.response_payload
        )
        if calculated != rec.record_hash:
            return False, len(records), rec.id
            
        expected_prev = rec.record_hash
        
    return True, len(records), None