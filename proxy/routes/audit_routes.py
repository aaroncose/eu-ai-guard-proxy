import hashlib
import logging
import tempfile
import zipfile
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from proxy.config import settings
from proxy.database import get_db_session
from proxy.models import AuditLedger, AuditVerificationResponse
from proxy.security.asymmetric_signer import get_public_key_pem, sign_manifest_payload
from proxy.security.auth import verify_api_key
from proxy.security.crypto_chain import canonical_json, verify_ledger_integrity

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Audit & Compliance"])

# Por encima de este tamano el paquete pasa de memoria a un fichero temporal
SPOOL_MAX_BYTES = 32 * 1024 * 1024
READ_CHUNK = 64 * 1024


@router.get("/verify", response_model=AuditVerificationResponse)
async def verify_chain(
    session: AsyncSession = Depends(get_db_session),
    _: str = Depends(verify_api_key)
):
    is_valid, total_records, broken_id = await verify_ledger_integrity(session)
    return AuditVerificationResponse(
        is_valid=is_valid,
        total_records=total_records,
        first_corrupted_id=broken_id,
        verification_timestamp=datetime.now(timezone.utc)
    )


# Columnas del dossier, en el orden en que se serializan
EXPORT_COLUMNS = (
    AuditLedger.id,
    AuditLedger.request_id,
    AuditLedger.timestamp_utc,
    AuditLedger.app_id,
    AuditLedger.user_id,
    AuditLedger.model_requested,
    AuditLedger.request_payload,
    AuditLedger.response_payload,
    AuditLedger.tools_called,
    AuditLedger.is_blocked,
    AuditLedger.block_reason,
    AuditLedger.upstream_error,
    AuditLedger.previous_hash,
    AuditLedger.record_hash,
)


def _record_line(row) -> bytes:
    payload = canonical_json({
        "id": row.id,
        "request_id": row.request_id,
        "timestamp_utc": row.timestamp_utc.isoformat(),
        "app_id": row.app_id,
        "user_id": row.user_id,
        "model_requested": row.model_requested,
        "request_payload": row.request_payload,
        "response_payload": row.response_payload,
        "tools_called": row.tools_called,
        "is_blocked": row.is_blocked,
        "block_reason": row.block_reason,
        "upstream_error": row.upstream_error,
        "previous_hash": row.previous_hash,
        "record_hash": row.record_hash
    })
    return payload.encode("utf-8")


def _stream_file(handle):
    try:
        while True:
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                return
            yield chunk
    finally:
        handle.close()


@router.get("/export")
async def export_audit_dossier(
    app_id: Optional[str] = Query(default=None),
    date_from: Optional[date] = Query(default=None, description="Primer dia incluido, en UTC"),
    date_to: Optional[date] = Query(default=None, description="Ultimo dia incluido, en UTC"),
    limit: Optional[int] = Query(default=None, ge=1),
    session: AsyncSession = Depends(get_db_session),
    _: str = Depends(verify_api_key)
):
    """Genera el dossier firmado del periodo solicitado.

    El recorrido va por paginas y el paquete se arma sobre un fichero temporal,
    de modo que el tamano del ledger deja de marcar el consumo de memoria.
    """
    max_records = limit or settings.AUDIT_EXPORT_MAX_RECORDS
    max_records = min(max_records, settings.AUDIT_EXPORT_MAX_RECORDS)
    page_size = max(1, settings.AUDIT_PAGE_SIZE)

    filters = []
    if app_id:
        filters.append(AuditLedger.app_id == app_id)
    if date_from:
        filters.append(
            AuditLedger.timestamp_utc >= datetime.combine(date_from, time.min, tzinfo=timezone.utc)
        )
    if date_to:
        filters.append(
            AuditLedger.timestamp_utc
            < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc)
        )

    is_valid, _total, _broken = await verify_ledger_integrity(session)

    digest = hashlib.sha256()
    exported = 0
    truncated = False
    last_id = 0

    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX_BYTES)
    with zipfile.ZipFile(spool, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("audit_ledger.jsonl", "w") as ledger_entry:
            while exported < max_records:
                remaining = max_records - exported
                stmt = (
                    select(*EXPORT_COLUMNS)
                    .where(AuditLedger.id > last_id, *filters)
                    .order_by(AuditLedger.id.asc())
                    .limit(min(page_size, remaining + 1))
                )
                rows = (await session.execute(stmt)).all()
                if not rows:
                    break

                for row in rows:
                    if exported >= max_records:
                        truncated = True
                        break
                    line = _record_line(row) + b"\n"
                    ledger_entry.write(line)
                    digest.update(line)
                    exported += 1
                    last_id = row.id

                if truncated:
                    break

        manifest_data = {
            "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_records_exported": exported,
            "records_truncated": truncated,
            "filter_app_id": app_id,
            "filter_date_from": date_from.isoformat() if date_from else None,
            "filter_date_to": date_to.isoformat() if date_to else None,
            "chain_integrity_verified": is_valid,
            "ledger_sha256": digest.hexdigest(),
            "signature_algorithm": "ECDSA_SECP256R1_SHA256",
            "compliance_standard": "EU AI Act - Article 12, 19 & 26(6)"
        }
        manifest_bytes = canonical_json(manifest_data).encode("utf-8")
        signature_bytes = sign_manifest_payload(manifest_bytes)

        archive.writestr("audit_manifest.json", manifest_bytes)
        archive.writestr("manifest_signature.sig", signature_bytes)
        archive.writestr("public_key.pem", get_public_key_pem().encode("utf-8"))
        archive.writestr("signature.sha256", f"{digest.hexdigest()}  audit_ledger.jsonl\n")

    spool.seek(0)
    filename = f"EU_AI_Act_Audit_Dossier_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.zip"

    return StreamingResponse(
        _stream_file(spool),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
