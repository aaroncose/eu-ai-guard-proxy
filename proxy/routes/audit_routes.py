import io
import zipfile
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from proxy.database import get_db_session
from proxy.models import AuditLedger, AuditVerificationResponse
from proxy.security.crypto_chain import verify_ledger_integrity, canonical_json

router = APIRouter(tags=["Audit & Compliance"])

@router.get("/verify", response_model=AuditVerificationResponse)
async def verify_chain(session: AsyncSession = Depends(get_db_session)):
    is_valid, total_records, broken_id = await verify_ledger_integrity(session)
    return AuditVerificationResponse(
        is_valid=is_valid,
        total_records=total_records,
        first_corrupted_id=broken_id,
        verification_timestamp=datetime.now(timezone.utc)
    )

@router.get("/export")
async def export_audit_dossier(
    app_id: str = Query(default=None),
    session: AsyncSession = Depends(get_db_session)
):
    stmt = select(AuditLedger).order_by(AuditLedger.id.asc())
    if app_id:
        stmt = stmt.where(AuditLedger.app_id == app_id)
        
    result = await session.execute(stmt)
    records = result.scalars().all()

    # 1. Generar ledger.jsonl
    jsonl_lines = []
    for r in records:
        line = canonical_json({
            "id": r.id,
            "request_id": r.request_id,
            "timestamp_utc": r.timestamp_utc.isoformat(),
            "app_id": r.app_id,
            "user_id": r.user_id,
            "model_requested": r.model_requested,
            "request_payload": r.request_payload,
            "response_payload": r.response_payload,
            "tools_called": r.tools_called,
            "is_blocked": r.is_blocked,
            "previous_hash": r.previous_hash,
            "record_hash": r.record_hash
        })
        jsonl_lines.append(line)
    
    jsonl_content = "\n".join(jsonl_lines).encode("utf-8")
    jsonl_sha256 = hashlib.sha256(jsonl_content).hexdigest()

    is_valid, total, _ = await verify_ledger_integrity(session)

    # 2. Generar manifest.json
    manifest_data = {
        "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_records_exported": len(records),
        "chain_integrity_verified": is_valid,
        "ledger_sha256": jsonl_sha256,
        "compliance_standard": "EU AI Act - Article 12, 19 & 26(6)"
    }
    manifest_content = canonical_json(manifest_data).encode("utf-8")

    # 3. Empaquetar ZIP en memoria
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("audit_ledger.jsonl", jsonl_content)
        zf.writestr("audit_manifest.json", manifest_content)
        zf.writestr("signature.sha256", f"{jsonl_sha256}  audit_ledger.jsonl\n")

    zip_bytes = zip_buffer.getvalue()
    filename = f"EU_AI_Act_Audit_Dossier_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.zip"

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )