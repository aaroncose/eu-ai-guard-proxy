import gzip
import io
import json
from datetime import datetime, timezone, timedelta
import aioboto3
from typing import Optional
from sqlalchemy import select, update
from proxy.config import settings
from proxy.database import async_session_factory
from proxy.models import AuditLedger, DailyBatchManifest
from proxy.security.crypto_chain import compute_merkle_root, canonical_json

class S3WormArchiver:
    def __init__(self):
        self.session = aioboto3.Session(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.S3_REGION
        )

    async def archive_day_batch(self, target_date_str: str) -> Optional[DailyBatchManifest]:
        if not settings.S3_ENABLED:
            return None

        # Parsear rango del día UTC
        start_dt = datetime.strptime(target_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end_dt = start_dt + timedelta(days=1)

        async with async_session_factory() as db_session:
            stmt = select(AuditLedger).where(
                AuditLedger.timestamp_utc >= start_dt,
                AuditLedger.timestamp_utc < end_dt
            ).order_by(AuditLedger.id.asc())
            
            result = await db_session.execute(stmt)
            records = result.scalars().all()
            if not records:
                return None

            # Generar JSONL comprimido en memoria
            jsonl_buffer = io.BytesIO()
            with gzip.GzipFile(fileobj=jsonl_buffer, mode="wb") as gz:
                for rec in records:
                    line = canonical_json({
                        "id": rec.id,
                        "request_id": rec.request_id,
                        "timestamp_utc": rec.timestamp_utc.isoformat(),
                        "app_id": rec.app_id,
                        "user_id": rec.user_id,
                        "model_requested": rec.model_requested,
                        "request_payload": rec.request_payload,
                        "response_payload": rec.response_payload,
                        "tools_called": rec.tools_called,
                        "is_blocked": rec.is_blocked,
                        "block_reason": rec.block_reason,
                        "previous_hash": rec.previous_hash,
                        "record_hash": rec.record_hash
                    }) + "\n"
                    gz.write(line.encode("utf-8"))

            jsonl_bytes = jsonl_buffer.getvalue()
            merkle_root = compute_merkle_root([r.record_hash for r in records])
            object_key = f"audit_batches/{target_date_str}/ledger_{target_date_str}_{merkle_root[:16]}.jsonl.gz"

            # Calcular fecha de expiración para Object Lock WORM (180 días)
            retain_until = datetime.now(timezone.utc) + timedelta(days=settings.RETENTION_DAYS)

            # Subir a S3 con Object Lock (WORM - Compliance)
            async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL) as s3:
                await s3.put_object(
                    Bucket=settings.S3_BUCKET_NAME,
                    Key=object_key,
                    Body=jsonl_bytes,
                    ContentType="application/gzip",
                    ObjectLockMode="COMPLIANCE",
                    ObjectLockRetainUntilDate=retain_until,
                    Metadata={
                        "merkle_root": merkle_root,
                        "records_count": str(len(records)),
                        "batch_date": target_date_str
                    }
                )

            # Guardar manifiesto diario y marcar registros archivados
            manifest = DailyBatchManifest(
                batch_date=target_date_str,
                records_count=len(records),
                merkle_root_hash=merkle_root,
                s3_object_key=object_key
            )
            db_session.add(manifest)
            
            update_stmt = update(AuditLedger).where(
                AuditLedger.id.in_([r.id for r in records])
            ).values(archived_to_s3=True)
            await db_session.execute(update_stmt)
            await db_session.commit()
            return manifest

s3_archiver = S3WormArchiver()