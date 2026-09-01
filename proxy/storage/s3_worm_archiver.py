import gzip
import io
import json
from datetime import datetime, timezone, timedelta
from typing import Optional
import aioboto3
from sqlalchemy import select, update
from proxy.config import settings
from proxy.database import async_session_factory
from proxy.models import AuditLedger, DailyBatchManifest
from proxy.security.crypto_chain import compute_merkle_root, canonical_json
from proxy.security.eidas_tsp import request_eidas_timestamp
from proxy.security.asymmetric_signer import sign_manifest_payload
from proxy.security.rekor_transparency import publish_to_rekor

class S3WormArchiver:
    def __init__(self):
        self.session = aioboto3.Session(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.S3_REGION
        )

    async def archive_day_batch(self, target_date_str: str) -> Optional[DailyBatchManifest]:
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

            # 1. Comprimir JSONL canónico
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

            # 2. Firma ECDSA P-256
            manifest_bytes = canonical_json({
                "batch_date": target_date_str,
                "records_count": len(records),
                "merkle_root": merkle_root
            }).encode("utf-8")
            signature_bytes = sign_manifest_payload(manifest_bytes)
            signature_hex = signature_bytes.hex()

            # 3. Sello de Tiempo Cualificado eIDAS (RFC 3161)
            tsa_ok, tsr_bytes, _ = await request_eidas_timestamp(merkle_root)

            # 4. Anclaje en Sigstore Rekor
            rekor_ok, rekor_data, _ = await publish_to_rekor(merkle_root, signature_bytes)
            rekor_uuid = None
            rekor_index = None
            if rekor_ok and rekor_data:
                rekor_uuid = list(rekor_data.keys())[0]
                rekor_index = rekor_data[rekor_uuid].get("logIndex")

            object_key = f"audit_batches/{target_date_str}/ledger_{target_date_str}_{merkle_root[:16]}.jsonl.gz"

            # 5. Volcado WORM a S3 (si está activo)
            if settings.S3_ENABLED:
                retain_until = datetime.now(timezone.utc) + timedelta(days=settings.RETENTION_DAYS)
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
                            "ecdsa_signature": signature_hex,
                            "rekor_uuid": rekor_uuid or ""
                        }
                    )

            # 6. Registrar Manifiesto en Base de Datos
            manifest = DailyBatchManifest(
                batch_date=target_date_str,
                records_count=len(records),
                merkle_root_hash=merkle_root,
                s3_object_key=object_key,
                has_eidas_tsa=tsa_ok,
                eidas_tsr_path=f"tsa_{target_date_str}.tsr" if tsa_ok else None,
                ecdsa_signature_hex=signature_hex,
                rekor_log_index=rekor_index,
                rekor_entry_uuid=rekor_uuid
            )
            db_session.add(manifest)

            update_stmt = update(AuditLedger).where(
                AuditLedger.id.in_([r.id for r in records])
            ).values(archived_to_s3=True)
            await db_session.execute(update_stmt)
            await db_session.commit()
            return manifest

s3_archiver = S3WormArchiver()