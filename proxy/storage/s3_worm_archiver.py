import gzip
import io
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

import aioboto3
from sqlalchemy import select, update

from proxy.config import BASE_DIR, settings
from proxy.database import async_session_factory
from proxy.models import AuditLedger, DailyBatchManifest
from proxy.security.crypto_chain import compute_merkle_root, canonical_json, verify_ledger_integrity
from proxy.security.eidas_tsp import request_eidas_timestamp
from proxy.security.asymmetric_signer import sign_manifest_payload, sign_digest_directly
from proxy.security.rekor_transparency import publish_to_rekor

logger = logging.getLogger(__name__)

# Destino del token de sello de tiempo cuando el bucket WORM esta apagado
LOCAL_TSR_DIR = BASE_DIR / "data" / "timestamps"


class S3WormArchiver:
    def __init__(self):
        self.session = aioboto3.Session(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.S3_REGION
        )

    async def _persist_tsr(self, object_key: str, tsr_bytes: bytes) -> str:
        """Guarda el token de sello de tiempo y devuelve su ubicacion.

        El token es lo unico que acredita la fecha ante un tercero. Sin el, el
        manifiesto solo conserva un booleano que nadie puede comprobar.
        """
        if settings.S3_ENABLED:
            retain_until = datetime.now(timezone.utc) + timedelta(days=settings.RETENTION_DAYS)
            async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL) as s3:
                await s3.put_object(
                    Bucket=settings.S3_BUCKET_NAME,
                    Key=object_key,
                    Body=tsr_bytes,
                    ContentType="application/timestamp-reply",
                    ObjectLockMode="COMPLIANCE",
                    ObjectLockRetainUntilDate=retain_until,
                )
            return f"s3://{settings.S3_BUCKET_NAME}/{object_key}"

        LOCAL_TSR_DIR.mkdir(parents=True, exist_ok=True)
        local_path = LOCAL_TSR_DIR / Path(object_key).name
        local_path.write_bytes(tsr_bytes)
        return str(local_path)

    async def archive_day_batch(self, target_date_str: str) -> Optional[DailyBatchManifest]:
        start_dt = datetime.strptime(target_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end_dt = start_dt + timedelta(days=1)

        async with async_session_factory() as db_session:
            # 0. Un dia ya sellado se deja como esta. La fecha del lote es
            # unica, asi que repetir el archivado reventaria la insercion
            existing = (
                await db_session.execute(
                    select(DailyBatchManifest).where(DailyBatchManifest.batch_date == target_date_str)
                )
            ).scalar_one_or_none()
            if existing:
                logger.info("El lote %s ya estaba sellado", target_date_str)
                return existing

            # 1. Comprobacion de integridad pre-sellado
            is_valid, _, broken_id = await verify_ledger_integrity(db_session)
            integrity_status = "VERIFIED_CLEAN" if is_valid else "TAMPER_DETECTED"

            stmt = select(AuditLedger).where(
                AuditLedger.timestamp_utc >= start_dt,
                AuditLedger.timestamp_utc < end_dt
            ).order_by(AuditLedger.id.asc())
            
            result = await db_session.execute(stmt)
            records = result.scalars().all()
            if not records:
                return None

            # 2. Generacion del volcado comprimido
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
                        "upstream_error": rec.upstream_error,
                        "previous_hash": rec.previous_hash,
                        "record_hash": rec.record_hash
                    }) + "\n"
                    gz.write(line.encode("utf-8"))

            jsonl_bytes = jsonl_buffer.getvalue()
            merkle_root = compute_merkle_root([r.record_hash for r in records])

            # 3. Firma del Manifiesto Forense
            manifest_payload = {
                "batch_date": target_date_str,
                "records_count": len(records),
                "merkle_root": merkle_root,
                "integrity_status": integrity_status,
                "first_corrupted_id": broken_id
            }
            manifest_bytes = canonical_json(manifest_payload).encode("utf-8")
            signature_bytes = sign_manifest_payload(manifest_bytes)
            signature_hex = signature_bytes.hex()

            # 4. Sello de Tiempo Cualificado eIDAS (RFC 3161)
            tsa_ok, tsr_bytes, tsa_error = await request_eidas_timestamp(merkle_root)
            if not tsa_ok:
                logger.warning("El lote %s se queda sin sello de tiempo: %s", target_date_str, tsa_error)

            # 5. Anclaje en Sigstore Rekor
            rekor_sig = sign_digest_directly(bytes.fromhex(merkle_root))
            rekor_ok, rekor_data, rekor_error = await publish_to_rekor(merkle_root, rekor_sig)
            if not rekor_ok:
                logger.warning("El lote %s no llego a Rekor: %s", target_date_str, rekor_error)
            
            rekor_uuid = None
            rekor_index = None
            if rekor_ok and rekor_data:
                rekor_uuid = list(rekor_data.keys())[0]
                rekor_index = rekor_data[rekor_uuid].get("logIndex")

            object_key = f"audit_batches/{target_date_str}/ledger_{target_date_str}_{merkle_root[:16]}.jsonl.gz"

            tsr_location = None
            if tsa_ok and tsr_bytes:
                tsr_location = await self._persist_tsr(
                    object_key.replace(".jsonl.gz", ".tsr"), tsr_bytes
                )

            # 6. Almacenamiento WORM S3
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
                            "integrity_status": integrity_status,
                            "ecdsa_signature": signature_hex,
                            "rekor_uuid": rekor_uuid or ""
                        }
                    )

            # 7. Persistencia del Lote en Base de Datos
            manifest = DailyBatchManifest(
                batch_date=target_date_str,
                records_count=len(records),
                merkle_root_hash=merkle_root,
                s3_object_key=object_key,
                integrity_status=integrity_status,
                first_corrupted_id=broken_id,
                has_eidas_tsa=tsa_ok and tsr_location is not None,
                eidas_tsr_path=tsr_location,
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

    async def pending_batch_dates(self) -> List[str]:
        """Dias cerrados que conservan registros sin archivar.

        El planificador vive en memoria, asi que una parada del servicio a
        medianoche deja ese lote sin sellar hasta que alguien lo reclame.
        """
        now = datetime.now(timezone.utc)
        today_start = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)
        window_start = today_start - timedelta(days=max(1, settings.ARCHIVE_BACKFILL_DAYS))

        async with async_session_factory() as db_session:
            stmt = (
                select(AuditLedger.timestamp_utc)
                .where(
                    AuditLedger.archived_to_s3.is_(False),
                    AuditLedger.timestamp_utc >= window_start,
                    AuditLedger.timestamp_utc < today_start,
                )
                .order_by(AuditLedger.timestamp_utc.asc())
            )
            stamps = (await db_session.execute(stmt)).scalars().all()

        return sorted({stamp.astimezone(timezone.utc).strftime("%Y-%m-%d") for stamp in stamps})

    async def archive_pending_batches(self) -> List[str]:
        """Sella los lotes pendientes y devuelve las fechas procesadas."""
        processed = []
        for batch_date in await self.pending_batch_dates():
            try:
                manifest = await self.archive_day_batch(batch_date)
            except Exception:
                logger.exception("Fallo al recuperar el lote %s", batch_date)
                continue
            if manifest is not None:
                processed.append(batch_date)
        return processed


s3_archiver = S3WormArchiver()
