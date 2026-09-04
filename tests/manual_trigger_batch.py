import asyncio
from datetime import datetime, timezone
from proxy.storage.s3_worm_archiver import s3_archiver

async def trigger():
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    print(f"Ejecutando consolidacion de lote diario para {today_str}...")
    manifest = await s3_archiver.archive_day_batch(today_str)
    if manifest:
        print("Lote diario consolidado:")
        print(f"  - Fecha:            {manifest.batch_date}")
        print(f"  - Estado Forense:   {manifest.integrity_status}")
        if manifest.integrity_status != "VERIFIED_CLEAN":
            print(f"  - Registro Afectado: ID #{manifest.first_corrupted_id}")
        print(f"  - Total Registros:  {manifest.records_count}")
        print(f"  - Merkle Root Hash: {manifest.merkle_root_hash}")
        print(f"  - Sello eIDAS TSA:  {'Emitido' if manifest.has_eidas_tsa else 'Fallo'}")
        print(f"  - Rekor Log Index:  {manifest.rekor_log_index}")
        print(f"  - Rekor UUID:       {manifest.rekor_entry_uuid}")
    else:
        print("No habia registros para empaquetar en la fecha actual.")

if __name__ == "__main__":
    asyncio.run(trigger())