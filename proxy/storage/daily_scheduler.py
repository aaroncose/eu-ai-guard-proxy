import logging
from datetime import datetime, timezone, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from proxy.storage.s3_worm_archiver import s3_archiver

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="UTC")

JOB_ID = "daily_archival"
# Segundos tras la hora prevista en que el trabajo todavia puede ejecutarse.
# Con el valor por defecto de APScheduler (1 segundo) un arranque tardio
# descarta la ejecucion del dia
MISFIRE_GRACE_SECONDS = 3600


async def run_daily_archival_job():
    """Se ejecuta cada medianoche para archivar el lote del día anterior."""
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    await s3_archiver.archive_day_batch(yesterday)


async def run_startup_backfill():
    """Sella al arrancar los lotes que quedaron pendientes."""
    processed = await s3_archiver.archive_pending_batches()
    if processed:
        logger.info("Lotes recuperados en el arranque: %s", ", ".join(processed))
    return processed


def start_scheduler():
    scheduler.add_job(
        run_daily_archival_job,
        "cron",
        hour=0,
        minute=5,
        id=JOB_ID,
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=MISFIRE_GRACE_SECONDS,
    )
    scheduler.start()


def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
