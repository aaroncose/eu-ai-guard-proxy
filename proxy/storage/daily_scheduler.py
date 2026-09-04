from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime, timezone, timedelta
from proxy.storage.s3_worm_archiver import s3_archiver

scheduler = AsyncIOScheduler(timezone="UTC")

async def run_daily_archival_job():
    """Se ejecuta cada medianoche para archivar el lote del día anterior."""
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    await s3_archiver.archive_day_batch(yesterday)

def start_scheduler():
    scheduler.add_job(run_daily_archival_job, "cron", hour=0, minute=5)
    scheduler.start()

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)