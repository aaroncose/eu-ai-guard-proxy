import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from proxy.config import settings
from proxy.database import init_db
from proxy.routes import proxy_routes, audit_routes, health
from proxy.services.audit_worker import audit_worker
from proxy.storage.daily_scheduler import run_startup_backfill, shutdown_scheduler, start_scheduler

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

_backfill_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _backfill_task
    # Inicialización
    await init_db()
    await audit_worker.start()
    start_scheduler()
    # La recuperacion de lotes pendientes corre aparte para no retrasar el
    # arranque del servicio
    _backfill_task = asyncio.create_task(run_startup_backfill())
    yield
    # Apagado limpio
    shutdown_scheduler()
    if _backfill_task is not None and not _backfill_task.done():
        _backfill_task.cancel()
        try:
            await _backfill_task
        except asyncio.CancelledError:
            pass
    await audit_worker.stop()

app = FastAPI(
    title="EU AI Act Art. 12 Audit & Governance Gateway",
    version="1.1.0",
    lifespan=lifespan
)

# Sin origenes declarados no se monta CORS. Starlette, ante allow_origins=["*"]
# junto con allow_credentials=True, refleja el origen de quien pregunte y
# autoriza el envio de credenciales desde cualquier web
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
else:
    logger.info("CORS deshabilitado: CORS_ALLOW_ORIGINS esta vacio")

app.include_router(health.router)
app.include_router(proxy_routes.router, prefix="/v1")
app.include_router(audit_routes.router, prefix="/api/v1/audit")
