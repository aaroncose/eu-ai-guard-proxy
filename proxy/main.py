from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from proxy.database import init_db
from proxy.services.audit_worker import audit_worker
from proxy.storage.daily_scheduler import start_scheduler, shutdown_scheduler
from proxy.routes import proxy_routes, audit_routes, health

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicialización
    await init_db()
    await audit_worker.start()
    start_scheduler()
    yield
    # Apagado limpio
    shutdown_scheduler()
    await audit_worker.stop()

app = FastAPI(
    title="EU AI Act Art. 12 Audit & Governance Gateway",
    version="1.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(proxy_routes.router, prefix="/v1")
app.include_router(audit_routes.router, prefix="/api/v1/audit")