from fastapi import APIRouter

from proxy.services.audit_worker import audit_worker

router = APIRouter(tags=["Health"])

@router.get("/healthz")
async def healthz():
    """Estado del servicio con el pulso de la cola de auditoria.

    `audit_failed` distinto de cero senala apuntes que la base rechazo y que
    esperan en data/failed_audit.
    """
    return {
        "status": "ok",
        "service": "eu-ai-guard-proxy",
        "audit_pending": audit_worker.pending,
        "audit_failed": audit_worker.failed_count,
    }

@router.get("/livez")
async def livez():
    return {"alive": True}
