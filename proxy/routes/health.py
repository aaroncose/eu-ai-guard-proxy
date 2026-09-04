from fastapi import APIRouter

router = APIRouter(tags=["Health"])

@router.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "eu-ai-guard-proxy"}

@router.get("/livez")
async def livez():
    return {"alive": True}