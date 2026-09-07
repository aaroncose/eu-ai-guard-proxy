import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from proxy.security.auth import verify_api_key
from proxy.security.dlp_filter import mask_sensitive_data
from proxy.services.audit_worker import audit_worker
from proxy.services.forwarder import (
    StreamOutcome,
    forward_standard_request,
    forward_streaming_request,
    list_upstream_models,
)

router = APIRouter(tags=["AI Proxy"])


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str = Header(None),
    x_app_id: str = Header(default="default-app"),
    x_user_id: str = Header(default=None)
):
    verify_api_key(authorization=authorization)

    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    request_id = f"req-{uuid.uuid4().hex}"
    timestamp = datetime.now(timezone.utc)
    is_streaming = bool(body.get("stream", False))
    model_name = body.get("model", "unknown")
    client_ip = request.client.host if request.client else None

    masked_request = mask_sensitive_data(body)

    if not is_streaming:
        result = await forward_standard_request(body)
        masked_response = mask_sensitive_data(result.payload)

        # El apunte se encola tanto en el camino correcto como en el de error.
        # Una llamada que el proveedor rechaza tambien es una interaccion que
        # el Art. 12 obliga a conservar.
        await audit_worker.enqueue_log({
            "request_id": request_id,
            "timestamp": timestamp,
            "app_id": x_app_id,
            "user_id": x_user_id,
            "ip_address": client_ip,
            "model": model_name,
            "is_streaming": False,
            "request_payload": masked_request,
            "response_payload": masked_response,
            "tools_called": result.tools_called,
            "is_blocked": result.is_blocked,
            "block_reason": result.block_reason,
            "upstream_error": result.upstream_error,
        })

        return JSONResponse(content=result.payload, status_code=result.status_code)

    async def on_stream_complete(outcome: StreamOutcome):
        reconstructed = {
            "object": "chat.completion",
            "model": model_name,
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": outcome.content,
                        "tool_calls": outcome.tool_calls or None,
                    },
                    "finish_reason": outcome.finish_reason,
                }
            ],
        }
        await audit_worker.enqueue_log({
            "request_id": request_id,
            "timestamp": timestamp,
            "app_id": x_app_id,
            "user_id": x_user_id,
            "ip_address": client_ip,
            "model": model_name,
            "is_streaming": True,
            "request_payload": masked_request,
            "response_payload": mask_sensitive_data(reconstructed),
            "tools_called": outcome.tool_calls or None,
            "is_blocked": outcome.is_blocked,
            "block_reason": outcome.block_reason,
            "upstream_error": outcome.upstream_error,
        })

    return StreamingResponse(
        forward_streaming_request(body=body, on_complete_callback=on_stream_complete),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/models")
async def list_models(authorization: str = Header(None)):
    verify_api_key(authorization=authorization)
    result = await list_upstream_models()
    return JSONResponse(content=result.payload, status_code=result.status_code)
