import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Header, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from proxy.config import settings
from proxy.security.dlp_filter import mask_sensitive_data
from proxy.services.forwarder import forward_standard_request, forward_streaming_request
from proxy.services.audit_worker import audit_worker

router = APIRouter(tags=["AI Proxy"])

@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str = Header(None),
    x_app_id: str = Header(default="default-app"),
    x_user_id: str = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    body = await request.json()
    request_id = f"req-{uuid.uuid4().hex}"
    timestamp = datetime.now(timezone.utc)
    is_streaming = body.get("stream", False)
    model_name = body.get("model", "unknown")

    masked_request = mask_sensitive_data(body)

    if not is_streaming:
        response_data, is_blocked, block_reason = await forward_standard_request(
            body=body,
            headers={"Authorization": authorization}
        )
        masked_response = mask_sensitive_data(response_data)

        # Encolar en auditoría
        await audit_worker.enqueue_log({
            "request_id": request_id,
            "timestamp": timestamp,
            "app_id": x_app_id,
            "user_id": x_user_id,
            "ip_address": request.client.host if request.client else None,
            "model": model_name,
            "is_streaming": False,
            "request_payload": masked_request,
            "response_payload": masked_response,
            "tools_called": response_data.get("choices", [{}])[0].get("message", {}).get("tool_calls"),
            "is_blocked": is_blocked,
            "block_reason": block_reason
        })

        status_code = 403 if is_blocked else 200
        return JSONResponse(content=response_data, status_code=status_code)

    # Flujo de Streaming SSE
    async def on_stream_complete(reconstructed_resp: dict):
        masked_resp = mask_sensitive_data(reconstructed_resp)
        await audit_worker.enqueue_log({
            "request_id": request_id,
            "timestamp": timestamp,
            "app_id": x_app_id,
            "user_id": x_user_id,
            "ip_address": request.client.host if request.client else None,
            "model": model_name,
            "is_streaming": True,
            "request_payload": masked_request,
            "response_payload": masked_resp,
            "tools_called": None,
            "is_blocked": False,
            "block_reason": None
        })

    return StreamingResponse(
        forward_streaming_request(
            body=body,
            headers={"Authorization": authorization},
            on_complete_callback=on_stream_complete
        ),
        media_type="text/event-stream"
    )

@router.get("/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
            {"id": "claude-3-5-sonnet", "object": "model", "owned_by": "anthropic"}
        ]
    }