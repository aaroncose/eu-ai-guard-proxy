import json
import httpx
from typing import AsyncGenerator, Dict, Any, Tuple, Optional
from fastapi import HTTPException
from proxy.config import settings
from proxy.security.tool_guard import inspect_tool_calls
from proxy.security.dlp_filter import mask_sensitive_data

async def forward_standard_request(
    body: Dict[str, Any],
    headers: Dict[str, str]
) -> Tuple[Dict[str, Any], bool, Optional[str]]:
    target_url = f"{settings.UPSTREAM_BASE_URL.rstrip('/')}/chat/completions"
    
    auth_header = f"Bearer {settings.UPSTREAM_API_KEY}" if settings.UPSTREAM_API_KEY else headers.get("Authorization", "")
    forward_headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(target_url, json=body, headers=forward_headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            resp_data = resp.json()
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Upstream communication error: {str(exc)}")

    # Inspección de seguridad en herramientas
    tool_calls = None
    if "choices" in resp_data and len(resp_data["choices"]) > 0:
        message = resp_data["choices"][0].get("message", {})
        tool_calls = message.get("tool_calls")

    is_safe, block_reason = inspect_tool_calls(tool_calls)
    if not is_safe:
        blocked_response = {
            "id": resp_data.get("id", "blocked"),
            "object": "chat.completion",
            "created": resp_data.get("created", 0),
            "model": resp_data.get("model", body.get("model", "unknown")),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[BLOCKED BY GOVERNANCE PROXY]: {block_reason}"
                },
                "finish_reason": "stop"
            }],
            "usage": resp_data.get("usage", {})
        }
        return blocked_response, True, block_reason

    return resp_data, False, None

async def forward_streaming_request(
    body: Dict[str, Any],
    headers: Dict[str, str],
    on_complete_callback
) -> AsyncGenerator[bytes, None]:
    target_url = f"{settings.UPSTREAM_BASE_URL.rstrip('/')}/chat/completions"
    auth_header = f"Bearer {settings.UPSTREAM_API_KEY}" if settings.UPSTREAM_API_KEY else headers.get("Authorization", "")
    forward_headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header
    }

    accumulated_content = []
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        async with client.stream("POST", target_url, json=body, headers=forward_headers) as response:
            if response.status_code != 200:
                error_body = await response.aread()
                yield f"data: {json.dumps({'error': error_body.decode()})}\n\n".encode("utf-8")
                return

            async for line in response.aiter_lines():
                if not line:
                    continue
                yield f"{line}\n\n".encode("utf-8")
                
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        chunk = json.loads(line[6:])
                        choices = chunk.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content")
                            if content:
                                accumulated_content.append(content)
                    except Exception:
                        pass

    # Al finalizar el stream, reconstruir y encolar en background
    full_text = "".join(accumulated_content)
    reconstructed_response = {
        "object": "chat.completion",
        "model": body.get("model", "unknown"),
        "choices": [{
            "message": {"role": "assistant", "content": full_text},
            "finish_reason": "stop"
        }]
    }
    await on_complete_callback(reconstructed_response)