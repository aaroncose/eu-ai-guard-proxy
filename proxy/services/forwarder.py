import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx

from proxy.config import settings
from proxy.security.tool_guard import inspect_tool_calls

logger = logging.getLogger(__name__)

# Los eventos de un flujo SSE se separan por una linea en blanco, y la linea
# admite los tres finales que define la especificacion (WHATWG, server-sent
# events): CRLF, LF o CR
EVENT_SEPARATOR = re.compile(r"\r\n\r\n|\n\n|\r\r")
LINE_SEPARATOR = re.compile(r"\r\n|\n|\r")

DONE_SENTINEL = "[DONE]"


class UpstreamConfigurationError(RuntimeError):
    """El proxy carece de credencial propia para hablar con el proveedor."""


@dataclass
class UpstreamResult:
    """Desenlace de una llamada al proveedor, con lo que se responde y lo que se registra."""

    status_code: int
    payload: Dict[str, Any]
    is_blocked: bool = False
    block_reason: Optional[str] = None
    tools_called: Optional[List[Dict[str, Any]]] = None
    upstream_error: Optional[str] = None


@dataclass
class StreamOutcome:
    """Resultado de un flujo SSE, reconstruido para el ledger."""

    content: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: Optional[str] = None
    is_blocked: bool = False
    block_reason: Optional[str] = None
    upstream_error: Optional[str] = None


def _upstream_headers() -> Dict[str, str]:
    """Cabeceras hacia el proveedor, autenticadas con la credencial del proxy.

    La credencial del cliente se queda aqui. Reenviarla enviaria la clave del
    proxy al proveedor cada vez que UPSTREAM_API_KEY quedara sin configurar.
    """
    if not settings.UPSTREAM_API_KEY:
        raise UpstreamConfigurationError(
            "UPSTREAM_API_KEY sin configurar: el proxy no tiene credencial propia para el proveedor"
        )
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.UPSTREAM_API_KEY}",
    }


def _target_url(path: str) -> str:
    return f"{settings.UPSTREAM_BASE_URL.rstrip('/')}/{path.lstrip('/')}"


def _error_payload(message: str, code: str) -> Dict[str, Any]:
    """Error en el formato que ya espera un cliente de la API de chat."""
    return {"error": {"message": message, "type": "upstream_error", "code": code}}


def _blocked_completion(resp_data: Dict[str, Any], body: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "id": resp_data.get("id", "blocked"),
        "object": "chat.completion",
        "created": resp_data.get("created", int(time.time())),
        "model": resp_data.get("model", body.get("model", "unknown")),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[BLOCKED BY GOVERNANCE PROXY]: {reason}",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": resp_data.get("usage", {}),
    }


def _extract_tool_calls(resp_data: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    choices = resp_data.get("choices") or []
    if not choices:
        return None
    message = choices[0].get("message") or {}
    return message.get("tool_calls")


async def forward_standard_request(body: Dict[str, Any]) -> UpstreamResult:
    """Reenvia la peticion al proveedor y devuelve el desenlace completo.

    Devuelve un resultado en todos los casos, incluidos los de error, para que
    la ruta pueda dejar constancia de la interaccion antes de responder.
    """
    try:
        headers = _upstream_headers()
    except UpstreamConfigurationError as exc:
        logger.error("Configuracion del upstream incompleta: %s", exc)
        return UpstreamResult(
            status_code=500,
            payload=_error_payload(
                "Proxy misconfigured: upstream credential missing", "upstream_credential_missing"
            ),
            upstream_error=str(exc),
        )

    try:
        async with httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT) as client:
            resp = await client.post(_target_url("chat/completions"), json=body, headers=headers)
    except httpx.RequestError as exc:
        logger.warning("Fallo de comunicacion con el proveedor: %s", exc)
        return UpstreamResult(
            status_code=502,
            payload=_error_payload("Upstream communication error", "upstream_unreachable"),
            upstream_error=str(exc),
        )

    if resp.status_code != 200:
        # El cuerpo crudo del proveedor puede describir su infraestructura, asi
        # que se queda en el ledger y en el log
        detail = resp.text[:2000]
        logger.warning("El proveedor respondio %s: %s", resp.status_code, detail)
        return UpstreamResult(
            status_code=resp.status_code,
            payload=_error_payload(
                f"Upstream provider returned HTTP {resp.status_code}",
                f"upstream_status_{resp.status_code}",
            ),
            upstream_error=detail,
        )

    try:
        resp_data = resp.json()
    except ValueError as exc:
        logger.warning("El proveedor devolvio un cuerpo que no es JSON: %s", exc)
        return UpstreamResult(
            status_code=502,
            payload=_error_payload("Upstream returned a malformed body", "upstream_malformed_body"),
            upstream_error=resp.text[:2000],
        )

    tool_calls = _extract_tool_calls(resp_data)
    is_safe, block_reason = inspect_tool_calls(tool_calls)
    if not is_safe:
        return UpstreamResult(
            status_code=403,
            payload=_blocked_completion(resp_data, body, block_reason),
            is_blocked=True,
            block_reason=block_reason,
            tools_called=tool_calls,
        )

    return UpstreamResult(status_code=200, payload=resp_data, tools_called=tool_calls)


async def list_upstream_models() -> UpstreamResult:
    """Devuelve el catalogo de modelos del proveedor, sin inventar entradas."""
    try:
        headers = _upstream_headers()
    except UpstreamConfigurationError as exc:
        return UpstreamResult(
            status_code=500,
            payload=_error_payload(
                "Proxy misconfigured: upstream credential missing", "upstream_credential_missing"
            ),
            upstream_error=str(exc),
        )

    try:
        async with httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT) as client:
            resp = await client.get(_target_url("models"), headers=headers)
    except httpx.RequestError as exc:
        return UpstreamResult(
            status_code=502,
            payload=_error_payload("Upstream communication error", "upstream_unreachable"),
            upstream_error=str(exc),
        )

    if resp.status_code != 200:
        return UpstreamResult(
            status_code=resp.status_code,
            payload=_error_payload(
                f"Upstream provider returned HTTP {resp.status_code}",
                f"upstream_status_{resp.status_code}",
            ),
            upstream_error=resp.text[:2000],
        )

    try:
        return UpstreamResult(status_code=200, payload=resp.json())
    except ValueError as exc:
        return UpstreamResult(
            status_code=502,
            payload=_error_payload("Upstream returned a malformed body", "upstream_malformed_body"),
            upstream_error=str(exc),
        )


def _split_events(buffer: str) -> tuple:
    """Parte el buffer en eventos completos y devuelve el resto sin terminar."""
    parts = EVENT_SEPARATOR.split(buffer)
    return parts[:-1], parts[-1]


def _data_payloads(event: str) -> List[Dict[str, Any]]:
    """Devuelve los objetos JSON que transporta un evento SSE.

    Las lineas de campo `data` de un mismo evento se concatenan con un salto
    de linea, y una linea que empieza por dos puntos es un comentario.
    """
    data_lines = []
    for line in LINE_SEPARATOR.split(event):
        if not line or line.startswith(":"):
            continue
        field_name, _, value = line.partition(":")
        if field_name != "data":
            continue
        data_lines.append(value[1:] if value.startswith(" ") else value)

    if not data_lines:
        return []

    raw = "\n".join(data_lines)
    if raw.strip() == DONE_SENTINEL:
        return []

    try:
        payload = json.loads(raw)
    except ValueError:
        return []
    return [payload] if isinstance(payload, dict) else []


def _accumulate(payload: Dict[str, Any], outcome: StreamOutcome, tool_calls: Dict[int, Dict[str, Any]]) -> None:
    """Acumula contenido y llamadas a herramientas de un chunk de streaming.

    Los argumentos de cada herramienta llegan troceados entre chunks y se
    reconstruyen concatenando por el campo `index`, que el esquema de la API
    marca como obligatorio en cada fragmento.
    """
    for choice in payload.get("choices") or []:
        if choice.get("finish_reason"):
            outcome.finish_reason = choice["finish_reason"]

        delta = choice.get("delta") or {}
        content = delta.get("content")
        if content:
            outcome.content += content

        for call in delta.get("tool_calls") or []:
            index = call.get("index")
            if index is None:
                continue
            entry = tool_calls.setdefault(
                index, {"id": None, "type": None, "function": {"name": None, "arguments": ""}}
            )
            if call.get("id"):
                entry["id"] = call["id"]
            if call.get("type"):
                entry["type"] = call["type"]
            function_delta = call.get("function") or {}
            if function_delta.get("name"):
                entry["function"]["name"] = function_delta["name"]
            if function_delta.get("arguments"):
                entry["function"]["arguments"] += function_delta["arguments"]


def _materialize(tool_calls: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [tool_calls[index] for index in sorted(tool_calls)]


def _sse(payload: Dict[str, Any]) -> bytes:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _block_chunk(body: Dict[str, Any], reason: str) -> bytes:
    return _sse(
        {
            "id": "blocked",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": body.get("model", "unknown"),
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": f"[BLOCKED BY GOVERNANCE PROXY]: {reason}"},
                    "finish_reason": "stop",
                }
            ],
        }
    )


def _done() -> bytes:
    return f"data: {DONE_SENTINEL}\n\n".encode("utf-8")


async def forward_streaming_request(
    body: Dict[str, Any],
    on_complete_callback,
) -> AsyncGenerator[bytes, None]:
    """Reenvia el flujo SSE del proveedor mientras vigila las herramientas.

    Cada chunk se inspecciona antes de reenviarlo, asi que los bytes del
    proveedor llegan intactos al cliente mientras la respuesta sea limpia. Un
    flujo sin vigilar deja pasar cualquier orden destructiva con solo pedir
    `stream: true`.

    Al detectar una orden destructiva, el chunk que la completa se descarta y
    el flujo termina con un aviso de bloqueo, antes del finish_reason
    `tool_calls` que dispara la ejecucion en el cliente. Los fragmentos de
    texto entregados en chunks anteriores quedan en poder del cliente.

    El apunte de auditoria se emite en el `finally`, de modo que un corte del
    cliente o un fallo del proveedor tambien queda registrado.
    """
    outcome = StreamOutcome()
    tool_calls: Dict[int, Dict[str, Any]] = {}

    try:
        try:
            headers = _upstream_headers()
        except UpstreamConfigurationError as exc:
            outcome.upstream_error = str(exc)
            logger.error("Configuracion del upstream incompleta: %s", exc)
            yield _sse(
                _error_payload(
                    "Proxy misconfigured: upstream credential missing", "upstream_credential_missing"
                )
            )
            yield _done()
            return

        try:
            async with httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT) as client:
                async with client.stream(
                    "POST", _target_url("chat/completions"), json=body, headers=headers
                ) as response:
                    if response.status_code != 200:
                        raw = await response.aread()
                        outcome.upstream_error = raw.decode("utf-8", errors="replace")[:2000]
                        logger.warning(
                            "El proveedor respondio %s al flujo: %s",
                            response.status_code,
                            outcome.upstream_error,
                        )
                        yield _sse(
                            _error_payload(
                                f"Upstream provider returned HTTP {response.status_code}",
                                f"upstream_status_{response.status_code}",
                            )
                        )
                        yield _done()
                        return

                    buffer = ""
                    async for raw_chunk in response.aiter_bytes():
                        # El chunk se contabiliza antes de reenviarlo. Al reves,
                        # un corte del cliente justo despues del envio dejaria
                        # en el ledger una respuesta vacia que el usuario si
                        # llego a leer
                        buffer += raw_chunk.decode("utf-8", errors="replace")
                        events, buffer = _split_events(buffer)
                        for event in events:
                            for payload in _data_payloads(event):
                                _accumulate(payload, outcome, tool_calls)

                        if tool_calls:
                            is_safe, reason = inspect_tool_calls(_materialize(tool_calls))
                            if not is_safe:
                                outcome.is_blocked = True
                                outcome.block_reason = reason
                                # El chunk que completa la orden se queda sin
                                # reenviar
                                yield _block_chunk(body, reason)
                                yield _done()
                                return

                        yield raw_chunk
        except httpx.RequestError as exc:
            outcome.upstream_error = str(exc)
            logger.warning("Fallo de comunicacion con el proveedor durante el flujo: %s", exc)
            yield _sse(_error_payload("Upstream communication error", "upstream_unreachable"))
            yield _done()
            return

        # Un ultimo repaso sobre los argumentos ya completos
        if tool_calls and not outcome.is_blocked:
            is_safe, reason = inspect_tool_calls(_materialize(tool_calls))
            if not is_safe:
                outcome.is_blocked = True
                outcome.block_reason = reason
                yield _block_chunk(body, reason)
                yield _done()
    finally:
        outcome.tool_calls = _materialize(tool_calls)
        try:
            await on_complete_callback(outcome)
        except Exception:
            logger.exception("Fallo al registrar el desenlace del flujo")
