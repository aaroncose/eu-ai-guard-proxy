import json
import types

import httpx
import pytest

from proxy.config import settings
from proxy.services import forwarder


def sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode("utf-8")


DONE = b"data: [DONE]\n\n"


def install_transport(monkeypatch, handler):
    """Sustituye el cliente HTTP del forwarder por uno con transporte simulado."""

    def factory(**kwargs):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=kwargs.get("timeout", 5.0)
        )

    monkeypatch.setattr(
        forwarder,
        "httpx",
        types.SimpleNamespace(AsyncClient=factory, RequestError=httpx.RequestError),
    )


def streaming_handler(chunks, status_code=200):
    async def body():
        for chunk in chunks:
            yield chunk

    def handler(request):
        if status_code != 200:
            return httpx.Response(status_code, text="upstream is down")
        return httpx.Response(
            status_code, headers={"content-type": "text/event-stream"}, content=body()
        )

    return handler


async def collect(generator):
    return [chunk async for chunk in generator]


@pytest.fixture(autouse=True)
def upstream_credential(monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_API_KEY", "sk-upstream-test")


async def test_streaming_blocks_destructive_tool_call(monkeypatch):
    """Los argumentos llegan partidos entre chunks y el corte ocurre antes del cierre."""
    chunks = [
        sse({"choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
            {"index": 0, "id": "call_1", "type": "function",
             "function": {"name": "execute_query", "arguments": '{"query": "DR'}}
        ]}, "finish_reason": None}]}),
        sse({"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": 'OP TABLE clientes"}'}}
        ]}, "finish_reason": None}]}),
        sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
        DONE,
    ]
    install_transport(monkeypatch, streaming_handler(chunks))

    recorded = {}

    async def on_complete(outcome):
        recorded["outcome"] = outcome

    emitted = b"".join(
        await collect(forwarder.forward_streaming_request({"model": "gpt-4o", "stream": True}, on_complete))
    )

    assert b"BLOCKED BY GOVERNANCE PROXY" in emitted
    # El chunk que completa la orden y el cierre del proveedor se quedan dentro
    assert b"OP TABLE clientes" not in emitted
    assert b'"finish_reason": "tool_calls"' not in emitted
    assert emitted.endswith(DONE)

    outcome = recorded["outcome"]
    assert outcome.is_blocked is True
    assert "Destructive SQL" in outcome.block_reason
    assert outcome.tool_calls[0]["function"]["arguments"] == '{"query": "DROP TABLE clientes"}'


async def test_streaming_passthrough_is_byte_identical(monkeypatch):
    chunks = [
        b"event: message\ndata: " + json.dumps(
            {"choices": [{"index": 0, "delta": {"content": "hola "}}]}
        ).encode() + b"\n\n",
        sse({"choices": [{"index": 0, "delta": {"content": "mundo"}, "finish_reason": "stop"}]}),
        DONE,
    ]
    install_transport(monkeypatch, streaming_handler(chunks))

    recorded = {}

    async def on_complete(outcome):
        recorded["outcome"] = outcome

    emitted = b"".join(
        await collect(forwarder.forward_streaming_request({"model": "gpt-4o", "stream": True}, on_complete))
    )

    assert emitted == b"".join(chunks)
    outcome = recorded["outcome"]
    assert outcome.content == "hola mundo"
    assert outcome.finish_reason == "stop"
    assert outcome.is_blocked is False


async def test_streaming_records_upstream_error(monkeypatch):
    install_transport(monkeypatch, streaming_handler([], status_code=503))

    recorded = {}

    async def on_complete(outcome):
        recorded["outcome"] = outcome

    emitted = b"".join(
        await collect(forwarder.forward_streaming_request({"model": "gpt-4o", "stream": True}, on_complete))
    )

    assert b"upstream_status_503" in emitted
    assert recorded["outcome"].upstream_error == "upstream is down"


async def test_streaming_records_when_client_disconnects(monkeypatch):
    chunks = [
        sse({"choices": [{"index": 0, "delta": {"content": "primera parte"}}]}),
        sse({"choices": [{"index": 0, "delta": {"content": " y segunda"}, "finish_reason": "stop"}]}),
        DONE,
    ]
    install_transport(monkeypatch, streaming_handler(chunks))

    recorded = {}

    async def on_complete(outcome):
        recorded["outcome"] = outcome

    generator = forwarder.forward_streaming_request({"model": "gpt-4o", "stream": True}, on_complete)
    await generator.__anext__()
    await generator.aclose()

    assert "outcome" in recorded
    assert recorded["outcome"].content == "primera parte"


async def test_client_credential_never_reaches_upstream(monkeypatch):
    seen = {}

    def handler(request):
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    install_transport(monkeypatch, handler)

    result = await forwarder.forward_standard_request({"model": "gpt-4o"})

    assert result.status_code == 200
    assert seen["authorization"] == "Bearer sk-upstream-test"


async def test_missing_upstream_credential_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_API_KEY", "")

    def handler(request):  # pragma: no cover - no debe llegar a ejecutarse
        raise AssertionError("la peticion no debe salir sin credencial propia")

    install_transport(monkeypatch, handler)

    result = await forwarder.forward_standard_request({"model": "gpt-4o"})

    assert result.status_code == 500
    assert result.payload["error"]["code"] == "upstream_credential_missing"
