import httpx
import pytest

from proxy.config import settings
from proxy.services import forwarder
from tests.test_forwarder_streaming import install_transport


@pytest.fixture(autouse=True)
def upstream_credential(monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_API_KEY", "sk-upstream-test")


async def test_upstream_error_is_recorded_and_sanitized(monkeypatch):
    def handler(request):
        return httpx.Response(429, text="rate limit exceeded for organization org-123")

    install_transport(monkeypatch, handler)
    result = await forwarder.forward_standard_request({"model": "gpt-4o"})

    assert result.status_code == 429
    assert result.payload["error"]["code"] == "upstream_status_429"
    assert "org-123" not in str(result.payload)
    assert "org-123" in result.upstream_error


async def test_destructive_tool_call_is_blocked(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={
            "id": "chatcmpl-1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "sql", "arguments": '{"q": "DROP TABLE users"}'},
                    }],
                },
            }],
        })

    install_transport(monkeypatch, handler)
    result = await forwarder.forward_standard_request({"model": "gpt-4o"})

    assert result.status_code == 403
    assert result.is_blocked is True
    assert "BLOCKED BY GOVERNANCE PROXY" in result.payload["choices"][0]["message"]["content"]


async def test_transport_failure_returns_502(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    install_transport(monkeypatch, handler)
    result = await forwarder.forward_standard_request({"model": "gpt-4o"})

    assert result.status_code == 502
    assert result.payload["error"]["code"] == "upstream_unreachable"


async def test_models_are_taken_from_the_provider(monkeypatch):
    def handler(request):
        assert request.url.path.endswith("/models")
        return httpx.Response(200, json={"object": "list", "data": [{"id": "modelo-real"}]})

    install_transport(monkeypatch, handler)
    result = await forwarder.list_upstream_models()

    assert result.status_code == 200
    assert result.payload["data"][0]["id"] == "modelo-real"
