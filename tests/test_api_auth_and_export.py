import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from proxy.config import settings
from proxy.database import get_db_session
from proxy.main import app
from proxy.models import AuditLedger
from proxy.security.asymmetric_signer import verify_manifest_signature


@pytest.fixture
def client(test_session):
    app.dependency_overrides[get_db_session] = lambda: test_session
    transport = ASGITransport(app=app)
    yield AsyncClient(transport=transport, base_url="http://test")
    app.dependency_overrides.clear()


async def seed(session, count=3):
    base = datetime.now(timezone.utc) - timedelta(days=1)
    previous = settings.GENESIS_HASH
    for index in range(count):
        # Empieza en 1 para no chocar con el hash genesis, que es todo ceros
        record_hash = f"{index + 1:064d}"
        session.add(AuditLedger(
            request_id=f"req-{index}",
            timestamp_utc=base + timedelta(minutes=index),
            app_id="portal" if index % 2 == 0 else "otra-app",
            model_requested="gpt-4o",
            request_payload={"prompt": index},
            response_payload={"answer": index},
            previous_hash=previous,
            record_hash=record_hash,
        ))
        previous = record_hash
    await session.commit()


async def test_query_parameter_no_longer_authenticates(client, test_session):
    async with client as http:
        response = await http.get("/api/v1/audit/verify", params={"api_key": settings.PROXY_API_KEY})
        assert response.status_code == 401

        response = await http.get(
            "/api/v1/audit/verify",
            headers={"Authorization": f"Bearer {settings.PROXY_API_KEY}"},
        )
        assert response.status_code == 200


async def test_export_respects_filters_and_signs_the_manifest(client, test_session):
    await seed(test_session, count=4)

    async with client as http:
        response = await http.get(
            "/api/v1/audit/export",
            params={"app_id": "portal"},
            headers={"Authorization": f"Bearer {settings.PROXY_API_KEY}"},
        )

    assert response.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    assert set(archive.namelist()) == {
        "audit_ledger.jsonl",
        "audit_manifest.json",
        "manifest_signature.sig",
        "public_key.pem",
        "signature.sha256",
    }

    manifest_bytes = archive.read("audit_manifest.json")
    manifest = json.loads(manifest_bytes)
    assert manifest["total_records_exported"] == 2
    assert manifest["filter_app_id"] == "portal"
    assert manifest["records_truncated"] is False
    assert verify_manifest_signature(manifest_bytes, archive.read("manifest_signature.sig")) is True

    lines = [line for line in archive.read("audit_ledger.jsonl").decode().splitlines() if line]
    assert len(lines) == 2
    assert all(json.loads(line)["app_id"] == "portal" for line in lines)


async def test_export_limit_marks_the_manifest_as_truncated(client, test_session):
    await seed(test_session, count=4)

    async with client as http:
        response = await http.get(
            "/api/v1/audit/export",
            params={"limit": 2},
            headers={"Authorization": f"Bearer {settings.PROXY_API_KEY}"},
        )

    archive = zipfile.ZipFile(io.BytesIO(response.content))
    manifest = json.loads(archive.read("audit_manifest.json"))
    assert manifest["total_records_exported"] == 2
    assert manifest["records_truncated"] is True


async def test_healthz_reports_the_audit_queue(client):
    async with client as http:
        response = await http.get("/healthz")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["audit_pending"] == 0
    assert body["audit_failed"] == 0
