import pytest
from datetime import datetime, timezone
from proxy.models import AuditLedger
from proxy.security.crypto_chain import generate_record_hash, verify_ledger_integrity
from proxy.config import settings

@pytest.mark.asyncio
async def test_crypto_chain_integrity(test_session):
    # 1. Crear bloque 1
    t1 = datetime.now(timezone.utc)
    h1 = generate_record_hash(settings.GENESIS_HASH, "req-1", t1.isoformat(), "gpt-4o", {"p": 1}, {"r": 1})
    rec1 = AuditLedger(
        request_id="req-1",
        timestamp_utc=t1,
        app_id="test",
        model_requested="gpt-4o",
        request_payload={"p": 1},
        response_payload={"r": 1},
        previous_hash=settings.GENESIS_HASH,
        record_hash=h1
    )
    test_session.add(rec1)

    # 2. Crear bloque 2
    t2 = datetime.now(timezone.utc)
    h2 = generate_record_hash(h1, "req-2", t2.isoformat(), "gpt-4o", {"p": 2}, {"r": 2})
    rec2 = AuditLedger(
        request_id="req-2",
        timestamp_utc=t2,
        app_id="test",
        model_requested="gpt-4o",
        request_payload={"p": 2},
        response_payload={"r": 2},
        previous_hash=h1,
        record_hash=h2
    )
    test_session.add(rec2)
    await test_session.commit()

    # 3. Verificar cadena íntegra
    is_valid, count, broken_id = await verify_ledger_integrity(test_session)
    assert is_valid is True
    assert count == 2
    assert broken_id is None

    # 4. Simular ataque/manipulación alterando el payload del bloque 1
    rec1.request_payload = {"p": "hacked"}
    await test_session.commit()

    # 5. La verificación debe fallar de inmediato
    is_valid, count, broken_id = await verify_ledger_integrity(test_session)
    assert is_valid is False
    assert broken_id == rec1.id