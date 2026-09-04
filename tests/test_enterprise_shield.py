import pytest
from proxy.security.asymmetric_signer import (
    ensure_signing_key_pair,
    sign_manifest_payload,
    verify_manifest_signature
)
from proxy.security.eidas_tsp import create_rfc3161_request

def test_ecdsa_signature_verification():
    payload = b'{"test_data": "sample_manifest"}'
    signature = sign_manifest_payload(payload)
    assert verify_manifest_signature(payload, signature) is True
    assert verify_manifest_signature(b'{"test_data": "tampered"}', signature) is False

def test_rfc3161_der_request_generation():
    fake_digest = bytes.fromhex("a" * 64)
    der_req = create_rfc3161_request(fake_digest, nonce=12345678)
    assert isinstance(der_req, bytes)
    assert len(der_req) > 0