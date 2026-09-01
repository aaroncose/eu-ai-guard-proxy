import asyncio
from datetime import datetime, timezone
from proxy.security.crypto_chain import compute_merkle_root, canonical_json
from proxy.security.asymmetric_signer import (
    sign_manifest_payload,
    sign_digest_directly,
    verify_manifest_signature
)
from proxy.security.eidas_tsp import request_eidas_timestamp
from proxy.security.rekor_transparency import publish_to_rekor

async def run_shield_verification():
    fake_hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    ]
    merkle_root = compute_merkle_root(fake_hashes)

    # 1. Verificacion de firma ECDSA P-256
    manifest_bytes = canonical_json({
        "batch_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "merkle_root": merkle_root,
        "records_count": 2
    }).encode("utf-8")
    
    signature = sign_manifest_payload(manifest_bytes)
    is_valid_sig = verify_manifest_signature(manifest_bytes, signature)
    assert is_valid_sig is True

    # 2. Obtencion de sello de tiempo RFC 3161
    tsa_ok, tsr_bytes, _ = await request_eidas_timestamp(merkle_root)
    assert tsa_ok is True
    assert tsr_bytes is not None

    # 3. Publicacion en Sigstore Rekor
    rekor_sig = sign_digest_directly(bytes.fromhex(merkle_root))
    rekor_ok, rekor_data, rekor_err = await publish_to_rekor(merkle_root, rekor_sig)
    
    print(f"Merkle Root: {merkle_root}")
    print(f"Signature Status: {'VALID' if is_valid_sig else 'INVALID'}")
    print(f"RFC 3161 TSA Token: {len(tsr_bytes)} bytes received")
    
    if rekor_ok and rekor_data:
        entry_uuid = list(rekor_data.keys())[0]
        log_index = rekor_data[entry_uuid].get("logIndex")
        print(f"Rekor Entry UUID: {entry_uuid}")
        print(f"Rekor Log Index: {log_index}")
    else:
        print(f"Rekor Error: {rekor_err}")

if __name__ == "__main__":
    asyncio.run(run_shield_verification())