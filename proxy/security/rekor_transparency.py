import base64
import httpx
from typing import Dict, Any, Tuple, Optional
from proxy.security.asymmetric_signer import get_public_key_pem

REKOR_PUBLIC_API = "https://rekor.sigstore.dev/api/v1/log/entries"

async def publish_to_rekor(
    merkle_root_hex: str,
    signature_bytes: bytes
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Publica el Merkle Root firmado en el log de transparencia pública de Sigstore Rekor.
    """
    public_key_b64 = base64.b64encode(get_public_key_pem().encode("utf-8")).decode("utf-8")
    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    # Estructura del schema hashedrekord de Rekor v0.0.1
    entry_payload = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": merkle_root_hex
                }
            },
            "signature": {
                "content": signature_b64,
                "publicKey": {
                    "content": public_key_b64
                }
            }
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(REKOR_PUBLIC_API, json=entry_payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                # Retorna el UUID de la entrada y la prueba de inclusión
                return True, data, None
            return False, None, f"Rekor rejected with status {resp.status_code}: {resp.text}"
    except Exception as exc:
        return False, None, f"Failed to connect to Rekor: {str(exc)}"