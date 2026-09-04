import os
import httpx
from typing import Optional, Tuple
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import encoder, decoder

# Estructuras ASN.1 según RFC 3161
class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Null())
    )

class MessageImprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('hashedMessage', univ.OctetString())
    )

class TimeStampReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(1)),
        namedtype.NamedType('messageImprint', MessageImprint()),
        namedtype.OptionalNamedType('reqPolicy', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('nonce', univ.Integer()),
        namedtype.DefaultedNamedType('certReq', univ.Boolean(True))
    )

# OID estándar para SHA-256 (2.16.840.1.101.3.4.2.1)
SHA256_OID = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')

def create_rfc3161_request(digest_bytes: bytes, nonce: Optional[int] = None) -> bytes:
    algo_id = AlgorithmIdentifier()
    algo_id.setComponentByName('algorithm', SHA256_OID)
    algo_id.setComponentByName('parameters', univ.Null(''))

    imprint = MessageImprint()
    imprint.setComponentByName('hashAlgorithm', algo_id)
    imprint.setComponentByName('hashedMessage', univ.OctetString(digest_bytes))

    req = TimeStampReq()
    req.setComponentByName('version', univ.Integer(1))
    req.setComponentByName('messageImprint', imprint)
    req.setComponentByName('certReq', univ.Boolean(True))
    if nonce:
        req.setComponentByName('nonce', univ.Integer(nonce))

    return encoder.encode(req)

async def request_eidas_timestamp(
    merkle_root_hex: str, 
    tsa_url: str = "http://timestamp.digicert.com"
) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """
    Envía el hash Merkle Root a una TSA RFC 3161 y obtiene el token .tsr oficial.
    """
    try:
        digest_bytes = bytes.fromhex(merkle_root_hex)
        nonce = int.from_bytes(os.urandom(8), byteorder='big')
        req_der = create_rfc3161_request(digest_bytes, nonce=nonce)

        headers = {
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply"
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(tsa_url, content=req_der, headers=headers)
            if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/timestamp-reply"):
                return True, resp.content, None
            return False, None, f"TSA responded with HTTP {resp.status_code}: {resp.text}"
    except Exception as exc:
        return False, None, f"Failed to acquire RFC 3161 timestamp: {str(exc)}"