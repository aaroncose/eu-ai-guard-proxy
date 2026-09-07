import os
import httpx
from typing import Optional, Tuple
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc3161, rfc5652

from proxy.config import settings

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

# PKIStatus del RFC 3161. El resto de valores son rechazos.
GRANTED = 0
GRANTED_WITH_MODS = 1

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


def extract_tst_info(tsr_bytes: bytes) -> rfc3161.TSTInfo:
    """Devuelve el TSTInfo que la TSA firmó dentro del token.

    El token es un CMS SignedData cuyo contenido encapsulado es el TSTInfo, y
    ahí viven el hash sellado, la fecha y el nonce.

    Lanza pyasn1.error.PyAsn1Error si la respuesta viene malformada.
    """
    response, _ = decoder.decode(tsr_bytes, asn1Spec=rfc3161.TimeStampResp())

    status = int(response['status']['status'])
    if status not in (GRANTED, GRANTED_WITH_MODS):
        raise ValueError(f"La TSA rechazó la petición con PKIStatus {status}")

    token = response['timeStampToken']
    if not token.isValue:
        raise ValueError("La respuesta de la TSA llegó sin token")

    signed_data, _ = decoder.decode(token['content'], asn1Spec=rfc5652.SignedData())
    econtent = signed_data['encapContentInfo']['eContent']
    if not econtent.isValue:
        raise ValueError("El token de la TSA llegó sin contenido firmado")

    tst_info, _ = decoder.decode(bytes(econtent), asn1Spec=rfc3161.TSTInfo())
    return tst_info


def verify_timestamp_response(
    tsr_bytes: bytes, digest_bytes: bytes, nonce: Optional[int]
) -> Optional[str]:
    """Comprueba que el token sella el hash enviado en esta misma petición.

    Devuelve None cuando el token es coherente, y el motivo del rechazo en caso
    contrario. El nonce es lo que impide que alguien reutilice un token antiguo
    como respuesta a una petición nueva.
    """
    try:
        tst_info = extract_tst_info(tsr_bytes)
    except ValueError as exc:
        return str(exc)
    except Exception as exc:
        return f"Token de la TSA ilegible: {type(exc).__name__} {exc}".strip()

    imprint = tst_info['messageImprint']
    if imprint['hashAlgorithm']['algorithm'] != SHA256_OID:
        return "La TSA selló con un algoritmo de hash distinto del solicitado"

    if bytes(imprint['hashedMessage']) != digest_bytes:
        return "El hash sellado por la TSA difiere del enviado"

    if nonce is not None:
        returned = tst_info['nonce']
        if not returned.isValue:
            return "La TSA devolvió el token sin nonce"
        if int(returned) != nonce:
            return "El nonce devuelto por la TSA difiere del enviado"

    return None


async def request_eidas_timestamp(
    merkle_root_hex: str,
    tsa_url: Optional[str] = None
) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """
    Envía el hash Merkle Root a una TSA RFC 3161 y obtiene el token .tsr oficial.
    """
    try:
        tsa_url = tsa_url or settings.EIDAS_TSA_URL
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
                reason = verify_timestamp_response(resp.content, digest_bytes, nonce)
                if reason:
                    return False, None, reason
                return True, resp.content, None
            return False, None, f"TSA responded with HTTP {resp.status_code}: {resp.text}"
    except Exception as exc:
        return False, None, f"Failed to acquire RFC 3161 timestamp: {str(exc)}"
