import secrets
from typing import Optional
from fastapi import Header, HTTPException, status
from proxy.config import settings

def verify_api_key(
    authorization: Optional[str] = Header(default=None)
) -> str:
    """
    Valida de forma segura (tiempo constante) que la petición proporcione
    una clave válida coincidente con settings.PROXY_API_KEY vía cabecera
    Authorization: Bearer <key>.

    La clave viaja solo en la cabecera. Una credencial en la cadena de
    consulta queda escrita en los logs de acceso, en el historial del
    navegador y en cualquier intermediario del camino.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if not token or not settings.PROXY_API_KEY or not secrets.compare_digest(token, settings.PROXY_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Set Authorization: Bearer <PROXY_API_KEY>",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return token
