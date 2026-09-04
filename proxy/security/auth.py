import secrets
from typing import Optional
from fastapi import Header, Query, HTTPException, status
from proxy.config import settings

def verify_api_key(
    authorization: Optional[str] = Header(default=None),
    api_key: Optional[str] = Query(default=None)
) -> str:
    """
    Valida de forma segura (tiempo constante) que la petición proporcione
    una clave válida coincidente con settings.PROXY_API_KEY vía cabecera
    Authorization: Bearer <key> o parámetro de consulta ?api_key=<key>.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()
    elif api_key:
        token = api_key.strip()

    if not token or not settings.PROXY_API_KEY or not secrets.compare_digest(token, settings.PROXY_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Set Authorization: Bearer <PROXY_API_KEY>",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return token
