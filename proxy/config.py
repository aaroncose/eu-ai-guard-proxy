import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List, Optional

# Ruta absoluta a la raíz del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "audit_ledger.db"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    
    # Red y Servicio
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    DEBUG: bool = Field(default=False)

    # Origenes autorizados para CORS, separados por comas. Vacio deshabilita
    # CORS, que es lo correcto para un proxy consumido desde servidor
    CORS_ALLOW_ORIGINS: str = Field(default="")

    # URL publica del proxy, usada por el dashboard para descargar el dossier
    PROXY_PUBLIC_URL: str = Field(default="http://localhost:8000")
    
    # Upstream Provider
    UPSTREAM_BASE_URL: str = Field(default="https://api.openai.com/v1")
    UPSTREAM_API_KEY: str = Field(default="")
    UPSTREAM_TIMEOUT: float = Field(default=60.0)
    
    # Persistencia Local (Ruta Absoluta Garantizada)
    DATABASE_URL: str = Field(default=f"sqlite+aiosqlite:///{DEFAULT_DB_PATH}")

    # Reintentos de escritura en el ledger antes de mandar el apunte al
    # buzon de fallidos
    AUDIT_WRITE_MAX_ATTEMPTS: int = Field(default=3)
    # Plazo para vaciar la cola de auditoria al apagar el servicio
    AUDIT_DRAIN_TIMEOUT: float = Field(default=10.0)
    # Tope de registros por exportacion, para acotar el tamano del dossier
    AUDIT_EXPORT_MAX_RECORDS: int = Field(default=50000)
    # Tamano de pagina al recorrer el ledger, usado en verificacion y export
    AUDIT_PAGE_SIZE: int = Field(default=1000)
    
    # Almacenamiento Seguro S3 / R2 (WORM - Art. 12)
    S3_ENABLED: bool = Field(default=False)
    S3_ENDPOINT_URL: Optional[str] = Field(default=None)
    S3_BUCKET_NAME: str = Field(default="ai-audit-ledger-eu")
    S3_REGION: str = Field(default="eu-central-1")
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None)
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None)
    RETENTION_DAYS: int = Field(default=180)
    # Dias hacia atras que revisa el arranque en busca de lotes sin sellar
    ARCHIVE_BACKFILL_DAYS: int = Field(default=30)

    # Sello de tiempo RFC 3161. La URL sale a configuracion para poder apuntar
    # a una TSA cualificada de la lista de confianza europea
    EIDAS_TSA_URL: str = Field(default="https://timestamp.digicert.com")
    
    # Seguridad y Claves
    PROXY_API_KEY: str = Field(default="sk-guard-local-dev-key")
    GENESIS_HASH: str = Field(default="0" * 64)
    # Cifra la clave privada que firma los manifiestos. Quien copie el fichero
    # sin esta frase no puede firmar en nombre del proxy
    SIGNING_KEY_PASSPHRASE: str = Field(default="dev-insecure-signing-passphrase")

    @property
    def cors_origins(self) -> List[str]:
        """Lista de origenes autorizados, ya despiezada y sin huecos."""
        return [origin.strip() for origin in self.CORS_ALLOW_ORIGINS.split(",") if origin.strip()]

settings = Settings()
