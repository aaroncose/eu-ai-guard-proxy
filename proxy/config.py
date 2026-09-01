from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    
    # Red y Servicio
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    DEBUG: bool = Field(default=False)
    
    # Upstream Provider
    UPSTREAM_BASE_URL: str = Field(default="https://api.openai.com/v1")
    UPSTREAM_API_KEY: str = Field(default="")
    
    # Persistencia Local
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./audit_ledger.db")
    
    # Almacenamiento Seguro S3 / R2 (WORM - Art. 12)
    S3_ENABLED: bool = Field(default=False)
    S3_ENDPOINT_URL: Optional[str] = Field(default=None)  # Opcional (para MinIO o Cloudflare R2)
    S3_BUCKET_NAME: str = Field(default="ai-audit-ledger-eu")
    S3_REGION: str = Field(default="eu-central-1")
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None)
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None)
    RETENTION_DAYS: int = Field(default=180)  # 6 meses exigidos por la EU AI Act
    
    # Seguridad y Claves
    PROXY_API_KEY: str = Field(default="sk-guard-local-dev-key")
    GENESIS_HASH: str = Field(default="0" * 64)

settings = Settings()