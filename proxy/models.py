from datetime import datetime, timezone
from typing import Any, Optional, Dict
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, Boolean, JSON, Text
from pydantic import BaseModel

class Base(DeclarativeBase):
    pass

class AuditLedger(Base):
    __tablename__ = "audit_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        index=True, 
        nullable=False
    )
    
    # Contexto y Usuario
    app_id: Mapped[str] = mapped_column(String(64), index=True, default="default-app")
    user_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    
    # Datos de la Inferencia
    model_requested: Mapped[str] = mapped_column(String(128), nullable=False)
    is_streaming: Mapped[bool] = mapped_column(Boolean, default=False)
    request_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    response_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    
    # Control de Herramientas
    tools_called: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    block_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Criptografía
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    archived_to_s3: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

class DailyBatchManifest(Base):
    __tablename__ = "daily_batch_manifests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_date: Mapped[str] = mapped_column(String(10), unique=True, index=True)  # YYYY-MM-DD
    records_count: Mapped[int] = mapped_column(Integer, nullable=False)
    merkle_root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    s3_object_key: Mapped[str] = mapped_column(String(255), nullable=False)
    upload_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# ESTA ES LA CLASE QUE FALTABA:
class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_records: int
    first_corrupted_id: Optional[int] = None
    verification_timestamp: datetime