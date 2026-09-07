import logging

from sqlalchemy import inspect as sa_inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from proxy.config import settings
from proxy.models import Base

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True
)

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


def _audit_ledger_columns(sync_conn) -> set:
    return {column["name"] for column in sa_inspect(sync_conn).get_columns("audit_ledger")}


async def _migrate_audit_ledger(conn) -> None:
    """Lleva una base ya creada al esquema actual.

    create_all deja intactas las tablas existentes, asi que la columna nueva y
    la restriccion de la cadena se aplican aqui. Las dos sentencias son
    idempotentes y valen para SQLite y para PostgreSQL.
    """
    columns = await conn.run_sync(_audit_ledger_columns)
    if "upstream_error" not in columns:
        await conn.execute(text("ALTER TABLE audit_ledger ADD COLUMN upstream_error TEXT"))
        logger.info("Columna upstream_error anadida a audit_ledger")

    try:
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_ledger_previous_hash "
                "ON audit_ledger (previous_hash)"
            )
        )
    except SQLAlchemyError:
        # Una base con la cadena ya bifurcada rechaza el indice. El arranque
        # sigue y el aviso queda registrado para repararla a mano.
        logger.exception(
            "No se pudo crear uq_audit_ledger_previous_hash: hay hashes previos repetidos en el ledger"
        )


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _migrate_audit_ledger(conn)


async def get_db_session():
    async with async_session_factory() as session:
        yield session
