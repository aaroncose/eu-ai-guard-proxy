# tamper_test.py
import asyncio
import json
from sqlalchemy import select
from proxy.database import async_session_factory, init_db
from proxy.models import AuditLedger

async def alter_record():
    # 1. Asegurar que las tablas existen
    await init_db()

    async with async_session_factory() as session:
        async with session.begin():
            stmt = select(AuditLedger).where(AuditLedger.id == 1)
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()

            if not record:
                print(" No hay registros con ID #1 en la base de datos.")
                print("Ejecuta primero una llamada de prueba con python tests/test_client.py")
                return

            print(f"📄 Payload original en BD (ID #1): {record.request_payload}")

            # 2. Modificar maliciosamente el contenido guardado sin recalcular el hash
            payload = dict(record.request_payload) if isinstance(record.request_payload, dict) else json.loads(record.request_payload)
            payload["hacked"] = True
            payload["messages"] = [{"role": "user", "content": "Texto manipulado fraudulentamente por un atacante."}]
            
            record.request_payload = payload
            session.add(record)

    print("\n [ATAQUE COMPLETADO]: Se ha modificado el registro en la base de datos.")

if __name__ == "__main__":
    asyncio.run(alter_record())