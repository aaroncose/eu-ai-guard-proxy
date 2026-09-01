import streamlit as st
import asyncio
import pandas as pd
import httpx
from datetime import datetime
from sqlalchemy import select
from proxy.database import async_session_factory
from proxy.models import AuditLedger, DailyBatchManifest
from proxy.security.crypto_chain import verify_ledger_integrity

st.set_page_config(
    page_title="EU AI Act Governance Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ EU AI Act Art. 12 Governance & Audit Gateway")
st.markdown("Panel de control de inmutabilidad criptográfica, retención WORM y contención de agentes.")

tab1, tab2, tab3 = st.tabs([
    "📊 Auditoría en Tiempo Real", 
    "🔒 Verificación Criptográfica (Art. 12)", 
    "📦 Exportar Expediente Oficial"
])

async def load_ledger_data():
    async with async_session_factory() as session:
        stmt = select(AuditLedger).order_by(AuditLedger.id.desc()).limit(100)
        res = await session.execute(stmt)
        return res.scalars().all()

with tab1:
    st.subheader("Últimos Registros del Ledger")
    records = asyncio.run(load_ledger_data())
    
    if records:
        col1, col2, col3 = st.columns(3)
        total_calls = len(records)
        blocked_calls = sum(1 for r in records if r.is_blocked)
        
        col1.metric("Llamadas Registradas (Top 100)", total_calls)
        col2.metric("Llamadas Bloqueadas (Guard)", blocked_calls)
        col3.metric("Conexión BD", "Activa (Asíncrona)")

        df = pd.DataFrame([{
            "ID": r.id,
            "Fecha (UTC)": r.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "App ID": r.app_id,
            "Modelo": r.model_requested,
            "Bloqueado": "🚨 Sí" if r.is_blocked else "✅ No",
            "Hash Actual": r.record_hash[:16] + "..."
        } for r in records])
        
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No hay llamadas registradas todavía. Envía una petición al proxy para comenzar.")

with tab2:
    st.subheader("Verificación Formal de Cadena Inmutable")
    st.write("Recalcula todos los hashes SHA-256 encadenados para demostrar ante auditoría que no ha habido manipulación de datos.")
    
    if st.button("Ejecutar Verificación Criptográfica"):
        async def run_verify():
            async with async_session_factory() as session:
                return await verify_ledger_integrity(session)

        is_valid, total, broken_id = asyncio.run(run_verify())
        
        if is_valid:
            st.success(f"✅ CADENA 100% ÍNTEGRA: Se han verificado {total} registros. Cero manipulaciones detectadas.")
        else:
            st.error(f"🚨 ALERTA CRÍTICA: Integridad rota en el registro ID #{broken_id}. Datos manipulados o alterados.")

with tab3:
    st.subheader("Generar Dossier de Cumplimiento Art. 12 / 19")
    st.write("Descarga un archivo ZIP firmado con los logs JSONL canónicos y el manifiesto criptográfico.")
    
    if st.button("Descargar Expediente ZIP"):
        st.markdown("[Haz clic aquí para descargar vía API directa](http://localhost:8000/api/v1/audit/export)")