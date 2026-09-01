import streamlit as st
import asyncio
import pandas as pd
import json
from datetime import datetime, timezone
from sqlalchemy import select, func, delete
from proxy.database import async_session_factory
from proxy.models import AuditLedger, DailyBatchManifest
from proxy.security.crypto_chain import verify_ledger_integrity
from proxy.security.asymmetric_signer import get_public_key_pem

st.set_page_config(
    page_title="EU AI Guard Proxy - Governance Console",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .stMetric { background-color: rgba(240, 242, 246, 0.05); padding: 12px; border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.1); }
    </style>
""", unsafe_allow_html=True)

async def get_metrics():
    async with async_session_factory() as session:
        total_stmt = select(func.count(AuditLedger.id))
        blocked_stmt = select(func.count(AuditLedger.id)).where(AuditLedger.is_blocked == True)
        models_stmt = select(AuditLedger.model_requested, func.count(AuditLedger.id)).group_by(AuditLedger.model_requested)
        
        total = (await session.execute(total_stmt)).scalar() or 0
        blocked = (await session.execute(blocked_stmt)).scalar() or 0
        models_res = (await session.execute(models_stmt)).all()
        
        return total, blocked, dict(models_res)

async def get_recent_logs(limit=50):
    async with async_session_factory() as session:
        stmt = select(AuditLedger).order_by(AuditLedger.id.desc()).limit(limit)
        res = await session.execute(stmt)
        return res.scalars().all()

async def get_manifests():
    async with async_session_factory() as session:
        stmt = select(DailyBatchManifest).order_by(DailyBatchManifest.id.desc()).limit(10)
        res = await session.execute(stmt)
        return res.scalars().all()

async def reset_demo_database():
    async with async_session_factory() as session:
        async with session.begin():
            await session.execute(delete(AuditLedger))
            await session.execute(delete(DailyBatchManifest))

with st.sidebar:
    st.markdown("### EU AI Guard Proxy")
    st.caption("Conformidad Tecnica: Articulos 12, 19 y 26(6) EU AI Act")
    st.markdown("---")
    
    st.markdown("**Capas Criptograficas Activas:**")
    st.markdown("- SHA-256 Encadenamiento secuencial")
    st.markdown("- RGPD / DLP Enmascaramiento en memoria")
    st.markdown("- ECDSA NIST P-256 Firma asimetrica")
    st.markdown("- RFC 3161 Sello de tiempo eIDAS")
    st.markdown("- Sigstore Rekor Log de transparencia")
    
    st.markdown("---")
    st.markdown("**Clave Publica del Servidor (ECDSA):**")
    try:
        pub_pem = get_public_key_pem()
        st.code(pub_pem, language="text")
    except Exception:
        st.caption("Clave no inicializada")
        
    st.markdown("---")
    if st.button("Vaciar Registros Locales", use_container_width=True):
        asyncio.run(reset_demo_database())
        st.info("Base de datos reiniciada.")
        st.rerun()

st.title("Consola de Auditoria y Gobernanza de IA")
st.caption("Panel de control de inmutabilidad criptografica, contencion de agentes y cumplimiento regulatorio.")

total_records, total_blocked, models_breakdown = asyncio.run(get_metrics())

col1, col2, col3, col4 = st.columns(4)
col1.metric("Decisiones Auditadas", total_records)
col2.metric("Llamadas Bloqueadas (Guard)", total_blocked)
col3.metric("Modelos en Trafico", len(models_breakdown))
col4.metric("Estado de Registro", "Activo" if total_records > 0 else "En Espera")

st.markdown("---")

tab_audit, tab_verify, tab_batches, tab_export = st.tabs([
    "Auditoria de Eventos",
    "Verificacion Matematica (Art. 12)",
    "Lotes Diarios y Transparencia",
    "Exportacion de Expediente"
])

with tab_audit:
    st.subheader("Registro de Trafico Interceptado (Ultimos 50 Eventos)")
    logs = asyncio.run(get_recent_logs(50))
    
    if logs:
        table_data = []
        for l in logs:
            table_data.append({
                "ID": l.id,
                "Timestamp (UTC)": l.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
                "Request ID": l.request_id[:16] + "...",
                "App ID": l.app_id,
                "Modelo": l.model_requested,
                "Streaming": "Si" if l.is_streaming else "No",
                "Estado": "Bloqueado" if l.is_blocked else "Autorizado",
                "Hash Actual": l.record_hash[:16] + "..."
            })
        
        st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)
        
        st.markdown("#### Inspeccion Detallada de Registro")
        selected_id = st.selectbox("Seleccionar ID para auditar payload completo:", [l.id for l in logs])
        selected_log = next(l for l in logs if l.id == selected_id)
        
        col_req, col_res = st.columns(2)
        with col_req:
            st.markdown("**Carga Util de Entrada (DLP Enmascarado):**")
            st.json(selected_log.request_payload)
        with col_res:
            st.markdown("**Respuesta del Modelo / Herramientas:**")
            st.json(selected_log.response_payload)
            
        st.markdown("**Metadatos Criptograficos del Evento:**")
        st.code(f"Previous Hash: {selected_log.previous_hash}\nRecord Hash:   {selected_log.record_hash}", language="text")
    else:
        st.info("No hay eventos registrados en la base de datos.")

with tab_verify:
    st.subheader("Verificacion Secuencial de Integridad Criptografica")
    st.write(
        "Recalculo determinista de la funcion hash SHA-256 a lo largo de la secuencia historica "
        "para validar la no alteracion de registros segun el Articulo 12 del Reglamento UE 2024/1689."
    )
    
    if st.button("Ejecutar Verificacion Formal Art. 12", type="primary"):
        async def execute_verification():
            async with async_session_factory() as session:
                return await verify_ledger_integrity(session)
                
        is_valid, count, broken_id = asyncio.run(execute_verification())
        
        if is_valid:
            st.success(f"CADENA INTEGRA: Se han auditado y validado {count} registros historicos secuenciales.")
        else:
            st.error(f"FALLO DE INTEGRIDAD: Discrepancia matematica detectada en el registro ID #{broken_id}.")

with tab_batches:
    st.subheader("Sellado de Lotes Diarios y Anclaje de Confianza Externa")
    st.write("Agregacion diaria a medianoche UTC, sellos de tiempo cualificados eIDAS (RFC 3161) y anclaje en Sigstore Rekor.")
    
    manifests = asyncio.run(get_manifests())
    if manifests:
        manifest_data = []
        for m in manifests:
            manifest_data.append({
                "Fecha Lote": m.batch_date,
                "Total Registros": m.records_count,
                "Merkle Root": m.merkle_root_hash[:16] + "...",
                "Sello eIDAS": "Token TSR Emitido" if m.has_eidas_tsa else "Pendiente",
                "Firma ECDSA": "Verificada" if m.ecdsa_signature_hex else "No",
                "Rekor Log Index": m.rekor_log_index or "No publicado",
                "Rekor UUID": m.rekor_entry_uuid or "N/A"
            })
        st.dataframe(pd.DataFrame(manifest_data), use_container_width=True, hide_index=True)
        
        st.markdown("#### Consulta Publica en Sigstore Rekor")
        for m in manifests:
            if m.rekor_log_index:
                st.markdown(f"- Lote `{m.batch_date}`: [Verificar en Sigstore Rekor Explorer (Log Index #{m.rekor_log_index})](https://search.sigstore.dev/?logIndex={m.rekor_log_index})")
    else:
        st.info("No se han consolidado lotes diarios programados todavia. El planificador ejecuta el empaquetado a las 00:05 UTC.")

with tab_export:
    st.subheader("Generacion de Dossier de Cumplimiento")
    st.write(
        "Descarga del expediente sellado para auditorias de la Oficina Europea de Inteligencia Artificial "
        "o autoridades nacionales de supervision."
    )
    
    st.markdown("""
    **Contenido del paquete de exportacion (.ZIP):**
    - `audit_ledger.jsonl`: Registros canonicos de inferencia y decision.
    - `audit_manifest.json`: Metadatos del lote y definicion del algoritmo de firma.
    - `manifest_signature.sig`: Firma asimetrica del manifiesto (ECDSA NIST P-256).
    - `public_key.pem`: Clave publica para verificacion independiente.
    - `signature.sha256`: Hash SHA-256 del archivo de registros.
    """)
    
    st.markdown(
        '<a href="http://localhost:8000/api/v1/audit/export" target="_blank">'
        '<button style="background-color:#1f6feb;color:white;padding:8px 16px;border:none;border-radius:4px;font-weight:600;cursor:pointer;">'
        'Descargar Expediente de Auditoria Art. 12 (.ZIP)'
        '</button></a>',
        unsafe_allow_html=True
    )