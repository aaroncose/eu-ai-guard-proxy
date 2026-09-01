# EU AI Guard Proxy

Reverse proxy determinista de alto rendimiento y sellado criptográfico multicapa diseñado para la observabilidad inmutable, la contención de ejecución de agentes y el cumplimiento técnico de los Artículos 12, 19 y 26(6) del Reglamento Europeo de Inteligencia Artificial (EU AI Act - Reglamento UE 2024/1689).

## Descripción Técnica
El sistema se interpone de forma transparente entre las aplicaciones cliente y cualquier proveedor de modelos de lenguaje compatible con la especificación estándar de inferencia (OpenAI, OpenRouter, Azure OpenAI, AWS Bedrock, Anthropic vía gateways, vLLM, Ollama o despliegues locales on-premise). Su arquitectura desacopla el ciclo de vida de la petición de red del procesamiento de gobernanza mediante una cola asíncrona de persistencia secuencial atómica.

## Capacidades Principales

- **Compatibilidad Universal Multi-Proveedor**: Agnóstico al proveedor subyacente. Permite operar con servicios comerciales cerrados o modelos de pesos abiertos (Llama, Mistral, Qwen, DeepSeek) sin modificar la capa de integración de la aplicación.

- **Registro Inmutable Art. 12 (Tamper-Evident Ledger)**: Encadenamiento criptográfico secuencial basado en SHA-256 sobre payloads JSON serializados de forma canónica. Cualquier alteración de datos históricos invalida la verificación matemática de la cadena.

- **Anonimización Previa a la Persistencia (RGPD)**: Detección y enmascaramiento determinista en memoria de identificadores personales (DNI/NIE, tarjetas de crédito, correos electrónicos y claves API) antes de su persistencia en disco o base de datos.

- **Guardarraíl Determinista de Herramientas (Pre-Tool Execution)**: Inspección sintáctica previa de argumentos generados por el modelo (tool_calls) para abortar comandos destructivos de bases de datos (DROP, DELETE, TRUNCATE) e inyecciones a nivel de sistema operativo antes de su ejecución.

- **Sello de Tiempo Cualificado eIDAS (RFC 3161 / TSP)**: Integración con Autoridades de Sellado de Tiempo (TSA) cualificadas de la Unión Europea para otorgar presunción jurídica de fecha cierta e integridad de los lotes de auditoría (Reglamento UE 910/2014).

- **Firma Asimétrica ECDSA NIST P-256**: Firma digital del manifiesto de auditoría mediante par de claves en curva elíptica secp256r1 (FIPS 186-4) para certificar autoría y no-repudio corporativo.

- **Registro de Transparencia Pública Inmutable (Sigstore Rekor)**: Anclaje del Merkle Root diario en el log público de Rekor, generando pruebas de inclusión (Inclusion Proof) y números de secuencia auditables por terceros independientes.

- **Archivado WORM (Write Once, Read Many)**: Rutina programada para agregación de registros diarios y exportación automatizada a almacenamiento compatible con S3 en modo COMPLIANCE (retención obligatoria de 180 días).

- **Compatibilidad Total de Streaming**: Soporte nativo para Server-Sent Events (SSE) sin degradación de latencia para el cliente final, reconstruyendo el buffer completo en segundo plano para su posterior firma.
## Arquitectura Criptográfica del Sistema

```
[Cliente / Agente] 
       │ (HTTP / SSE)
       ▼
[FastAPI Reverse Proxy] ────► [Upstream Provider (OpenAI / OpenRouter / Azure / vLLM)]
       │                                │
       ├─► [Tool Execution Guard] ◄─────┘
       │
       ├─► [DLP Masking Engine]
       │
       ▼
[Async Queue (Worker)]
       │
       ├─► [Ledger Database (PostgreSQL / SQLite)] ──► [SHA-256 Hash Chain]
       │
       ▼ (Medianoche UTC: Agregación de Merkle Root Diario)
       ├─► [1. eIDAS TSA (RFC 3161)] ───────► Token .tsr cualificado
       ├─► [2. Firma ECDSA NIST P-256] ─────► Firma .sig del manifiesto
       ├─► [3. Sigstore Rekor API] ─────────► Log Index & Inclusion Proof
       │
       ▼
[WORM Archiver] ──► [S3 / Cloudflare R2 con Object Lock en modo COMPLIANCE (180 días)]
```

## Requisitos del Entorno

- Python 3.12+
- Docker y Docker Compose (para despliegue contenerizado)
- Base de datos: SQLite (desarrollo local) o PostgreSQL 15+ (entornos de producción)

## Configuración y Variables de Entorno
Copie la plantilla de configuración:

```bash
cp .env.example .env
```

### Tabla de Parámetros

| Variable | Tipo | Valor por Defecto | Descripción |
|----------|------|-------------------|-------------|
| `HOST` | String | `0.0.0.0` | Dirección de escucha del proxy. |
| `PORT` | Entero | `8000` | Puerto de escucha del proxy. |
| `UPSTREAM_BASE_URL` | String | `https://api.openai.com/v1` | URL base del endpoint de inferencia del proveedor. |
| `UPSTREAM_API_KEY` | String | `""` | Clave de API del proveedor de inferencia configurado. |
| `DATABASE_URL` | String | `sqlite+aiosqlite:///...` | URI asíncrona de conexión a base de datos. |
| `PROXY_API_KEY` | String | `sk-guard-local-dev-key` | Clave requerida en cabeceras de autorización del cliente. |
| `S3_ENABLED` | Booleano | `False` | Habilita el archivado diario a S3/R2 en modo WORM. |
| `S3_ENDPOINT_URL` | String | `None` | Endpoint S3 personalizado (opcional, para MinIO o Cloudflare R2). |
| `S3_BUCKET_NAME` | String | `ai-audit-ledger-eu` | Nombre del bucket con Object Lock habilitado. |
| `S3_REGION` | String | `eu-central-1` | Región del bucket de almacenamiento. |
| `RETENTION_DAYS` | Entero | `180` | Período de bloqueo de borrado en S3 (Art. 12/19 AI Act). |

## Adaptabilidad de Proveedores Upstream
El proxy reenvía el tráfico hacia cualquier servicio que soporte la especificación `/v1/chat/completions`. Ejemplos de configuración en `.env`:

### 1. OpenRouter (Acceso a Claude, Gemini, Llama, DeepSeek)

```env
UPSTREAM_BASE_URL=https://openrouter.ai/api/v1
UPSTREAM_API_KEY=sk-or-v1-tu-clave
```

### 2. Despliegues Locales / On-Premise (vLLM, Ollama, TGI)

```env
UPSTREAM_BASE_URL=http://localhost:11434/v1
UPSTREAM_API_KEY=none
```

### 3. Azure OpenAI Service

```env
UPSTREAM_BASE_URL=https://tu-recurso.openai.azure.com/openai/deployments/tu-modelo
UPSTREAM_API_KEY=tu-clave-azure
```

## Despliegue con Docker Compose

```bash
docker compose up -d --build
```

### Servicios expuestos:

- **Proxy de Inferencia y Auditoría**: http://localhost:8000
- **Dashboard de Verificación y Control**: http://localhost:8501

## Integración con Aplicaciones Cliente
La integración no requiere SDKs propietarios. Únicamente se debe redefinir `base_url` en los clientes estándar:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-guard-local-dev-key"
)

response = client.chat.completions.create(
    model="gpt-4o",  # o cualquier identificador soportado por el upstream
    messages=[
        {"role": "user", "content": "Verificación de trazabilidad operativa."}
    ],
    extra_headers={
        "X-App-ID": "payment-fraud-detection",
        "X-User-ID": "usr-49102"
    }
)

print(response.choices[0].message.content)
```

## Endpoints de la API

### Inferencia y Proxy

- **POST `/v1/chat/completions`**: Intercepta, aplica filtros DLP, evalúa herramientas y registra la interacción bajo encadenamiento hash.
- **GET `/v1/models`**: Consulta de modelos expuestos.

### Auditoría y Cumplimiento Regulatorio

- **GET `/api/v1/audit/verify`**: Ejecuta el algoritmo de verificación matemática sobre toda la secuencia histórica de registros.
- **GET `/api/v1/audit/export`**: Genera y descarga un archivo ZIP con los registros canónicos en formato JSONL, el manifiesto firmado con ECDSA P-256, la clave pública PEM y la firma hash SHA-256.

### Salud del Servicio

- **GET `/healthz`**: Comprobación del estado operativo del servicio.
- **GET `/livez`**: Liveness probe para orquestadores de contenedores.

## Suite de Pruebas

Ejecución de pruebas unitarias, de integración, firma criptográfica y esquemas ASN.1:

```bash
pytest -v
```

## Licencia

Propiedad comercial privada. Todos los derechos reservados. Queda prohibida la copia, distribución, modificación o uso no autorizado de este software sin una licencia comercial expresa y por escrito de su titular.