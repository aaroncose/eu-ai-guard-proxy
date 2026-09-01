import httpx
import json

PROXY_URL = "http://localhost:8000/v1/chat/completions"
HEADERS = {
    "Authorization": "Bearer sk-guard-local-dev-key",
    "Content-Type": "application/json",
    "X-App-ID": "fintech-portal-web",
    "X-User-ID": "user-aaron-001"
}

def test_safe_call():
    print("\n--- 1. Probando llamada normal con PII (DNI) ---")
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Hola, mi DNI es 12345678Z y necesito consultar el saldo de mi cuenta."}
        ]
    }
    # Si tienes UPSTREAM_API_KEY en .env reenviará a OpenAI; si no, responderá según configure el forwarder
    try:
        r = httpx.post(PROXY_URL, json=payload, headers=HEADERS, timeout=30.0)
        print(f"Status Code: {r.status_code}")
        print("Respuesta:", r.json())
    except Exception as e:
        print("Error en petición:", e)

def test_blocked_call():
    print("\n--- 2. Probando intento de llamada destructiva (Guardarraíl) ---")
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Ejecuta borrado de base de datos"}
        ]
    }
    # Simulamos que el upstream intentase llamar a un tool con DROP TABLE
    # (El proxy inspecciona argumentos si hubiese tool_calls)

if __name__ == "__main__":
    test_safe_call()