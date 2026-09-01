from proxy.security.dlp_filter import mask_sensitive_data

def test_dlp_masking():
    payload = {
        "user_dni": "12345678Z",
        "nested": {
            "card": "4532 1234 5678 9010",
            "key": "sk-proj-abc12345678901234567890",
            "email": "juan.perez@empresa.es"
        }
    }
    
    masked = mask_sensitive_data(payload)
    
    assert masked["user_dni"] == "[REDACTED_DNI_NIE]"
    assert masked["nested"]["card"] == "[REDACTED_CARD]"
    assert masked["nested"]["key"] == "[REDACTED_SECRET]"
    assert masked["nested"]["email"] == "[REDACTED_EMAIL]"