from proxy.security.dlp_filter import mask_sensitive_data, mask_text, passes_luhn


def test_dlp_masking():
    payload = {
        "user_dni": "12345678Z",
        "nested": {
            # PAN de prueba de Visa, valido segun Luhn
            "card": "4111 1111 1111 1111",
            "key": "sk-proj-abc12345678901234567890",
            "email": "juan.perez@empresa.es"
        }
    }
    
    masked = mask_sensitive_data(payload)
    
    assert masked["user_dni"] == "[REDACTED_DNI_NIE]"
    assert masked["nested"]["card"] == "[REDACTED_CARD]"
    assert masked["nested"]["key"] == "[REDACTED_SECRET]"
    assert masked["nested"]["email"] == "[REDACTED_EMAIL]"


def test_luhn_accepts_known_test_pans():
    assert passes_luhn("4111111111111111") is True
    assert passes_luhn("5555555555554444") is True
    assert passes_luhn("378282246310005") is True


def test_luhn_rejects_arbitrary_digits():
    assert passes_luhn("1234567890123456") is False
    assert passes_luhn("4532123456789010") is False


def test_long_number_without_check_digit_is_left_alone():
    # Un importe o un identificador interno deja de enmascararse como tarjeta
    assert mask_text("total 12345678901234 euros") == "total 12345678901234 euros"
    assert mask_text("referencia 4532 1234 5678 9010") == "referencia 4532 1234 5678 9010"


def test_card_with_separators_is_masked():
    assert mask_text("pago con 4111-1111-1111-1111 hoy") == "pago con [REDACTED_CARD] hoy"
