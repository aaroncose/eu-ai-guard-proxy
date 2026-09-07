import re
from typing import Any, Dict, List, Union

DNI_NIE_PATTERN = re.compile(r"\b[XYZxyz]?\d{7,8}[A-HJ-NP-TV-Z]\b")
# Rango de longitud de un PAN segun ISO/IEC 7812, con separadores opcionales
CARD_CANDIDATE_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SECRET_KEY_PATTERN = re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9\.\-_]{15,})\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")


def passes_luhn(digits: str) -> bool:
    """Comprueba el digito de control de Luhn, el que valida un PAN.

    Sin esta comprobacion, cualquier cifra larga (un importe, un identificador
    interno) se enmascara como si fuera una tarjeta.
    """
    if not digits.isdigit():
        return False

    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card(match: re.Match) -> str:
    digits = re.sub(r"[ -]", "", match.group(0))
    if 13 <= len(digits) <= 19 and passes_luhn(digits):
        return "[REDACTED_CARD]"
    return match.group(0)


def mask_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    # El DNI y el NIE se enmascaran sin validar la letra de control, porque un
    # identificador mal tecleado sigue siendo un dato personal
    text = DNI_NIE_PATTERN.sub("[REDACTED_DNI_NIE]", text)
    text = CARD_CANDIDATE_PATTERN.sub(_mask_card, text)
    text = SECRET_KEY_PATTERN.sub("[REDACTED_SECRET]", text)
    text = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    return text


def mask_sensitive_data(payload: Union[Dict[str, Any], List[Any], str, Any]) -> Any:
    if isinstance(payload, dict):
        return {k: mask_sensitive_data(v) for k, v in payload.items()}
    elif isinstance(payload, list):
        return [mask_sensitive_data(item) for item in payload]
    elif isinstance(payload, str):
        return mask_text(payload)
    return payload
