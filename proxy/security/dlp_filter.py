import re
from typing import Any, Dict, List, Union

DNI_NIE_PATTERN = re.compile(r"\b[XYZxyz]?\d{7,8}[A-HJ-NP-TV-Z]\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
SECRET_KEY_PATTERN = re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9\.\-_]{15,})\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

def mask_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = DNI_NIE_PATTERN.sub("[REDACTED_DNI_NIE]", text)
    text = CREDIT_CARD_PATTERN.sub("[REDACTED_CARD]", text)
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