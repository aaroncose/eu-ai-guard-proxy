import json
import re
from typing import Any, Dict, List, Optional, Tuple

SQL_DESTRUCTIVE_PATTERN = re.compile(
    r"\b(DROP\s+TABLE|DROP\s+DATABASE|DELETE\s+FROM|TRUNCATE\s+TABLE|ALTER\s+TABLE|GRANT\s+ALL)\b",
    re.IGNORECASE
)
SHELL_DESTRUCTIVE_PATTERN = re.compile(
    r"(\brm\s+-rf\b|:\(\)\{\s*:\|:&\s*\};:|chmod\s+777|\bshutdown\b|\breboot\b|>\s*/dev/sda)",
    re.IGNORECASE
)

# Comentario SQL usado como separador, la forma habitual de partir una palabra
# clave para esquivar una comparacion de texto
SQL_COMMENT_PATTERN = re.compile(r"/\*.*?\*/", re.DOTALL)
WHITESPACE_PATTERN = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Deja el texto en la forma que compara el guardarrail.

    Los comentarios SQL intercalados pasan a ser un espacio y cualquier
    secuencia de espacios, tabuladores o saltos se colapsa en uno solo.
    """
    return WHITESPACE_PATTERN.sub(" ", SQL_COMMENT_PATTERN.sub(" ", text)).strip()


def _flatten(value: Any) -> List[str]:
    """Devuelve los textos que hay dentro de un argumento de herramienta."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        pieces = []
        for key, item in value.items():
            pieces.append(str(key))
            pieces.extend(_flatten(item))
        return pieces
    if isinstance(value, list):
        pieces = []
        for item in value:
            pieces.extend(_flatten(item))
        return pieces
    return [str(value)]


def candidate_texts(arg_value: Any) -> List[str]:
    """Textos a inspeccionar de un campo de argumentos.

    Los argumentos llegan como una cadena JSON. Al deserializarla, un
    `DROP\\u0020TABLE` escapado se convierte en el texto que el patron busca.
    """
    texts = [str(arg_value)]
    if isinstance(arg_value, str):
        try:
            texts.extend(_flatten(json.loads(arg_value)))
        except (ValueError, TypeError):
            pass
    else:
        texts.extend(_flatten(arg_value))
    return texts


def inspect_single_argument(arg_value: Any) -> Tuple[bool, Optional[str]]:
    for text in candidate_texts(arg_value):
        normalized = normalize(text)
        if SQL_DESTRUCTIVE_PATTERN.search(normalized):
            return False, "Blocked by AI Guard: Destructive SQL command detected in tool arguments."
        if SHELL_DESTRUCTIVE_PATTERN.search(normalized):
            return False, "Blocked by AI Guard: Destructive shell command detected in tool arguments."
    return True, None


def inspect_tool_calls(tool_calls: Optional[List[Dict[str, Any]]]) -> Tuple[bool, Optional[str]]:
    if not tool_calls:
        return True, None

    for tool in tool_calls:
        function_data = tool.get("function") or {}
        for field in ("name", "arguments"):
            value = function_data.get(field)
            if value in (None, ""):
                continue
            is_safe, reason = inspect_single_argument(value)
            if not is_safe:
                return False, reason

    return True, None
