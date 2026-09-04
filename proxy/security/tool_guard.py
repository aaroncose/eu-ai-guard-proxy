import re
from typing import Any, Dict, List, Tuple, Optional

SQL_DESTRUCTIVE_PATTERN = re.compile(
    r"\b(DROP\s+TABLE|DROP\s+DATABASE|DELETE\s+FROM|TRUNCATE\s+TABLE|ALTER\s+TABLE|GRANT\s+ALL)\b",
    re.IGNORECASE
)
SHELL_DESTRUCTIVE_PATTERN = re.compile(
    r"(\brm\s+-rf\b|:\(\)\{\s*:\|:&\s*\};:|chmod\s+777|\bshutdown\b|\breboot\b|>\s*/dev/sda)",
    re.IGNORECASE
)

def inspect_single_argument(arg_value: Any) -> Tuple[bool, Optional[str]]:
    text = str(arg_value)
    if SQL_DESTRUCTIVE_PATTERN.search(text):
        return False, "Blocked by AI Guard: Destructive SQL command detected in tool arguments."
    if SHELL_DESTRUCTIVE_PATTERN.search(text):
        return False, "Blocked by AI Guard: Destructive shell command detected in tool arguments."
    return True, None

def inspect_tool_calls(tool_calls: Optional[List[Dict[str, Any]]]) -> Tuple[bool, Optional[str]]:
    if not tool_calls:
        return True, None

    for tool in tool_calls:
        function_data = tool.get("function", {})
        arguments = function_data.get("arguments", "")
        is_safe, reason = inspect_single_argument(arguments)
        if not is_safe:
            return False, reason

    return True, None