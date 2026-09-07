import json

from proxy.security.tool_guard import inspect_tool_calls, normalize


def test_tool_guard_blocks_destructive_sql():
    tool_calls = [{
        "function": {
            "name": "execute_query",
            "arguments": "{\"query\": \"DROP TABLE users;\"}"
        }
    }]
    is_safe, reason = inspect_tool_calls(tool_calls)
    assert is_safe is False
    assert "Destructive SQL" in reason


def test_tool_guard_allows_safe_calls():
    tool_calls = [{
        "function": {
            "name": "get_weather",
            "arguments": "{\"city\": \"Valencia\"}"
        }
    }]
    is_safe, reason = inspect_tool_calls(tool_calls)
    assert is_safe is True
    assert reason is None


def test_tool_guard_blocks_sql_split_by_comment():
    tool_calls = [{
        "function": {
            "name": "execute_query",
            "arguments": json.dumps({"query": "DROP/**/TABLE clientes"})
        }
    }]
    is_safe, reason = inspect_tool_calls(tool_calls)
    assert is_safe is False
    assert "Destructive SQL" in reason


def test_tool_guard_blocks_escaped_whitespace_in_json():
    # El espacio llega escapado, asi que solo aparece tras deserializar
    tool_calls = [{
        "function": {
            "name": "execute_query",
            "arguments": "{\"query\": \"DELETE\\u0020FROM pedidos\"}"
        }
    }]
    is_safe, reason = inspect_tool_calls(tool_calls)
    assert is_safe is False


def test_tool_guard_inspects_multiline_arguments():
    tool_calls = [{
        "function": {
            "name": "run_script",
            "arguments": json.dumps({"cmd": "echo hola\n   rm   -rf   /var"})
        }
    }]
    is_safe, reason = inspect_tool_calls(tool_calls)
    assert is_safe is False
    assert "shell" in reason.lower()


def test_normalize_collapses_whitespace_and_comments():
    assert normalize("DROP/**/TABLE   users") == "DROP TABLE users"
