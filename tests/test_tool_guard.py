from proxy.security.tool_guard import inspect_tool_calls

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
