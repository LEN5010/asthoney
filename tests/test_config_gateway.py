import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from src.config import AppSettings, DashScopeClient


def test_openai_compatible_url_appends_v1_chat_completions():
    settings = AppSettings(dashscope_base_url="https://gateway.example.com")
    assert settings.openai_compatible_chat_url == "https://gateway.example.com/v1/chat/completions"


def test_openai_compatible_url_keeps_existing_v1():
    settings = AppSettings(dashscope_base_url="https://gateway.example.com/v1")
    assert settings.openai_compatible_chat_url == "https://gateway.example.com/v1/chat/completions"


def test_empty_base_url_disables_openai_compatible_path():
    settings = AppSettings(dashscope_base_url="")
    assert settings.openai_compatible_chat_url is None


@pytest.mark.parametrize("effort", ["", "low", "medium", "high"])
def test_gateway_forwards_only_configured_reasoning_effort(monkeypatch, effort):
    """Check the actual HTTP body without calling a real model or loading local secrets."""
    settings = AppSettings(
        _env_file=None,
        dashscope_api_key="test-key",
        dashscope_base_url="https://gateway.example.com/v1",
        dashscope_model="test-model",
        dashscope_reasoning_effort=effort,
    )
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(respond), **kwargs),
    )
    result = asyncio.run(DashScopeClient(settings).chat([{"role": "user", "content": "hello"}]))
    assert result == "ok"
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url) == "https://gateway.example.com/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-key"
    payload = json.loads(request.content)
    assert payload["model"] == "test-model"
    if effort:
        assert payload["reasoning_effort"] == effort
    else:
        assert "reasoning_effort" not in payload


def test_invalid_reasoning_effort_fails_configuration():
    with pytest.raises(ValidationError):
        AppSettings(_env_file=None, dashscope_reasoning_effort="typo")
