from src.config import AppSettings


def test_openai_compatible_url_appends_v1_chat_completions():
    settings = AppSettings(dashscope_base_url="https://gateway.example.com")
    assert settings.openai_compatible_chat_url == "https://gateway.example.com/v1/chat/completions"


def test_openai_compatible_url_keeps_existing_v1():
    settings = AppSettings(dashscope_base_url="https://gateway.example.com/v1")
    assert settings.openai_compatible_chat_url == "https://gateway.example.com/v1/chat/completions"


def test_empty_base_url_disables_openai_compatible_path():
    settings = AppSettings(dashscope_base_url="")
    assert settings.openai_compatible_chat_url is None
