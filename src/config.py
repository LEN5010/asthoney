from __future__ import annotations

import asyncio
import logging
import random
from functools import lru_cache
from http import HTTPStatus
from typing import Any

import dashscope
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from dashscope.common.error import APIError as DashScopeAPIError
    from dashscope.common.error import InvalidTask
    from dashscope.common.error import RateLimitError
except Exception:  # pragma: no cover - compatibility for older SDK variants
    class RateLimitError(Exception):
        pass

    class DashScopeAPIError(Exception):
        pass

    class InvalidTask(Exception):
        pass


class DashScopeInvocationError(RuntimeError):
    """Raised when a DashScope invocation cannot be completed."""


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Generative Infinite Deception Maze"
    app_env: str = "development"
    log_level: str = "INFO"

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    honeypot_bind_host: str = "0.0.0.0"
    honeypot_ports: str = "2222,2323"
    honeypot_protocols: str = "ssh,tcp"
    honeypot_read_timeout_seconds: float = 45.0
    honeypot_write_prompt: str = "maze@corp-gateway:~$ "
    honeypot_ssh_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    session_memory_window: int = 12
    synthetic_subnet: str = "10.0.5.0/24"
    default_persona: str = "compromised_linux_terminal"

    dashscope_api_key: str = ""
    dashscope_model: str = "qwen-max"
    dashscope_timeout_seconds: float = 45.0
    dashscope_max_retries: int = 4
    dashscope_retry_base_seconds: float = 1.25
    dashscope_temperature: float = 0.25
    dashscope_top_p: float = 0.85

    neo4j_uri: str = "bolt://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "please_change_me"
    neo4j_database: str = "neo4j"
    neo4j_encrypted: bool = False

    oss_endpoint: str = ""
    oss_access_key_id: str = ""
    oss_access_key_secret: str = ""
    oss_bucket_name: str = ""

    mcp_trap_token: str = "maze-trap-token"
    preemptive_action_mode: str = "simulate"
    alert_severity_threshold: str = "high"

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        return value.upper()

    @field_validator("honeypot_protocols")
    @classmethod
    def normalize_protocols(cls, value: str) -> str:
        return ",".join([item.strip().lower() for item in value.split(",") if item.strip()])

    @property
    def honeypot_ports_list(self) -> list[int]:
        ports: list[int] = []
        for item in self.honeypot_ports.split(","):
            item = item.strip()
            if not item:
                continue
            ports.append(int(item))
        return ports

    @property
    def honeypot_protocol_list(self) -> list[str]:
        return [item.strip().lower() for item in self.honeypot_protocols.split(",") if item.strip()]


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()


class DashScopeClient:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self.logger = logging.getLogger(self.__class__.__name__)
        if settings.dashscope_api_key:
            dashscope.api_key = settings.dashscope_api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.settings.dashscope_api_key)

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
    ) -> str:
        if not self.is_configured:
            raise DashScopeInvocationError("DASHSCOPE_API_KEY is not configured")

        chosen_model = model or self.settings.dashscope_model
        chosen_temperature = (
            self.settings.dashscope_temperature if temperature is None else temperature
        )
        chosen_top_p = self.settings.dashscope_top_p if top_p is None else top_p

        last_error: Exception | None = None
        for attempt in range(1, self.settings.dashscope_max_retries + 1):
            try:
                response = await self._invoke(
                    model=chosen_model,
                    messages=messages,
                    temperature=chosen_temperature,
                    top_p=chosen_top_p,
                )
                return self._extract_text(response)
            except RateLimitError as exc:
                last_error = exc
                delay = self._backoff(attempt)
                self.logger.warning(
                    "DashScope rate limited on attempt %s/%s; retrying in %.2fs",
                    attempt,
                    self.settings.dashscope_max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
            except (DashScopeAPIError, InvalidTask, TimeoutError) as exc:
                last_error = exc
                delay = self._backoff(attempt)
                self.logger.warning(
                    "DashScope transient failure on attempt %s/%s: %s; retrying in %.2fs",
                    attempt,
                    self.settings.dashscope_max_retries,
                    exc,
                    delay,
                )
                await asyncio.sleep(delay)
            except Exception as exc:  # pragma: no cover - defensive path for SDK differences
                last_error = exc
                self.logger.exception("DashScope invocation failed with an unexpected error")
                break

        raise DashScopeInvocationError(
            f"DashScope invocation failed after {self.settings.dashscope_max_retries} attempts"
        ) from last_error

    async def _invoke(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        top_p: float,
    ) -> Any:
        generation = getattr(dashscope, "Generation", None)
        if generation is None:
            raise DashScopeInvocationError("dashscope.Generation is unavailable")

        kwargs = {
            "model": model,
            "messages": messages,
            "result_format": "message",
            "temperature": temperature,
            "top_p": top_p,
        }

        if hasattr(generation, "acall") and callable(generation.acall):
            return await generation.acall(**kwargs)

        return await asyncio.to_thread(generation.call, **kwargs)

    def _extract_text(self, response: Any) -> str:
        status_code = getattr(response, "status_code", None)
        if status_code is not None and int(status_code) not in (HTTPStatus.OK, 200):
            code = getattr(response, "code", "unknown")
            message = getattr(response, "message", "unknown DashScope error")
            raise DashScopeInvocationError(f"DashScope returned {status_code} {code}: {message}")

        if isinstance(response, dict):
            payload = response.get("output", response)
            return self._extract_text_from_payload(payload)

        payload = getattr(response, "output", response)
        return self._extract_text_from_payload(payload)

    def _extract_text_from_payload(self, payload: Any) -> str:
        if isinstance(payload, dict):
            choices = payload.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                content = message.get("content", "")
                return self._normalize_content(content)
            for key in ("text", "content"):
                if payload.get(key):
                    return self._normalize_content(payload[key])

        choices = getattr(payload, "choices", None)
        if choices:
            first_choice = choices[0]
            message = getattr(first_choice, "message", None)
            if message is not None:
                content = getattr(message, "content", "")
                return self._normalize_content(content)
            text = getattr(first_choice, "text", None)
            if text:
                return self._normalize_content(text)

        text = getattr(payload, "text", None)
        if text:
            return self._normalize_content(text)

        content = getattr(payload, "content", None)
        if content:
            return self._normalize_content(content)

        raise DashScopeInvocationError("DashScope returned an unreadable response payload")

    def _normalize_content(self, content: Any) -> str:
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    value = item.get("text") or item.get("content") or ""
                    if value:
                        parts.append(str(value))
                else:
                    parts.append(str(item))
            return "\n".join(part for part in parts if part).strip()
        return str(content).strip()

    def _backoff(self, attempt: int) -> float:
        base = self.settings.dashscope_retry_base_seconds
        jitter = random.uniform(0.1, 0.5)
        return base * (2 ** (attempt - 1)) + jitter
