"""Environment-based configuration for the AI provider.

Never read API keys in frontend code. All values come from backend env vars.

Vars:
  CIVICSHIELD_AI_PROVIDER: "muse_spark" | "mock" | "disabled" (default: mock)
  META_API_KEY: bearer token for Meta Model API (required for muse_spark)
  META_API_BASE_URL: override base URL (default https://api.meta.com/v1)
  META_MODEL_ID: model identifier (default "muse-spark")
  AI_TIMEOUT_SECONDS: per-request timeout (default 15.0)
  AI_MAX_RETRIES: retries on transient errors (default 1)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_BASE_URL = "https://api.meta.com/v1"
DEFAULT_MODEL_ID = "muse-spark"


@dataclass(frozen=True)
class AIConfig:
    provider: str = "mock"
    api_key: str | None = None
    base_url: str = DEFAULT_BASE_URL
    model_id: str = DEFAULT_MODEL_ID
    timeout_seconds: float = 15.0
    max_retries: int = 1

    @property
    def model_enabled(self) -> bool:
        return self.provider == "muse_spark" and bool(self.api_key)


#: Path of the .env file most recently loaded by _load_dotenv (None if none).
#: Reported via ai_service.status() so a mock/offline status is diagnosable
#: without ever exposing the key itself.
LAST_DOTENV_FILE: str | None = None


def _load_dotenv() -> str | None:
    """Load KEY=VALUE lines from a nearby .env into os.environ (no override).

    The backend previously read os.environ only, so a key saved in a `.env`
    file was silently ignored (status stayed mock/offline-fallback).
    Searches: $CIVICSHIELD_DOTENV, cwd/.env, this file's backend/ and repo
    parents' .env. Stdlib only; missing files are a no-op. Returns the first
    file that contributed at least one value, else None.
    """
    global LAST_DOTENV_FILE
    candidates: list[Path] = []
    explicit = os.environ.get("CIVICSHIELD_DOTENV")
    if explicit:
        candidates.append(Path(explicit))
    here = Path(__file__).resolve()
    candidates.append(Path.cwd() / ".env")
    for parent in [here, *here.parents]:
        candidates.append(parent / ".env")
        if parent.name == "civicshield":
            break
    seen: set[str] = set()
    loaded_from: str | None = None
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.lower().startswith("export "):
                line = line[7:].strip()
            name, _, value = line.partition("=")
            name = name.strip()
            if not name or name in os.environ or not name.isidentifier():
                continue
            value = value.strip().strip('"').strip("'")
            if value == "":
                continue  # empty placeholder: behave as unset so a later
                # filled-in value is picked up without a restart
            os.environ[name] = value
            if loaded_from is None:
                loaded_from = str(path)
    if loaded_from is not None:
        LAST_DOTENV_FILE = loaded_from
    return loaded_from


def load_ai_config(env: dict | None = None) -> AIConfig:
    if env is None:
        _load_dotenv()
    src = env if env is not None else os.environ
    provider = str(src.get("CIVICSHIELD_AI_PROVIDER", "mock")).strip().lower()
    if provider not in ("muse_spark", "mock", "disabled"):
        provider = "mock"
    try:
        timeout = float(src.get("AI_TIMEOUT_SECONDS", 15.0))
    except (TypeError, ValueError):
        timeout = 15.0
    timeout = min(max(timeout, 1.0), 120.0)
    try:
        retries = int(src.get("AI_MAX_RETRIES", 1))
    except (TypeError, ValueError):
        retries = 1
    retries = min(max(retries, 0), 3)
    return AIConfig(
        provider=provider,
        api_key=src.get("META_API_KEY") or None,
        base_url=str(src.get("META_API_BASE_URL", DEFAULT_BASE_URL)).rstrip("/"),
        model_id=str(src.get("META_MODEL_ID", DEFAULT_MODEL_ID)),
        timeout_seconds=timeout,
        max_retries=retries,
    )
