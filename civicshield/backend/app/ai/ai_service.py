"""AI service: model-first with deterministic fallback + status indicator."""
from __future__ import annotations

from . import muse_spark_adapter as adapter
from . import config as ai_config_mod
from .config import AIConfig, load_ai_config
from .deterministic_fallback import fallback_plan
from .schemas import FindingContext, RemediationPlanPayload


def generate_remediation(
    ctx: FindingContext, config: AIConfig | None = None
) -> RemediationPlanPayload:
    config = config or load_ai_config()
    if config.provider == "disabled":
        plan = fallback_plan(ctx)
        plan.limitations = "AI disabled by configuration; offline template used."
        return plan
    result = adapter.generate_plan(ctx, config)
    if result.ok and result.plan is not None:
        return result.plan
    return fallback_plan(ctx)


def status(config: AIConfig | None = None) -> dict:
    config = config or load_ai_config()
    return {
        "provider": config.provider,
        "model_id": config.model_id,
        "model_available": config.model_enabled,
        # Safe diagnostics: presence of a key, never its value; which .env
        # file (if any) supplied values, so mock/offline is self-explaining.
        "has_key": bool(config.api_key),
        "dotenv_file": ai_config_mod.LAST_DOTENV_FILE,
        "timeout_seconds": config.timeout_seconds,
        "mode": "live" if config.model_enabled else "offline-fallback",
    }
