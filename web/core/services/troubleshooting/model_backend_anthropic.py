"""Anthropic Messages API backend for the completion-only model broker (ClaudeA / ClaudeB).

One plain ``messages.create`` call per request: no tools, no server tools, no
files, no MCP and no code execution are declared, so the model can only return
text.  The broker pins a single model identity; refusals and provider failures
are surfaced as stable codes so the global orchestrator fails over to the next
agent rather than this backend silently substituting another model.
"""

from __future__ import annotations

from typing import Any

from .model_broker import (
    AUTHENTICATION_UNAVAILABLE, CONTEXT_EXHAUSTED, OUTPUT_TRUNCATED, PROVIDER_ERROR, PROVIDER_REFUSED,
    PROVIDER_REQUEST_REJECTED, PROVIDER_TIMEOUT, PROVIDER_UNREACHABLE, QUOTA_EXHAUSTED, RATE_LIMITED, BackendError,
)

EFFORTS = ("low", "medium", "high")


def _retry_after(error: Any) -> float | None:
    try:
        return float(error.response.headers.get("retry-after"))
    except (AttributeError, TypeError, ValueError):
        return None


class AnthropicCompletionBackend:
    def __init__(self, *, model: str, api_key: str, timeout: float = 50.0, max_tokens: int = 16000, effort: str = "medium",
                 client: Any = None):
        import anthropic  # pylint: disable=import-error  # installed only in the model-broker runtime (deploy/sandbox/model-broker-requirements.txt)

        self._sdk = anthropic
        self.model = str(model)
        self.max_tokens = int(max_tokens)
        self.effort = effort if effort in EFFORTS else "medium"
        self.credential_configured = bool(api_key) or client is not None
        # One bounded attempt: retries and failover belong to the orchestrator, which holds the fenced lease.
        self.client = client if client is not None else (
            anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0) if api_key else None)

    def complete(self, system: str, prompt: str) -> tuple[str, dict]:
        sdk = self._sdk
        if self.client is None:
            raise BackendError(AUTHENTICATION_UNAVAILABLE)
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                output_config={"effort": self.effort},
                messages=[{"role": "user", "content": prompt}],
            )
        except (sdk.AuthenticationError, sdk.PermissionDeniedError) as exc:
            raise BackendError(AUTHENTICATION_UNAVAILABLE) from exc
        except sdk.RateLimitError as exc:
            raise BackendError(RATE_LIMITED, retry_after=_retry_after(exc)) from exc
        except sdk.BadRequestError as exc:
            message = str(getattr(exc, "message", "") or "").lower()
            if "credit balance" in message or "billing" in message:
                raise BackendError(QUOTA_EXHAUSTED) from exc
            if "prompt is too long" in message or "context" in message:
                raise BackendError(CONTEXT_EXHAUSTED) from exc
            raise BackendError(PROVIDER_REQUEST_REJECTED) from exc
        except sdk.APITimeoutError as exc:
            raise BackendError(PROVIDER_TIMEOUT) from exc
        except sdk.APIConnectionError as exc:
            raise BackendError(PROVIDER_UNREACHABLE) from exc
        except sdk.APIStatusError as exc:
            raise BackendError(PROVIDER_ERROR if exc.status_code >= 500 else PROVIDER_REQUEST_REJECTED) from exc
        if response.stop_reason == "refusal":
            raise BackendError(PROVIDER_REFUSED)
        if response.stop_reason == "max_tokens":
            raise BackendError(OUTPUT_TRUNCATED)
        text = "".join(block.text for block in response.content if block.type == "text")
        usage = getattr(response, "usage", None)
        return text, {"input_tokens": getattr(usage, "input_tokens", None), "output_tokens": getattr(usage, "output_tokens", None)}
