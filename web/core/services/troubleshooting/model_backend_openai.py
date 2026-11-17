"""OpenAI Responses API backend for the completion-only model broker (Codex identity).

One plain ``responses.create`` call per request with no tools declared, so the
model can only return text.  Failures become stable codes for the orchestrator.
"""

from __future__ import annotations

from typing import Any

from .model_broker import (
    AUTHENTICATION_UNAVAILABLE, CONTEXT_EXHAUSTED, OUTPUT_TRUNCATED, PROVIDER_ERROR, PROVIDER_REFUSED,
    PROVIDER_REQUEST_REJECTED, PROVIDER_TIMEOUT, PROVIDER_UNREACHABLE, QUOTA_EXHAUSTED, RATE_LIMITED, BackendError,
)


_QUOTA_MARKERS = frozenset({"insufficient_quota", "credit_balance_exhausted", "billing_hard_limit_reached", "billing_not_active"})


def _retry_after(error: Any) -> float | None:
    try:
        return float(error.response.headers.get("retry-after"))
    except (AttributeError, TypeError, ValueError):
        return None


class OpenAICompletionBackend:
    def __init__(self, *, model: str, api_key: str, timeout: float = 50.0, max_tokens: int = 16000, client: Any = None):
        import openai

        self._sdk = openai
        self.model = str(model)
        self.max_tokens = int(max_tokens)
        self.credential_configured = bool(api_key) or client is not None
        self.client = client if client is not None else (
            openai.OpenAI(api_key=api_key, timeout=timeout, max_retries=0) if api_key else None)

    def complete(self, system: str, prompt: str) -> tuple[str, dict]:
        sdk = self._sdk
        if self.client is None:
            raise BackendError(AUTHENTICATION_UNAVAILABLE)
        try:
            response = self.client.responses.create(model=self.model, instructions=system, input=prompt,
                                                    max_output_tokens=self.max_tokens, store=False)
        except (sdk.AuthenticationError, sdk.PermissionDeniedError) as exc:
            raise BackendError(AUTHENTICATION_UNAVAILABLE) from exc
        except sdk.RateLimitError as exc:
            # HTTP 429 covers two different conditions.  An exhausted credit balance or billing limit is reported with
            # type ``insufficient_quota`` and codes such as ``credit_balance_exhausted``; retrying does not help.
            if _QUOTA_MARKERS & {str(getattr(exc, "code", "") or ""), str(getattr(exc, "type", "") or "")}:
                raise BackendError(QUOTA_EXHAUSTED) from exc
            raise BackendError(RATE_LIMITED, retry_after=_retry_after(exc)) from exc
        except sdk.BadRequestError as exc:
            if str(getattr(exc, "code", "") or "") == "context_length_exceeded":
                raise BackendError(CONTEXT_EXHAUSTED) from exc
            raise BackendError(PROVIDER_REQUEST_REJECTED) from exc
        except sdk.APITimeoutError as exc:
            raise BackendError(PROVIDER_TIMEOUT) from exc
        except sdk.APIConnectionError as exc:
            raise BackendError(PROVIDER_UNREACHABLE) from exc
        except sdk.APIStatusError as exc:
            raise BackendError(PROVIDER_ERROR if exc.status_code >= 500 else PROVIDER_REQUEST_REJECTED) from exc
        if getattr(response, "status", "") == "incomplete":
            raise BackendError(OUTPUT_TRUNCATED)
        text = getattr(response, "output_text", "") or ""
        if not text and any(getattr(part, "type", "") == "refusal" for item in (getattr(response, "output", None) or [])
                            for part in (getattr(item, "content", None) or [])):
            raise BackendError(PROVIDER_REFUSED)
        usage = getattr(response, "usage", None)
        return text, {"input_tokens": getattr(usage, "input_tokens", None), "output_tokens": getattr(usage, "output_tokens", None)}
