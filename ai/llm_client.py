"""
LLM client — NVIDIA DeepSeek primary, Gemini fallback, with caching + rate limiting.

Features:
- Response caching (hash of prompt → cached for AI_CACHE_TTL_SECONDS)
- Per-topic debouncing (min interval between same-topic calls)
- Request coalescing (concurrent same-prompt requests share one API call)
- Graceful fallback: NVIDIA → Gemini → local heuristic
- Non-blocking async API
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.logger import get_logger

log = get_logger("llm")


# ---------- Load .env ----------
def _load_env() -> dict[str, str]:
    env_file = Path(__file__).resolve().parent.parent / ".env"
    env: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    # Also allow real env vars to override
    for k in list(env):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


_env = _load_env()

NVIDIA_API_KEY = _env.get("NVIDIA_API_KEY", "")
# Candidate models — tried in order. If one is EOL/404, falls to next.
NVIDIA_MODEL_CANDIDATES = [
    _env.get("NVIDIA_MODEL", ""),
    "meta/llama-3.3-70b-instruct",
    "meta/llama-3.1-8b-instruct",
    "nvidia/llama-3.1-nemotron-70b-instruct",
    "mistralai/mistral-7b-instruct-v0.3",
    "google/gemma-2-9b-it",
]
# Remove empties + dedupe keeping order
_seen = set()
NVIDIA_MODEL_CANDIDATES = [m for m in NVIDIA_MODEL_CANDIDATES if m and not (m in _seen or _seen.add(m))]

GEMINI_API_KEY = _env.get("GEMINI_API_KEY", "")
GEMINI_MODEL = _env.get("GEMINI_MODEL", "gemini-2.0-flash-exp")

CACHE_TTL = int(_env.get("AI_CACHE_TTL_SECONDS", "60"))
MIN_INTERVAL = float(_env.get("AI_MIN_INTERVAL_SECONDS", "5"))
MAX_TOKENS = int(_env.get("AI_MAX_TOKENS", "1024"))


# ---------- Cache & coalescing ----------
@dataclass
class _CacheEntry:
    value: str
    expires_at: float
    provider: str = "cache"


class LLMClient:
    """
    Thread + asyncio safe LLM client with fallback chain.
    """

    def __init__(self) -> None:
        self._cache: dict[str, _CacheEntry] = {}
        self._last_call_by_topic: dict[str, float] = {}
        self._in_flight: dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()

        # Usage tracking
        self._usage = {
            "calls_total": 0,
            "calls_nvidia": 0,
            "calls_gemini": 0,
            "calls_cached": 0,
            "calls_fallback": 0,
            "errors": 0,
            "first_call_at": None,
            "last_call_at": None,
        }
        # Soft cap (per session) — warns when approaching
        self.soft_cap_per_session = 200

        # Providers
        self._nvidia_client = None
        self._gemini_model = None
        self._nvidia_model: str | None = None   # selected at first successful call

        if NVIDIA_API_KEY:
            try:
                from openai import OpenAI
                self._nvidia_client = OpenAI(
                    base_url="https://integrate.api.nvidia.com/v1",
                    api_key=NVIDIA_API_KEY,
                )
                log.info(f"NVIDIA LLM ready (candidates: {NVIDIA_MODEL_CANDIDATES[:3]}...)")
            except Exception as e:  # noqa: BLE001
                log.warning(f"NVIDIA client init failed: {e}")

        if GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=GEMINI_API_KEY)
                self._gemini_model = genai.GenerativeModel(GEMINI_MODEL)
                log.info(f"Gemini LLM ready ({GEMINI_MODEL})")
            except Exception as e:  # noqa: BLE001
                log.warning(f"Gemini client init failed: {e}")

    # -------- Public API --------

    @property
    def available(self) -> bool:
        return self._nvidia_client is not None or self._gemini_model is not None

    def providers(self) -> list[str]:
        out = []
        if self._nvidia_client: out.append("nvidia:deepseek")
        if self._gemini_model: out.append("gemini")
        if not out: out.append("rule-based-fallback")
        return out

    async def ask(
        self,
        prompt: str,
        system: str = "",
        topic: str | None = None,
        max_tokens: int | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Ask LLM. Returns {'text': str, 'provider': str, 'cached': bool, 'latency_ms': int}.

        - topic: bucket name for debouncing (same topic calls limited to 1 per MIN_INTERVAL).
        - use_cache: if True, identical prompts within CACHE_TTL return cached response.
        """
        prompt = prompt.strip()
        if not prompt:
            return {"text": "", "provider": "empty", "cached": False, "latency_ms": 0}

        key = self._cache_key(system, prompt)
        now = time.time()

        # 1) Check cache
        if use_cache:
            entry = self._cache.get(key)
            if entry and entry.expires_at > now:
                self._usage["calls_cached"] += 1
                return {"text": entry.value, "provider": entry.provider + "+cache", "cached": True, "latency_ms": 0}

        # 2) Topic debounce
        if topic and topic in self._last_call_by_topic:
            elapsed = now - self._last_call_by_topic[topic]
            if elapsed < MIN_INTERVAL:
                return {
                    "text": f"[rate-limited: wait {MIN_INTERVAL - elapsed:.1f}s for topic '{topic}']",
                    "provider": "rate-limit",
                    "cached": False,
                    "latency_ms": 0,
                }

        # 3) Request coalescing
        if key in self._in_flight:
            fut = self._in_flight[key]
            try:
                text = await asyncio.wait_for(fut, timeout=30)
                return {"text": text, "provider": "coalesced", "cached": True, "latency_ms": 0}
            except Exception:
                pass

        # 4) Make the call
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        self._in_flight[key] = fut
        start = time.time()

        try:
            text, provider = await self._call_with_fallback(system, prompt, max_tokens or MAX_TOKENS)
            latency_ms = int((time.time() - start) * 1000)

            # Cache + track topic
            if text and not text.startswith("[error"):
                self._cache[key] = _CacheEntry(value=text, expires_at=now + CACHE_TTL, provider=provider)
            if topic:
                self._last_call_by_topic[topic] = now

            fut.set_result(text)
            return {"text": text, "provider": provider, "cached": False, "latency_ms": latency_ms}
        except Exception as e:  # noqa: BLE001
            fut.set_exception(e)
            return {"text": f"[error: {e}]", "provider": "error", "cached": False, "latency_ms": 0}
        finally:
            self._in_flight.pop(key, None)

    def ask_sync(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Blocking wrapper for sync callers."""
        try:
            loop = asyncio.get_running_loop()
            fut = asyncio.run_coroutine_threadsafe(self.ask(*args, **kwargs), loop)
            return fut.result(timeout=35)
        except RuntimeError:
            return asyncio.run(self.ask(*args, **kwargs))

    # -------- Internal --------

    @staticmethod
    def _cache_key(system: str, prompt: str) -> str:
        h = hashlib.sha256()
        h.update(system.encode("utf-8"))
        h.update(b"||")
        h.update(prompt.encode("utf-8"))
        return h.hexdigest()[:32]

    async def _call_with_fallback(
        self, system: str, prompt: str, max_tokens: int,
    ) -> tuple[str, str]:
        import time as _t
        self._usage["calls_total"] += 1
        if self._usage["first_call_at"] is None:
            self._usage["first_call_at"] = _t.time()
        self._usage["last_call_at"] = _t.time()

        # NVIDIA first
        if self._nvidia_client:
            try:
                text = await self._call_nvidia(system, prompt, max_tokens)
                if text:
                    self._usage["calls_nvidia"] += 1
                    return text, "nvidia"
            except Exception as e:  # noqa: BLE001
                log.warning(f"NVIDIA call failed: {e}")
                self._usage["errors"] += 1

        # Gemini fallback
        if self._gemini_model:
            try:
                text = await self._call_gemini(system, prompt, max_tokens)
                if text:
                    self._usage["calls_gemini"] += 1
                    return text, "gemini"
            except Exception as e:  # noqa: BLE001
                log.warning(f"Gemini call failed: {e}")
                self._usage["errors"] += 1

        # Ultimate fallback
        self._usage["calls_fallback"] += 1
        return self._local_fallback(prompt), "local-fallback"

    def usage_stats(self) -> dict:
        """Return current LLM usage counters."""
        u = dict(self._usage)
        u["soft_cap"] = self.soft_cap_per_session
        u["soft_cap_warn"] = u["calls_total"] >= int(self.soft_cap_per_session * 0.8)
        u["soft_cap_exceeded"] = u["calls_total"] >= self.soft_cap_per_session
        return u

    async def _call_nvidia(self, system: str, prompt: str, max_tokens: int) -> str:
        """Call NVIDIA via OpenAI-compatible SDK with model fallback chain."""
        def _try_model(model_name: str) -> str:
            messages: list[dict[str, str]] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            resp = self._nvidia_client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=0.7,
                top_p=0.95,
                max_tokens=max_tokens,
                stream=False,
            )
            return resp.choices[0].message.content or ""

        def _blocking() -> str:
            # If we already found a working model, use it
            if self._nvidia_model:
                try:
                    return _try_model(self._nvidia_model)
                except Exception as e:
                    # Model might be deprecated now; drop and retry
                    msg = str(e).lower()
                    if "410" in msg or "gone" in msg or "404" in msg or "not found" in msg:
                        log.warning(f"Model {self._nvidia_model} no longer available, retrying...")
                        self._nvidia_model = None
                    else:
                        raise

            # Try candidates in order
            last_err = None
            for model in NVIDIA_MODEL_CANDIDATES:
                try:
                    text = _try_model(model)
                    self._nvidia_model = model  # cache successful
                    log.info(f"NVIDIA using model: {model}")
                    return text
                except Exception as e:
                    last_err = e
                    msg = str(e).lower()
                    if "410" in msg or "gone" in msg or "404" in msg or "not found" in msg:
                        continue  # try next
                    raise
            raise RuntimeError(f"all NVIDIA candidates failed; last error: {last_err}")

        return await asyncio.get_event_loop().run_in_executor(None, _blocking)

    async def _call_gemini(self, system: str, prompt: str, max_tokens: int) -> str:
        """Call Gemini."""
        def _blocking() -> str:
            full_prompt = f"{system}\n\n{prompt}" if system else prompt
            resp = self._gemini_model.generate_content(
                full_prompt,
                generation_config={
                    "max_output_tokens": max_tokens,
                    "temperature": 0.7,
                },
            )
            return resp.text or ""

        return await asyncio.get_event_loop().run_in_executor(None, _blocking)

    @staticmethod
    def _local_fallback(prompt: str) -> str:
        """Deterministic rule-based response when no LLM available."""
        prompt_lower = prompt.lower()
        if "cpu" in prompt_lower and any(x in prompt_lower for x in ("high", "spike", "100")):
            return "High CPU detected. Recommend killing the top CPU process and monitoring for repeated offenders."
        if "memory" in prompt_lower or "ram" in prompt_lower:
            return "Memory pressure detected. Recommend clearing temp files and killing top memory-consuming process."
        if "disk" in prompt_lower:
            return "Disk usage high. Recommend cleanup of cached files and log rotation."
        if "solved" in prompt_lower or "fixed" in prompt_lower:
            return "Based on current metrics, the issue appears to be resolved."
        return "System telemetry ingested. No immediate action required — continue monitoring."


# Global singleton
client = LLMClient()
