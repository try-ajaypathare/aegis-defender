"""
Robust JSON extraction from LLM responses.

LLMs often wrap JSON in markdown code fences, prefix with explanation text,
or include trailing commentary. This module handles all common cases.
"""
from __future__ import annotations

import json
import re
from typing import Any


_FENCE_RE = re.compile(r"^```(?:json|JSON)?\s*\n?", re.MULTILINE)
_CLOSE_FENCE_RE = re.compile(r"\n?```\s*$", re.MULTILINE)


def extract_json(text: str) -> dict[str, Any] | None:
    """
    Extract a JSON object from LLM text response.
    Handles markdown fences, leading/trailing prose, nested objects.
    Returns None if nothing parseable found.
    """
    if not text or not isinstance(text, str):
        return None

    # 1. Try direct parse on the stripped text
    cleaned = text.strip()
    if cleaned:
        try:
            obj = json.loads(cleaned)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    # 2. Strip markdown fences
    cleaned = _FENCE_RE.sub("", cleaned, count=1)
    cleaned = _CLOSE_FENCE_RE.sub("", cleaned, count=1)
    cleaned = cleaned.strip()

    if cleaned:
        try:
            obj = json.loads(cleaned)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    # 3. Find balanced JSON object using bracket counting
    obj = _find_balanced_object(text)
    if obj is not None:
        return obj

    # 4. Aggressive cleanup — remove trailing commas, single quotes
    fixed = _aggressive_clean(text)
    if fixed:
        try:
            obj = json.loads(fixed)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    return None


def _find_balanced_object(text: str) -> dict[str, Any] | None:
    """Find first {...} block with balanced braces, respecting strings."""
    first = text.find("{")
    if first < 0:
        return None

    depth = 0
    in_string = False
    escape = False

    for i in range(first, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                candidate = text[first:i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        return obj
                except json.JSONDecodeError:
                    # Try removing trailing commas
                    fixed = re.sub(r",(\s*[}\]])", r"\1", candidate)
                    try:
                        obj = json.loads(fixed)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        return None
    return None


def _aggressive_clean(text: str) -> str:
    """Last-ditch cleanup for malformed JSON."""
    # Find {...} block first
    first = text.find("{")
    last = text.rfind("}")
    if first < 0 or last <= first:
        return ""

    candidate = text[first:last + 1]
    # Remove trailing commas before close
    candidate = re.sub(r",(\s*[}\]])", r"\1", candidate)
    # Replace single quotes around keys/values with double quotes (cautious)
    # Only when single quote is at start of a key or after `: `
    candidate = re.sub(r"(?<=[{,]\s)'([^']+?)'(?=\s*:)", r'"\1"', candidate)
    return candidate
