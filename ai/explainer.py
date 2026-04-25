"""
SHAP-based explainer — WHY did AI flag this?
Falls back to simple feature deviation if SHAP not available.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from ai.feature_extractor import feature_names


def explain(
    model_iforest: Any,
    scaler: Any,
    features: list[float],
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """
    Return top_k most influential features with direction (high/low).
    Uses SHAP if installed, otherwise feature z-score deviation.
    """
    names = feature_names()
    x = np.array(features, dtype=float)

    try:
        import shap  # type: ignore

        x_scaled = scaler.transform(x.reshape(1, -1))
        explainer = shap.TreeExplainer(model_iforest)
        shap_values = explainer.shap_values(x_scaled)[0]

        # Rank by absolute contribution
        pairs = sorted(
            zip(names, shap_values, x.tolist()),
            key=lambda t: abs(t[1]),
            reverse=True,
        )
        top = pairs[:top_k]
        return [
            {
                "feature": n,
                "value": round(v, 3),
                "contribution": round(float(s), 4),
                "direction": "high" if s > 0 else "low",
            }
            for n, s, v in top
        ]
    except Exception:
        pass

    # Fallback: z-score deviation from scaler mean
    try:
        mean = scaler.mean_
        std = scaler.scale_
        z = (x - mean) / (std + 1e-9)
        pairs = sorted(zip(names, z, x.tolist()), key=lambda t: abs(t[1]), reverse=True)
        top = pairs[:top_k]
        return [
            {
                "feature": n,
                "value": round(v, 3),
                "contribution": round(float(zv), 4),
                "direction": "high" if zv > 0 else "low",
            }
            for n, zv, v in top
        ]
    except Exception:
        return []


def explanation_text(explanations: list[dict[str, Any]]) -> str:
    """Humanize explanation list."""
    if not explanations:
        return "No explanation available"
    parts = []
    for e in explanations:
        direction = "unusually high" if e["direction"] == "high" else "unusually low"
        parts.append(f"{e['feature']}={e['value']} ({direction})")
    return "; ".join(parts)
