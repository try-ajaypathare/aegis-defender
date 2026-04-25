"""
Ensemble predictor — combines Isolation Forest + Sequence Autoencoder.
Weighted voting with configurable weights.
"""
from __future__ import annotations

from typing import Any

from ai.models.isolation_forest import IForestModel
from ai.models.lstm_autoencoder import SequenceAutoencoder


class EnsembleModel:
    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.iforest = IForestModel()
        self.ae = SequenceAutoencoder()
        self.weights = weights or {"iforest": 0.6, "ae": 0.4}

    def load(self) -> bool:
        return self.iforest.load() or self.ae.load()

    def predict(self, features: list[float]) -> dict[str, Any]:
        p1 = self.iforest.predict(features)
        p2 = self.ae.predict(features)

        ready_count = int(p1["ready"]) + int(p2["ready"])
        if ready_count == 0:
            return {"is_anomaly": False, "score": 0.0, "confidence": "unknown", "ready": False}

        total_w = 0.0
        score = 0.0
        if p1["ready"]:
            score += self.weights["iforest"] * p1["score"]
            total_w += self.weights["iforest"]
        if p2["ready"]:
            score += self.weights["ae"] * p2["score"]
            total_w += self.weights["ae"]
        final = score / total_w if total_w > 0 else 0.0

        # Anomaly if either says so with medium+ confidence
        is_anomaly = bool(
            (p1["ready"] and p1["is_anomaly"] and p1["confidence"] != "low")
            or (p2["ready"] and p2["is_anomaly"] and p2["confidence"] != "low")
        )

        confidence = "high" if (p1.get("confidence") == "high" or p2.get("confidence") == "high") else "medium"

        return {
            "is_anomaly": is_anomaly,
            "score": round(final, 4),
            "confidence": confidence,
            "ready": True,
            "components": {"iforest": p1, "autoencoder": p2},
        }
