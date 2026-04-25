"""
Isolation Forest wrapper.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


MODEL_DIR = Path(__file__).resolve().parent.parent / "saved"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"


class IForestModel:
    def __init__(self) -> None:
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.meta: dict[str, Any] = {}

    def train(
        self,
        X: np.ndarray,
        contamination: float = 0.05,
        n_estimators: int = 150,
    ) -> dict[str, Any]:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        self.model = model
        self.scaler = scaler
        self.meta = {
            "samples": int(X.shape[0]),
            "features": int(X.shape[1]),
            "contamination": contamination,
            "n_estimators": n_estimators,
        }
        return self.meta

    def predict(self, features: list[float]) -> dict[str, Any]:
        if self.model is None or self.scaler is None:
            return {"is_anomaly": False, "score": 0.0, "confidence": "unknown", "ready": False}

        x = np.array(features).reshape(1, -1)
        x_scaled = self.scaler.transform(x)
        pred = int(self.model.predict(x_scaled)[0])  # -1 anomaly, 1 normal
        score = float(self.model.decision_function(x_scaled)[0])

        # Normalize score to [0, 1] — higher = more anomalous
        normalized = max(0.0, min(1.0, 0.5 - score))

        confidence = "high" if abs(score) > 0.2 else ("medium" if abs(score) > 0.1 else "low")

        return {
            "is_anomaly": pred == -1,
            "score": round(normalized, 4),
            "raw_score": round(score, 4),
            "confidence": confidence,
            "ready": True,
        }

    def save(self) -> None:
        if self.model is None:
            return
        joblib.dump({"model": self.model, "scaler": self.scaler, "meta": self.meta}, MODEL_PATH)

    def load(self) -> bool:
        if not MODEL_PATH.exists():
            return False
        try:
            data = joblib.load(MODEL_PATH)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.meta = data.get("meta", {})
            return True
        except Exception:
            return False
