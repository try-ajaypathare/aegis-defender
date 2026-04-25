"""
LSTM Autoencoder — time-series anomaly detection.
Stub implementation using a simple numpy-based autoencoder
(avoids heavy TensorFlow dep). Activate full LSTM if tensorflow is installed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np


MODEL_DIR = Path(__file__).resolve().parent.parent / "saved"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "lstm_autoencoder.joblib"


class SequenceAutoencoder:
    """
    Lightweight sequence-based anomaly detector.
    Uses rolling mean + std to flag deviations over time windows.
    For heavyweight LSTM, install tensorflow and swap in the
    Keras version.
    """

    def __init__(self, window_size: int = 10) -> None:
        self.window_size = window_size
        self.window_mean: np.ndarray | None = None
        self.window_std: np.ndarray | None = None
        self.reconstruction_threshold: float = 0.0
        self.meta: dict[str, Any] = {}

    def train(self, sequences: np.ndarray) -> dict[str, Any]:
        """
        sequences: shape (N_samples, N_features)
        Builds per-feature mean/std and sets reconstruction threshold.
        """
        self.window_mean = sequences.mean(axis=0)
        self.window_std = sequences.std(axis=0) + 1e-6

        # Reconstruction errors for training set → 95th percentile as threshold
        errors = self._reconstruction_errors(sequences)
        self.reconstruction_threshold = float(np.percentile(errors, 95))
        self.meta = {
            "samples": int(sequences.shape[0]),
            "features": int(sequences.shape[1]),
            "threshold": self.reconstruction_threshold,
            "window_size": self.window_size,
        }
        return self.meta

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        z = (X - self.window_mean) / self.window_std
        return np.abs(z).mean(axis=1)

    def predict(self, features: list[float]) -> dict[str, Any]:
        if self.window_mean is None or self.window_std is None:
            return {"is_anomaly": False, "score": 0.0, "confidence": "unknown", "ready": False}

        x = np.array(features, dtype=float)
        z = (x - self.window_mean) / self.window_std
        err = float(np.abs(z).mean())

        score = min(1.0, err / (self.reconstruction_threshold * 2 + 1e-9))
        is_anomaly = err > self.reconstruction_threshold

        confidence = "high" if err > 2 * self.reconstruction_threshold else (
            "medium" if is_anomaly else "low"
        )

        return {
            "is_anomaly": bool(is_anomaly),
            "score": round(score, 4),
            "raw_score": round(err, 4),
            "confidence": confidence,
            "ready": True,
        }

    def save(self) -> None:
        joblib.dump({
            "mean": self.window_mean,
            "std": self.window_std,
            "threshold": self.reconstruction_threshold,
            "meta": self.meta,
        }, MODEL_PATH)

    def load(self) -> bool:
        if not MODEL_PATH.exists():
            return False
        try:
            data = joblib.load(MODEL_PATH)
            self.window_mean = data["mean"]
            self.window_std = data["std"]
            self.reconstruction_threshold = data["threshold"]
            self.meta = data.get("meta", {})
            return True
        except Exception:
            return False
