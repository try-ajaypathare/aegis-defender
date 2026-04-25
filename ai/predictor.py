"""
Predictor — real-time inference using trained models.
"""
from __future__ import annotations

import json
from typing import Any

from ai.explainer import explain, explanation_text
from ai.feature_extractor import extract
from ai.models.ensemble import EnsembleModel
from ai.models.isolation_forest import IForestModel
from shared.config_loader import get_config
from shared.logger import get_logger

log = get_logger("ai-predictor")


class Predictor:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._engine = self.cfg.ai.engine

        if self._engine == "ensemble":
            self._model = EnsembleModel()
        else:
            self._model = IForestModel()

        self._ready = self._model.load()
        if self._ready:
            log.info(f"AI model loaded ({self._engine})")
        else:
            log.info("No AI model found — predictions disabled until training")

    def reload(self) -> None:
        self._ready = self._model.load()

    @property
    def ready(self) -> bool:
        return self._ready

    def predict(self, metric: dict[str, Any]) -> dict[str, Any]:
        if not self._ready or not self.cfg.ai.enabled:
            return {"is_anomaly": False, "score": 0.0, "confidence": "unknown", "ready": False}

        features = extract(metric)
        result = self._model.predict(features)

        # Add explanation if flagged
        if result.get("is_anomaly") and self.cfg.ai.use_shap_explanations:
            try:
                if self._engine == "ensemble":
                    iforest = self._model.iforest  # type: ignore[attr-defined]
                    expl = explain(iforest.model, iforest.scaler, features, top_k=3)
                else:
                    expl = explain(self._model.model, self._model.scaler, features, top_k=3)  # type: ignore[attr-defined]
                result["explanation"] = expl
                result["explanation_text"] = explanation_text(expl)
            except Exception as e:  # noqa: BLE001
                log.debug(f"Explanation failed: {e}")
                result["explanation"] = []

        # Respect anomaly threshold from config
        if result.get("score", 0) < self.cfg.ai.anomaly_threshold:
            result["is_anomaly"] = False

        return result
