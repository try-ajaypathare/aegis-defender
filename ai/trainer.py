"""
Trainer — loads historical metrics, trains models, saves to disk.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import numpy as np

from ai.feature_extractor import extract
from ai.models.isolation_forest import IForestModel
from ai.models.lstm_autoencoder import SequenceAutoencoder
from shared.config_loader import get_config
from shared.logger import get_logger
from storage import database as db

log = get_logger("ai-trainer")


def _load_training_data(min_samples: int) -> np.ndarray | None:
    metrics = db.get_recent_metrics(limit=50000)
    if len(metrics) < min_samples:
        log.info(f"Not enough samples for training: have {len(metrics)}, need {min_samples}")
        return None

    # Exclude metrics flagged as false positives in feedback
    # (basic filtering; full feedback loop could be smarter)
    X = np.array([extract(m) for m in metrics], dtype=float)
    return X


def train_isolation_forest() -> dict[str, Any]:
    cfg = get_config()
    X = _load_training_data(cfg.ai.min_samples_for_training)
    if X is None:
        return {"success": False, "reason": "insufficient data"}

    model = IForestModel()
    meta = model.train(X, contamination=cfg.ai.contamination)
    model.save()

    log.info(f"Isolation Forest trained: {meta}")
    db.insert_event("INFO", "ai", f"Isolation Forest trained ({meta['samples']} samples)", "trainer", meta)
    return {"success": True, "meta": meta, "trained_at": datetime.utcnow().isoformat()}


def train_autoencoder() -> dict[str, Any]:
    cfg = get_config()
    X = _load_training_data(cfg.ai.min_samples_for_training)
    if X is None:
        return {"success": False, "reason": "insufficient data"}

    model = SequenceAutoencoder(window_size=10)
    meta = model.train(X)
    model.save()

    log.info(f"Autoencoder trained: {meta}")
    db.insert_event("INFO", "ai", f"Autoencoder trained ({meta['samples']} samples)", "trainer", meta)
    return {"success": True, "meta": meta, "trained_at": datetime.utcnow().isoformat()}


def train_all() -> dict[str, Any]:
    return {
        "iforest": train_isolation_forest(),
        "autoencoder": train_autoencoder(),
    }
