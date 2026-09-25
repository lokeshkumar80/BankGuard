"""Load the trained Isolation Forest model and run fraud inference on transactions."""
import logging
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "model" / "model.pkl"

_model = None


def _load_model():
    """Lazily load and cache the Isolation Forest model from disk."""
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"{MODEL_PATH} not found. Run `python fraud/train.py` first to train a model."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def is_fraudulent(transaction: dict) -> bool:
    """Return True if the Isolation Forest model flags the transaction as anomalous."""
    model = _load_model()
    features = pd.DataFrame([transaction])
    prediction = model.predict(features)[0]
    flagged = prediction == -1

    if flagged:
        logger.warning("fraud_flagged transaction_keys=%s", list(transaction.keys()))

    return bool(flagged)


def build_feature_vector(amount: float) -> dict:
    """Build a transaction feature vector matching the training schema (Time, V1-V28, Amount).

    V1-V28 are PCA-derived features from the original Kaggle dataset; a live transaction has
    no access to that PCA transform, so they are simulated as Gaussian noise for demo purposes.
    """
    features = {"Time": time.time() % 172792}
    rng = np.random.default_rng()
    for i in range(1, 29):
        features[f"V{i}"] = float(rng.normal(0, 1))
    features["Amount"] = amount
    return features
