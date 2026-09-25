"""Train an Isolation Forest anomaly detector on the Kaggle Credit Card Fraud dataset."""
import logging
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_PATH = Path(__file__).resolve().parent / "creditcard.csv"
MODEL_DIR = Path(__file__).resolve().parent / "model"
MODEL_PATH = MODEL_DIR / "model.pkl"


def train() -> None:
    """Train the Isolation Forest model on creditcard.csv and save it to model/model.pkl."""
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH} not found. Download creditcard.csv from "
            "https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud and place it in fraud/"
        )

    df = pd.read_csv(DATA_PATH)
    features = df.drop(columns=["Class"])
    labels = df["Class"]

    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )

    model = IsolationForest(contamination=0.001, random_state=42)
    model.fit(x_train)

    # IsolationForest predicts 1 for inliers and -1 for anomalies; map to 0/1 fraud labels.
    raw_predictions = model.predict(x_test)
    predictions = [1 if p == -1 else 0 for p in raw_predictions]

    report = classification_report(y_test, predictions, digits=4)
    print(report)
    logger.info("training_complete")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info("model_saved path=%s", MODEL_PATH)


if __name__ == "__main__":
    train()
