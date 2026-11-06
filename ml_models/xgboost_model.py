"""Train and evaluate the XGBoost model on kaggle_processed.csv."""

from pathlib import Path
from typing import Dict, Tuple

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ml_models.feature_engineering import SELECTED_FEATURES
from ml_models.splits import CHRONOLOGICAL, split_dataset


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "datasets" / "kaggle_processed.csv"
SAVED_MODEL_PATH = BASE_DIR / "saved_models" / "xgboost.pkl"
REPORT_PATH = BASE_DIR / "evaluation" / "classification_report_xgboost.txt"


def prepare_data(dataset_path: Path = DATASET_PATH, strategy: str = CHRONOLOGICAL) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.DataFrame, pd.Series, StandardScaler]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Processed dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if "label" not in df.columns:
        raise ValueError("Dataset is missing 'label' column")

    train, val, test = split_dataset(df, strategy)
    X_train, y_train = train[SELECTED_FEATURES], train["label"].astype(int)
    X_val, y_val = val[SELECTED_FEATURES], val["label"].astype(int)
    X_test, y_test = test[SELECTED_FEATURES], test["label"].astype(int)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    return X_train_scaled, X_val_scaled, y_train, y_val, X_test_scaled, y_test, scaler


def train_xgboost(dataset_path: Path = DATASET_PATH, strategy: str = CHRONOLOGICAL, save: bool = True) -> Dict[str, float]:
    X_train, X_val, y_train, y_val, X_test, y_test, scaler = prepare_data(dataset_path, strategy)

    pos_count = max(1, int((y_train == 1).sum()))
    neg_count = max(1, int((y_train == 0).sum()))
    scale_pos_weight = neg_count / pos_count

    model = XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=500,
        learning_rate=0.1,
        max_depth=5,
        min_child_weight=5,
        subsample=0.9,
        colsample_bytree=0.9,
        gamma=0,
        reg_alpha=0.1,
        reg_lambda=1,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
        early_stopping_rounds=30,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "pr_auc": float(average_precision_score(y_test, y_prob)),
    }

    if not save:
        return metrics

    SAVED_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "feature_names": SELECTED_FEATURES,
        },
        SAVED_MODEL_PATH,
    )

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = classification_report(y_test, y_pred, digits=4)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("XGBoost Classification Report\n")
        f.write(report)
        f.write("\n")
        for key, value in metrics.items():
            f.write(f"{key}: {value:.6f}\n")

    print(f"XGBoost saved: {SAVED_MODEL_PATH}")
    print(f"XGBoost metrics: {metrics}")
    return metrics


if __name__ == "__main__":
    train_xgboost()
