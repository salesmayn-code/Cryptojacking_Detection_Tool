"""Train and evaluate the Random Forest model on kaggle_processed.csv."""

from pathlib import Path
from typing import Dict, Tuple

import joblib
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, PredefinedSplit

from ml_models.feature_engineering import SELECTED_FEATURES
from ml_models.splits import CHRONOLOGICAL, split_dataset


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "datasets" / "kaggle_processed.csv"
SAVED_MODEL_PATH = BASE_DIR / "saved_models" / "random_forest.pkl"
REPORT_PATH = BASE_DIR / "evaluation" / "classification_report_randomforest.txt"
PARAM_GRID = {
    "n_estimators": [100, 200, 300],
    "max_depth": [None, 20, 40],
}


def prepare_data(dataset_path: Path = DATASET_PATH, strategy: str = CHRONOLOGICAL) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series, pd.DataFrame, pd.Series]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Processed dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if "label" not in df.columns:
        raise ValueError("Dataset is missing 'label' column")

    train, val, test = split_dataset(df, strategy)
    return (
        train[SELECTED_FEATURES],
        train["label"].astype(int),
        val[SELECTED_FEATURES],
        val["label"].astype(int),
        test[SELECTED_FEATURES],
        test["label"].astype(int),
    )


def train_random_forest(dataset_path: Path = DATASET_PATH, strategy: str = CHRONOLOGICAL, save: bool = True) -> Dict[str, float]:
    X_train, y_train, X_val, y_val, X_test, y_test = prepare_data(dataset_path, strategy)

    base_model = RandomForestClassifier(
        min_samples_split=4,
        min_samples_leaf=4,
        max_features="sqrt",
        bootstrap=False,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # Score candidates on the 15% validation split so the test split stays unseen.
    search = GridSearchCV(
        base_model,
        PARAM_GRID,
        scoring="f1",
        cv=PredefinedSplit([-1] * len(X_train) + [0] * len(X_val)),
        refit=False,
    )
    search.fit(pd.concat([X_train, X_val]), pd.concat([y_train, y_val]))

    model = clone(base_model).set_params(**search.best_params_)
    model.fit(X_train, y_train)

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
            "scaler": None,
            "feature_names": SELECTED_FEATURES,
        },
        SAVED_MODEL_PATH,
    )

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = classification_report(y_test, y_pred, digits=4)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("RandomForest Classification Report\n")
        f.write(f"Best parameters: {search.best_params_}\n")
        f.write(report)
        f.write("\n")
        for key, value in metrics.items():
            f.write(f"{key}: {value:.6f}\n")

    print(f"Random Forest best parameters: {search.best_params_}")
    print(f"Random Forest saved: {SAVED_MODEL_PATH}")
    print(f"Random Forest metrics: {metrics}")
    return metrics


if __name__ == "__main__":
    train_random_forest()
