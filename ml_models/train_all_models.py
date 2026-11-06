"""Run model training pipeline: preprocess dataset, train models, and write summary."""

from datetime import datetime
import json
from pathlib import Path

from ml_models.evaluate_models import evaluate_models
from ml_models.feature_engineering import SELECTED_FEATURES
from ml_models.preprocess_kaggle_data import preprocess_data
from ml_models.random_forest_model import train_random_forest
from ml_models.splits import RANDOM
from ml_models.xgboost_model import train_xgboost


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "datasets"
EVAL_DIR = BASE_DIR / "evaluation"
SAVED_MODELS_DIR = BASE_DIR / "saved_models"

ANORMAL_CSV = DATA_DIR / "final-anormal-data-set.csv"
NORMAL_CSV = DATA_DIR / "final-normal-data-set.csv"
PROCESSED_CSV = DATA_DIR / "kaggle_processed.csv"
COMPARISON_REPORT = EVAL_DIR / "model_comparison.txt"
METADATA_JSON = SAVED_MODELS_DIR / "model_metadata.json"


def _ensure_kaggle_files_exist() -> None:
    missing = [str(path) for path in (ANORMAL_CSV, NORMAL_CSV) if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing required Kaggle dataset files: {missing}")


def _format_metrics_row(model_name: str, metrics: dict) -> str:
    return (
        f"{model_name:<16} | "
        f"{metrics.get('accuracy', 0.0):>8.4f} | "
        f"{metrics.get('precision', 0.0):>9.4f} | "
        f"{metrics.get('recall', 0.0):>6.4f} | "
        f"{metrics.get('f1', 0.0):>8.4f} | "
        f"{metrics.get('roc_auc', 0.0):>7.4f}"
    )


def train_all_models() -> dict:
    _ensure_kaggle_files_exist()

    processed_df = preprocess_data(PROCESSED_CSV)
    xgb_metrics = train_xgboost(PROCESSED_CSV)
    rf_metrics = train_random_forest(PROCESSED_CSV)

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        "CryptoDetect Model Comparison",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        "",
        "Model            | Accuracy | Precision | Recall | F1-Score | ROC-AUC",
        "-" * 72,
        _format_metrics_row("XGBoost", xgb_metrics),
        _format_metrics_row("RandomForest", rf_metrics),
    ]
    COMPARISON_REPORT.write_text("\n".join(lines), encoding="utf-8")

    SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    metadata = {
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "dataset": "ml_models/datasets/kaggle_processed.csv",
        "n_samples": int(len(processed_df)),
        "n_features": len(SELECTED_FEATURES),
        "features": SELECTED_FEATURES,
        "target": "label",
        "xgboost": {"test_metrics": xgb_metrics},
        "random_forest": {"test_metrics": rf_metrics},
    }
    METADATA_JSON.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    evaluate_models(
        {
            "XGBoost": lambda path: train_xgboost(path, RANDOM, save=False),
            "Random Forest": lambda path: train_random_forest(path, RANDOM, save=False),
        },
        dataset_path=PROCESSED_CSV,
    )

    print(f"Comparison report: {COMPARISON_REPORT}")
    print(f"Model metadata: {METADATA_JSON}")

    return {
        "xgboost": xgb_metrics,
        "random_forest": rf_metrics,
        "processed_rows": int(len(processed_df)),
    }


if __name__ == "__main__":
    train_all_models()
