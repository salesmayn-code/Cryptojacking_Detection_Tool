"""Preprocess Kaggle cryptojacking CSV files into a training-ready dataset."""

from pathlib import Path
import pandas as pd

from ml_models.feature_engineering import SELECTED_FEATURES


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "datasets"
ANORMAL_CSV = DATA_DIR / "final-anormal-data-set.csv"
NORMAL_CSV = DATA_DIR / "final-normal-data-set.csv"
OUTPUT_CSV = DATA_DIR / "kaggle_processed.csv"


def _load_labeled_dataset(csv_path: Path, label: int) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"Missing dataset file: {csv_path}")

    df = pd.read_csv(csv_path, low_memory=False)
    missing = [col for col in SELECTED_FEATURES if col not in df.columns]
    if missing:
        raise ValueError(f"Dataset {csv_path.name} is missing required columns: {missing}")

    selected = df[SELECTED_FEATURES].copy()
    for col in SELECTED_FEATURES:
        selected[col] = pd.to_numeric(selected[col], errors="coerce")

    selected["label"] = int(label)
    selected = selected.dropna(subset=SELECTED_FEATURES)
    selected = selected[(selected["mem_percent"] >= 0) & (selected["mem_percent"] <= 100)]

    return selected


def preprocess_data(output_csv: Path = OUTPUT_CSV) -> pd.DataFrame:
    """Build a clean labeled dataset from normal + anormal files."""
    normal_df = _load_labeled_dataset(NORMAL_CSV, label=0)
    anormal_df = _load_labeled_dataset(ANORMAL_CSV, label=1)

    combined = pd.concat([normal_df, anormal_df], ignore_index=True)
    combined = combined.sample(frac=1.0, random_state=42).reset_index(drop=True)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_csv, index=False)

    class_counts = combined["label"].value_counts().to_dict()
    print(f"Saved processed dataset: {output_csv}")
    print(f"Rows: {len(combined)} | Features: {len(SELECTED_FEATURES)}")
    print(f"Class distribution: {class_counts}")

    return combined


if __name__ == "__main__":
    preprocess_data()
