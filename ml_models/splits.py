"""Train, validation, and test splits for the time-series telemetry."""

from typing import Tuple

import pandas as pd
from sklearn.model_selection import train_test_split

CHRONOLOGICAL = "chronological"
RANDOM = "random"


def split_dataset(df: pd.DataFrame, strategy: str = CHRONOLOGICAL) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Return 70% train, 15% validation, and 15% test frames.

    The chronological split divides each class by time, so every test sample is
    later than the training samples of its class. It splits per class because the
    normal and attack data come from separate files and may not overlap in time.
    """
    if strategy == CHRONOLOGICAL:
        return _chronological_split(df)
    if strategy == RANDOM:
        return _random_split(df)
    raise ValueError(f"Unknown split strategy: {strategy}")


def _chronological_split(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    if "timestamp" not in df.columns:
        raise ValueError("Chronological split needs a 'timestamp' column")

    train, val, test = [], [], []
    for _, group in df.groupby("label"):
        ordered = group.sort_values("timestamp", kind="stable")
        train_end = int(len(ordered) * 0.70)
        val_end = int(len(ordered) * 0.85)
        train.append(ordered.iloc[:train_end])
        val.append(ordered.iloc[train_end:val_end])
        test.append(ordered.iloc[val_end:])
    return pd.concat(train), pd.concat(val), pd.concat(test)


def _random_split(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train, temp = train_test_split(df, test_size=0.30, random_state=42, stratify=df["label"])
    val, test = train_test_split(temp, test_size=0.50, random_state=42, stratify=temp["label"])
    return train, val, test
