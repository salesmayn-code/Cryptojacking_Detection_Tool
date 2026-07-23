"""Compatibility wrapper for the canonical PH4 feature pipeline."""

from ml_models.feature_engineering.feature_pipeline import (  # noqa: F401
    FEATURE_BOUNDS,
    N_FEATURES,
    SELECTED_FEATURES,
    extract_features_from_metrics,
    get_feature_index,
    validate_feature_vector,
)

__all__ = [
    "SELECTED_FEATURES",
    "N_FEATURES",
    "FEATURE_BOUNDS",
    "extract_features_from_metrics",
    "validate_feature_vector",
    "get_feature_index",
]
