"""Unit tests for the Machine Learning anomaly detection module (Isolation Forest)."""

from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from dos_detector.features import compute_window_features
from dos_detector.ml import (
    FEATURE_NAMES,
    extract_window_features,
    extract_windows_matrix,
    get_default_baseline_model,
    load_model,
    save_model,
    train_isolation_forest,
)
from dos_detector.models import PacketRecord, TrafficWindow


@pytest.fixture
def sample_benign_windows() -> list[TrafficWindow]:
    """Generate deterministic benign sample windows for testing."""
    windows: list[TrafficWindow] = []
    for w_idx in range(5):
        records = [
            PacketRecord(
                timestamp=float(w_idx + (p * 0.05)),
                src_ip=f"192.168.1.{10 + p}",
                dst_ip="10.0.0.1",
                protocol="TCP",
                src_port=30000 + p,
                dst_port=80,
                packet_size=120,
                tcp_flags=frozenset({"ACK"}),
            )
            for p in range(20)
        ]
        windows.append(compute_window_features(records, float(w_idx), float(w_idx + 1.0)))
    return windows


@pytest.mark.unit
def test_extract_window_features(sample_benign_windows: list[TrafficWindow]) -> None:
    """Verify feature vector length, ordering, and data type."""
    window = sample_benign_windows[0]
    features = extract_window_features(window)

    assert isinstance(features, np.ndarray)
    assert features.shape == (len(FEATURE_NAMES),)
    assert features.dtype == np.float64
    assert not np.isnan(features).any()
    assert not np.isinf(features).any()

    # Verify specific feature indices
    assert features[0] == float(window.packet_rate)
    assert features[1] == float(window.byte_rate)
    assert features[2] == float(window.syn_ack_ratio)


@pytest.mark.unit
def test_extract_windows_matrix(sample_benign_windows: list[TrafficWindow]) -> None:
    """Verify conversion of multiple windows into a 2D feature matrix."""
    matrix = extract_windows_matrix(sample_benign_windows)
    assert matrix.shape == (len(sample_benign_windows), len(FEATURE_NAMES))

    # Empty list edge case
    empty_matrix = extract_windows_matrix([])
    assert empty_matrix.shape == (0, len(FEATURE_NAMES))


@pytest.mark.unit
def test_train_isolation_forest(sample_benign_windows: list[TrafficWindow]) -> None:
    """Verify training Isolation Forest on benign windows."""
    model = train_isolation_forest(
        sample_benign_windows,
        contamination=0.05,
        n_estimators=50,
        random_state=42,
    )
    assert isinstance(model, IsolationForest)
    assert hasattr(model, "estimators_")
    assert len(model.estimators_) == 50

    # Training with fewer than 2 windows must raise ValueError
    with pytest.raises(ValueError, match="At least 2 windows required"):
        train_isolation_forest(sample_benign_windows[:1])


@pytest.mark.unit
def test_save_and_load_model(tmp_path: Path, sample_benign_windows: list[TrafficWindow]) -> None:
    """Verify model persistence with joblib."""
    model = train_isolation_forest(sample_benign_windows, n_estimators=20)
    model_path = tmp_path / "models" / "test_iforest.joblib"

    save_model(model, model_path)
    assert model_path.is_file()

    loaded = load_model(model_path)
    assert isinstance(loaded, IsolationForest)

    # Check predictions are identical
    X = extract_windows_matrix(sample_benign_windows)
    np.testing.assert_array_equal(model.predict(X), loaded.predict(X))

    # Error handling
    with pytest.raises(FileNotFoundError):
        load_model(tmp_path / "nonexistent.joblib")


@pytest.mark.unit
def test_get_default_baseline_model() -> None:
    """Verify default cached baseline model returns fitted IsolationForest."""
    model1 = get_default_baseline_model()
    assert isinstance(model1, IsolationForest)

    # Subsequent call returns cached singleton
    model2 = get_default_baseline_model()
    assert model1 is model2
