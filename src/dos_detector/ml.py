"""Machine Learning anomaly detection utilities using Isolation Forest.

Provides feature extraction from TrafficWindows, training pipelines,
model serialization with joblib, and a default pre-trained baseline model.
"""

import logging
from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from dos_detector.features import compute_window_features
from dos_detector.models import PacketRecord, TrafficWindow

logger = logging.getLogger(__name__)

# Ordered names of features extracted from each TrafficWindow
FEATURE_NAMES: tuple[str, ...] = (
    "packet_rate",
    "byte_rate",
    "syn_ack_ratio",
    "syn_tcp_ratio",
    "normalized_ip_entropy",
    "top_source_ip_ratio",
    "top_dst_port_ratio",
    "dns_ratio",
    "udp_ratio",
    "top_http_uri_ratio",
)

_DEFAULT_BASELINE_MODEL: IsolationForest | None = None


def extract_window_features(window: TrafficWindow) -> np.ndarray:
    """Extract an ordered 1D numerical feature vector from a TrafficWindow.

    Args:
        window: Aggregated metrics for an observation interval.

    Returns:
        1D numpy array of shape (10,) containing normalized floating-point metrics.
    """
    syn_tcp_ratio = (window.syn_count / window.tcp_count) if window.tcp_count > 0 else 0.0

    raw_features = [
        float(window.packet_rate),
        float(window.byte_rate),
        float(window.syn_ack_ratio),
        float(syn_tcp_ratio),
        float(window.normalized_ip_entropy),
        float(window.top_source_ip_ratio),
        float(window.top_dst_port_ratio),
        float(window.dns_ratio),
        float(window.udp_ratio),
        float(window.top_http_uri_ratio),
    ]

    # Defensive sanitation against NaN or infinite values from corrupted data
    sanitized = np.nan_to_num(raw_features, nan=0.0, posinf=1e6, neginf=0.0)
    return np.array(sanitized, dtype=np.float64)


def extract_windows_matrix(windows: Sequence[TrafficWindow]) -> np.ndarray:
    """Convert a sequence of TrafficWindows into a 2D feature matrix.

    Args:
        windows: Collection of TrafficWindows.

    Returns:
        2D numpy array of shape (N, 10).
    """
    if not windows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)

    rows = [extract_window_features(w) for w in windows]
    return np.vstack(rows)


def train_isolation_forest(
    windows: Sequence[TrafficWindow],
    contamination: float = 0.01,
    n_estimators: int = 100,
    random_state: int = 42,
) -> IsolationForest:
    """Train an Isolation Forest anomaly detector on benign baseline windows.

    Args:
        windows: Baseline traffic windows (assumed to represent legitimate network activity).
        contamination: Estimated proportion of outliers in the baseline training set.
        n_estimators: Number of isolation trees to construct.
        random_state: Deterministic seed for reproducible tree construction.

    Returns:
        Fitted IsolationForest model.

    Raises:
        ValueError: If fewer than 2 traffic windows are provided for training.
    """
    if len(windows) < 2:
        msg = f"At least 2 windows required to fit Isolation Forest, got {len(windows)}"
        raise ValueError(msg)

    feature_matrix = extract_windows_matrix(windows)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(feature_matrix)
    logger.info(
        "Fitted Isolation Forest model on %d windows with contamination=%.3f",
        len(windows),
        contamination,
    )
    return model


def save_model(model: IsolationForest, file_path: str | Path) -> None:
    """Persist a trained Isolation Forest model to disk using joblib.

    Args:
        model: Trained IsolationForest instance.
        file_path: Destination file path (e.g., models/baseline.joblib).
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, str(path))
    logger.info("Saved Isolation Forest model to %s", path)


def load_model(file_path: str | Path) -> IsolationForest:
    """Load a persisted Isolation Forest model from disk.

    Args:
        file_path: Path to serialized model file.

    Returns:
        Trained IsolationForest model.

    Raises:
        FileNotFoundError: If the specified model file does not exist.
        TypeError: If the deserialized object is not an IsolationForest.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Model file not found: {path}")

    # Note: Loading joblib models involves pickle deserialization; ensure model files come from trusted sources.
    loaded: object = joblib.load(str(path))  # noqa: S301

    if not isinstance(loaded, IsolationForest):
        msg = f"Loaded model object is {type(loaded)}, expected IsolationForest"
        raise TypeError(msg)

    logger.info("Loaded Isolation Forest model from %s", path)
    return loaded


def _build_synthetic_benign_windows(num_windows: int = 60) -> list[TrafficWindow]:
    """Generate synthetic legitimate web browsing windows for the default baseline."""
    windows: list[TrafficWindow] = []
    base_time = 1000.0

    for w_idx in range(num_windows):
        start_time = base_time + (w_idx * 1.0)
        end_time = start_time + 1.0

        # Normal browsing: 15-35 packets per window with legitimate TCP flags and varied IPs
        records: list[PacketRecord] = []
        num_pkts = 15 + ((w_idx * 7) % 20)
        for p_idx in range(num_pkts):
            t = start_time + (p_idx / num_pkts)
            client_id = 10 + (p_idx % 8)
            records.append(
                PacketRecord(
                    timestamp=t,
                    src_ip=f"192.168.1.{client_id}",
                    dst_ip="93.184.216.34",
                    protocol="TCP",
                    src_port=40000 + ((w_idx * 100 + p_idx) % 20000),
                    dst_port=443 if p_idx % 2 == 0 else 80,
                    packet_size=128 + ((p_idx * 37) % 500),
                    tcp_flags=frozenset({"ACK" if p_idx % 3 != 0 else "SYN"}),
                    label="BENIGN",
                )
            )

        windows.append(compute_window_features(records, start_time, end_time))

    return windows


def get_default_baseline_model() -> IsolationForest:
    """Retrieve or build the default cached Isolation Forest baseline model.

    Returns:
        Pre-fitted IsolationForest model representing legitimate background traffic.
    """
    global _DEFAULT_BASELINE_MODEL
    if _DEFAULT_BASELINE_MODEL is None:
        logger.info("Building default in-memory Isolation Forest baseline model...")
        benign_windows = _build_synthetic_benign_windows(num_windows=60)
        _DEFAULT_BASELINE_MODEL = train_isolation_forest(
            benign_windows,
            contamination=0.01,
            n_estimators=100,
            random_state=42,
        )
    return _DEFAULT_BASELINE_MODEL
