"""DoS Attack Detector.

A defensive, offline network traffic analysis engine for detecting Denial-of-Service (DoS)
attack patterns using configurable rules and anomaly detection.
"""

from dos_detector.alerting import AlertSink, InMemoryAlertSink
from dos_detector.config import DetectionConfig
from dos_detector.detector import BaseDetector, RuleBasedDetector
from dos_detector.evaluation import (
    AttackSchedule,
    DatasetEvaluator,
    EvaluationMetrics,
    GroundTruthInterval,
)
from dos_detector.features import (
    SlidingWindowAggregator,
    compute_shannon_entropy,
    compute_window_features,
    stream_sliding_windows,
)
from dos_detector.ingestion import (
    CIC_IDS2017_CSV_MAPPING,
    CsvFieldMapping,
    stream_csv,
    stream_pcap,
)
from dos_detector.ml import (
    FEATURE_NAMES,
    extract_window_features,
    extract_windows_matrix,
    get_default_baseline_model,
    load_model,
    save_model,
    train_isolation_forest,
)
from dos_detector.models import (
    DetectionAlert,
    PacketRecord,
    Severity,
    TrafficWindow,
)

__version__ = "0.1.0"

__all__ = [
    "CIC_IDS2017_CSV_MAPPING",
    "AlertSink",
    "AttackSchedule",
    "BaseDetector",
    "CsvFieldMapping",
    "DatasetEvaluator",
    "DetectionAlert",
    "DetectionConfig",
    "EvaluationMetrics",
    "FEATURE_NAMES",
    "GroundTruthInterval",
    "InMemoryAlertSink",
    "PacketRecord",
    "RuleBasedDetector",
    "Severity",
    "SlidingWindowAggregator",
    "TrafficWindow",
    "__version__",
    "compute_shannon_entropy",
    "compute_window_features",
    "extract_window_features",
    "extract_windows_matrix",
    "get_default_baseline_model",
    "load_model",
    "save_model",
    "stream_csv",
    "stream_pcap",
    "stream_sliding_windows",
    "train_isolation_forest",
]
