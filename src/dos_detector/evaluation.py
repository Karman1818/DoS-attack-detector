"""Evaluation harness for benchmark labeled datasets (e.g., CIC-IDS2017, CIC-DDoS2019).

Computes defensive detection metrics: True Positives (TP), False Positives (FP),
True Negatives (TN), False Negatives (FN), Precision, Recall (Detection Rate),
Specificity, False Positive Rate, F1-Score, and per-attack breakdown.
"""

import json
import logging
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dos_detector.detector import BaseDetector
from dos_detector.features import SlidingWindowAggregator
from dos_detector.ingestion import (
    CIC_IDS2017_CSV_MAPPING,
    CsvFieldMapping,
    stream_csv,
    stream_pcap,
)
from dos_detector.models import PacketRecord

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GroundTruthInterval:
    """Time-interval ground-truth definition (used for PCAP datasets like CIC-IDS2017)."""

    start_time: float
    end_time: float
    label: str
    description: str = ""

    def overlaps(self, start: float, end: float) -> bool:
        """Check if this interval overlaps with observation window [start, end]."""
        return max(self.start_time, start) < min(self.end_time, end)


@dataclass(frozen=True, slots=True)
class AttackSchedule:
    """Collection of ground-truth attack intervals for a dataset capture."""

    intervals: tuple[GroundTruthInterval, ...] = ()

    def overlaps_attack(self, start: float, end: float) -> tuple[str, ...]:
        """Return all attack labels overlapping the window interval [start, end]."""
        labels = [iv.label for iv in self.intervals if iv.overlaps(start, end)]
        return tuple(labels)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackSchedule":
        """Build schedule from parsed dictionary."""
        raw_intervals = data.get("attacks") or data.get("intervals") or []
        parsed: list[GroundTruthInterval] = []
        for item in raw_intervals:
            parsed.append(
                GroundTruthInterval(
                    start_time=float(item["start"]),
                    end_time=float(item["end"]),
                    label=str(item.get("label", "ATTACK")),
                    description=str(item.get("description", "")),
                )
            )
        return cls(intervals=tuple(parsed))

    @classmethod
    def from_json(cls, json_path: str | Path) -> "AttackSchedule":
        """Load schedule from JSON file."""
        path = Path(json_path)
        if not path.is_file():
            raise FileNotFoundError(f"Schedule file not found: {path}")
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


@dataclass(frozen=True, slots=True)
class PerClassMetrics:
    """Detection performance metrics for a specific attack category."""

    label: str
    total_windows: int
    detected_windows: int
    triggered_rules: dict[str, int] = field(default_factory=dict)

    @property
    def missed_windows(self) -> int:
        """Windows where this attack was active but missed by the detector."""
        return max(0, self.total_windows - self.detected_windows)

    @property
    def recall(self) -> float:
        """Recall / Detection rate (TPR) for this attack category."""
        return self.detected_windows / self.total_windows if self.total_windows > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize per-class metrics to dictionary."""
        return {
            "label": self.label,
            "total_windows": self.total_windows,
            "detected_windows": self.detected_windows,
            "missed_windows": self.missed_windows,
            "recall": round(self.recall, 4),
            "triggered_rules": dict(self.triggered_rules),
        }


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    """Comprehensive evaluation metrics for DoS/DDoS detection on labeled datasets."""

    total_windows: int
    total_packets: int
    evaluation_duration_seconds: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    per_class: dict[str, PerClassMetrics] = field(default_factory=dict)
    rule_counts: dict[str, int] = field(default_factory=dict)

    @property
    def accuracy(self) -> float:
        """Overall classification accuracy across all evaluation windows."""
        return (
            (self.true_positives + self.true_negatives) / self.total_windows
            if self.total_windows > 0
            else 0.0
        )

    @property
    def precision(self) -> float:
        """Precision (Positive Predictive Value): TP / (TP + FP)."""
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        """Recall / Detection Rate (Sensitivity): TP / (TP + FN)."""
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 1.0

    @property
    def f1_score(self) -> float:
        """Harmonic mean of precision and recall."""
        p = self.precision
        r = self.recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def specificity(self) -> float:
        """Specificity / True Negative Rate: TN / (TN + FP)."""
        denom = self.true_negatives + self.false_positives
        return self.true_negatives / denom if denom > 0 else 1.0

    @property
    def false_positive_rate(self) -> float:
        """False Positive Rate (Fall-out): FP / (FP + TN)."""
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to clean JSON-serializable dictionary."""
        return {
            "summary": {
                "total_windows": self.total_windows,
                "total_packets": self.total_packets,
                "evaluation_duration_seconds": round(self.evaluation_duration_seconds, 3),
                "confusion_matrix": {
                    "true_positives": self.true_positives,
                    "false_positives": self.false_positives,
                    "true_negatives": self.true_negatives,
                    "false_negatives": self.false_negatives,
                },
                "metrics": {
                    "accuracy": round(self.accuracy, 4),
                    "precision": round(self.precision, 4),
                    "recall": round(self.recall, 4),
                    "f1_score": round(self.f1_score, 4),
                    "specificity": round(self.specificity, 4),
                    "false_positive_rate": round(self.false_positive_rate, 4),
                },
            },
            "per_class": {k: v.to_dict() for k, v in self.per_class.items()},
            "rule_counts": dict(self.rule_counts),
        }

    def export_json(self, file_path: str | Path) -> None:
        """Save evaluation report to JSON file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def render_ascii_report(self, title: str = "Dataset Benchmark Evaluation Report") -> str:
        """Render a formatted, human-readable terminal report."""
        lines: list[str] = []
        border = "=" * 80
        sep = "+-------------------------------+---------------+----------------------------------+"

        lines.append("\n" + border)
        lines.append(f"[*] {title}")
        lines.append(border)
        lines.append(
            f"[*] Windows Evaluated: {self.total_windows:,} | "
            f"Packets Processed: {self.total_packets:,} | "
            f"Time: {self.evaluation_duration_seconds:.2f}s"
        )
        lines.append("")

        # Confusion Matrix
        cm_border = "+--------------------+-------------------------+---------------------------+"
        lines.append("CONFUSION MATRIX:")
        lines.append(cm_border)
        lines.append(
            "| Actual \\ Predicted | Predicted ATTACK        | Predicted BENIGN          |"
        )
        lines.append(cm_border)
        lines.append(
            f"| Actual ATTACK      | TP: {self.true_positives:<19} | FN: {self.false_negatives:<21} |"
        )
        lines.append(
            f"| Actual BENIGN      | FP: {self.false_positives:<19} | TN: {self.true_negatives:<21} |"
        )
        lines.append(cm_border)
        lines.append("")

        # Classification Metrics Table
        lines.append("CLASSIFICATION METRICS:")
        lines.append(sep)
        lines.append(
            "| Metric                        | Value         | Interpretation                   |"
        )
        lines.append(sep)
        lines.append(
            f"| Accuracy                      | {self.accuracy * 100:>6.2f}%        | Overall classification accuracy  |"
        )
        lines.append(
            f"| Precision (PPV)               | {self.precision * 100:>6.2f}%        | Positive alert fidelity          |"
        )
        lines.append(
            f"| Recall / Detection Rate (TPR) | {self.recall * 100:>6.2f}%        | Attack coverage sensitivity      |"
        )
        lines.append(
            f"| Specificity (TNR)             | {self.specificity * 100:>6.2f}%        | Benign traffic pass-rate         |"
        )
        lines.append(
            f"| False Positive Rate (FPR)     | {self.false_positive_rate * 100:>6.2f}%        | Benign misclassification rate    |"
        )
        lines.append(
            f"| F1-Score                      | {self.f1_score * 100:>6.2f}%        | Harmonic mean of Precision/Recall|"
        )
        lines.append(sep)
        lines.append("")

        # Per-Attack Class Breakdown
        if self.per_class:
            class_sep = "+------------------------------+---------+----------+--------+---------------------+"
            lines.append("PER-ATTACK DETECTION BREAKDOWN:")
            lines.append(class_sep)
            lines.append(
                "| Ground Truth Class           | Windows | Detected | Recall | Primary Rules       |"
            )
            lines.append(class_sep)
            for label, stats in sorted(self.per_class.items()):
                top_rule = (
                    max(stats.triggered_rules, key=lambda r: stats.triggered_rules[r])
                    if stats.triggered_rules
                    else "None"
                )
                if len(top_rule) > 19:
                    top_rule = top_rule[:16] + "..."
                lines.append(
                    f"| {label:<28} | {stats.total_windows:>7} | {stats.detected_windows:>8} | {stats.recall * 100:>5.1f}% | {top_rule:<19} |"
                )
            lines.append(class_sep)
            lines.append("")

        # Triggered Rules Summary
        if self.rule_counts:
            rule_sep = "+------------------------------------------+-------------------+"
            lines.append("HEURISTIC RULE TRIGGER COUNTS:")
            lines.append(rule_sep)
            lines.append("| Detection Rule Name                      | Windows Triggered |")
            lines.append(rule_sep)
            for rule_name, count in sorted(self.rule_counts.items(), key=lambda x: -x[1]):
                lines.append(f"| {rule_name:<40} | {count:>17} |")
            lines.append(rule_sep)

        lines.append(border + "\n")
        return "\n".join(lines)


class DatasetEvaluator:
    """Evaluates a detection engine against labeled network datasets."""

    def __init__(
        self,
        detector: BaseDetector,
        window_size: float = 1.0,
        step_size: float = 0.2,
        attack_schedule: AttackSchedule | None = None,
    ) -> None:
        self.detector = detector
        self.window_size = window_size
        self.step_size = step_size
        self.attack_schedule = attack_schedule

    def evaluate_stream(self, packets: Iterable[PacketRecord]) -> EvaluationMetrics:
        """Evaluate a packet stream containing labeled records or evaluated against schedule."""
        start_eval_time = time.perf_counter()
        aggregator = SlidingWindowAggregator(
            window_size=self.window_size,
            step_size=self.step_size,
        )

        tp = 0
        fp = 0
        tn = 0
        fn = 0
        total_packets = 0
        total_windows = 0
        rule_counts: dict[str, int] = Counter()
        per_class_total: dict[str, int] = Counter()
        per_class_detected: dict[str, int] = Counter()
        per_class_rules: dict[str, dict[str, int]] = defaultdict(lambda: Counter())

        def _counting_stream() -> Iterator[PacketRecord]:
            nonlocal total_packets
            for pkt in packets:
                total_packets += 1
                yield pkt

        for window in aggregator.aggregate(_counting_stream()):
            total_windows += 1

            # Determine ground-truth labels for this observation window
            attack_labels: set[str] = {
                lbl
                for lbl in window.ground_truth_labels
                if lbl.strip().upper() not in {"BENIGN", "NORMAL", "0", "NONE", ""}
            }

            # Check attack schedule if provided
            if self.attack_schedule:
                schedule_labels = self.attack_schedule.overlaps_attack(
                    window.start_time, window.end_time
                )
                attack_labels.update(schedule_labels)

            is_actual_attack = len(attack_labels) > 0

            # Track class totals
            if is_actual_attack:
                for lbl in attack_labels:
                    per_class_total[lbl] += 1
            else:
                per_class_total["BENIGN"] += 1

            # Run detector on window
            alerts = self.detector.evaluate_window(window)
            is_predicted_attack = len(alerts) > 0

            # Classify window into confusion matrix
            if is_actual_attack and is_predicted_attack:
                tp += 1
                for lbl in attack_labels:
                    per_class_detected[lbl] += 1
                    for alert in alerts:
                        per_class_rules[lbl][alert.rule_name] += 1
                for alert in alerts:
                    rule_counts[alert.rule_name] += 1
            elif not is_actual_attack and is_predicted_attack:
                fp += 1
                for alert in alerts:
                    rule_counts[alert.rule_name] += 1
            elif not is_actual_attack and not is_predicted_attack:
                tn += 1
            else:  # is_actual_attack and not is_predicted_attack
                fn += 1

        elapsed = max(0.001, time.perf_counter() - start_eval_time)

        # Build per-class metrics
        per_class_metrics: dict[str, PerClassMetrics] = {}
        for label, total_win in per_class_total.items():
            det_win = per_class_detected.get(label, 0)
            rules = dict(per_class_rules.get(label, {}))
            per_class_metrics[label] = PerClassMetrics(
                label=label,
                total_windows=total_win,
                detected_windows=det_win,
                triggered_rules=rules,
            )

        return EvaluationMetrics(
            total_windows=total_windows,
            total_packets=total_packets,
            evaluation_duration_seconds=elapsed,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            per_class=per_class_metrics,
            rule_counts=dict(rule_counts),
        )

    def evaluate_csv(
        self,
        csv_path: str | Path,
        mapping: CsvFieldMapping | None = None,
    ) -> EvaluationMetrics:
        """Stream and evaluate a CSV dataset file (e.g., CIC-IDS2017)."""
        field_mapping = mapping or CIC_IDS2017_CSV_MAPPING
        return self.evaluate_stream(stream_csv(csv_path, mapping=field_mapping))

    def evaluate_pcap(
        self,
        pcap_path: str | Path,
        schedule_path: str | Path | None = None,
    ) -> EvaluationMetrics:
        """Stream and evaluate an offline PCAP file against an optional attack schedule."""
        if schedule_path:
            self.attack_schedule = AttackSchedule.from_json(schedule_path)
        return self.evaluate_stream(stream_pcap(pcap_path))


def generate_synthetic_benchmark_stream() -> list[PacketRecord]:
    """Generate a multi-phase labeled network benchmark capture stream for validation.

    Phases:
    - 0s - 10s: Benign background web browsing (BENIGN)
    - 10s - 15s: TCP SYN Flood attack (DoS SYN-Flood)
    - 15s - 25s: Benign background web browsing (BENIGN)
    - 25s - 30s: L7 HTTP Flood on /login.php (DoS Hulk / WebDDoS)
    - 30s - 40s: Benign background web browsing (BENIGN)
    - 40s - 45s: Volumetric UDP Flood (DDoS LOIC-UDP)
    - 45s - 55s: Benign recovery traffic (BENIGN)
    """
    records: list[PacketRecord] = []

    def _add_benign(start: float, end: float) -> None:
        # ~20 pps of regular browsing
        t = start
        while t < end:
            records.append(
                PacketRecord(
                    timestamp=t,
                    src_ip=f"192.168.1.{10 + (int(t * 10) % 50)}",
                    dst_ip="93.184.216.34",
                    protocol="TCP",
                    src_port=40000 + (int(t * 100) % 20000),
                    dst_port=443,
                    packet_size=120,
                    tcp_flags=frozenset({"ACK"}),
                    label="BENIGN",
                )
            )
            t += 0.05

    # Phase 1: Benign
    _add_benign(0.0, 10.0)

    # Phase 2: TCP SYN Flood (10.0 - 15.0) -> 150 SYN/s
    t = 10.0
    while t < 15.0:
        records.append(
            PacketRecord(
                timestamp=t,
                src_ip="192.0.2.66",
                dst_ip="192.168.1.100",
                protocol="TCP",
                src_port=50000 + (int(t * 1000) % 15000),
                dst_port=80,
                packet_size=64,
                tcp_flags=frozenset({"SYN"}),
                label="DoS SYN-Flood",
            )
        )
        t += 0.0066  # ~150 pps

    # Phase 3: Benign
    _add_benign(15.0, 25.0)

    # Phase 4: L7 HTTP GET Flood (25.0 - 30.0) -> 40 req/s to /login.php
    t = 25.0
    while t < 30.0:
        records.append(
            PacketRecord(
                timestamp=t,
                src_ip="192.0.2.77",
                dst_ip="192.168.1.100",
                protocol="TCP",
                src_port=55000 + (int(t * 1000) % 10000),
                dst_port=80,
                packet_size=350,
                tcp_flags=frozenset({"ACK", "PSH"}),
                http_method="GET",
                http_uri="/login.php",
                label="DoS Hulk / WebDDoS",
            )
        )
        t += 0.025  # ~40 pps

    # Phase 5: Benign
    _add_benign(30.0, 40.0)

    # Phase 6: Volumetric UDP Flood (40.0 - 45.0) -> 1200 pps
    t = 40.0
    while t < 45.0:
        records.append(
            PacketRecord(
                timestamp=t,
                src_ip=f"10.0.0.{1 + (int(t * 1000) % 250)}",
                dst_ip="192.168.1.100",
                protocol="UDP",
                src_port=12345,
                dst_port=9999,
                packet_size=1024,
                label="DDoS LOIC-UDP",
            )
        )
        t += 0.000833  # ~1200 pps

    # Phase 7: Benign recovery
    _add_benign(45.0, 55.0)

    return sorted(records, key=lambda x: x.timestamp)
