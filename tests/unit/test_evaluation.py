"""Unit tests for the benchmark dataset evaluation harness."""

import json
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from dos_detector.config import DetectionConfig
from dos_detector.detector import RuleBasedDetector
from dos_detector.evaluation import (
    AttackSchedule,
    DatasetEvaluator,
    EvaluationMetrics,
    GroundTruthInterval,
    PerClassMetrics,
    generate_synthetic_benchmark_stream,
)
from dos_detector.ingestion import CIC_IDS2017_CSV_MAPPING
from dos_detector.models import PacketRecord


@pytest.mark.unit
def test_ground_truth_interval_overlap() -> None:
    """Verify time interval overlap logic."""
    interval = GroundTruthInterval(start_time=10.0, end_time=20.0, label="DoS Hulk")

    # Strictly before
    assert not interval.overlaps(0.0, 9.9)
    # Strictly after
    assert not interval.overlaps(20.1, 30.0)
    # Touching boundary
    assert not interval.overlaps(0.0, 10.0)
    assert not interval.overlaps(20.0, 30.0)
    # Overlapping start
    assert interval.overlaps(9.0, 11.0)
    # Overlapping end
    assert interval.overlaps(19.0, 21.0)
    # Enclosed within
    assert interval.overlaps(12.0, 18.0)
    # Enclosing interval
    assert interval.overlaps(5.0, 25.0)


@pytest.mark.unit
def test_attack_schedule_from_dict_and_json(tmp_path: Path) -> None:
    """Verify building AttackSchedule from dictionary and JSON file."""
    schedule_data = {
        "attacks": [
            {"start": 100.0, "end": 200.0, "label": "DoS Slowloris", "description": "Slow HTTP"},
            {"start": 300.0, "end": 400.0, "label": "DDoS LOIC", "description": "UDP Flood"},
        ]
    }
    schedule = AttackSchedule.from_dict(schedule_data)
    assert len(schedule.intervals) == 2
    assert schedule.overlaps_attack(150.0, 160.0) == ("DoS Slowloris",)
    assert schedule.overlaps_attack(500.0, 600.0) == ()

    json_file = tmp_path / "schedule.json"
    with json_file.open("w", encoding="utf-8") as f:
        json.dump(schedule_data, f)

    loaded = AttackSchedule.from_json(json_file)
    assert len(loaded.intervals) == 2
    assert loaded.overlaps_attack(350.0, 360.0) == ("DDoS LOIC",)


@pytest.mark.unit
def test_evaluation_metrics_calculations() -> None:
    """Test precision, recall, F1-score, accuracy, and specificity formulas."""
    metrics = EvaluationMetrics(
        total_windows=100,
        total_packets=5000,
        evaluation_duration_seconds=1.5,
        true_positives=40,
        false_positives=5,
        true_negatives=50,
        false_negatives=5,
        per_class={
            "DoS SYN-Flood": PerClassMetrics(
                label="DoS SYN-Flood",
                total_windows=45,
                detected_windows=40,
                triggered_rules={"SYN_FLOOD_SUSPECTED": 40},
            )
        },
        rule_counts={"SYN_FLOOD_SUSPECTED": 45},
    )

    assert metrics.accuracy == (40 + 50) / 100  # 0.90
    assert metrics.precision == 40 / (40 + 5)  # ~0.8889
    assert metrics.recall == 40 / (40 + 5)  # ~0.8889
    assert metrics.specificity == 50 / (50 + 5)  # ~0.9091
    assert metrics.false_positive_rate == 5 / (5 + 50)  # ~0.0909
    assert round(metrics.f1_score, 4) == round(2 * (40 / 45 * 40 / 45) / (40 / 45 + 40 / 45), 4)

    # Dictionary serialization
    serialized = metrics.to_dict()
    assert serialized["summary"]["total_windows"] == 100
    assert "precision" in serialized["summary"]["metrics"]
    assert "DoS SYN-Flood" in serialized["per_class"]


@pytest.mark.unit
def test_evaluation_metrics_zero_division_safety() -> None:
    """Ensure evaluation metrics handle all-benign or all-attack edge cases without ZeroDivisionError."""
    # All benign traffic, 0 TP and 0 FP
    metrics_benign = EvaluationMetrics(
        total_windows=50,
        total_packets=1000,
        evaluation_duration_seconds=0.5,
        true_positives=0,
        false_positives=0,
        true_negatives=50,
        false_negatives=0,
    )
    assert metrics_benign.precision == 1.0
    assert metrics_benign.recall == 1.0
    assert metrics_benign.f1_score == 1.0
    assert metrics_benign.specificity == 1.0
    assert metrics_benign.false_positive_rate == 0.0

    # Report rendering
    report = metrics_benign.render_ascii_report()
    assert "CONFUSION MATRIX" in report
    assert "CLASSIFICATION METRICS" in report


@pytest.mark.unit
def test_export_json_and_load(tmp_path: Path) -> None:
    """Verify saving metrics report to JSON."""
    metrics = EvaluationMetrics(
        total_windows=20,
        total_packets=200,
        evaluation_duration_seconds=0.1,
        true_positives=10,
        false_positives=0,
        true_negatives=10,
        false_negatives=0,
    )
    out_file = tmp_path / "eval_results.json"
    metrics.export_json(out_file)

    assert out_file.is_file()
    with out_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["summary"]["metrics"]["accuracy"] == 1.0


@pytest.mark.unit
def test_evaluate_stream_with_labeled_packets() -> None:
    """Test DatasetEvaluator using an in-memory stream of labeled packets."""
    config = DetectionConfig(
        window_size_seconds=1.0,
        syn_flood_pps_threshold=50.0,
        min_consecutive_windows=1,
        alert_cooldown_seconds=0.0,
    )
    detector = RuleBasedDetector(config=config)
    evaluator = DatasetEvaluator(detector=detector, window_size=1.0, step_size=0.5)

    packets: list[PacketRecord] = []
    # 0s - 3s: Benign
    for i in range(30):
        packets.append(
            PacketRecord(
                timestamp=i * 0.1,
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                protocol="TCP",
                src_port=10000 + i,
                dst_port=80,
                packet_size=100,
                tcp_flags=frozenset({"ACK"}),
                label="BENIGN",
            )
        )

    # 3s - 5s: SYN Flood (100 SYN packets in 2s -> 50 pps)
    for i in range(120):
        packets.append(
            PacketRecord(
                timestamp=3.0 + (i * 0.015),
                src_ip="172.16.0.5",
                dst_ip="10.0.0.1",
                protocol="TCP",
                src_port=20000 + i,
                dst_port=80,
                packet_size=64,
                tcp_flags=frozenset({"SYN"}),
                label="DoS SYN-Flood",
            )
        )

    metrics = evaluator.evaluate_stream(packets)
    assert metrics.total_windows > 0
    assert metrics.false_positives == 0  # 0 FP on benign traffic
    assert metrics.true_positives > 0  # detected SYN flood
    assert "DoS SYN-Flood" in metrics.per_class
    assert metrics.per_class["DoS SYN-Flood"].detected_windows > 0


@pytest.mark.unit
def test_evaluate_csv_cic_format(tmp_path: Path) -> None:
    """Verify evaluation against a synthesized CIC-IDS2017 format CSV."""
    csv_file = tmp_path / "cic_sample.csv"
    lines = [
        "Destination Port, Flow Duration, Total Length of Fwd Packets, SYN Flag Count, ACK Flag Count, RST Flag Count, Timestamp, Label",
    ]

    # 10 benign rows
    for i in range(10):
        lines.append(f"80, 500, 100, 0, 1, 0, 2017-07-07 08:30:0{i}, BENIGN")

    # 50 SYN flood rows
    for i in range(50):
        ts = f"2017-07-07 08:30:{10 + (i // 5)}"
        lines.append(f"80, 10, 64, 1, 0, 0, {ts}, DoS Slowloris")

    csv_file.write_text("\n".join(lines), encoding="utf-8")

    config = DetectionConfig(
        window_size_seconds=1.0,
        syn_flood_pps_threshold=20.0,
        min_consecutive_windows=1,
        alert_cooldown_seconds=0.0,
    )
    detector = RuleBasedDetector(config=config)
    evaluator = DatasetEvaluator(detector=detector, window_size=1.0, step_size=0.5)

    metrics = evaluator.evaluate_csv(csv_file, mapping=CIC_IDS2017_CSV_MAPPING)
    assert metrics.total_packets == 60
    assert metrics.false_positives == 0


@pytest.mark.unit
def test_evaluate_pcap_with_schedule(tmp_path: Path) -> None:
    """Verify evaluation against a PCAP with an external attack schedule."""
    pcap_file = tmp_path / "test_capture.pcap"
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkts = []

    # 0s - 3s: Benign ACKs
    for i in range(15):
        pkt = eth / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=1234, dport=80, flags="A")
        pkt.time = float(i * 0.2)
        pkts.append(pkt)

    # 3s - 5s: Flood
    for i in range(100):
        pkt = eth / IP(src="172.16.0.99", dst="10.0.0.1") / TCP(sport=2000 + i, dport=80, flags="S")
        pkt.time = 3.0 + float(i * 0.02)
        pkts.append(pkt)

    wrpcap(str(pcap_file), pkts)

    schedule_file = tmp_path / "schedule.json"
    schedule_data = {
        "attacks": [
            {
                "start": 3.0,
                "end": 5.0,
                "label": "SYN-Flood-Attack",
                "description": "Simulated flood",
            }
        ]
    }
    schedule_file.write_text(json.dumps(schedule_data), encoding="utf-8")

    config = DetectionConfig(
        window_size_seconds=1.0,
        syn_flood_pps_threshold=30.0,
        min_consecutive_windows=1,
        alert_cooldown_seconds=0.0,
    )
    detector = RuleBasedDetector(config=config)
    evaluator = DatasetEvaluator(detector=detector, window_size=1.0, step_size=0.5)

    metrics = evaluator.evaluate_pcap(pcap_file, schedule_path=schedule_file)
    assert metrics.total_packets == 115
    assert metrics.true_positives > 0
    assert metrics.false_positives == 0
    assert "SYN-Flood-Attack" in metrics.per_class


@pytest.mark.unit
def test_synthetic_benchmark_stream_structure() -> None:
    """Verify generate_synthetic_benchmark_stream returns sorted multi-vector labeled records."""
    stream = generate_synthetic_benchmark_stream()
    assert len(stream) > 1000

    # Monotonic timestamps
    timestamps = [p.timestamp for p in stream]
    assert timestamps == sorted(timestamps)

    # Contains expected attack vectors
    labels = {p.label for p in stream if p.label}
    assert "BENIGN" in labels
    assert "DoS SYN-Flood" in labels
    assert "DoS Hulk / WebDDoS" in labels
    assert "DDoS LOIC-UDP" in labels
