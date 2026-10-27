"""Unit tests for the rule-based detection engine and DoS vs DDoS classification."""

import pytest

from dos_detector.config import DetectionConfig
from dos_detector.detector import RuleBasedDetector, classify_attack_distribution
from dos_detector.models import Severity, TrafficWindow


@pytest.mark.unit
def test_normal_traffic_generates_no_alerts(
    default_config: DetectionConfig, normal_traffic_window: TrafficWindow
) -> None:
    detector = RuleBasedDetector(config=default_config)
    alerts = detector.evaluate_window(normal_traffic_window)
    assert len(alerts) == 0


@pytest.mark.unit
def test_syn_flood_generates_high_severity_alert(default_config: DetectionConfig) -> None:
    detector = RuleBasedDetector(config=default_config)
    suspicious_window = TrafficWindow(
        start_time=100.0,
        end_time=101.0,
        total_packets=200,
        total_bytes=12800,
        packet_rate=200.0,
        byte_rate=12800.0,
        syn_count=190,
        ack_count=5,
        rst_count=0,
        unique_src_ips=20,
        unique_dst_ports=1,
        normalized_ip_entropy=0.85,
    )

    alerts = detector.evaluate_window(suspicious_window)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "SYN_FLOOD_SUSPECTED"
    assert alert.severity == Severity.HIGH
    assert alert.confidence >= 0.8
    assert alert.attack_type == "DISTRIBUTED_DOS (DDoS)"
    assert alert.distribution_confidence >= 0.8
    assert "syn_pps" in alert.metrics_snapshot


@pytest.mark.unit
def test_single_source_dos_classification() -> None:
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=500,
        total_bytes=32000,
        packet_rate=500.0,
        byte_rate=32000.0,
        syn_count=500,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_source_ip="192.168.1.100",
        top_source_ip_ratio=1.0,
        normalized_ip_entropy=0.0,
    )

    attack_type, conf, note = classify_attack_distribution(window)
    assert attack_type == "SINGLE_SOURCE_DOS"
    assert conf == 1.0
    assert "192.168.1.100" in note


@pytest.mark.unit
def test_distributed_ddos_classification() -> None:
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=1000,
        total_bytes=64000,
        packet_rate=1000.0,
        byte_rate=64000.0,
        syn_count=900,
        ack_count=10,
        rst_count=0,
        unique_src_ips=150,
        unique_dst_ports=1,
        top_source_ip="10.0.0.1",
        top_source_ip_ratio=0.05,
        normalized_ip_entropy=0.92,
    )

    attack_type, conf, note = classify_attack_distribution(window)
    assert attack_type == "DISTRIBUTED_DOS (DDoS)"
    assert conf >= 0.9
    assert "DDoS suspected" in note


@pytest.mark.unit
def test_coordinated_dos_classification() -> None:
    # 4 distinct sources splitting traffic evenly -> coordinated DoS
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=400,
        total_bytes=25600,
        packet_rate=400.0,
        byte_rate=25600.0,
        syn_count=400,
        ack_count=0,
        rst_count=0,
        unique_src_ips=4,
        unique_dst_ports=1,
        top_source_ip="192.168.1.10",
        top_source_ip_ratio=0.25,
        normalized_ip_entropy=1.0,
    )

    attack_type, conf, note = classify_attack_distribution(window)
    assert attack_type == "COORDINATED_DOS"
    assert conf >= 0.7
    assert "Coordinated DoS suspected" in note


@pytest.mark.unit
def test_volumetric_flood_generates_alert(default_config: DetectionConfig) -> None:
    detector = RuleBasedDetector(config=default_config)
    high_volume_window = TrafficWindow(
        start_time=100.0,
        end_time=101.0,
        total_packets=10_000,
        total_bytes=15_000_000,  # 15 MB/s (exceeds default 10 MB/s)
        packet_rate=10_000.0,
        byte_rate=15_000_000.0,
        syn_count=100,
        ack_count=100,
        rst_count=0,
        unique_src_ips=50,
        unique_dst_ports=10,
    )

    alerts = detector.evaluate_window(high_volume_window)
    alert_rules = [a.rule_name for a in alerts]
    assert "VOLUMETRIC_FLOOD_SUSPECTED" in alert_rules
    assert "PACKET_RATE_FLOOD_SUSPECTED" in alert_rules
