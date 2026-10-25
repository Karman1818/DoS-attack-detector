"""Unit tests for the rule-based detection engine."""

import pytest

from dos_detector.config import DetectionConfig
from dos_detector.detector import RuleBasedDetector
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
    )

    alerts = detector.evaluate_window(suspicious_window)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "SYN_FLOOD_SUSPECTED"
    assert alert.severity == Severity.HIGH
    assert alert.confidence >= 0.8
    assert "syn_pps" in alert.metrics_snapshot


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
