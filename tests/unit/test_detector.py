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
    assert "Coordinated DoS" in note


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


@pytest.mark.unit
def test_dns_flood_detection_from_single_source() -> None:
    """Validate detection of high-rate DNS / UDP amplification or flood from single IP."""
    config = DetectionConfig(
        dns_flood_pps_threshold=500.0,
        min_consecutive_windows=1,
    )
    detector = RuleBasedDetector(config=config)

    # Simulating CIC-DDoS-2019-DNS: 172.16.0.5 flooding DNS requests/responses
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=5000,
        total_bytes=2_500_000,
        packet_rate=5000.0,
        byte_rate=2_500_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_source_ip="172.16.0.5",
        top_source_ip_ratio=1.0,
        udp_count=5000,
        dns_count=5000,
        top_dst_ip="192.168.50.1",
        top_dst_ip_ratio=1.0,
        top_dst_port=53,
        top_dst_port_ratio=1.0,
    )

    alerts = detector.evaluate_window(window)
    assert len(alerts) >= 1
    dns_alert = next((a for a in alerts if a.rule_name == "DNS_FLOOD_SUSPECTED"), None)
    assert dns_alert is not None
    # In CIC-DDoS-2019, DNS amplification is classified as a DRDoS (Distributed Reflection) vector
    assert "DISTRIBUTED_DOS" in dns_alert.attack_type
    assert dns_alert.ddos_probability >= 0.85
    assert dns_alert.dos_probability <= 0.15
    assert "DDoS" in dns_alert.distribution_summary
    assert dns_alert.confidence >= 0.85
    assert dns_alert.metrics_snapshot["dns_pps"] == 5000.0


@pytest.mark.unit
def test_micro_burst_filtered_by_consecutive_windows() -> None:
    """Ensure a transient single-window burst does not trigger an alert when min_consecutive=2."""
    config = DetectionConfig(
        packet_flood_pps_threshold=1000.0,
        min_consecutive_windows=2,
    )
    detector = RuleBasedDetector(config=config)

    # Window 1: Isolated micro-burst (e.g., 1287 pps)
    burst_window_1 = TrafficWindow(
        start_time=10.0,
        end_time=11.0,
        total_packets=1287,
        total_bytes=800_000,
        packet_rate=1287.0,
        byte_rate=800_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_dst_ip_ratio=1.0,
    )
    alerts_1 = detector.evaluate_window(burst_window_1)
    # First window should be suppressed as a potential transient burst
    assert len(alerts_1) == 0

    # Window 2: Sustained flood continuing
    burst_window_2 = TrafficWindow(
        start_time=10.2,
        end_time=11.2,
        total_packets=1300,
        total_bytes=810_000,
        packet_rate=1300.0,
        byte_rate=810_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_dst_ip_ratio=1.0,
    )
    alerts_2 = detector.evaluate_window(burst_window_2)
    # Second window confirms sustained attack -> alert emitted
    assert len(alerts_2) == 1
    assert alerts_2[0].rule_name == "PACKET_RATE_FLOOD_SUSPECTED"


@pytest.mark.unit
def test_alert_cooldown_suppresses_duplicate_sliding_alerts() -> None:
    """Ensure overlapping sliding windows do not spam duplicate alerts within cooldown window."""
    config = DetectionConfig(
        packet_flood_pps_threshold=1000.0,
        min_consecutive_windows=1,
        alert_cooldown_seconds=1.0,
    )
    detector = RuleBasedDetector(config=config)

    window_1 = TrafficWindow(
        start_time=1.0,
        end_time=2.0,
        total_packets=2000,
        total_bytes=1_000_000,
        packet_rate=2000.0,
        byte_rate=1_000_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_dst_ip_ratio=1.0,
    )
    alerts_1 = detector.evaluate_window(window_1)
    assert len(alerts_1) == 1

    # Window 2: 0.2s later (overlapping window within 1.0s cooldown)
    window_2 = TrafficWindow(
        start_time=1.2,
        end_time=2.2,
        total_packets=2100,
        total_bytes=1_050_000,
        packet_rate=2100.0,
        byte_rate=1_050_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_dst_ip_ratio=1.0,
    )
    alerts_2 = detector.evaluate_window(window_2)
    assert len(alerts_2) == 0  # Suppressed by cooldown!

    # Window 3: 1.5s later (past 1.0s cooldown)
    window_3 = TrafficWindow(
        start_time=2.5,
        end_time=3.5,
        total_packets=2050,
        total_bytes=1_020_000,
        packet_rate=2050.0,
        byte_rate=1_020_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        top_dst_ip_ratio=1.0,
    )
    alerts_3 = detector.evaluate_window(window_3)
    assert len(alerts_3) == 1


@pytest.mark.unit
def test_multi_target_benign_transit_traffic_not_flagged_as_ddos() -> None:
    """Verify that multi-target distributed browsing traffic is not falsely marked as DDoS."""
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=1200,
        total_bytes=600_000,
        packet_rate=1200.0,
        byte_rate=600_000.0,
        syn_count=20,
        ack_count=100,
        rst_count=0,
        unique_src_ips=17,
        unique_dst_ips=15,  # Communicating with 15 different servers
        unique_dst_ports=8,
        top_dst_ip="93.184.216.34",
        top_dst_ip_ratio=0.15,  # No concentrated victim target!
        top_dst_port=443,
        top_dst_port_ratio=0.30,
        normalized_ip_entropy=0.88,
    )

    attack_type, conf, note = classify_attack_distribution(window)
    assert attack_type == "DISTRIBUTED_TRANSIT_TRAFFIC"
    assert conf < 0.50
    assert "low threat confidence" in note

    # Detector should not raise PACKET_RATE_FLOOD_SUSPECTED for distributed transit traffic
    detector = RuleBasedDetector()
    alerts = detector.evaluate_window(window)
    assert len(alerts) == 0


@pytest.mark.unit
def test_http_web_ddos_detection() -> None:
    """Validate detection of Layer 7 repetitive HTTP GET flood (WebDDoS) targeting /c.php."""
    config = DetectionConfig(
        http_flood_pps_threshold=30.0,
        min_http_requests=30,
        http_uri_repetition_threshold=0.60,
        min_consecutive_windows=1,
    )
    detector = RuleBasedDetector(config=config)

    # Simulating CIC-DDoS-2019-WebDDoS: 200 HTTP requests in 1.0s window, 90% targeting /c.php
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=300,
        total_bytes=150_000,
        packet_rate=300.0,
        byte_rate=150_000.0,
        syn_count=10,
        ack_count=90,
        rst_count=0,
        unique_src_ips=5,
        unique_dst_ports=1,
        tcp_count=300,
        http_request_count=200,
        top_http_uri="/c.php",
        top_http_uri_ratio=0.90,
        top_dst_ip="192.168.50.4",
        top_dst_ip_ratio=0.95,
        top_dst_port=80,
        top_dst_port_ratio=0.95,
    )

    alerts = detector.evaluate_window(window)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "HTTP_WEB_DDOS_SUSPECTED"
    assert alert.severity == Severity.HIGH
    assert "/c.php" in alert.description
    assert alert.metrics_snapshot["top_http_uri"] == "/c.php"
    assert alert.metrics_snapshot["top_http_uri_ratio"] == 0.90


@pytest.mark.unit
def test_massive_syn_flood_with_server_responses_triggers_high_alert() -> None:
    """Ensure massive SYN flood (>26k pps) triggers alert even if server replies with SYN-ACK/RST."""
    config = DetectionConfig(
        syn_flood_pps_threshold=100.0,
        syn_ack_ratio_threshold=3.0,
        min_consecutive_windows=1,
    )
    detector = RuleBasedDetector(config=config)

    # Simulating CIC-DDoS-2019-SynFlood: 26,000 pps, server responds with ACKs (ratio=1.2 < 3.0)
    # But syn_pps = 14,000 and syn_ratio_in_tcp = 70%
    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=26_000,
        total_bytes=1_600_000,
        packet_rate=26_000.0,
        byte_rate=1_600_000.0,
        syn_count=18_000,
        ack_count=8_000,
        rst_count=500,
        tcp_count=26_000,
        unique_src_ips=150,
        unique_dst_ports=1,
        top_dst_ip="192.168.50.4",
        top_dst_ip_ratio=0.99,
        top_dst_port=80,
        top_dst_port_ratio=0.99,
        normalized_ip_entropy=0.95,
    )

    alerts = detector.evaluate_window(window)
    assert len(alerts) >= 1
    syn_alert = next((a for a in alerts if a.rule_name == "SYN_FLOOD_SUSPECTED"), None)
    assert syn_alert is not None
    assert syn_alert.severity == Severity.HIGH
    # Should NOT be shadowed or subsumed by general PACKET_RATE_FLOOD
    assert not any(a.rule_name == "PACKET_RATE_FLOOD_SUSPECTED" for a in alerts)


@pytest.mark.unit
def test_rule_priority_dns_before_udp_flood() -> None:
    """Ensure DNS flood on port 53 is prioritized over generic UDP flood."""
    config = DetectionConfig(
        dns_flood_pps_threshold=500.0,
        udp_flood_pps_threshold=1000.0,
        min_consecutive_windows=1,
    )
    detector = RuleBasedDetector(config=config)

    window = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=5200,
        total_bytes=3_000_000,
        packet_rate=5200.0,
        byte_rate=3_000_000.0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        unique_src_ips=1,
        unique_dst_ports=1,
        udp_count=5200,
        dns_count=5200,
        top_dst_ip="192.168.50.1",
        top_dst_ip_ratio=1.0,
        top_dst_port=53,
        top_dst_port_ratio=1.0,
    )

    alerts = detector.evaluate_window(window)
    rule_names = [a.rule_name for a in alerts]
    assert "DNS_FLOOD_SUSPECTED" in rule_names
    assert "UDP_FLOOD_SUSPECTED" not in rule_names
    assert "PACKET_RATE_FLOOD_SUSPECTED" not in rule_names
