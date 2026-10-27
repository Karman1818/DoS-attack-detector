"""Integration test exercising packet-to-alert pipeline flow."""

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from dos_detector.alerting import InMemoryAlertSink
from dos_detector.config import DetectionConfig
from dos_detector.detector import RuleBasedDetector
from dos_detector.features import compute_window_features, stream_sliding_windows
from dos_detector.ingestion import stream_pcap
from dos_detector.models import PacketRecord


@pytest.mark.integration
def test_end_to_end_synthetic_syn_flood_pipeline(
    default_config: DetectionConfig,
    synthetic_syn_flood_packets: list[PacketRecord],
) -> None:
    # 1. Feature extraction from synthetic packets
    window = compute_window_features(
        records=synthetic_syn_flood_packets,
        start_time=1000.0,
        end_time=1001.0,
    )

    # 2. Rule evaluation
    detector = RuleBasedDetector(config=default_config)
    alerts = detector.evaluate_window(window)

    # 3. Alert sink consumption
    sink = InMemoryAlertSink()
    for alert in alerts:
        sink.emit(alert)

    # 4. Verification
    assert len(sink.alerts) >= 1
    syn_alert = next(a for a in sink.alerts if a.rule_name == "SYN_FLOOD_SUSPECTED")
    assert syn_alert.confidence > 0.8
    assert "syn_pps" in syn_alert.metrics_snapshot


@pytest.mark.integration
def test_pcap_file_to_detection_pipeline(tmp_path: Path, default_config: DetectionConfig) -> None:
    # Create temporary PCAP with 120 SYN packets (exceeds 100 pps threshold)
    pcap_path = tmp_path / "flood.pcap"
    packets = [
        IP(src=f"192.0.2.{i % 20 + 1}", dst="198.51.100.1")
        / TCP(sport=40000 + i, dport=80, flags="S")
        for i in range(120)
    ]
    # Set synthetic timestamps over a 1-second interval
    for i, pkt in enumerate(packets):
        pkt.time = 2000.0 + (i * 0.008)

    wrpcap(str(pcap_path), packets)

    # Stream from PCAP file offline
    streamed_records = list(stream_pcap(pcap_path))
    assert len(streamed_records) == 120

    # Aggregate into window
    window = compute_window_features(streamed_records, start_time=2000.0, end_time=2001.0)

    # Detect
    detector = RuleBasedDetector(config=default_config)
    alerts = detector.evaluate_window(window)

    assert len(alerts) >= 1
    assert any(a.rule_name == "SYN_FLOOD_SUSPECTED" for a in alerts)


@pytest.mark.integration
def test_sliding_window_stream_integration(tmp_path: Path, default_config: DetectionConfig) -> None:
    # 150 packets spread across 2.0s
    pcap_path = tmp_path / "sliding_test.pcap"
    packets = [
        IP(src=f"10.0.0.{1 + (i % 30)}", dst="192.168.1.1")
        / TCP(sport=50000 + i, dport=80, flags="S")
        for i in range(150)
    ]
    for i, pkt in enumerate(packets):
        pkt.time = 3000.0 + (i * 0.01)  # 100 packets/sec over 1.5s

    wrpcap(str(pcap_path), packets)

    # Full decoupled pipeline: PCAP -> Sliding Windows -> Detector -> Sink
    packet_stream = stream_pcap(pcap_path)
    window_stream = stream_sliding_windows(packet_stream, window_size=1.0, step_size=0.2)

    detector = RuleBasedDetector(config=default_config)
    sink = InMemoryAlertSink()

    windows_count = 0
    for window in window_stream:
        windows_count += 1
        for alert in detector.evaluate_window(window):
            sink.emit(alert)

    # Multiple overlapping windows should be produced
    assert windows_count >= 3
    # High SYN rate across 30 IPs should trigger distributed DDoS detection
    assert len(sink.alerts) >= 1
    assert any(a.attack_type == "DISTRIBUTED_DOS (DDoS)" for a in sink.alerts)
