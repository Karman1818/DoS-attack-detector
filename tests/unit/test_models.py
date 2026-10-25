"""Unit tests for domain models and properties."""

import pytest

from dos_detector.models import PacketRecord, Severity, TrafficWindow


@pytest.mark.unit
def test_packet_record_is_immutable() -> None:
    record = PacketRecord(
        timestamp=100.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        protocol="TCP",
        src_port=54321,
        dst_port=80,
        packet_size=128,
        tcp_flags=frozenset({"SYN"}),
    )
    with pytest.raises(AttributeError):
        # Frozen dataclass should reject attribute mutations
        record.src_port = 8080  # type: ignore[misc]


@pytest.mark.unit
def test_traffic_window_syn_ack_ratio_calculation() -> None:
    window_balanced = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=20,
        total_bytes=1000,
        packet_rate=20.0,
        byte_rate=1000.0,
        syn_count=10,
        ack_count=10,
        rst_count=0,
        unique_src_ips=2,
        unique_dst_ports=1,
    )
    assert window_balanced.syn_ack_ratio == 1.0

    window_zero_ack = TrafficWindow(
        start_time=0.0,
        end_time=1.0,
        total_packets=50,
        total_bytes=2500,
        packet_rate=50.0,
        byte_rate=2500.0,
        syn_count=50,
        ack_count=0,
        rst_count=0,
        unique_src_ips=10,
        unique_dst_ports=1,
    )
    assert window_zero_ack.syn_ack_ratio == 50.0


@pytest.mark.unit
def test_severity_enumeration_values() -> None:
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"
