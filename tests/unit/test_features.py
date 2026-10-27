"""Unit tests for feature computation, Shannon entropy, and sliding window aggregation."""

import pytest

from dos_detector.features import (
    SlidingWindowAggregator,
    compute_shannon_entropy,
    compute_window_features,
)
from dos_detector.models import PacketRecord


@pytest.mark.unit
def test_compute_window_features(synthetic_syn_flood_packets: list[PacketRecord]) -> None:
    window = compute_window_features(
        records=synthetic_syn_flood_packets,
        start_time=1000.0,
        end_time=1001.0,
    )

    assert window.total_packets == 150
    assert window.syn_count == 150
    assert window.ack_count == 0
    assert window.packet_rate == pytest.approx(150.0)
    assert window.unique_dst_ports == 1
    assert window.unique_src_ips > 1
    assert window.ip_entropy > 0.0
    assert 0.0 <= window.normalized_ip_entropy <= 1.0


@pytest.mark.unit
def test_shannon_entropy_single_source() -> None:
    # 100 packets all from the same IP -> zero entropy (order)
    raw, norm = compute_shannon_entropy(counts=[100], total=100)
    assert raw == 0.0
    assert norm == 0.0


@pytest.mark.unit
def test_shannon_entropy_uniform_distribution() -> None:
    # 4 sources with equal shares (25 each, total 100)
    # H = -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2.0 bits
    # Max entropy for 4 items = log2(4) = 2.0 -> Normalized = 1.0 (100% disordered)
    raw, norm = compute_shannon_entropy(counts=[25, 25, 25, 25], total=100)
    assert raw == pytest.approx(2.0)
    assert norm == pytest.approx(1.0)


@pytest.mark.unit
def test_sliding_window_aggregator_invalid_args() -> None:
    with pytest.raises(ValueError, match="window_size must be positive"):
        SlidingWindowAggregator(window_size=0.0)

    with pytest.raises(ValueError, match="step_size must be positive"):
        SlidingWindowAggregator(window_size=1.0, step_size=-0.1)

    with pytest.raises(ValueError, match="cannot exceed window_size"):
        SlidingWindowAggregator(window_size=1.0, step_size=2.0)


@pytest.mark.unit
def test_sliding_window_aggregator_overlapping_windows() -> None:
    # Generate 10 packets spaced by 0.2s from t=0.0s to t=1.8s
    packets = [
        PacketRecord(
            timestamp=i * 0.2,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            protocol="TCP",
            src_port=10000 + i,
            dst_port=80,
            packet_size=64,
            tcp_flags=frozenset({"SYN"}),
        )
        for i in range(10)
    ]

    aggregator = SlidingWindowAggregator(window_size=1.0, step_size=0.4)
    windows = list(aggregator.aggregate(packets))

    # Expect multiple overlapping windows advancing by 0.4s
    assert len(windows) >= 3
    assert windows[0].start_time == pytest.approx(0.0)
    assert windows[0].end_time == pytest.approx(1.0)

    assert windows[1].start_time == pytest.approx(0.4)
    assert windows[1].end_time == pytest.approx(1.4)


@pytest.mark.unit
def test_sliding_window_aggregator_large_time_gap() -> None:
    # 2 packets at t=0, then a 500s gap, then 2 packets at t=500
    packets = [
        PacketRecord(
            timestamp=0.1,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            protocol="TCP",
            packet_size=64,
        ),
        PacketRecord(
            timestamp=0.2,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            protocol="TCP",
            packet_size=64,
        ),
        PacketRecord(
            timestamp=500.1,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            protocol="TCP",
            packet_size=64,
        ),
        PacketRecord(
            timestamp=500.2,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            protocol="TCP",
            packet_size=64,
        ),
    ]

    aggregator = SlidingWindowAggregator(window_size=1.0, step_size=0.2)
    windows = list(aggregator.aggregate(packets))

    # Should not produce 2500 empty windows! It should advance efficiently.
    assert len(windows) <= 15


@pytest.mark.unit
def test_sliding_window_aggregator_out_of_order_bisect() -> None:
    # Packet sequence with out-of-order jitter (0.3 arrives after 0.5)
    packets = [
        PacketRecord(timestamp=0.1, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
        PacketRecord(timestamp=0.5, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
        PacketRecord(timestamp=0.3, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),  # Jitter!
        PacketRecord(timestamp=0.8, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
        PacketRecord(timestamp=1.5, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"),
    ]

    aggregator = SlidingWindowAggregator(window_size=1.0, step_size=0.4)
    windows = list(aggregator.aggregate(packets))

    # Window 0: [0.1, 1.1] -> Contains 4 packets (0.1, 0.3, 0.5, 0.8)
    assert windows[0].total_packets == 4

    # Window 1: [0.5, 1.5] -> Both 0.1 and 0.3 should be properly evicted by bisect sorting!
    # Contains: 0.5, 0.8
    assert windows[1].total_packets == 2


@pytest.mark.unit
def test_protocol_and_target_features_extraction() -> None:
    """Validate extraction of TCP, UDP, DNS and victim destination target metrics."""
    packets = [
        # 3 DNS packets (UDP to port 53)
        PacketRecord(
            timestamp=0.1,
            src_ip="172.16.0.5",
            dst_ip="192.168.1.1",
            protocol="UDP",
            src_port=54321,
            dst_port=53,
            packet_size=120,
        ),
        PacketRecord(
            timestamp=0.2,
            src_ip="172.16.0.5",
            dst_ip="192.168.1.1",
            protocol="UDP",
            src_port=54322,
            dst_port=53,
            packet_size=120,
        ),
        PacketRecord(
            timestamp=0.3,
            src_ip="172.16.0.5",
            dst_ip="192.168.1.1",
            protocol="UDP",
            src_port=54323,
            dst_port=53,
            packet_size=120,
        ),
        # 1 HTTP packet (TCP to port 80)
        PacketRecord(
            timestamp=0.4,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.2",
            protocol="TCP",
            src_port=60000,
            dst_port=80,
            packet_size=60,
            tcp_flags=frozenset({"SYN"}),
        ),
    ]

    window = compute_window_features(records=packets, start_time=0.0, end_time=1.0)

    assert window.total_packets == 4
    assert window.udp_count == 3
    assert window.tcp_count == 1
    assert window.dns_count == 3
    assert window.dns_ratio == pytest.approx(0.75)
    assert window.udp_ratio == pytest.approx(0.75)
    assert window.top_dst_ip == "192.168.1.1"
    assert window.top_dst_ip_ratio == pytest.approx(0.75)
    assert window.top_dst_port == 53
    assert window.top_dst_port_ratio == pytest.approx(0.75)
