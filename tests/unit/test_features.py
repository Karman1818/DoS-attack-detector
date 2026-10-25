"""Unit tests for feature computation and aggregation."""

import pytest

from dos_detector.features import compute_window_features
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
