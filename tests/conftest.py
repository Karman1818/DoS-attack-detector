"""Pytest configuration and deterministic fixtures for unit and integration tests.

All fixtures generate synthetic in-memory data to ensure tests are reproducible,
fast, and safe to execute offline in any environment.
"""

import pytest

from dos_detector.config import DetectionConfig
from dos_detector.models import PacketRecord, TrafficWindow


@pytest.fixture
def default_config() -> DetectionConfig:
    """Provide a standard detection configuration for testing."""
    return DetectionConfig(
        window_size_seconds=1.0,
        syn_flood_pps_threshold=100.0,
        syn_ack_ratio_threshold=3.0,
        volumetric_bps_threshold=10_000_000.0,
        packet_flood_pps_threshold=1_000.0,
        min_packets_for_ratio_eval=10,
    )


@pytest.fixture
def synthetic_syn_flood_packets() -> list[PacketRecord]:
    """Generate synthetic SYN flood packets without accompanying ACKs."""
    packets: list[PacketRecord] = []
    base_time = 1000.0
    for i in range(150):
        packets.append(
            PacketRecord(
                timestamp=base_time + (i * 0.005),
                src_ip=f"192.0.2.{i % 20 + 1}",
                dst_ip="198.51.100.10",
                protocol="TCP",
                src_port=40000 + i,
                dst_port=80,
                packet_size=64,
                tcp_flags=frozenset({"SYN"}),
            )
        )
    return packets


@pytest.fixture
def normal_traffic_window() -> TrafficWindow:
    """Provide a balanced, non-suspicious traffic window."""
    return TrafficWindow(
        start_time=1000.0,
        end_time=1001.0,
        total_packets=50,
        total_bytes=40_000,
        packet_rate=50.0,
        byte_rate=40_000.0,
        syn_count=10,
        ack_count=20,
        rst_count=1,
        unique_src_ips=5,
        unique_dst_ports=2,
    )
