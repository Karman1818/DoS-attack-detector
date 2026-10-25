"""Feature extraction and time-window aggregation for network packets.

Calculates volumetric metrics and protocol flag distributions over discrete
time intervals for downstream rule and model evaluation.
"""

from collections.abc import Sequence

from dos_detector.models import PacketRecord, TrafficWindow


def compute_window_features(
    records: Sequence[PacketRecord],
    start_time: float,
    end_time: float,
) -> TrafficWindow:
    """Aggregate a sequence of packet records into a TrafficWindow.

    Args:
        records: Collection of packet records falling within the window.
        start_time: Epoch timestamp of the window opening.
        end_time: Epoch timestamp of the window closing.

    Returns:
        TrafficWindow containing computed aggregate rates and metrics.
    """
    total_packets = len(records)
    total_bytes = sum(pkt.packet_size for pkt in records)
    duration = max(0.001, end_time - start_time)

    packet_rate = total_packets / duration
    byte_rate = total_bytes / duration

    syn_count = sum(1 for pkt in records if "SYN" in pkt.tcp_flags and "ACK" not in pkt.tcp_flags)
    ack_count = sum(1 for pkt in records if "ACK" in pkt.tcp_flags)
    rst_count = sum(1 for pkt in records if "RST" in pkt.tcp_flags)

    unique_src_ips = len({pkt.src_ip for pkt in records if pkt.src_ip})
    unique_dst_ports = len({pkt.dst_port for pkt in records if pkt.dst_port is not None})

    return TrafficWindow(
        start_time=start_time,
        end_time=end_time,
        total_packets=total_packets,
        total_bytes=total_bytes,
        packet_rate=packet_rate,
        byte_rate=byte_rate,
        syn_count=syn_count,
        ack_count=ack_count,
        rst_count=rst_count,
        unique_src_ips=unique_src_ips,
        unique_dst_ports=unique_dst_ports,
    )
