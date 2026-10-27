"""Feature extraction and time-window aggregation for network packets.

Calculates volumetric metrics, protocol flag distributions, and Shannon entropy
over discrete and sliding time windows for downstream detection evaluation.
"""

import bisect
import math
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Sequence

from dos_detector.models import PacketRecord, TrafficWindow


def compute_shannon_entropy(counts: Sequence[int], total: int) -> tuple[float, float]:
    """Calculate raw Shannon entropy and normalized entropy (0.0 to 1.0).

    Args:
        counts: Occurrences of each distinct symbol (e.g., packet count per IP).
        total: Sum of all counts.

    Returns:
        tuple of (raw_entropy_bits, normalized_entropy_ratio)
    """
    if total <= 1 or len(counts) <= 1:
        return 0.0, 0.0

    entropy = 0.0
    for count in counts:
        if count > 0:
            prob = count / total
            entropy -= prob * math.log2(prob)

    max_entropy = math.log2(len(counts))
    normalized = min(1.0, max(0.0, entropy / max_entropy)) if max_entropy > 0 else 0.0
    return entropy, normalized


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
        TrafficWindow containing computed aggregate rates, ratios, and entropy metrics.
    """
    total_packets = len(records)
    total_bytes = sum(pkt.packet_size for pkt in records)
    duration = max(0.001, end_time - start_time)

    packet_rate = total_packets / duration
    byte_rate = total_bytes / duration

    syn_count = sum(1 for pkt in records if "SYN" in pkt.tcp_flags and "ACK" not in pkt.tcp_flags)
    ack_count = sum(1 for pkt in records if "ACK" in pkt.tcp_flags)
    rst_count = sum(1 for pkt in records if "RST" in pkt.tcp_flags)

    # IP distribution and entropy calculations
    ip_counter = Counter(pkt.src_ip for pkt in records if pkt.src_ip)
    ip_packets_total = sum(ip_counter.values())
    unique_src_ips = len(ip_counter)
    unique_dst_ports = len({pkt.dst_port for pkt in records if pkt.dst_port is not None})

    top_ip: str | None = None
    top_ip_ratio = 0.0
    if ip_counter and ip_packets_total > 0:
        most_common = ip_counter.most_common(1)[0]
        top_ip = most_common[0]
        top_ip_ratio = most_common[1] / ip_packets_total

    raw_entropy, norm_entropy = compute_shannon_entropy(
        counts=list(ip_counter.values()),
        total=ip_packets_total,
    )

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
        ip_entropy=raw_entropy,
        normalized_ip_entropy=norm_entropy,
        top_source_ip=top_ip,
        top_source_ip_ratio=top_ip_ratio,
    )


class SlidingWindowAggregator:
    """Streaming aggregator that produces overlapping TrafficWindows from a packet stream.

    Maintains a FIFO deque of packets within the current observation horizon and advances
    the window boundary by `step_size` intervals.
    """

    def __init__(self, window_size: float = 1.0, step_size: float = 0.2) -> None:
        if window_size <= 0:
            msg = f"window_size must be positive, got {window_size}"
            raise ValueError(msg)
        if step_size <= 0:
            msg = f"step_size must be positive, got {step_size}"
            raise ValueError(msg)
        if step_size > window_size:
            msg = f"step_size ({step_size}) cannot exceed window_size ({window_size})"
            raise ValueError(msg)

        self.window_size = window_size
        self.step_size = step_size

    def aggregate(self, packet_stream: Iterable[PacketRecord]) -> Iterator[TrafficWindow]:
        """Process packet stream and yield successive sliding traffic windows.

        Args:
            packet_stream: Chronological iterable of PacketRecord objects.

        Yields:
            TrafficWindow instances as the sliding window advances.
        """
        buffer: deque[PacketRecord] = deque()
        iterator = iter(packet_stream)

        try:
            first_pkt = next(iterator)
        except StopIteration:
            return

        buffer.append(first_pkt)
        window_start = first_pkt.timestamp
        window_end = window_start + self.window_size

        for pkt in iterator:
            # Ignore severely out-of-order packets that belong to already evicted windows
            if pkt.timestamp < window_start:
                continue

            # If the new packet exceeds the current window boundary, slide the window
            while pkt.timestamp >= window_end:
                yield compute_window_features(list(buffer), window_start, window_end)

                window_start += self.step_size
                window_end = window_start + self.window_size

                # Evict packets that have fallen out of the new window boundary
                while buffer and buffer[0].timestamp < window_start:
                    buffer.popleft()

                # Optimization: if buffer is empty and the new packet is far in the future,
                # jump directly to avoid emitting thousands of empty gap windows
                if not buffer and pkt.timestamp >= window_end:
                    window_start = pkt.timestamp
                    window_end = window_start + self.window_size

            # Fast-path for chronological packets (99.9% of traffic), binary insertion for out-of-order jitter
            if not buffer or pkt.timestamp >= buffer[-1].timestamp:
                buffer.append(pkt)
            else:
                bisect.insort(buffer, pkt, key=lambda p: p.timestamp)

        # Yield any remaining window when stream ends
        if buffer:
            final_end = max(window_end, buffer[-1].timestamp)
            yield compute_window_features(list(buffer), window_start, final_end)

    def __call__(self, packet_stream: Iterable[PacketRecord]) -> Iterator[TrafficWindow]:
        """Alias for aggregate(). Enables calling the instance directly."""
        return self.aggregate(packet_stream)


def stream_sliding_windows(
    packet_stream: Iterable[PacketRecord],
    window_size: float = 1.0,
    step_size: float = 0.2,
) -> Iterator[TrafficWindow]:
    """Stream sliding traffic windows directly from a packet stream.

    Convenience wrapper around SlidingWindowAggregator.

    Args:
        packet_stream: Chronological iterable of PacketRecord objects.
        window_size: Duration of the observation window in seconds.
        step_size: Interval to slide the window forward in seconds.

    Yields:
        Successive TrafficWindow objects.
    """
    aggregator = SlidingWindowAggregator(window_size=window_size, step_size=step_size)
    yield from aggregator.aggregate(packet_stream)
