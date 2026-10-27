"""Detection engine interfaces and rule-based anomaly detectors.

Applies configurable heuristic rules against aggregated traffic windows to identify
potential Denial-of-Service attack indicators and classifies distribution (DoS vs DDoS).
"""

from abc import ABC, abstractmethod

from dos_detector.config import DetectionConfig
from dos_detector.models import DetectionAlert, Severity, TrafficWindow


def classify_attack_distribution(window: TrafficWindow) -> tuple[str, float, str]:
    """Determine whether traffic anomaly is single-source DoS, coordinated, or distributed DDoS.

    Uses Shannon entropy and top source IP ratios to calculate distribution probabilities.

    Returns:
        tuple of (attack_type, distribution_confidence, explanatory_note)
    """
    if window.unique_src_ips <= 1:
        top_ip = window.top_source_ip or "unknown"
        return (
            "SINGLE_SOURCE_DOS",
            1.0,
            f"Single-source DoS: 100% of packets originate from {top_ip}.",
        )

    # Distributed DDoS requires a sufficient pool of unique sources and elevated entropy
    if window.unique_src_ips >= 10 and (
        window.normalized_ip_entropy >= 0.6 or window.unique_src_ips >= 20
    ):
        conf = max(window.normalized_ip_entropy, min(1.0, window.unique_src_ips / 50.0))
        return (
            "DISTRIBUTED_DOS (DDoS)",
            conf,
            (
                f"Distributed DDoS suspected ({conf * 100:.1f}% confidence): "
                f"High IP entropy ({window.normalized_ip_entropy * 100:.1f}%) "
                f"across {window.unique_src_ips} distinct source IPs."
            ),
        )

    # Small-scale coordinated attack (e.g., 2-9 distinct sources acting together)
    if window.unique_src_ips >= 2 and window.normalized_ip_entropy >= 0.7:
        return (
            "COORDINATED_DOS",
            window.normalized_ip_entropy,
            (
                f"Coordinated DoS suspected ({window.normalized_ip_entropy * 100:.1f}% confidence): "
                f"Evenly distributed traffic across {window.unique_src_ips} distinct source IPs."
            ),
        )

    # Otherwise, suspect a concentrated single-source or primary attacker
    top_ip = window.top_source_ip or "unknown"
    ratio = window.top_source_ip_ratio
    conf = ratio if ratio > 0 else 0.70
    return (
        "SINGLE_SOURCE_DOS",
        conf,
        (
            f"Single-source DoS suspected ({conf * 100:.1f}% confidence): "
            f"Primary IP {top_ip} accounts for {ratio * 100:.1f}% of window traffic."
        ),
    )


class BaseDetector(ABC):
    """Abstract interface for all detection mechanisms (rule-based or machine-learning)."""

    @abstractmethod
    def evaluate_window(self, window: TrafficWindow) -> list[DetectionAlert]:
        """Analyze a traffic window and return any generated alerts.

        Args:
            window: Aggregated metrics for the observation interval.

        Returns:
            List of suspicious activity alerts detected within the window.
        """


class RuleBasedDetector(BaseDetector):
    """Rule-based DoS detector evaluating deterministic threshold heuristics.

    Does not require external training data and produces fully explainable alerts
    with distribution classification (DoS vs DDoS).
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self.config.validate()

    def evaluate_window(self, window: TrafficWindow) -> list[DetectionAlert]:
        """Evaluate traffic window against configured DoS heuristics."""
        alerts: list[DetectionAlert] = []

        attack_type, dist_conf, dist_explanation = classify_attack_distribution(window)

        # Heuristic 1: SYN Flood Detection
        # High volume of SYN packets without corresponding ACKs
        syn_pps = window.syn_count / window.duration_seconds if window.duration_seconds > 0 else 0
        if (
            syn_pps >= self.config.syn_flood_pps_threshold
            and window.total_packets >= self.config.min_packets_for_ratio_eval
            and window.syn_ack_ratio >= self.config.syn_ack_ratio_threshold
        ):
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="SYN_FLOOD_SUSPECTED",
                    severity=Severity.HIGH,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    description=(
                        f"High rate of unacknowledged SYN packets ({syn_pps:.1f} SYN/s, "
                        f"SYN/ACK ratio: {window.syn_ack_ratio:.2f}). {dist_explanation}"
                    ),
                    confidence=0.85,
                    metrics_snapshot={
                        "syn_count": window.syn_count,
                        "ack_count": window.ack_count,
                        "syn_pps": syn_pps,
                        "syn_ack_ratio": window.syn_ack_ratio,
                        "attack_type": attack_type,
                        "distribution_confidence": dist_conf,
                        "ip_entropy": window.ip_entropy,
                        "normalized_ip_entropy": window.normalized_ip_entropy,
                    },
                )
            )

        # Heuristic 2: Volumetric Traffic Flood
        # Byte rate exceeding threshold
        if window.byte_rate >= self.config.volumetric_bps_threshold:
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="VOLUMETRIC_FLOOD_SUSPECTED",
                    severity=Severity.MEDIUM,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    description=(
                        f"Traffic throughput ({window.byte_rate / 1_000_000:.2f} MB/s) "
                        f"exceeds volumetric threshold "
                        f"({self.config.volumetric_bps_threshold / 1_000_000:.2f} MB/s). "
                        f"{dist_explanation}"
                    ),
                    confidence=0.70,
                    metrics_snapshot={
                        "byte_rate": window.byte_rate,
                        "packet_rate": window.packet_rate,
                        "threshold": self.config.volumetric_bps_threshold,
                        "attack_type": attack_type,
                        "distribution_confidence": dist_conf,
                    },
                )
            )

        # Heuristic 3: High Packet-Rate Flood
        if window.packet_rate >= self.config.packet_flood_pps_threshold:
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="PACKET_RATE_FLOOD_SUSPECTED",
                    severity=Severity.MEDIUM,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    description=(
                        f"Packet rate ({window.packet_rate:.1f} pps) exceeds "
                        f"threshold ({self.config.packet_flood_pps_threshold:.1f} pps). "
                        f"{dist_explanation}"
                    ),
                    confidence=0.75,
                    metrics_snapshot={
                        "packet_rate": window.packet_rate,
                        "total_packets": window.total_packets,
                        "threshold": self.config.packet_flood_pps_threshold,
                        "attack_type": attack_type,
                        "distribution_confidence": dist_conf,
                    },
                )
            )

        return alerts
