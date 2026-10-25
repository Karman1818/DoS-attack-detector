"""Detection engine interfaces and rule-based anomaly detectors.

Applies configurable heuristic rules against aggregated traffic windows to identify
potential Denial-of-Service attack indicators.
"""

from abc import ABC, abstractmethod

from dos_detector.config import DetectionConfig
from dos_detector.models import DetectionAlert, Severity, TrafficWindow


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

    Designed for stage 1 offline analysis. Does not require external training data
    and produces fully explainable alerts.
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self.config.validate()

    def evaluate_window(self, window: TrafficWindow) -> list[DetectionAlert]:
        """Evaluate traffic window against configured DoS heuristics."""
        alerts: list[DetectionAlert] = []

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
                    description=(
                        f"High rate of unacknowledged SYN packets ({syn_pps:.1f} SYN/s, "
                        f"SYN/ACK ratio: {window.syn_ack_ratio:.2f}). Possible SYN flood."
                    ),
                    confidence=0.85,
                    metrics_snapshot={
                        "syn_count": window.syn_count,
                        "ack_count": window.ack_count,
                        "syn_pps": syn_pps,
                        "syn_ack_ratio": window.syn_ack_ratio,
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
                    description=(
                        f"Traffic throughput ({window.byte_rate / 1_000_000:.2f} MB/s) "
                        f"exceeds volumetric threshold "
                        f"({self.config.volumetric_bps_threshold / 1_000_000:.2f} MB/s)."
                    ),
                    confidence=0.70,
                    metrics_snapshot={
                        "byte_rate": window.byte_rate,
                        "packet_rate": window.packet_rate,
                        "threshold": self.config.volumetric_bps_threshold,
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
                    description=(
                        f"Packet rate ({window.packet_rate:.1f} pps) exceeds "
                        f"threshold ({self.config.packet_flood_pps_threshold:.1f} pps)."
                    ),
                    confidence=0.75,
                    metrics_snapshot={
                        "packet_rate": window.packet_rate,
                        "total_packets": window.total_packets,
                        "threshold": self.config.packet_flood_pps_threshold,
                    },
                )
            )

        return alerts
