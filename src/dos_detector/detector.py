"""Detection engine interfaces and rule-based anomaly detectors.

Applies configurable heuristic rules against aggregated traffic windows to identify
potential Denial-of-Service attack indicators and classifies distribution (DoS vs DDoS).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from dos_detector.config import DetectionConfig
from dos_detector.models import DetectionAlert, Severity, TrafficWindow


@dataclass(frozen=True, slots=True)
class AttackClassification:
    """Detailed taxonomy of DoS vs DDoS distribution probabilities."""

    attack_type: str
    confidence: float
    dos_probability: float
    ddos_probability: float
    explanation: str

    def __iter__(self) -> Any:
        """Enable backward-compatible tuple unpacking (attack_type, conf, explanation)."""
        yield self.attack_type
        yield self.confidence
        yield self.explanation


def classify_attack_distribution(window: TrafficWindow) -> AttackClassification:
    """Determine whether traffic anomaly is single-source DoS, coordinated, or distributed DDoS.

    Calculates exact percentage probabilities for DoS vs DDoS using Shannon entropy,
    source distribution, protocol reflection vectors (e.g., DNS DRDoS), and target concentration.

    Returns:
        AttackClassification containing attack_type, probabilities (DoS % vs DDoS %), and explanation.
    """
    # Vector Check 1: DNS Amplification / Reflection (DRDoS)
    # In datasets like CIC-DDoS-2019, DNS floods are distributed reflection DDoS attacks
    # where an attacker abuses open DNS resolvers or floods from an attack infrastructure node.
    if window.dns_count >= 10 and window.dns_pps >= 200.0 and window.dns_ratio >= 0.50:
        ddos_prob = 0.90 if window.dns_pps < 2000.0 else 0.95
        dos_prob = round(1.0 - ddos_prob, 2)
        return AttackClassification(
            attack_type="DISTRIBUTED_DOS (DRDoS Amplification)",
            confidence=ddos_prob,
            dos_probability=dos_prob,
            ddos_probability=ddos_prob,
            explanation=(
                f"Distributed Reflection Denial-of-Service (DRDoS) suspected "
                f"({ddos_prob * 100:.0f}% DDoS vs {dos_prob * 100:.0f}% DoS): "
                f"DNS amplification/reflection vector utilizing port 53 ({window.dns_pps:.1f} DNS pps)."
            ),
        )

    # Vector Check 2: High-Rate UDP Flood DDoS
    if window.udp_count >= 10 and window.udp_pps >= 500.0 and window.udp_ratio >= 0.60:
        ddos_prob = 0.90
        dos_prob = 0.10
        return AttackClassification(
            attack_type="DISTRIBUTED_DOS (UDP Flood DDoS)",
            confidence=ddos_prob,
            dos_probability=dos_prob,
            ddos_probability=ddos_prob,
            explanation=(
                f"Distributed UDP Flood DDoS suspected "
                f"({ddos_prob * 100:.0f}% DDoS vs {dos_prob * 100:.0f}% DoS): "
                f"High-rate UDP flood ({window.udp_pps:.1f} UDP pps, {window.udp_ratio * 100:.1f}% traffic)."
            ),
        )

    # Check for multi-target benign transit traffic (many sources to many destinations)
    # In benign browsing/transit, packets disperse across numerous destination IPs
    is_multi_target_transit = (
        window.unique_dst_ips >= 5
        and window.top_dst_ip_ratio > 0.0
        and window.top_dst_ip_ratio < 0.40
    )

    # Distributed DDoS requires a sufficient pool of unique sources and elevated entropy
    if window.unique_src_ips >= 10 and (
        window.normalized_ip_entropy >= 0.6 or window.unique_src_ips >= 20
    ):
        if is_multi_target_transit:
            return AttackClassification(
                attack_type="DISTRIBUTED_TRANSIT_TRAFFIC",
                confidence=0.20,
                dos_probability=0.85,
                ddos_probability=0.15,
                explanation=(
                    f"Distributed transit traffic (low threat confidence: 15% DDoS): "
                    f"{window.unique_src_ips} source IPs distributed across "
                    f"{window.unique_dst_ips} distinct destination targets."
                ),
            )

        ddos_prob = round(min(0.99, max(0.85, window.normalized_ip_entropy)), 2)
        dos_prob = round(1.0 - ddos_prob, 2)
        target_info = f" targeting {window.top_dst_ip}" if window.top_dst_ip else ""
        port_info = f" on port {window.top_dst_port}" if window.top_dst_port else ""
        return AttackClassification(
            attack_type="DISTRIBUTED_DOS (DDoS)",
            confidence=ddos_prob,
            dos_probability=dos_prob,
            ddos_probability=ddos_prob,
            explanation=(
                f"Distributed DDoS suspected ({ddos_prob * 100:.0f}% DDoS vs {dos_prob * 100:.0f}% DoS): "
                f"High IP entropy ({window.normalized_ip_entropy * 100:.1f}%) "
                f"across {window.unique_src_ips} distinct source IPs{target_info}{port_info}."
            ),
        )

    # Small-scale coordinated attack (e.g., 2-9 distinct sources acting together)
    if window.unique_src_ips >= 2 and window.normalized_ip_entropy >= 0.7:
        ddos_prob = round(min(0.80, max(0.60, window.normalized_ip_entropy * 0.75)), 2)
        dos_prob = round(1.0 - ddos_prob, 2)
        return AttackClassification(
            attack_type="COORDINATED_DOS",
            confidence=window.normalized_ip_entropy,
            dos_probability=dos_prob,
            ddos_probability=ddos_prob,
            explanation=(
                f"Coordinated DoS/DDoS suspected ({ddos_prob * 100:.0f}% DDoS vs {dos_prob * 100:.0f}% DoS): "
                f"Evenly distributed traffic across {window.unique_src_ips} distinct source IPs."
            ),
        )

    # Single source or concentrated primary attacker
    top_ip = window.top_source_ip or "unknown"
    ratio = window.top_source_ip_ratio

    # If packet rate is extreme (> 5000 pps), high likelihood of botnet node or high-volume DDoS generator
    if window.packet_rate >= 5000.0:
        ddos_prob = 0.70
        dos_prob = 0.30
        return AttackClassification(
            attack_type="DISTRIBUTED_DOS (High-Rate Botnet Generator Suspected)",
            confidence=0.70,
            dos_probability=dos_prob,
            ddos_probability=ddos_prob,
            explanation=(
                f"High-rate attack suspected ({ddos_prob * 100:.0f}% DDoS vs {dos_prob * 100:.0f}% DoS): "
                f"Extreme volume ({window.packet_rate:.1f} pps) from primary IP {top_ip}."
            ),
        )

    conf = ratio if ratio > 0 else 0.90
    dos_prob = 0.95
    ddos_prob = 0.05
    return AttackClassification(
        attack_type="SINGLE_SOURCE_DOS",
        confidence=conf,
        dos_probability=dos_prob,
        ddos_probability=ddos_prob,
        explanation=(
            f"Single-source DoS suspected ({dos_prob * 100:.0f}% DoS vs {ddos_prob * 100:.0f}% DDoS): "
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
    with layered protocol analysis, victim target concentration, and alert suppression.
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self.config.validate()
        self._consecutive_violations: dict[str, int] = {}
        self._last_alert_time: dict[str, float] = {}

    def reset(self) -> None:
        """Reset internal violation and alert suppression tracking state."""
        self._consecutive_violations.clear()
        self._last_alert_time.clear()

    def _should_emit(self, rule_name: str, triggered: bool, timestamp: float) -> bool:
        """Check violation persistence and cooldown suppression before raising an alert."""
        if not triggered:
            self._consecutive_violations[rule_name] = 0
            return False

        count = self._consecutive_violations.get(rule_name, 0) + 1
        self._consecutive_violations[rule_name] = count

        # Suppress micro-bursts that do not persist across minimum required windows
        if count < self.config.min_consecutive_windows:
            return False

        # Suppress duplicate alerts within the cooldown period
        last_time = self._last_alert_time.get(rule_name, -1e9)
        if timestamp - last_time < self.config.alert_cooldown_seconds:
            return False

        self._last_alert_time[rule_name] = timestamp
        return True

    def evaluate_window(self, window: TrafficWindow) -> list[DetectionAlert]:
        """Evaluate traffic window against configured DoS heuristics."""
        alerts: list[DetectionAlert] = []

        cls = classify_attack_distribution(window)
        attack_type = cls.attack_type
        dist_conf = cls.confidence
        dos_prob = cls.dos_probability
        ddos_prob = cls.ddos_probability
        dist_explanation = cls.explanation

        # Heuristic 1: DNS Amplification / Reflection / Query Flood Detection (Port 53)
        is_dns_flood = (
            window.dns_count >= self.config.min_packets_for_ratio_eval
            and window.dns_pps >= self.config.dns_flood_pps_threshold
            and window.dns_ratio >= self.config.dns_ratio_threshold
        )
        if self._should_emit("DNS_FLOOD_SUSPECTED", is_dns_flood, window.end_time):
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="DNS_FLOOD_SUSPECTED",
                    severity=Severity.HIGH,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    dos_probability=dos_prob,
                    ddos_probability=ddos_prob,
                    description=(
                        f"High volume of DNS traffic ({window.dns_pps:.1f} DNS pps, "
                        f"{window.dns_ratio * 100:.1f}% of window traffic). {dist_explanation}"
                    ),
                    confidence=0.90,
                    metrics_snapshot={
                        "dns_count": window.dns_count,
                        "dns_pps": window.dns_pps,
                        "dns_ratio": window.dns_ratio,
                        "total_packets": window.total_packets,
                        "threshold": self.config.dns_flood_pps_threshold,
                        "attack_type": attack_type,
                        "distribution_confidence": dist_conf,
                        "dos_probability": dos_prob,
                        "ddos_probability": ddos_prob,
                    },
                )
            )

        # Heuristic 2: General UDP Flood Detection (non-DNS)
        is_udp_flood = (
            not is_dns_flood
            and window.udp_count >= self.config.min_packets_for_ratio_eval
            and window.udp_pps >= self.config.udp_flood_pps_threshold
            and window.udp_ratio >= self.config.udp_ratio_threshold
        )
        if self._should_emit("UDP_FLOOD_SUSPECTED", is_udp_flood, window.end_time):
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="UDP_FLOOD_SUSPECTED",
                    severity=Severity.HIGH,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    dos_probability=dos_prob,
                    ddos_probability=ddos_prob,
                    description=(
                        f"High rate of UDP traffic ({window.udp_pps:.1f} UDP pps, "
                        f"{window.udp_ratio * 100:.1f}% of window traffic). {dist_explanation}"
                    ),
                    confidence=0.85,
                    metrics_snapshot={
                        "udp_count": window.udp_count,
                        "udp_pps": window.udp_pps,
                        "udp_ratio": window.udp_ratio,
                        "threshold": self.config.udp_flood_pps_threshold,
                        "attack_type": attack_type,
                        "distribution_confidence": dist_conf,
                        "dos_probability": dos_prob,
                        "ddos_probability": ddos_prob,
                    },
                )
            )

        # Heuristic 3: TCP SYN Flood Detection
        syn_pps = window.syn_count / window.duration_seconds if window.duration_seconds > 0 else 0
        syn_ratio_in_tcp = window.syn_count / max(1, window.tcp_count)
        is_syn_flood = (
            syn_pps >= self.config.syn_flood_pps_threshold
            and window.total_packets >= self.config.min_packets_for_ratio_eval
            and window.syn_ack_ratio >= self.config.syn_ack_ratio_threshold
            and (
                window.tcp_count == 0 or syn_ratio_in_tcp >= self.config.syn_ratio_in_tcp_threshold
            )
        )
        if self._should_emit("SYN_FLOOD_SUSPECTED", is_syn_flood, window.end_time):
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="SYN_FLOOD_SUSPECTED",
                    severity=Severity.HIGH,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    dos_probability=dos_prob,
                    ddos_probability=ddos_prob,
                    description=(
                        f"High rate of unacknowledged SYN packets ({syn_pps:.1f} SYN/s, "
                        f"SYN/ACK ratio: {window.syn_ack_ratio:.2f}). {dist_explanation}"
                    ),
                    confidence=0.85,
                    metrics_snapshot={
                        "syn_count": window.syn_count,
                        "ack_count": window.ack_count,
                        "tcp_count": window.tcp_count,
                        "syn_pps": syn_pps,
                        "syn_ack_ratio": window.syn_ack_ratio,
                        "syn_ratio_in_tcp": syn_ratio_in_tcp,
                        "attack_type": attack_type,
                        "distribution_confidence": dist_conf,
                        "dos_probability": dos_prob,
                        "ddos_probability": ddos_prob,
                        "ip_entropy": window.ip_entropy,
                        "normalized_ip_entropy": window.normalized_ip_entropy,
                    },
                )
            )

        # Heuristic 4: Volumetric Traffic Flood (Byte throughput)
        is_volumetric = window.byte_rate >= self.config.volumetric_bps_threshold
        if self._should_emit("VOLUMETRIC_FLOOD_SUSPECTED", is_volumetric, window.end_time):
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="VOLUMETRIC_FLOOD_SUSPECTED",
                    severity=Severity.MEDIUM,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    dos_probability=dos_prob,
                    ddos_probability=ddos_prob,
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
                        "dos_probability": dos_prob,
                        "ddos_probability": ddos_prob,
                    },
                )
            )

        # Heuristic 5: High Packet-Rate Flood
        # Subsumes generic rate alert if a specific protocol flood was already identified,
        # and requires victim target concentration or extreme volume to filter transit bursts
        target_conc = max(window.top_dst_ip_ratio, window.top_dst_port_ratio)
        is_targeted_or_extreme = (
            window.unique_dst_ports <= 1
            or target_conc >= self.config.target_concentration_threshold
            or window.packet_rate >= (self.config.packet_flood_pps_threshold * 2.0)
            or (window.top_dst_ip is None and window.unique_dst_ips <= 1)
        )
        is_packet_flood = (
            window.packet_rate >= self.config.packet_flood_pps_threshold
            and not is_dns_flood
            and not is_syn_flood
            and not is_udp_flood
            and is_targeted_or_extreme
            and attack_type != "DISTRIBUTED_TRANSIT_TRAFFIC"
        )
        if self._should_emit("PACKET_RATE_FLOOD_SUSPECTED", is_packet_flood, window.end_time):
            alerts.append(
                DetectionAlert(
                    timestamp=window.end_time,
                    rule_name="PACKET_RATE_FLOOD_SUSPECTED",
                    severity=Severity.MEDIUM,
                    attack_type=attack_type,
                    distribution_confidence=dist_conf,
                    dos_probability=dos_prob,
                    ddos_probability=ddos_prob,
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
                        "dos_probability": dos_prob,
                        "ddos_probability": ddos_prob,
                    },
                )
            )

        return alerts
