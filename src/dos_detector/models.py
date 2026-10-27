"""Core domain models for packet records, window aggregations, and detection alerts.

All models are immutable (frozen) to prevent subtle state-mutation bugs across
analysis pipelines.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Severity levels for suspicious traffic alerts."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Normalized, offline representation of an observed network packet.

    Decouples raw capture sources (e.g., PCAP, CSV) from feature extraction
    and detection logic.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    packet_size: int = 0
    tcp_flags: frozenset[str] = field(default_factory=frozenset)
    # Layer 7 (Application) metadata
    http_method: str | None = None
    http_uri: str | None = None
    # Ground-truth label for evaluation (e.g., "BENIGN", "DoS Hulk", "DDoS")
    label: str | None = None


@dataclass(frozen=True, slots=True)
class TrafficWindow:
    """Aggregated traffic metrics computed over a discrete time window."""

    start_time: float
    end_time: float
    total_packets: int
    total_bytes: int
    packet_rate: float
    byte_rate: float
    syn_count: int
    ack_count: int
    rst_count: int
    unique_src_ips: int
    unique_dst_ports: int
    ip_entropy: float = 0.0
    normalized_ip_entropy: float = 0.0
    top_source_ip: str | None = None
    top_source_ip_ratio: float = 0.0
    # Protocol layer metrics
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    dns_count: int = 0
    # Layer 7 HTTP metrics
    http_request_count: int = 0
    top_http_uri: str | None = None
    top_http_uri_ratio: float = 0.0
    # Destination target metrics (for DDoS target concentration analysis)
    unique_dst_ips: int = 0
    top_dst_ip: str | None = None
    top_dst_ip_ratio: float = 0.0
    top_dst_port: int | None = None
    top_dst_port_ratio: float = 0.0
    # Ground truth labels observed in this observation window
    ground_truth_labels: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_attack_window(self) -> bool:
        """Return True if any packet in this window has a non-benign attack label."""
        return any(
            lbl.strip().upper() not in {"BENIGN", "NORMAL", "0", "NONE", ""}
            for lbl in self.ground_truth_labels
        )

    @property
    def duration_seconds(self) -> float:
        """Calculate the duration of the traffic window."""
        return max(0.0, self.end_time - self.start_time)

    @property
    def syn_ack_ratio(self) -> float:
        """Calculate the ratio of SYN to ACK packets.

        In healthy bidirectional TCP traffic, SYN packets are followed by ACK packets.
        A severe disproportion (high SYN with zero/low ACK) is a classic indicator
        of SYN flood attacks.
        """
        if self.ack_count == 0:
            return float(self.syn_count) if self.syn_count > 0 else 0.0
        return self.syn_count / self.ack_count

    @property
    def dns_pps(self) -> float:
        """Calculate DNS packets per second within the window."""
        return self.dns_count / self.duration_seconds if self.duration_seconds > 0 else 0.0

    @property
    def udp_pps(self) -> float:
        """Calculate UDP packets per second within the window."""
        return self.udp_count / self.duration_seconds if self.duration_seconds > 0 else 0.0

    @property
    def tcp_pps(self) -> float:
        """Calculate TCP packets per second within the window."""
        return self.tcp_count / self.duration_seconds if self.duration_seconds > 0 else 0.0

    @property
    def dns_ratio(self) -> float:
        """Calculate the proportion of DNS packets in the window."""
        return self.dns_count / self.total_packets if self.total_packets > 0 else 0.0

    @property
    def udp_ratio(self) -> float:
        """Calculate the proportion of UDP packets in the window."""
        return self.udp_count / self.total_packets if self.total_packets > 0 else 0.0

    @property
    def tcp_ratio(self) -> float:
        """Calculate the proportion of TCP packets in the window."""
        return self.tcp_count / self.total_packets if self.total_packets > 0 else 0.0

    @property
    def http_pps(self) -> float:
        """Calculate HTTP requests per second within the window."""
        return self.http_request_count / self.duration_seconds if self.duration_seconds > 0 else 0.0

    @property
    def http_ratio(self) -> float:
        """Calculate the proportion of HTTP request packets in the window."""
        return self.http_request_count / self.total_packets if self.total_packets > 0 else 0.0


@dataclass(frozen=True, slots=True)
class DetectionAlert:
    """Structured notification describing an anomalous or suspicious traffic pattern.

    Alerts are defensive and explanatory, highlighting suspected behavior,
    DoS vs DDoS distribution probabilities, and potential false-positive factors.
    """

    timestamp: float
    rule_name: str
    severity: Severity
    description: str
    confidence: float
    attack_type: str = "UNKNOWN"
    distribution_confidence: float = 0.0
    dos_probability: float = 0.0
    ddos_probability: float = 0.0
    metrics_snapshot: dict[str, Any] = field(default_factory=dict)

    @property
    def distribution_summary(self) -> str:
        """Human-readable summary of DoS vs DDoS distribution probabilities."""
        ddos_pct = self.ddos_probability * 100.0
        dos_pct = self.dos_probability * 100.0
        if ddos_pct >= 50.0:
            return f"DDoS ({ddos_pct:.0f}%) vs DoS ({dos_pct:.0f}%)"
        return f"DoS ({dos_pct:.0f}%) vs DDoS ({ddos_pct:.0f}%)"
