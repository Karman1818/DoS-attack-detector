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


@dataclass(frozen=True, slots=True)
class DetectionAlert:
    """Structured notification describing an anomalous or suspicious traffic pattern.

    Alerts are defensive and explanatory, highlighting suspected behavior and
    potential false-positive factors rather than claiming absolute certainty.
    """

    timestamp: float
    rule_name: str
    severity: Severity
    description: str
    confidence: float
    metrics_snapshot: dict[str, Any] = field(default_factory=dict)
