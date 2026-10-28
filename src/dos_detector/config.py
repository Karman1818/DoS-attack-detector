"""Configuration and detection thresholds for the rule-based engine.

Thresholds must be configurable because normal traffic patterns vary drastically
between environments (e.g., local home lab vs. enterprise edge gateway).
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Configurable thresholds used by the DoS detection engine."""

    # Duration of analysis time window in seconds
    window_size_seconds: float = 1.0

    # SYN flood heuristic thresholds
    syn_flood_pps_threshold: float = 100.0
    syn_ack_ratio_threshold: float = 3.0
    syn_ratio_in_tcp_threshold: float = 0.50

    # Volumetric traffic threshold (bytes per second)
    volumetric_bps_threshold: float = 10_000_000.0  # ~10 MB/s

    # Packet flood threshold (packets per second)
    packet_flood_pps_threshold: float = 1_000.0

    # Protocol-specific flood thresholds (DNS and UDP)
    dns_flood_pps_threshold: float = 500.0
    dns_ratio_threshold: float = 0.50
    udp_flood_pps_threshold: float = 1_000.0
    udp_ratio_threshold: float = 0.60

    # Layer 7 HTTP application flood thresholds (WebDDoS)
    http_flood_pps_threshold: float = 30.0
    min_http_requests: int = 30
    http_uri_repetition_threshold: float = 0.60

    # Minimum target concentration ratio to qualify high-volume traffic as targeted attack
    target_concentration_threshold: float = 0.60

    # Minimum number of packets in a window before ratio rules trigger (reduces noise)
    min_packets_for_ratio_eval: int = 10

    # Sliding-window alert persistence and suppression
    # Minimum consecutive windows exceeding threshold before raising an alert (filters micro-bursts)
    min_consecutive_windows: int = 1
    # Minimum time between duplicate alerts for the same rule (avoids alert storms in sliding windows)
    alert_cooldown_seconds: float = 1.0

    # Detection engine mode: 'hybrid' (rules + ML fallback), 'base' (rules only), or 'ml' (Isolation Forest only)
    detector_mode: str = "hybrid"

    # Machine Learning (Isolation Forest) settings
    ml_model_path: str | None = None
    ml_contamination: float = 0.01

    def validate(self) -> None:
        """Validate configuration parameters.

        Raises:
            ValueError: If any configuration value is non-positive or illogical.
        """
        if self.window_size_seconds <= 0:
            msg = f"window_size_seconds must be positive, got {self.window_size_seconds}"
            raise ValueError(msg)
        if self.syn_flood_pps_threshold <= 0:
            msg = f"syn_flood_pps_threshold must be positive, got {self.syn_flood_pps_threshold}"
            raise ValueError(msg)
        if self.volumetric_bps_threshold <= 0:
            msg = f"volumetric_bps_threshold must be positive, got {self.volumetric_bps_threshold}"
            raise ValueError(msg)
        if self.packet_flood_pps_threshold <= 0:
            msg = f"packet_flood_pps_threshold must be positive, got {self.packet_flood_pps_threshold}"
            raise ValueError(msg)
        if self.dns_flood_pps_threshold <= 0:
            msg = f"dns_flood_pps_threshold must be positive, got {self.dns_flood_pps_threshold}"
            raise ValueError(msg)
        if self.udp_flood_pps_threshold <= 0:
            msg = f"udp_flood_pps_threshold must be positive, got {self.udp_flood_pps_threshold}"
            raise ValueError(msg)
        if self.http_flood_pps_threshold <= 0:
            msg = f"http_flood_pps_threshold must be positive, got {self.http_flood_pps_threshold}"
            raise ValueError(msg)
        if self.min_http_requests < 1:
            msg = f"min_http_requests must be >= 1, got {self.min_http_requests}"
            raise ValueError(msg)
        if not (0.0 < self.http_uri_repetition_threshold <= 1.0):
            msg = f"http_uri_repetition_threshold must be in (0, 1], got {self.http_uri_repetition_threshold}"
            raise ValueError(msg)
        if self.min_consecutive_windows < 1:
            msg = f"min_consecutive_windows must be >= 1, got {self.min_consecutive_windows}"
            raise ValueError(msg)
        if self.alert_cooldown_seconds < 0:
            msg = f"alert_cooldown_seconds must be non-negative, got {self.alert_cooldown_seconds}"
            raise ValueError(msg)
        valid_modes = {"base", "rule", "ml", "hybrid"}
        if self.detector_mode.lower() not in valid_modes:
            msg = f"detector_mode must be one of {valid_modes}, got '{self.detector_mode}'"
            raise ValueError(msg)
        if not (0.0 < self.ml_contamination < 0.5):
            msg = f"ml_contamination must be between 0.0 and 0.5, got {self.ml_contamination}"
            raise ValueError(msg)
