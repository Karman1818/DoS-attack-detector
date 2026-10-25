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

    # Volumetric traffic threshold (bytes per second)
    volumetric_bps_threshold: float = 10_000_000.0  # ~10 MB/s

    # Packet flood threshold (packets per second)
    packet_flood_pps_threshold: float = 1_000.0

    # Minimum number of packets in a window before ratio rules trigger (reduces noise)
    min_packets_for_ratio_eval: int = 10

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
