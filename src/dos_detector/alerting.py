"""Alert reporting and distribution interfaces.

Provides sink abstractions to decouple detection events from output channels
(e.g., logging, consoles, or future SIEM integrations).
"""

from collections.abc import Sequence
from typing import Protocol

from dos_detector.models import DetectionAlert


class AlertSink(Protocol):
    """Protocol defining how detection alerts are consumed."""

    def emit(self, alert: DetectionAlert) -> None:
        """Emit a single detection alert."""
        ...


class InMemoryAlertSink:
    """In-memory alert sink for test suites and offline batch processing."""

    def __init__(self) -> None:
        self._alerts: list[DetectionAlert] = []

    def emit(self, alert: DetectionAlert) -> None:
        """Store alert in memory."""
        self._alerts.append(alert)

    @property
    def alerts(self) -> Sequence[DetectionAlert]:
        """Return all collected alerts."""
        return tuple(self._alerts)

    def clear(self) -> None:
        """Clear all stored alerts."""
        self._alerts.clear()


class ConsoleAlertSink:
    """Human-readable console alert sink designed for defensive analysis."""

    def emit(self, alert: DetectionAlert) -> None:
        """Format and print alert details safely without dumping raw payloads."""
        type_str = f" | Type: {alert.attack_type}" if alert.attack_type != "UNKNOWN" else ""
        print(
            f"[{alert.severity.value}] {alert.rule_name}{type_str} @ {alert.timestamp:.2f}s "
            f"(Confidence: {alert.confidence * 100:.0f}%): {alert.description}"
        )
