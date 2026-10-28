"""SIEM (Security Information and Event Management) integration and export interfaces.

Provides formatting and streaming sinks for industry-standard security telemetry formats:
- CEF (Common Event Format - Micro Focus ArcSight)
- Syslog RFC 5424 with Structured Data (rsyslog, syslog-ng, Graylog, QRadar)
- JSON / NDJSON (Splunk HEC, ElasticSearch, OpenSearch, Microsoft Sentinel)
"""

import json
import os
import socket
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import IO, Any

from dos_detector import __version__
from dos_detector.models import DetectionAlert, Severity

# CEF severity mapping on the 0-10 integer scale
CEF_SEVERITY_MAP: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 5,
    Severity.HIGH: 8,
    Severity.CRITICAL: 10,
}

# RFC 5424 Syslog severity levels (0=Emergency to 7=Debug)
SYSLOG_SEVERITY_MAP: dict[Severity, int] = {
    Severity.CRITICAL: 2,
    Severity.HIGH: 3,
    Severity.MEDIUM: 4,
    Severity.LOW: 5,
    Severity.INFO: 6,
}

# Default Syslog facility: local0 (16)
DEFAULT_SYSLOG_FACILITY: int = 16


class SiemFormat(StrEnum):
    """Supported SIEM export and streaming formats."""

    CEF = "cef"
    SYSLOG = "syslog"
    JSON = "json"
    NDJSON = "ndjson"


def _escape_cef_value(val: Any) -> str:
    """Escape special characters in CEF extension values.

    Per ArcSight CEF specification, backslashes, equals signs, and newlines must be escaped.
    """
    text = str(val)
    return text.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def _escape_cef_header(val: Any) -> str:
    """Escape pipe and backslash characters in CEF header prefixes."""
    text = str(val)
    return text.replace("\\", "\\\\").replace("|", "\\|")


def format_alert_cef(
    alert: DetectionAlert,
    vendor: str = "DoS-Detector",
    product: str = "DefensiveEngine",
    version: str = __version__,
) -> str:
    """Serialize a DetectionAlert into ArcSight Common Event Format (CEF:0).

    Format:
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Args:
        alert: Detection alert to format.
        vendor: Device vendor identifier.
        product: Device product name.
        version: Application version.

    Returns:
        Formatted single-line CEF string.
    """
    cef_sev = CEF_SEVERITY_MAP.get(alert.severity, 5)
    sig_id = _escape_cef_header(alert.rule_name)
    name = _escape_cef_header(alert.rule_name.replace("_", " ").title())
    ven = _escape_cef_header(vendor)
    prod = _escape_cef_header(product)
    ver = _escape_cef_header(version)

    # Extract network endpoints from snapshot if present
    snapshot = alert.metrics_snapshot
    src_ip = snapshot.get("src_ip") or snapshot.get("top_source_ip")
    dst_ip = snapshot.get("dst_ip") or snapshot.get("top_dst_ip")
    dst_port = snapshot.get("dst_port") or snapshot.get("top_dst_port")
    pkt_cnt = snapshot.get("total_packets") or snapshot.get("syn_count") or 1

    # Standard CEF extension attributes
    ext_fields: list[tuple[str, Any]] = [
        ("msg", alert.description),
        ("cs1", alert.rule_name),
        ("cs1Label", "RuleName"),
        ("cs2", alert.attack_type),
        ("cs2Label", "AttackType"),
        ("cfp1", round(alert.confidence, 3)),
        ("cfp1Label", "Confidence"),
        ("rt", int(alert.timestamp * 1000)),
    ]

    if src_ip:
        ext_fields.append(("src", src_ip))
    if dst_ip:
        ext_fields.append(("dst", dst_ip))
    if dst_port is not None:
        ext_fields.append(("dpt", int(dst_port)))
    if pkt_cnt is not None:
        ext_fields.append(("cnt", int(pkt_cnt)))

    # Determine protocol label
    if "SYN" in alert.rule_name:
        ext_fields.append(("proto", "TCP"))
    elif "UDP" in alert.rule_name or "DNS" in alert.rule_name:
        ext_fields.append(("proto", "UDP"))
    elif "HTTP" in alert.rule_name:
        ext_fields.append(("proto", "TCP"))
        ext_fields.append(("app", "HTTP"))

    extension_str = " ".join(f"{k}={_escape_cef_value(v)}" for k, v in ext_fields)
    return f"CEF:0|{ven}|{prod}|{ver}|{sig_id}|{name}|{cef_sev}|{extension_str}"


def format_alert_syslog_rfc5424(
    alert: DetectionAlert,
    hostname: str | None = None,
    app_name: str = "dos-detector",
    proc_id: str | None = None,
    facility: int = DEFAULT_SYSLOG_FACILITY,
) -> str:
    """Serialize a DetectionAlert into IETF RFC 5424 Syslog format with Structured Data.

    Format:
        <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT] MSG

    Args:
        alert: Detection alert to format.
        hostname: Reporting sensor hostname (defaults to local socket hostname).
        app_name: Syslog application tag.
        proc_id: Process ID (defaults to current OS PID).
        facility: Syslog facility code (default: 16 / local0).

    Returns:
        Formatted single-line RFC 5424 Syslog string.
    """
    sys_sev = SYSLOG_SEVERITY_MAP.get(alert.severity, 4)
    pri = (facility * 8) + sys_sev
    host = hostname or socket.gethostname() or "sensor"
    pid = proc_id or str(os.getpid())
    msg_id = alert.rule_name

    # ISO 8601 UTC timestamp
    dt = datetime.fromtimestamp(alert.timestamp, tz=UTC)
    ts_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Structured Data element (SD-ID: dosAlert@5424)
    snapshot = alert.metrics_snapshot
    src_ip = snapshot.get("src_ip") or snapshot.get("top_source_ip") or "unknown"
    dst_ip = snapshot.get("dst_ip") or snapshot.get("top_dst_ip") or "unknown"

    sd_params = [
        f'rule="{alert.rule_name}"',
        f'severity="{alert.severity.value}"',
        f'confidence="{alert.confidence:.3f}"',
        f'attackType="{alert.attack_type}"',
        f'src="{src_ip}"',
        f'dst="{dst_ip}"',
    ]
    structured_data = f"[dosAlert@5424 {' '.join(sd_params)}]"

    return (
        f"<{pri}>1 {ts_iso} {host} {app_name} {pid} {msg_id} {structured_data} {alert.description}"
    )


def format_alert_json(alert: DetectionAlert, indent: int | None = None) -> str:
    """Serialize a DetectionAlert into JSON / NDJSON format.

    Args:
        alert: Detection alert to format.
        indent: Optional indentation for pretty-printed JSON (None for NDJSON single-line).

    Returns:
        JSON formatted string.
    """
    dt = datetime.fromtimestamp(alert.timestamp, tz=UTC)
    ts_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    payload: dict[str, Any] = {
        "timestamp": alert.timestamp,
        "timestamp_iso": ts_iso,
        "rule_name": alert.rule_name,
        "severity": alert.severity.value,
        "attack_type": alert.attack_type,
        "confidence": round(alert.confidence, 3),
        "description": alert.description,
        "distribution": {
            "confidence": round(alert.distribution_confidence, 3),
            "dos_probability": round(alert.dos_probability, 3),
            "ddos_probability": round(alert.ddos_probability, 3),
            "summary": alert.distribution_summary,
        },
        "metrics_snapshot": alert.metrics_snapshot,
    }
    return json.dumps(payload, indent=indent, default=str)


def format_alert(alert: DetectionAlert, format_type: SiemFormat | str) -> str:
    """Format a DetectionAlert into the target SIEM string representation.

    Args:
        alert: Detection alert to format.
        format_type: Target SIEM standard ('cef', 'syslog', 'json', or 'ndjson').

    Returns:
        Formatted event string.
    """
    fmt = SiemFormat(str(format_type).lower())
    if fmt == SiemFormat.CEF:
        return format_alert_cef(alert)
    if fmt == SiemFormat.SYSLOG:
        return format_alert_syslog_rfc5424(alert)
    if fmt in (SiemFormat.JSON, SiemFormat.NDJSON):
        return format_alert_json(alert, indent=None)
    msg = f"Unsupported SIEM format: {format_type}"
    raise ValueError(msg)


class SiemAlertSink:
    """Alert sink that writes formatted SIEM events to an output stream or file.

    Implements the AlertSink protocol defined in dos_detector.alerting.
    """

    def __init__(
        self,
        target: IO[str] | Path | str,
        format_type: SiemFormat | str = SiemFormat.CEF,
    ) -> None:
        self.format_type = SiemFormat(str(format_type).lower())
        self._owned_file: IO[str] | None = None

        if isinstance(target, (str, Path)):
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._stream: IO[str] = path.open("a", encoding="utf-8")
            self._owned_file = self._stream
        else:
            self._stream = target

    def emit(self, alert: DetectionAlert) -> None:
        """Format alert and write to output sink followed by newline."""
        formatted_line = format_alert(alert, self.format_type)
        self._stream.write(formatted_line + "\n")
        self._stream.flush()

    def close(self) -> None:
        """Close the output stream if owned by this sink."""
        if self._owned_file is not None and not self._owned_file.closed:
            self._owned_file.close()

    def __enter__(self) -> "SiemAlertSink":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def export_alerts_to_file(
    alerts: Sequence[DetectionAlert],
    output_path: Path | str,
    format_type: SiemFormat | str,
) -> int:
    """Batch export a collection of alerts into a file formatted for SIEM ingest.

    Args:
        alerts: Collection of detection alerts.
        output_path: Destination file path.
        format_type: Target format ('cef', 'syslog', or 'json').

    Returns:
        Number of exported alerts.
    """
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    with dest.open("w", encoding="utf-8") as f:
        for alert in alerts:
            line = format_alert(alert, format_type)
            f.write(line + "\n")

    return len(alerts)
