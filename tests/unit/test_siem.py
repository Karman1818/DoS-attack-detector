"""Unit tests for SIEM integrations (CEF, Syslog RFC 5424, and JSON/NDJSON)."""

import io
import json
from pathlib import Path

import pytest

from dos_detector.models import DetectionAlert, Severity
from dos_detector.siem import (
    SiemAlertSink,
    SiemFormat,
    export_alerts_to_file,
    format_alert,
    format_alert_cef,
    format_alert_json,
    format_alert_syslog_rfc5424,
)


@pytest.fixture
def sample_alert() -> DetectionAlert:
    """Fixture providing a deterministic DetectionAlert for formatting tests."""
    return DetectionAlert(
        timestamp=1700000000.5,
        rule_name="SYN_FLOOD_SUSPECTED",
        severity=Severity.HIGH,
        description="High rate of TCP SYN flood packets (1500.0 SYN/s, SYN/ACK ratio: 15.00).",
        confidence=0.92,
        attack_type="DISTRIBUTED_DOS (DDoS)",
        distribution_confidence=0.85,
        dos_probability=0.15,
        ddos_probability=0.85,
        metrics_snapshot={
            "syn_pps": 1500.0,
            "syn_ack_ratio": 15.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "total_packets": 3000,
        },
    )


@pytest.mark.unit
def test_format_alert_cef(sample_alert: DetectionAlert) -> None:
    """Verify ArcSight CEF formatting, header fields, and escaped extensions."""
    cef_line = format_alert_cef(sample_alert)

    assert cef_line.startswith("CEF:0|DoS-Detector|DefensiveEngine|")
    assert "|SYN_FLOOD_SUSPECTED|Syn Flood Suspected|8|" in cef_line
    assert "src=192.168.1.100" in cef_line
    assert "dst=10.0.0.1" in cef_line
    assert "dpt=80" in cef_line
    assert "proto=TCP" in cef_line
    assert "cnt=3000" in cef_line
    assert "cfp1=0.92" in cef_line
    assert "cs1=SYN_FLOOD_SUSPECTED" in cef_line
    assert "cs2=DISTRIBUTED_DOS (DDoS)" in cef_line


@pytest.mark.unit
def test_format_alert_cef_escaping() -> None:
    """Verify special characters (=, |, \\) are safely escaped in CEF values."""
    alert = DetectionAlert(
        timestamp=1700000000.0,
        rule_name="CUSTOM|RULE=TEST",
        severity=Severity.CRITICAL,
        description="Malicious payload key=value with | pipe and \\ backslash",
        confidence=0.99,
        metrics_snapshot={"top_source_ip": "1.2.3.4"},
    )
    cef_line = format_alert_cef(alert)

    # In CEF header, pipe must be escaped as \|
    assert "CUSTOM\\|RULE=TEST" in cef_line
    # In CEF extension, = must be escaped as \=, and \ as \\
    assert "msg=Malicious payload key\\=value with | pipe and \\\\ backslash" in cef_line
    assert "|10|" in cef_line  # CRITICAL -> 10


@pytest.mark.unit
def test_format_alert_syslog_rfc5424(sample_alert: DetectionAlert) -> None:
    """Verify IETF RFC 5424 Syslog priority, ISO timestamp, and Structured Data."""
    syslog_msg = format_alert_syslog_rfc5424(
        sample_alert,
        hostname="soc-sensor-01",
        app_name="dos-detector",
        proc_id="12345",
    )

    # Facility 16 * 8 + Severity.HIGH (3) = 131
    assert syslog_msg.startswith("<131>1 ")
    assert " soc-sensor-01 dos-detector 12345 SYN_FLOOD_SUSPECTED " in syslog_msg
    assert (
        '[dosAlert@5424 rule="SYN_FLOOD_SUSPECTED" severity="HIGH" confidence="0.920" '
        'attackType="DISTRIBUTED_DOS (DDoS)" src="192.168.1.100" dst="10.0.0.1"]'
    ) in syslog_msg
    assert syslog_msg.endswith(sample_alert.description)


@pytest.mark.unit
def test_format_alert_json(sample_alert: DetectionAlert) -> None:
    """Verify single-line NDJSON format parses cleanly with expected keys."""
    json_str = format_alert_json(sample_alert)
    data = json.loads(json_str)

    assert data["rule_name"] == "SYN_FLOOD_SUSPECTED"
    assert data["severity"] == "HIGH"
    assert data["attack_type"] == "DISTRIBUTED_DOS (DDoS)"
    assert data["confidence"] == 0.92
    assert data["distribution"]["ddos_probability"] == 0.85
    assert data["metrics_snapshot"]["src_ip"] == "192.168.1.100"
    assert "timestamp_iso" in data


@pytest.mark.unit
def test_format_alert_dispatcher(sample_alert: DetectionAlert) -> None:
    """Verify generic format_alert dispatcher handles all enum values."""
    cef = format_alert(sample_alert, SiemFormat.CEF)
    assert cef.startswith("CEF:0|")

    syslog = format_alert(sample_alert, "syslog")
    assert syslog.startswith("<131>1")

    ndjson = format_alert(sample_alert, "json")
    assert json.loads(ndjson)["rule_name"] == sample_alert.rule_name

    with pytest.raises(ValueError, match="is not a valid SiemFormat"):
        format_alert(sample_alert, "unsupported_format")


@pytest.mark.unit
def test_siem_alert_sink_streaming(sample_alert: DetectionAlert) -> None:
    """Verify SiemAlertSink writes formatted output to an IO stream."""
    buffer = io.StringIO()
    sink = SiemAlertSink(buffer, format_type=SiemFormat.CEF)
    sink.emit(sample_alert)

    output = buffer.getvalue()
    assert output.startswith("CEF:0|")
    assert output.endswith("\n")


@pytest.mark.unit
def test_siem_alert_sink_file_context(sample_alert: DetectionAlert, tmp_path: Path) -> None:
    """Verify SiemAlertSink manages file handle lifecycle with context manager."""
    out_file = tmp_path / "cef_events.log"
    with SiemAlertSink(out_file, format_type=SiemFormat.CEF) as sink:
        sink.emit(sample_alert)
        sink.emit(sample_alert)

    assert out_file.is_file()
    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("CEF:0|")


@pytest.mark.unit
def test_export_alerts_to_file(sample_alert: DetectionAlert, tmp_path: Path) -> None:
    """Verify batch export function writes all alerts to destination file."""
    alerts = [sample_alert, sample_alert]
    out_file = tmp_path / "alerts.ndjson"

    count = export_alerts_to_file(alerts, out_file, format_type=SiemFormat.JSON)
    assert count == 2

    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert parsed["rule_name"] == "SYN_FLOOD_SUSPECTED"
