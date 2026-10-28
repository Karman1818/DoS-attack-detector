"""Unit tests verifying CLI integration with SIEM exporters (CEF, Syslog, JSON)."""

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from dos_detector.cli import _process_packet_stream, main
from dos_detector.config import DetectionConfig
from dos_detector.ingestion import stream_pcap


def _create_synthetic_syn_pcap(path: Path, count: int = 150) -> None:
    """Helper to create a deterministic PCAP with SYN flood traffic."""
    packets = [
        IP(src=f"192.168.1.{10 + (i % 5)}", dst="10.0.0.1")
        / TCP(sport=30000 + i, dport=80, flags="S")
        for i in range(count)
    ]
    for i, pkt in enumerate(packets):
        pkt.time = 1000.0 + (i * 0.005)  # 200 pps
    wrpcap(str(path), packets)


@pytest.mark.unit
def test_cli_process_stream_export_cef_file(tmp_path: Path) -> None:
    """Verify _process_packet_stream writes CEF events to specified output file."""
    pcap_file = tmp_path / "traffic.pcap"
    cef_file = tmp_path / "alerts.cef"
    _create_synthetic_syn_pcap(pcap_file)

    config = DetectionConfig(syn_flood_pps_threshold=50.0)
    _process_packet_stream(
        packet_stream=stream_pcap(pcap_file),
        config=config,
        source_desc=str(pcap_file),
        export_siem="cef",
        export_output=str(cef_file),
    )

    assert cef_file.is_file()
    lines = cef_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0
    assert all(line.startswith("CEF:0|DoS-Detector|DefensiveEngine|") for line in lines)
    assert any("SYN_FLOOD_SUSPECTED" in line for line in lines)


@pytest.mark.unit
def test_cli_process_stream_export_json_file(tmp_path: Path) -> None:
    """Verify _process_packet_stream writes NDJSON events to file."""
    pcap_file = tmp_path / "traffic.pcap"
    json_file = tmp_path / "alerts.ndjson"
    _create_synthetic_syn_pcap(pcap_file)

    config = DetectionConfig(syn_flood_pps_threshold=50.0)
    _process_packet_stream(
        packet_stream=stream_pcap(pcap_file),
        config=config,
        source_desc=str(pcap_file),
        export_siem="json",
        export_output=str(json_file),
    )

    assert json_file.is_file()
    lines = json_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0
    for line in lines:
        data = json.loads(line)
        assert "rule_name" in data
        assert "severity" in data
        assert "confidence" in data


@pytest.mark.unit
def test_cli_process_stream_export_stdout(tmp_path: Path) -> None:
    """Verify streaming SIEM events to stdout when export_output is omitted."""
    pcap_file = tmp_path / "traffic.pcap"
    _create_synthetic_syn_pcap(pcap_file)

    config = DetectionConfig(syn_flood_pps_threshold=50.0)

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    with patch("sys.stdout", stdout_capture), patch("sys.stderr", stderr_capture):
        _process_packet_stream(
            packet_stream=stream_pcap(pcap_file),
            config=config,
            source_desc=str(pcap_file),
            export_siem="syslog",
            export_output=None,
        )

    out_content = stdout_capture.getvalue().strip()
    err_content = stderr_capture.getvalue().strip()

    # stdout should contain clean syslog lines
    assert "<131>1 " in out_content
    # stderr should contain human progress banners
    assert "Analyzing Network Traffic Source" in err_content
    assert "Analysis Complete" in err_content


@pytest.mark.unit
def test_cli_main_pcap_with_siem_flag(tmp_path: Path) -> None:
    """Verify running end-to-end main CLI command with --export-siem flag."""
    pcap_file = tmp_path / "cli_test.pcap"
    cef_file = tmp_path / "cli_alerts.cef"
    _create_synthetic_syn_pcap(pcap_file)

    test_args = [
        "dos-detector",
        "pcap",
        str(pcap_file),
        "--export-siem",
        "cef",
        "--export-output",
        str(cef_file),
        "--syn-threshold",
        "50",
    ]

    with patch("sys.argv", test_args):
        main()

    assert cef_file.is_file()
    lines = cef_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0
    assert lines[0].startswith("CEF:0|")
