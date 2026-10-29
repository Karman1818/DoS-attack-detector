"""Unit and integration tests for the FastAPI backend and monitoring server."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from dos_detector.config import DetectionConfig
from dos_detector.server import create_app


@pytest.fixture
def test_client() -> TestClient:
    """Create a FastAPI TestClient instance with default configuration."""
    config = DetectionConfig(
        syn_flood_pps_threshold=50.0,
        packet_flood_pps_threshold=500.0,
        min_consecutive_windows=1,
        alert_cooldown_seconds=0.0,
    )
    app = create_app(config=config)
    return TestClient(app)


@pytest.mark.unit
def test_get_dashboard_returns_html(test_client: TestClient) -> None:
    """Verify root endpoint returns the interactive HTML dashboard."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "DoS Attack Detector" in response.text
    assert '<canvas id="trafficChart"' in response.text
    assert 'id="dropZone"' in response.text
    assert "initDragAndDrop" in response.text
    assert "exportSiem" in response.text
    assert "exportSiem('cef')" in response.text
    assert "exportSiem('syslog')" in response.text
    assert "exportSiem('ndjson')" in response.text


@pytest.mark.unit
def test_health_endpoint(test_client: TestClient) -> None:
    """Verify health status endpoint returns active mode and telemetry."""
    response = test_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["detector_mode"] == "hybrid"
    assert "version" in data
    assert "model_description" in data


@pytest.mark.unit
def test_get_and_update_config(test_client: TestClient) -> None:
    """Verify dynamic threshold updates and detector mode switching."""
    # Read config
    res_get = test_client.get("/api/config")
    assert res_get.status_code == 200
    cfg_data = res_get.json()
    assert cfg_data["detector_mode"] == "hybrid"

    # Update config to base mode
    res_post = test_client.post(
        "/api/config",
        json={"detector_mode": "base", "syn_flood_pps_threshold": 250.0},
    )
    assert res_post.status_code == 200
    health_data = res_post.json()
    assert health_data["detector_mode"] == "base"

    # Verify updated values persisted
    res_get_updated = test_client.get("/api/config")
    assert res_get_updated.json()["detector_mode"] == "base"
    assert res_get_updated.json()["syn_flood_pps_threshold"] == 250.0

    # Invalid update raises 422
    res_invalid = test_client.post(
        "/api/config",
        json={"syn_flood_pps_threshold": -10.0},
    )
    assert res_invalid.status_code == 422


@pytest.mark.unit
def test_analyze_demo_endpoint(test_client: TestClient) -> None:
    """Verify running the synthetic benchmark simulation demo."""
    response = test_client.post("/api/analyze/demo")
    assert response.status_code == 200
    data = response.json()
    assert data["total_packets"] > 0
    assert data["total_windows"] > 0
    assert data["total_alerts"] > 0
    assert len(data["timeline"]) > 0
    assert len(data["alerts"]) > 0
    assert "Educational Simulation Demo" in data["source_name"]


@pytest.mark.unit
def test_analyze_upload_pcap(test_client: TestClient, tmp_path: Path) -> None:
    """Verify safe offline PCAP upload and automated inspection."""
    pcap_path = tmp_path / "test_upload.pcap"
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkts = []

    # 100 SYN packets in 1s -> 100 pps
    for i in range(100):
        pkt = eth / IP(src="192.0.2.1", dst="10.0.0.1") / TCP(sport=10000 + i, dport=80, flags="S")
        pkt.time = 1000.0 + (i * 0.01)
        pkts.append(pkt)

    wrpcap(str(pcap_path), pkts)

    with pcap_path.open("rb") as f:
        response = test_client.post(
            "/api/analyze/upload",
            files={"file": ("test_upload.pcap", f, "application/vnd.tcpdump.pcap")},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_packets"] == 100
    assert data["total_alerts"] > 0


@pytest.mark.unit
def test_analyze_upload_invalid_extension(test_client: TestClient) -> None:
    """Verify rejecting unsupported file formats."""
    response = test_client.post(
        "/api/analyze/upload",
        files={"file": ("malicious.exe", b"MZ...", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Unsupported file extension" in response.json()["detail"]


@pytest.mark.unit
def test_alerts_history_and_clear(test_client: TestClient) -> None:
    """Verify alerts endpoint and clearing history."""
    # Run demo to generate alerts
    test_client.post("/api/analyze/demo")

    # Fetch alerts
    res_alerts = test_client.get("/api/alerts")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json()
    assert len(alerts) > 0

    # Clear alerts
    res_clear = test_client.post("/api/alerts/clear")
    assert res_clear.status_code == 200
    assert res_clear.json()["status"] == "cleared"

    # Verify empty
    res_after = test_client.get("/api/alerts")
    assert res_after.json() == []


@pytest.mark.unit
def test_cli_serve_subparser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify CLI parses serve arguments and starts uvicorn server."""
    import uvicorn

    from dos_detector.cli import main

    mock_run_called = False

    def mock_run(app: object, host: str, port: int, log_level: str) -> None:
        nonlocal mock_run_called
        mock_run_called = True
        assert host == "127.0.0.1"
        assert port == 9000

    monkeypatch.setattr(uvicorn, "run", mock_run)
    monkeypatch.setattr(
        "sys.argv",
        ["dos-detector", "serve", "--port", "9000", "--detector", "base"],
    )
    main()
    assert mock_run_called is True


@pytest.mark.unit
def test_upload_custom_model_and_reset(test_client: TestClient, tmp_path: Path) -> None:
    """Verify uploading a custom trained .joblib model and resetting to baseline."""
    import joblib
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(n_estimators=10, random_state=42)
    X_dummy = [[1.0] * 10, [2.0] * 10]
    model.fit(X_dummy)

    model_file = tmp_path / "custom_test_model.joblib"
    joblib.dump(model, str(model_file))

    with model_file.open("rb") as f:
        res = test_client.post(
            "/api/model/upload",
            files={"file": ("custom_test_model.joblib", f, "application/octet-stream")},
        )
    assert res.status_code == 200
    data = res.json()
    assert "Custom model (custom_test_model.joblib)" in data["model_description"]

    # Invalid extension
    res_bad_ext = test_client.post(
        "/api/model/upload",
        files={"file": ("bad_model.pkl", b"invalid", "application/octet-stream")},
    )
    assert res_bad_ext.status_code == 400

    # Reset back to default
    res_reset = test_client.post("/api/model/reset")
    assert res_reset.status_code == 200
    assert "Built-in reference baseline" in res_reset.json()["model_description"]


@pytest.mark.unit
def test_export_alerts_cef(test_client: TestClient) -> None:
    """Verify exporting alerts in CEF format via REST API."""
    test_client.post("/api/analyze/demo")
    response = test_client.get("/api/alerts/export?format=cef")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "attachment; filename=" in response.headers["content-disposition"]
    assert response.headers["content-disposition"].endswith('.cef"')
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) > 0
    assert all(line.startswith("CEF:0|DoS-Detector|DefensiveEngine|") for line in lines)
    assert "cs1=" in response.text
    assert "msg=" in response.text


@pytest.mark.unit
def test_export_alerts_syslog(test_client: TestClient) -> None:
    """Verify exporting alerts in Syslog RFC 5424 format via REST API."""
    test_client.post("/api/analyze/demo")
    response = test_client.get("/api/alerts/export?format=syslog")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "attachment; filename=" in response.headers["content-disposition"]
    assert response.headers["content-disposition"].endswith('.log"')
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) > 0
    for line in lines:
        assert line.startswith("<")
        assert "dos-detector" in line
        assert "[dosAlert@5424" in line


@pytest.mark.unit
def test_export_alerts_ndjson(test_client: TestClient) -> None:
    """Verify exporting alerts in NDJSON format for streaming ingestion."""
    import json

    test_client.post("/api/analyze/demo")
    response = test_client.get("/api/alerts/export?format=ndjson")
    assert response.status_code == 200
    assert "application/x-ndjson" in response.headers["content-type"]
    assert "attachment; filename=" in response.headers["content-disposition"]
    assert response.headers["content-disposition"].endswith('.ndjson"')
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) > 0
    for line in lines:
        parsed = json.loads(line)
        assert "rule_name" in parsed
        assert "severity" in parsed
        assert "confidence" in parsed


@pytest.mark.unit
def test_export_alerts_json(test_client: TestClient) -> None:
    """Verify exporting alerts in standard JSON format."""
    import json

    test_client.post("/api/analyze/demo")
    response = test_client.get("/api/alerts/export?format=json")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    assert "attachment; filename=" in response.headers["content-disposition"]
    assert response.headers["content-disposition"].endswith('.json"')
    parsed = json.loads(response.text)
    assert isinstance(parsed, list)
    assert len(parsed) > 0


@pytest.mark.unit
def test_export_alerts_filtering_by_severity(test_client: TestClient) -> None:
    """Verify filtering exported alerts by severity level."""
    test_client.post("/api/analyze/demo")
    res_high = test_client.get("/api/alerts/export?format=cef&severity=HIGH")
    assert res_high.status_code == 200
    for line in res_high.text.splitlines():
        if line.strip():
            assert "|8|" in line

    res_none = test_client.get("/api/alerts/export?format=cef&severity=LOW")
    assert res_none.status_code == 200
    assert res_none.text.strip() == ""


@pytest.mark.unit
def test_export_alerts_invalid_format(test_client: TestClient) -> None:
    """Verify 400 error when an unsupported SIEM format is requested."""
    response = test_client.get("/api/alerts/export?format=xml_unknown")
    assert response.status_code == 400
    assert "Unsupported SIEM format 'xml_unknown'" in response.json()["detail"]


@pytest.mark.unit
def test_export_alerts_empty_after_clear(test_client: TestClient) -> None:
    """Verify export is empty when alerts are cleared."""
    test_client.post("/api/analyze/demo")
    test_client.post("/api/alerts/clear")
    response = test_client.get("/api/alerts/export?format=cef")
    assert response.status_code == 200
    assert response.text.strip() == ""
