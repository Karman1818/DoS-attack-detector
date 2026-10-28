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
