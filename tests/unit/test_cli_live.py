"""Unit tests for the live capture CLI subcommand and defensive guardrails."""

from unittest.mock import MagicMock

import pytest

from dos_detector.cli import main
from dos_detector.models import NetworkInterfaceInfo, PacketRecord


@pytest.mark.unit
def test_cli_live_list_interfaces(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --list-interfaces prints discovered network adapters and exits cleanly."""
    mock_ifaces = [
        NetworkInterfaceInfo(
            name="Wi-Fi",
            description="Intel Wi-Fi 6 AX200",
            interface_type="Wi-Fi",
            ip_addresses=("192.168.0.100",),
            mac_address="00:11:22:33:44:55",
            guid_or_id="{WIFI-GUID}",
        ),
        NetworkInterfaceInfo(
            name="Ethernet",
            description="Realtek PCIe Controller",
            interface_type="Ethernet",
            ip_addresses=("10.0.0.2",),
            mac_address="66:77:88:99:aa:bb",
            guid_or_id="{ETH-GUID}",
        ),
    ]

    monkeypatch.setattr("dos_detector.cli.get_network_interfaces", lambda: mock_ifaces)
    monkeypatch.setattr("sys.argv", ["dos-detector", "live", "--list-interfaces"])

    main()

    captured = capsys.readouterr()
    assert "AVAILABLE NETWORK INTERFACES" in captured.out
    assert "[Wi-Fi] Wi-Fi" in captured.out
    assert "192.168.0.100" in captured.out
    assert "[Ethernet] Ethernet" in captured.out
    assert "{ETH-GUID}" in captured.out


@pytest.mark.unit
def test_cli_live_missing_authorization_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify live capture refuses to start without explicit --authorized-lab confirmation."""
    monkeypatch.setattr("sys.argv", ["dos-detector", "live", "--interface", "Wi-Fi"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "DEFENSIVE SAFETY & LEGAL GUARD" in captured.err
    assert "--authorized-lab" in captured.err


@pytest.mark.unit
def test_cli_live_authorized_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify live capture runs pipeline when --authorized-lab is provided."""
    dummy_records = [
        PacketRecord(
            timestamp=100.0,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            packet_size=64,
            tcp_flags=frozenset({"SYN"}),
        ),
        PacketRecord(
            timestamp=100.1,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            packet_size=64,
            tcp_flags=frozenset({"ACK"}),
        ),
    ]

    mock_stream = MagicMock(return_value=iter(dummy_records))
    monkeypatch.setattr("dos_detector.cli.stream_live", mock_stream)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dos-detector",
            "live",
            "--interface",
            "eth0",
            "--authorized-lab",
            "--count",
            "2",
            "--bpf",
            "tcp port 80",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "AUTHORIZED LAB MODE" in captured.out
    assert "eth0" in captured.out
    assert "tcp port 80" in captured.out
    assert "Analysis Complete" in captured.out
    mock_stream.assert_called_once_with(interface="eth0", bpf_filter="tcp port 80", max_packets=2)


@pytest.mark.unit
def test_cli_live_runtime_error_handling(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify graceful error reporting when packet sniffer encounters permission errors."""

    def mock_fail(**kwargs: object) -> object:
        raise RuntimeError("Npcap driver service is not running")

    monkeypatch.setattr("dos_detector.cli.stream_live", mock_fail)
    monkeypatch.setattr(
        "sys.argv",
        ["dos-detector", "live", "--interface", "eth0", "--authorized-lab"],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Failed to start live capture" in captured.err
    assert "Troubleshooting" in captured.err
    assert "Administrator" in captured.err
