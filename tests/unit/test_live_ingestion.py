"""Unit tests for live network traffic ingestion and interface discovery."""

import threading
import time
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from dos_detector.ingestion import (
    _classify_interface_type,
    get_network_interfaces,
    resolve_interface_name,
    stream_live,
)
from dos_detector.models import NetworkInterfaceInfo


@pytest.mark.unit
def test_classify_interface_type() -> None:
    """Verify hardware and logical interface classification."""
    assert _classify_interface_type("Wi-Fi", "RZ616 Wi-Fi 6E 160MHz") == "Wi-Fi"
    assert _classify_interface_type("wlan0", "Intel Wireless-AC 9560") == "Wi-Fi"
    assert _classify_interface_type("Ethernet", "Realtek PCIe GbE Family Controller") == "Ethernet"
    assert _classify_interface_type("eth0", "Intel Gigabit Network Connection") == "Ethernet"
    assert _classify_interface_type("Loopback", "Software Loopback Interface 1") == "Loopback"
    assert _classify_interface_type("lo", "Loopback interface") == "Loopback"
    assert _classify_interface_type("OpenVPN", "TAP-Windows Adapter V9") == "Virtual / VPN"
    assert _classify_interface_type("docker0", "Bridge interface") == "Virtual / VPN"
    assert _classify_interface_type("Bluetooth", "Bluetooth PAN") == "Bluetooth"
    assert _classify_interface_type("UnknownDevice", "Generic Device") == "Other"


@pytest.mark.unit
def test_get_network_interfaces_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify interface discovery parses metadata and filters noisy drivers."""
    mock_raw_list = [
        {
            "name": "Ethernet",
            "description": "Realtek PCIe GbE Family Controller",
            "guid": "{E08167A7-1111-2222-3333-D4C775DCB93D}",
            "mac": "e8:80:88:bd:04:9d",
            "ips": ["fe80::ac9:713c:ea5d:9855", "192.168.1.50"],
        },
        {
            "name": "Wi-Fi",
            "description": "RZ616 Wi-Fi 6E 160MHz",
            "guid": "{D79E1536-4444-5555-6666-015B1833BC4A}",
            "mac": "74:97:79:75:2a:33",
            "ips": ["192.168.0.83"],
        },
        {
            "name": "Ethernet-QoS Packet Scheduler-0000",
            "description": "Realtek PCIe GbE-QoS Packet Scheduler",
            "guid": "{FILTER-GUID}",
            "mac": "",
            "ips": [],
        },
    ]

    import scapy.arch.windows as scapy_win

    monkeypatch.setattr(scapy_win, "get_windows_if_list", lambda: mock_raw_list)
    monkeypatch.setattr("sys.platform", "win32")

    ifaces = get_network_interfaces()
    assert len(ifaces) == 2
    assert ifaces[0].name == "Ethernet"
    assert ifaces[0].interface_type == "Ethernet"
    assert ifaces[0].ip_addresses == ("192.168.1.50",)

    assert ifaces[1].name == "Wi-Fi"
    assert ifaces[1].interface_type == "Wi-Fi"
    assert ifaces[1].ip_addresses == ("192.168.0.83",)


@pytest.mark.unit
def test_resolve_interface_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify resolving friendly name, IP address, or GUID to an active adapter."""
    mock_ifaces = [
        NetworkInterfaceInfo(
            name="Wi-Fi",
            description="Intel Wi-Fi 6 AX200",
            interface_type="Wi-Fi",
            ip_addresses=("192.168.0.100",),
            mac_address="00:11:22:33:44:55",
            guid_or_id="{WIFI-GUID-1234}",
        ),
        NetworkInterfaceInfo(
            name="Ethernet 2",
            description="Realtek Gaming Controller",
            interface_type="Ethernet",
            ip_addresses=("10.0.0.5",),
            mac_address="66:77:88:99:aa:bb",
            guid_or_id="{ETH-GUID-5678}",
        ),
    ]

    monkeypatch.setattr("dos_detector.ingestion.get_network_interfaces", lambda: mock_ifaces)

    # Exact name match
    assert resolve_interface_name("Wi-Fi") == "Wi-Fi"
    assert resolve_interface_name("wi-fi") == "Wi-Fi"

    # IP match
    assert resolve_interface_name("192.168.0.100") == "Wi-Fi"
    assert resolve_interface_name("10.0.0.5") == "Ethernet 2"

    # GUID match
    assert resolve_interface_name("{WIFI-GUID-1234}") == "{WIFI-GUID-1234}"

    # Partial substring match
    assert resolve_interface_name("Realtek") == "Ethernet 2"

    # Empty raises ValueError
    with pytest.raises(ValueError, match="cannot be empty"):
        resolve_interface_name("   ")


@pytest.mark.unit
def test_stream_live_producer_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify live capture generator streams packets via Producer-Consumer background worker."""
    fake_packets = []
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    for i in range(5):
        pkt = (
            eth / IP(src=f"192.0.2.{i}", dst="10.0.0.1") / TCP(sport=10000 + i, dport=80, flags="S")
        )
        pkt.time = 1000.0 + i
        fake_packets.append(pkt)

    def mock_sniff(**kwargs: Any) -> None:
        prn = kwargs.get("prn")
        assert prn is not None
        for pkt in fake_packets:
            prn(pkt)

    monkeypatch.setattr("scapy.sendrecv.sniff", mock_sniff)
    monkeypatch.setattr("dos_detector.ingestion.resolve_interface_name", lambda iface: iface)

    records = list(stream_live(interface="eth0", max_packets=5))
    assert len(records) == 5
    assert records[0].src_ip == "192.0.2.0"
    assert records[0].dst_ip == "10.0.0.1"
    assert records[0].src_port == 10000
    assert records[0].dst_port == 80
    assert "SYN" in records[0].tcp_flags


@pytest.mark.unit
def test_stream_live_stops_with_event(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify external threading.Event terminates the live capture stream cleanly."""
    stop_event = threading.Event()
    eth = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="1.1.1.1", dst="2.2.2.2")
        / TCP(sport=1234, dport=80)
    )

    def mock_sniff(**kwargs: Any) -> None:
        prn = kwargs.get("prn")
        assert prn is not None
        # Send packets in a loop until stop_event is set
        while not stop_event.is_set():
            prn(eth)
            time.sleep(0.01)

    monkeypatch.setattr("scapy.sendrecv.sniff", mock_sniff)
    monkeypatch.setattr("dos_detector.ingestion.resolve_interface_name", lambda iface: iface)

    stream = stream_live(interface="lo", stop_event=stop_event)
    collected = []
    for record in stream:
        collected.append(record)
        if len(collected) == 3:
            stop_event.set()

    assert len(collected) == 3


@pytest.mark.unit
def test_stream_live_propagates_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify sniffer worker exceptions are surfaced cleanly to caller."""

    def mock_sniff_fail(**kwargs: Any) -> None:
        raise PermissionError("Access denied opening raw socket")

    monkeypatch.setattr("scapy.sendrecv.sniff", mock_sniff_fail)
    monkeypatch.setattr("dos_detector.ingestion.resolve_interface_name", lambda iface: iface)

    with pytest.raises(RuntimeError, match="Ensure you have administrative privileges"):
        list(stream_live(interface="eth0"))
