"""Unit tests for offline PCAP and CSV packet streamers."""

from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from dos_detector.ingestion import (
    CIC_IDS2017_CSV_MAPPING,
    stream_csv,
    stream_pcap,
)


@pytest.mark.unit
def test_stream_pcap_raises_file_not_found() -> None:
    with pytest.raises(FileNotFoundError, match="PCAP capture file not found"):
        list(stream_pcap("non_existent_file.pcap"))


@pytest.mark.unit
def test_stream_pcap_with_mixed_traffic(tmp_path: Path) -> None:
    pcap_file = tmp_path / "sample.pcap"

    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")

    # Create synthetic packets with full Ethernet frame to prevent interface resolution
    tcp_syn = eth / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=50000, dport=80, flags="S")
    tcp_syn_ack = (
        eth / IP(src="198.51.100.1", dst="192.0.2.1") / TCP(sport=80, dport=50000, flags="SA")
    )
    udp_pkt = eth / IP(src="192.0.2.2", dst="198.51.100.2") / UDP(sport=5353, dport=53)
    icmp_pkt = eth / IP(src="192.0.2.3", dst="198.51.100.3") / ICMP()
    arp_pkt = eth / ARP(hwsrc="00:11:22:33:44:55", psrc="192.0.2.1", pdst="192.0.2.2")

    wrpcap(str(pcap_file), [tcp_syn, tcp_syn_ack, udp_pkt, icmp_pkt, arp_pkt])

    records = list(stream_pcap(pcap_file))

    # ARP must be skipped, leaving 4 IP records
    assert len(records) == 4

    # 1. TCP SYN
    r0 = records[0]
    assert r0.src_ip == "192.0.2.1"
    assert r0.dst_ip == "198.51.100.1"
    assert r0.protocol == "TCP"
    assert r0.src_port == 50000
    assert r0.dst_port == 80
    assert "SYN" in r0.tcp_flags
    assert "ACK" not in r0.tcp_flags
    assert r0.packet_size > 0

    # 2. TCP SYN-ACK
    r1 = records[1]
    assert r1.protocol == "TCP"
    assert "SYN" in r1.tcp_flags
    assert "ACK" in r1.tcp_flags

    # 3. UDP
    r2 = records[2]
    assert r2.protocol == "UDP"
    assert r2.src_port == 5353
    assert r2.dst_port == 53
    assert len(r2.tcp_flags) == 0

    # 4. ICMP
    r3 = records[3]
    assert r3.protocol == "ICMP"
    assert r3.src_port is None
    assert r3.dst_port is None


@pytest.mark.unit
def test_stream_csv_raises_file_not_found() -> None:
    with pytest.raises(FileNotFoundError, match="CSV file not found"):
        list(stream_csv("non_existent_file.csv"))


@pytest.mark.unit
def test_stream_csv_default_mapping(tmp_path: Path) -> None:
    csv_file = tmp_path / "traffic.csv"
    csv_file.write_text(
        "timestamp,src_ip,dst_ip,protocol,src_port,dst_port,packet_size,tcp_flags\n"
        "100.0, 10.0.0.1 , 10.0.0.2 ,TCP, 12345 , 80 , 128 , SYN \n"
        '100.1, 10.0.0.2 , 10.0.0.1 ,TCP, 80 , 12345 , 64 , "SYN,ACK" \n'
        "100.2, 10.0.0.3 , 10.0.0.1 ,TCP, 80 , 12346 , 64 , SYN|RST \n",
        encoding="utf-8",
    )

    records = list(stream_csv(csv_file))
    assert len(records) == 3

    assert records[0].timestamp == 100.0
    assert records[0].src_ip == "10.0.0.1"
    assert records[0].dst_ip == "10.0.0.2"
    assert records[0].protocol == "TCP"
    assert records[0].src_port == 12345
    assert records[0].dst_port == 80
    assert records[0].packet_size == 128
    assert records[0].tcp_flags == frozenset({"SYN"})

    assert records[1].tcp_flags == frozenset({"SYN", "ACK"})
    assert records[2].tcp_flags == frozenset({"SYN", "RST"})


@pytest.mark.unit
def test_stream_csv_cic_ids2017_mapping(tmp_path: Path) -> None:
    csv_file = tmp_path / "cic_ids_sample.csv"
    csv_file.write_text(
        "Timestamp, Source IP, Destination IP, Protocol, Source Port, Destination Port, "
        "Total Length of Fwd Packets, SYN Flag Count\n"
        "1600.5, 172.16.0.1, 192.168.10.50, TCP, 443, 55555, 1500, 1\n",
        encoding="utf-8",
    )

    records = list(stream_csv(csv_file, mapping=CIC_IDS2017_CSV_MAPPING))
    assert len(records) == 1
    r = records[0]
    assert r.timestamp == 1600.5
    assert r.src_ip == "172.16.0.1"
    assert r.dst_ip == "192.168.10.50"
    assert r.src_port == 443
    assert r.dst_port == 55555
    assert r.packet_size == 1500
    assert "SYN" in r.tcp_flags


@pytest.mark.unit
def test_stream_pcap_extracts_http_metadata(tmp_path: Path) -> None:
    """Verify that HTTP GET requests on port 80 are parsed with method and normalized URI."""
    from scapy.packet import Raw

    pcap_file = tmp_path / "http_sample.pcap"
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    http_payload = b"GET /c.php?session=abc123xyz HTTP/1.1\r\nHost: target.local\r\n\r\n"
    pkt = (
        eth
        / IP(src="192.168.1.50", dst="192.168.1.1")
        / TCP(sport=43210, dport=80, flags="PA")
        / Raw(load=http_payload)
    )

    wrpcap(str(pcap_file), [pkt])
    records = list(stream_pcap(pcap_file))
    assert len(records) == 1
    r = records[0]
    assert r.http_method == "GET"
    assert r.http_uri == "/c.php"
