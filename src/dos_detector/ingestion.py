"""Offline packet and tabular network capture streamers.

Provides memory-efficient generators for streaming network traces from PCAP and CSV files
without loading entire multi-gigabyte captures into memory.
"""

import csv
import io
import logging
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Temporarily silence Scapy's Npcap service warnings on Windows during import
_old_stderr = sys.stderr
try:
    sys.stderr = io.StringIO()
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Packet
    from scapy.utils import PcapReader
finally:
    sys.stderr = _old_stderr

from dos_detector.models import PacketRecord

logger = logging.getLogger(__name__)

# Standard flag letter mappings used by Scapy
SCAPY_FLAG_NAMES: dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


@dataclass(frozen=True, slots=True)
class CsvFieldMapping:
    """Configurable column mapping for tabular network traffic CSV files."""

    timestamp_col: str = "timestamp"
    src_ip_col: str = "src_ip"
    dst_ip_col: str = "dst_ip"
    protocol_col: str = "protocol"
    src_port_col: str = "src_port"
    dst_port_col: str = "dst_port"
    packet_size_col: str = "packet_size"
    tcp_flags_col: str = "tcp_flags"


# Predefined mapping for Canadian Institute for Cybersecurity CIC-IDS2017 CSV exports
CIC_IDS2017_CSV_MAPPING = CsvFieldMapping(
    timestamp_col="Timestamp",
    src_ip_col="Source IP",
    dst_ip_col="Destination IP",
    protocol_col="Protocol",
    src_port_col="Source Port",
    dst_port_col="Destination Port",
    packet_size_col="Total Length of Fwd Packets",
    tcp_flags_col="SYN Flag Count",
)


def _parse_scapy_flags(raw_flags: Any) -> frozenset[str]:
    """Extract and normalize TCP flag names from Scapy FlagValue or string."""
    flag_letters = str(raw_flags)
    parsed: set[str] = set()
    for letter in flag_letters:
        if letter in SCAPY_FLAG_NAMES:
            parsed.add(SCAPY_FLAG_NAMES[letter])
    return frozenset(parsed)


def _packet_to_record(pkt: Packet) -> PacketRecord | None:
    """Extract normalized PacketRecord from a decoded Scapy packet.

    Returns None if the packet lacks an IP layer (e.g., pure ARP, STP, Ethernet frames).
    """
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    timestamp = float(pkt.time) if hasattr(pkt, "time") else 0.0
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    packet_size = len(pkt)

    src_port: int | None = None
    dst_port: int | None = None
    flags: frozenset[str] = frozenset()

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        flags = _parse_scapy_flags(tcp_layer.flags)
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = str(ip_layer.proto)

    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        packet_size=packet_size,
        tcp_flags=flags,
    )


def stream_pcap(file_path: str | Path) -> Iterator[PacketRecord]:
    """Stream packet records one by one from a PCAP/PCAPNG capture file.

    Memory-efficient generator that reads packets incrementally without loading
    the full capture into memory. Ignores malformed packets and non-IP traffic.

    Args:
        file_path: Path to the target PCAP/PCAPNG file.

    Yields:
        PacketRecord for each valid IP packet.

    Raises:
        FileNotFoundError: If the specified capture file does not exist.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP capture file not found: {path}")

    with PcapReader(str(path)) as reader:
        for idx, pkt in enumerate(reader):
            try:
                record = _packet_to_record(pkt)
                if record is not None:
                    yield record
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Skipping malformed packet at index %d in %s: %s",
                    idx,
                    path.name,
                    exc,
                )


def stream_csv(
    file_path: str | Path,
    mapping: CsvFieldMapping | None = None,
) -> Iterator[PacketRecord]:
    """Stream packet records row by row from a tabular CSV network capture file.

    Args:
        file_path: Path to the target CSV file.
        mapping: Column mapping definition. Defaults to standard field names.

    Yields:
        PacketRecord for each successfully parsed row.

    Raises:
        FileNotFoundError: If the specified CSV file does not exist.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    field_map = mapping or CsvFieldMapping()

    with path.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        for row_idx, raw_row in enumerate(reader):
            try:
                # Strip leading/trailing whitespace and surrounding quotes from keys and values
                row = {k.strip(): v.strip().strip("\"'") for k, v in raw_row.items() if k}

                # Timestamp parsing
                ts_str = row.get(field_map.timestamp_col, "0")
                try:
                    timestamp = float(ts_str)
                except ValueError:
                    timestamp = float(row_idx)

                src_ip = row.get(field_map.src_ip_col, "")
                dst_ip = row.get(field_map.dst_ip_col, "")
                protocol = row.get(field_map.protocol_col, "TCP")

                # Ports
                sport_raw = row.get(field_map.src_port_col)
                src_port = int(sport_raw) if sport_raw and sport_raw.isdigit() else None

                dport_raw = row.get(field_map.dst_port_col)
                dst_port = int(dport_raw) if dport_raw and dport_raw.isdigit() else None

                # Size
                size_raw = row.get(field_map.packet_size_col, "0")
                try:
                    packet_size = int(float(size_raw))
                except ValueError:
                    packet_size = 0

                # Flags parsing
                flags_raw = row.get(field_map.tcp_flags_col, "")
                flags: set[str] = set()
                if flags_raw in {"1", "1.0", "SYN"}:
                    flags.add("SYN")
                elif any(delim in flags_raw for delim in (",", "|", ";", "+")):
                    parts = re.split(r"[,|;+]", flags_raw)
                    flags.update(p.strip().upper() for p in parts if p.strip())
                elif flags_raw:
                    flags.add(flags_raw.strip().upper())

                yield PacketRecord(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    src_port=src_port,
                    dst_port=dst_port,
                    packet_size=packet_size,
                    tcp_flags=frozenset(flags),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Skipping invalid CSV row %d in %s: %s",
                    row_idx,
                    path.name,
                    exc,
                )
