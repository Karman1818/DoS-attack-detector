"""Offline packet and tabular network capture streamers.

Provides memory-efficient generators for streaming network traces from PCAP and CSV files
without loading entire multi-gigabyte captures into memory.
"""

import csv
import io
import logging
import queue
import re
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Temporarily silence Scapy's Npcap service warnings on Windows during import
_old_stderr = sys.stderr
try:
    sys.stderr = io.StringIO()
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Packet, Raw
    from scapy.utils import PcapReader
finally:
    sys.stderr = _old_stderr

from dos_detector.models import NetworkInterfaceInfo, PacketRecord

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
    ack_flags_col: str | None = None
    rst_flags_col: str | None = None
    label_col: str | None = None


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
    ack_flags_col="ACK Flag Count",
    rst_flags_col="RST Flag Count",
    label_col="Label",
)


def _parse_timestamp(ts_str: str, default_val: float) -> float:
    """Safely parse epoch float or common datetime formats in benchmark datasets."""
    clean_ts = ts_str.strip()
    if not clean_ts:
        return default_val
    try:
        return float(clean_ts)
    except ValueError:
        pass

    for fmt in (
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %I:%M:%S %p",
        "%d/%m/%Y %I:%M %p",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(clean_ts, fmt).timestamp()
        except ValueError:
            continue

    return default_val


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
    http_method: str | None = None
    http_uri: str | None = None

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        flags = _parse_scapy_flags(tcp_layer.flags)

        # Inspect Layer 7 HTTP requests (e.g., HTTP GET/POST Flood / WebDDoS)
        if (dst_port in (80, 8080, 443) or src_port in (80, 8080, 443)) and pkt.haslayer(Raw):
            try:
                load = bytes(pkt[Raw].load)
                if load.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                    tokens = load.split(b" ", 2)
                    if len(tokens) >= 2:
                        http_method = tokens[0].decode("ascii", errors="ignore")
                        # Normalize path and discard query string for endpoint clustering
                        raw_uri = tokens[1].decode("ascii", errors="ignore")
                        http_uri = raw_uri.split("?")[0]
            except (UnicodeDecodeError, ValueError, IndexError) as exc:
                logger.debug("Failed to decode HTTP payload: %s", exc)
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
    elif ip_layer.proto == 17:
        protocol = "UDP"
    elif ip_layer.proto == 6:
        protocol = "TCP"
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
        http_method=http_method,
        http_uri=http_uri,
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

                # Timestamp parsing with epoch or datetime formats
                ts_str = row.get(field_map.timestamp_col, "0")
                timestamp = _parse_timestamp(ts_str, default_val=float(row_idx))

                src_ip = row.get(field_map.src_ip_col, "")
                dst_ip = row.get(field_map.dst_ip_col, "")

                # Protocol normalization (handles numbers like 6/17 and names)
                proto_raw = row.get(field_map.protocol_col, "TCP").strip()
                if proto_raw in {"6", "6.0"}:
                    protocol = "TCP"
                elif proto_raw in {"17", "17.0"}:
                    protocol = "UDP"
                elif proto_raw in {"1", "1.0"}:
                    protocol = "ICMP"
                else:
                    protocol = proto_raw.upper() if proto_raw else "TCP"

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

                # Additional flags (e.g., CIC-IDS2017 ACK/RST columns)
                if field_map.ack_flags_col:
                    ack_raw = row.get(field_map.ack_flags_col, "").strip()
                    if ack_raw in {"1", "1.0", "ACK"}:
                        flags.add("ACK")
                if field_map.rst_flags_col:
                    rst_raw = row.get(field_map.rst_flags_col, "").strip()
                    if rst_raw in {"1", "1.0", "RST"}:
                        flags.add("RST")

                # Ground truth label parsing for evaluation
                label: str | None = None
                if field_map.label_col and field_map.label_col in row:
                    raw_label = row[field_map.label_col].strip()
                    if raw_label:
                        label = raw_label

                yield PacketRecord(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    src_port=src_port,
                    dst_port=dst_port,
                    packet_size=packet_size,
                    tcp_flags=frozenset(flags),
                    label=label,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Skipping invalid CSV row %d in %s: %s",
                    row_idx,
                    path.name,
                    exc,
                )


# ---------------------------------------------------------------------------
# Live Traffic Ingestion & Network Interface Discovery
# ---------------------------------------------------------------------------


def _classify_interface_type(name: str, description: str) -> str:
    """Classify network interface into a human-readable hardware or logical category."""
    combined = f"{name} {description}".lower()
    if any(k in combined for k in ("wi-fi", "wireless", "wlan", "802.11")):
        return "Wi-Fi"
    if "loopback" in combined:
        return "Loopback"
    if any(k in combined for k in ("virtual", "vpn", "tap", "tun", "veth", "hyper-v", "bridge")):
        return "Virtual / VPN"
    if any(k in combined for k in ("ethernet", "gbe", "pcie", "realtek", "intel", "lan", "eth")):
        return "Ethernet"
    if "bluetooth" in combined:
        return "Bluetooth"
    return "Other"


def get_network_interfaces() -> list[NetworkInterfaceInfo]:
    """Discover available network adapters on the host operating system.

    Returns:
        List of discovered NetworkInterfaceInfo records with hardware categorization.
    """
    interfaces: list[NetworkInterfaceInfo] = []

    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list

            raw_list = get_windows_if_list()
            for iface in raw_list:
                name = str(iface.get("name") or "")
                desc = str(iface.get("description") or "")
                guid = str(iface.get("guid") or "")
                mac = str(iface.get("mac") or "")
                ips = tuple(
                    str(ip) for ip in iface.get("ips", []) if not str(ip).startswith("fe80::")
                )

                # Filter out noisy miniports and virtual filter drivers
                if any(ignored in desc for ignored in ("Filter", "Scheduler", "WAN Miniport")):
                    continue

                iface_type = _classify_interface_type(name, desc)
                interfaces.append(
                    NetworkInterfaceInfo(
                        name=name,
                        description=desc,
                        interface_type=iface_type,
                        ip_addresses=ips,
                        mac_address=mac,
                        guid_or_id=guid,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to retrieve Windows interface list: %s", exc)
    else:
        try:
            from scapy.all import conf

            for iface_key, iface in conf.ifaces.items():
                name = getattr(iface, "name", str(iface_key))
                desc = getattr(iface, "description", name) or name
                mac = getattr(iface, "mac", "") or ""
                ip = getattr(iface, "ip", None)
                ips = (str(ip),) if ip else ()
                iface_type = _classify_interface_type(name, desc)
                interfaces.append(
                    NetworkInterfaceInfo(
                        name=name,
                        description=desc,
                        interface_type=iface_type,
                        ip_addresses=ips,
                        mac_address=mac,
                        guid_or_id=str(iface_key),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to retrieve Unix interface list: %s", exc)

    return interfaces


def resolve_interface_name(user_input: str) -> str:
    """Resolve user-supplied interface name, IP, or GUID to an active interface.

    Args:
        user_input: User-supplied interface string (e.g., 'Wi-Fi', '192.168.0.83', '{...}').

    Returns:
        Interface identifier accepted by Scapy's sniff().

    Raises:
        ValueError: If user input is empty or no matching interface is found.
    """
    cleaned = user_input.strip()
    if not cleaned:
        raise ValueError("Interface name cannot be empty.")

    interfaces = get_network_interfaces()
    if not interfaces:
        return cleaned

    # 1. Exact match by name (case-insensitive)
    for iface in interfaces:
        if iface.name.lower() == cleaned.lower():
            return iface.name

    # 2. Match by IP address
    for iface in interfaces:
        if cleaned in iface.ip_addresses:
            return iface.name

    # 3. Match by GUID / ID
    for iface in interfaces:
        if cleaned.lower() == iface.guid_or_id.lower():
            return iface.guid_or_id

    # 4. Partial substring match in name or description
    for iface in interfaces:
        if cleaned.lower() in iface.name.lower() or cleaned.lower() in iface.description.lower():
            return iface.name

    return cleaned


def stream_live(
    interface: str | None = None,
    bpf_filter: str | None = None,
    max_packets: int | None = None,
    queue_size: int = 10_000,
    stop_event: threading.Event | None = None,
) -> Iterator[PacketRecord]:
    """Capture and stream live network packets from an authorized interface using Producer-Consumer.

    A background worker thread continuously captures raw packets via Scapy's sniff(),
    normalizes them into immutable PacketRecord objects, and places them into a bounded
    FIFO queue. The calling thread consumes packets as a generator.

    Args:
        interface: Network interface name, IP, or GUID (None for default interface).
        bpf_filter: Optional Berkeley Packet Filter (BPF) syntax (e.g., 'tcp port 80').
        max_packets: Optional maximum number of packets to capture before stopping.
        queue_size: Maximum capacity of the internal buffer to prevent memory exhaustion.
        stop_event: Optional threading.Event to signal external termination.

    Yields:
        PacketRecord for each valid IP packet captured on the interface.

    Raises:
        RuntimeError: If live capture fails to initialize (e.g. missing Npcap/libpcap or privileges).
    """
    packet_queue: queue.Queue[PacketRecord | Exception | None] = queue.Queue(maxsize=queue_size)
    local_stop_event = stop_event or threading.Event()
    resolved_iface = resolve_interface_name(interface) if interface else None

    def _sniffer_worker() -> None:
        try:

            def _packet_callback(pkt: Packet) -> None:
                if local_stop_event.is_set():
                    return
                record = _packet_to_record(pkt)
                if record is not None:
                    try:
                        packet_queue.put(record, timeout=0.5)
                    except queue.Full:
                        logger.warning(
                            "Live packet queue full (%d items); dropping packet to preserve stability.",
                            queue_size,
                        )

            from scapy.sendrecv import sniff

            sniff_kwargs: dict[str, Any] = {
                "prn": _packet_callback,
                "store": False,
                "stop_filter": lambda _: local_stop_event.is_set(),
            }
            if resolved_iface:
                sniff_kwargs["iface"] = resolved_iface
            if bpf_filter:
                sniff_kwargs["filter"] = bpf_filter
            if max_packets:
                sniff_kwargs["count"] = max_packets

            sniff(**sniff_kwargs)
        except Exception as exc:  # noqa: BLE001
            packet_queue.put(exc)
        finally:
            packet_queue.put(None)

    worker = threading.Thread(
        target=_sniffer_worker,
        daemon=True,
        name="dos-detector-live-sniffer",
    )
    worker.start()
    packets_yielded = 0

    try:
        while True:
            if local_stop_event.is_set():
                break
            try:
                item = packet_queue.get(timeout=0.2)
            except queue.Empty:
                if not worker.is_alive():
                    break
                continue

            if item is None:
                break
            if isinstance(item, Exception):
                raise RuntimeError(
                    f"Live packet capture failed: {item}. Ensure you have administrative privileges "
                    "and that Npcap/libpcap is installed and running."
                ) from item

            yield item
            packets_yielded += 1
            if max_packets is not None and packets_yielded >= max_packets:
                break
    finally:
        local_stop_event.set()
        worker.join(timeout=2.0)
