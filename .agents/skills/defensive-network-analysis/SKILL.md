---
name: defensive-network-analysis
description: >-
  Provides procedures and safety guidelines for offline PCAP/CSV network traffic analysis,
  time-window aggregation, and defensive DoS/DDoS pattern detection. Use when working on
  traffic ingestion, feature extraction, and packet decoding.
---

# Defensive Network Analysis & PCAP Processing

This skill defines procedures for safe, efficient, and offline inspection of network traffic to identify Denial-of-Service attack indicators.

---

## 1. Safety & Operational Constraints

1. **Strictly Offline Processing**:
   - Use `scapy.utils.PcapReader` or `scapy.utils.rdpcap` for saved capture files (`.pcap`, `.pcapng`).
   - Do NOT use `sniff(iface=...)` or open live network interfaces unless specifically developing an authorized, isolated lab module in Stage 7.
   - Offline parsing does not require root, sudo, or Windows Administrator privileges.
2. **Untrusted Data Boundary**:
   - Treat all packet bytes as untrusted binary input.
   - Guard against malformed packets with defensive decoding (e.g., handling missing IP/TCP layers, corrupted headers, or truncated lengths).
   - Never pass packet payload strings into system command execution, file path generation, or eval statements.
3. **Privacy & Redaction**:
   - Never print or persist application payload bytes (e.g., HTTP bodies, passwords, personal data).
   - Only extract layer 3/4 structural metadata: IP addresses, transport protocols, port numbers, packet sizes, and TCP flags.

---

## 2. Ingestion & Streaming Patterns

### Memory Management for Large Captures
PCAP captures from benchmark datasets (e.g., CIC-IDS2017) can be tens of gigabytes. Reading an entire file into memory using `rdpcap()` will cause `MemoryError` or process termination.

**Recommended Streaming Pattern**:
```python
from collections.abc import Iterator
from scapy.utils import PcapReader
from dos_detector.models import PacketRecord


def stream_pcap(file_path: str) -> Iterator[PacketRecord]:
    """Stream packets one-by-one from a PCAP file without exhausting RAM."""
    with PcapReader(file_path) as reader:
        for raw_pkt in reader:
            record = normalize_packet(raw_pkt)
            if record is not None:
                yield record
```

---

## 3. DoS Traffic Indicators & Heuristics

When evaluating traffic metrics across discrete time windows (`TrafficWindow`):

| Attack Pattern | Key Signatures | Heuristic Metric |
| :--- | :--- | :--- |
| **TCP SYN Flood** | Rapid succession of SYN packets with no ACKs | High `syn_count`, high `syn_pps`, high `syn_ack_ratio` |
| **Volumetric UDP/ICMP Flood** | High bandwidth saturation overwhelming link | High `byte_rate` (bps), large uniform payload sizes |
| **High Packet-Rate Flood** | Overwhelming destination CPU interrupts | High `packet_rate` (pps) with small packet sizes |
| **Port Scan / Reconnaissance** | Single source probing many ports | High `unique_dst_ports` from single `src_ip` |

---

## 4. Analysis Checklist
- [ ] Ingestion logic checks whether the input file exists and handles empty/corrupt files gracefully.
- [ ] Packets missing IP or TCP headers (e.g., ARP, raw Ethernet) are filtered or handled without crashing.
- [ ] Time-window calculations accommodate clock skew or non-strictly-monotonic timestamps.
- [ ] Alerts include explanatory context and confidence levels rather than asserting definitive guilt.
