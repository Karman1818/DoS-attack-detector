"""Command-line interface (CLI) for DoS Attack Detector.

Provides interactive commands to analyze saved PCAP/CSV captures or run an
educational synthetic traffic demonstration.
"""

import argparse
import io
import sys
from collections.abc import Iterable
from pathlib import Path

# Temporarily silence Scapy's Npcap service warnings on Windows during import
_old_stderr = sys.stderr
try:
    sys.stderr = io.StringIO()
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap
finally:
    sys.stderr = _old_stderr

from dos_detector import __version__
from dos_detector.alerting import ConsoleAlertSink
from dos_detector.config import DetectionConfig
from dos_detector.detector import RuleBasedDetector
from dos_detector.features import compute_window_features
from dos_detector.ingestion import (
    CIC_IDS2017_CSV_MAPPING,
    stream_csv,
    stream_pcap,
)
from dos_detector.models import PacketRecord


def _generate_synthetic_demo_pcap(target_path: Path) -> int:
    """Generate a safe, synthetic offline PCAP file containing benign traffic and a SYN flood."""
    packets = []
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")

    # Phase 1: 5 seconds of normal web/DNS browsing (timestamps 1000.0s - 1005.0s)
    current_time = 1000.0
    for i in range(50):
        current_time += 0.1
        # Balanced HTTP traffic (SYN followed by ACK)
        packets.append(
            eth
            / IP(src=f"192.168.1.{10 + (i % 5)}", dst="93.184.216.34")
            / TCP(sport=50000 + i, dport=80, flags="S")
        )
        packets[-1].time = current_time

        packets.append(
            eth
            / IP(src="93.184.216.34", dst=f"192.168.1.{10 + (i % 5)}")
            / TCP(sport=80, dport=50000 + i, flags="SA")
        )
        packets[-1].time = current_time + 0.02

        packets.append(
            eth
            / IP(src=f"192.168.1.{10 + (i % 5)}", dst="93.184.216.34")
            / TCP(sport=50000 + i, dport=80, flags="A")
        )
        packets[-1].time = current_time + 0.04

        # Occasional DNS query
        packets.append(
            eth
            / IP(src=f"192.168.1.{10 + (i % 5)}", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
        )
        packets[-1].time = current_time + 0.05

    # Phase 2: Sudden 1-second burst of high-rate TCP SYN flood (timestamps 1005.0s - 1006.0s)
    # 250 unacknowledged SYN packets from random source IPs targeting port 80
    flood_time = 1005.0
    for i in range(250):
        flood_time += 0.004  # ~250 packets per second
        spoofed_src = f"198.51.100.{1 + (i % 254)}"
        packets.append(
            eth
            / IP(src=spoofed_src, dst="192.168.1.10")
            / TCP(sport=30000 + i, dport=80, flags="S")
        )
        packets[-1].time = flood_time

    # Phase 3: Traffic returns to normal low baseline (timestamps 1006.0s - 1008.0s)
    return_time = 1006.0
    for i in range(20):
        return_time += 0.1
        packets.append(
            eth
            / IP(src="192.168.1.15", dst="93.184.216.34")
            / TCP(sport=52000 + i, dport=80, flags="S")
        )
        packets[-1].time = return_time

    target_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target_path), packets)
    return len(packets)


def _process_packet_stream(
    packet_stream: Iterable[PacketRecord],
    config: DetectionConfig,
    source_desc: str,
) -> None:
    """Run window feature extraction and detection engine on packet stream."""
    sink = ConsoleAlertSink()
    detector = RuleBasedDetector(config=config)

    print("\n" + "=" * 70)
    print(f"[*] Analyzing Network Traffic Source: {source_desc}")
    print(
        f"[*] Window Size: {config.window_size_seconds}s | SYN Flood Threshold: {config.syn_flood_pps_threshold} pps"
    )
    print("=" * 70 + "\n")

    current_window_packets: list[PacketRecord] = []
    window_start: float | None = None
    total_packets_inspected = 0
    total_alerts_emitted = 0

    for pkt in packet_stream:
        total_packets_inspected += 1
        if window_start is None:
            window_start = pkt.timestamp

        # Check if packet exceeds current time window
        if pkt.timestamp - window_start >= config.window_size_seconds:
            window_end = window_start + config.window_size_seconds
            window = compute_window_features(current_window_packets, window_start, window_end)

            alerts = detector.evaluate_window(window)
            for alert in alerts:
                total_alerts_emitted += 1
                sink.emit(alert)

            # Advance window
            current_window_packets = [pkt]
            window_start = pkt.timestamp
        else:
            current_window_packets.append(pkt)

    # Process final window
    if current_window_packets and window_start is not None:
        window_end = max(window_start + 0.001, current_window_packets[-1].timestamp)
        window = compute_window_features(current_window_packets, window_start, window_end)
        alerts = detector.evaluate_window(window)
        for alert in alerts:
            total_alerts_emitted += 1
            sink.emit(alert)

    print("\n" + "-" * 70)
    print(f"[+] Analysis Complete: {total_packets_inspected} packets evaluated.")
    if total_alerts_emitted > 0:
        print(f"[!] Detections: {total_alerts_emitted} suspicious event(s) flagged.")
    else:
        print("[+] Detections: No anomalies found. Traffic profile is balanced.")
    print("-" * 70 + "\n")


def cmd_demo(args: argparse.Namespace) -> None:
    """Run an educational offline synthetic traffic demonstration."""
    sample_file = Path("data/samples/demo_attack.pcap")
    print(f"[*] Generating educational sample capture at: {sample_file} ...")
    count = _generate_synthetic_demo_pcap(sample_file)
    print(f"[+] Generated {count} synthetic packets (normal web browsing + simulated SYN flood).")

    config = DetectionConfig(
        window_size_seconds=args.window,
        syn_flood_pps_threshold=args.syn_threshold,
    )
    _process_packet_stream(stream_pcap(sample_file), config, str(sample_file))


def cmd_pcap(args: argparse.Namespace) -> None:
    """Analyze a local PCAP or PCAPNG capture file."""
    pcap_path = Path(args.file)
    if not pcap_path.is_file():
        print(f"[ERROR] File not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    config = DetectionConfig(
        window_size_seconds=args.window,
        syn_flood_pps_threshold=args.syn_threshold,
    )
    _process_packet_stream(stream_pcap(pcap_path), config, str(pcap_path))


def cmd_csv(args: argparse.Namespace) -> None:
    """Analyze a local CSV traffic file."""
    csv_path = Path(args.file)
    if not csv_path.is_file():
        print(f"[ERROR] File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    config = DetectionConfig(
        window_size_seconds=args.window,
        syn_flood_pps_threshold=args.syn_threshold,
    )
    mapping = CIC_IDS2017_CSV_MAPPING if args.cic else None
    _process_packet_stream(stream_csv(csv_path, mapping=mapping), config, str(csv_path))


def main() -> None:
    """CLI entry point for dos-detector."""
    parser = argparse.ArgumentParser(
        prog="dos-detector",
        description="Defensive offline network traffic analyzer for Denial-of-Service (DoS) patterns.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: demo
    parser_demo = subparsers.add_parser(
        "demo",
        help="Generate synthetic network traffic and demonstrate live detection.",
    )
    parser_demo.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Time window size in seconds (default: 1.0)",
    )
    parser_demo.add_argument(
        "--syn-threshold",
        type=float,
        default=100.0,
        help="SYN packets per second threshold (default: 100.0)",
    )
    parser_demo.set_defaults(func=cmd_demo)

    # Subcommand: pcap
    parser_pcap = subparsers.add_parser("pcap", help="Analyze an offline PCAP/PCAPNG file.")
    parser_pcap.add_argument("file", help="Path to PCAP capture file.")
    parser_pcap.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Time window size in seconds (default: 1.0)",
    )
    parser_pcap.add_argument(
        "--syn-threshold",
        type=float,
        default=100.0,
        help="SYN packets per second threshold (default: 100.0)",
    )
    parser_pcap.set_defaults(func=cmd_pcap)

    # Subcommand: csv
    parser_csv = subparsers.add_parser("csv", help="Analyze an offline CSV traffic file.")
    parser_csv.add_argument("file", help="Path to CSV file.")
    parser_csv.add_argument(
        "--cic",
        action="store_true",
        help="Use CIC-IDS2017 dataset column mapping format.",
    )
    parser_csv.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Time window size in seconds (default: 1.0)",
    )
    parser_csv.add_argument(
        "--syn-threshold",
        type=float,
        default=100.0,
        help="SYN packets per second threshold (default: 100.0)",
    )
    parser_csv.set_defaults(func=cmd_csv)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
