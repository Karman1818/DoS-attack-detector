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
from dos_detector.detector import (
    BaseDetector,
    HybridDetector,
    IsolationForestDetector,
    RuleBasedDetector,
)
from dos_detector.evaluation import (
    DatasetEvaluator,
    generate_synthetic_benchmark_stream,
)
from dos_detector.features import SlidingWindowAggregator
from dos_detector.ingestion import (
    CIC_IDS2017_CSV_MAPPING,
    stream_csv,
    stream_pcap,
)
from dos_detector.ml import (
    get_default_baseline_model,
    load_model,
    save_model,
    train_isolation_forest,
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


def _build_detection_config(args: argparse.Namespace) -> DetectionConfig:
    """Construct DetectionConfig from parsed CLI arguments."""
    raw_mode = getattr(args, "detector", "hybrid")
    detector_mode = "base" if raw_mode == "rule" else raw_mode

    return DetectionConfig(
        window_size_seconds=args.window,
        syn_flood_pps_threshold=args.syn_threshold,
        packet_flood_pps_threshold=args.pps_threshold,
        dns_flood_pps_threshold=args.dns_threshold,
        http_flood_pps_threshold=args.http_threshold,
        min_consecutive_windows=args.min_consecutive,
        alert_cooldown_seconds=args.cooldown,
        detector_mode=detector_mode,
        ml_model_path=getattr(args, "model", None),
    )


def _build_detector(
    config: DetectionConfig,
    model_path: str | Path | None = None,
) -> tuple[BaseDetector, str, str]:
    """Create configured detector instance and return (detector, mode_label, model_description)."""
    mode = config.detector_mode.lower()
    if mode == "rule":
        mode = "base"

    model_desc = "Built-in reference baseline (Isolation Forest)"
    ml_model = None
    if mode in ("ml", "hybrid"):
        target_path = model_path or config.ml_model_path
        if target_path:
            ml_model = load_model(target_path)
            model_desc = f"Custom model ({Path(target_path).name})"
        else:
            ml_model = get_default_baseline_model()

    if mode == "base":
        return RuleBasedDetector(config=config), "base", "N/A (Rule-based heuristics)"
    elif mode == "ml":
        return IsolationForestDetector(model=ml_model, config=config), "ml", model_desc
    elif mode == "hybrid":
        rule_det = RuleBasedDetector(config=config)
        ml_det = IsolationForestDetector(model=ml_model, config=config)
        return (
            HybridDetector(rule_detector=rule_det, ml_detector=ml_det, config=config),
            "hybrid",
            model_desc,
        )
    else:
        msg = f"Unknown detector mode: {mode}"
        raise ValueError(msg)


def _process_packet_stream(
    packet_stream: Iterable[PacketRecord],
    config: DetectionConfig,
    source_desc: str,
    step_size: float = 0.2,
) -> None:
    """Run sliding window feature extraction and detection engine on packet stream."""
    sink = ConsoleAlertSink()
    detector, mode_label, model_desc = _build_detector(config, model_path=config.ml_model_path)
    aggregator = SlidingWindowAggregator(
        window_size=config.window_size_seconds,
        step_size=step_size,
    )

    print("\n" + "=" * 88)
    print(f"[*] Analyzing Network Traffic Source: {source_desc}")
    print(f"[*] Running analysis with [{mode_label}] detector engine")
    if mode_label in ("ml", "hybrid"):
        print(f"[*] ML Anomaly Model: {model_desc}")
    print(
        f"[*] Observation Horizon: Window={config.window_size_seconds}s (step={step_size}s) | "
        f"Min Consecutive={config.min_consecutive_windows} | "
        f"Alert Cooldown={config.alert_cooldown_seconds}s"
    )
    if mode_label in ("base", "hybrid"):
        print("[*] Active Detection Engine Thresholds (Prioritized by Attack Specificity):")
        print(
            "+---------------------------+---------------+------------------------------------------+"
        )
        print(
            "| Heuristic Rule            | Threshold     | Trigger Condition                        |"
        )
        print(
            "+---------------------------+---------------+------------------------------------------+"
        )
        print(
            f"| DNS Flood (L4/L7)         | >= {config.dns_flood_pps_threshold:.0f} pps    | Port 53 UDP/TCP | DRDoS Amplification    |"
        )
        print(
            f"| HTTP WebDDoS (L7)         | >= {config.http_flood_pps_threshold:.0f} req/s   | Ports 80/8080 | URI Repetition >= {config.http_uri_repetition_threshold * 100:.0f}%   |"
        )
        print(
            f"| TCP SYN Flood (L4)        | >= {config.syn_flood_pps_threshold:.0f} pps    | SYN/ACK >= {config.syn_ack_ratio_threshold:.1f} OR (>=500 pps & SYN>=70%) |"
        )
        print(
            f"| UDP Flood (General)       | >= {config.udp_flood_pps_threshold:.0f} pps   | UDP Ratio >= {config.udp_ratio_threshold * 100:.0f}% (non-DNS fallback)      |"
        )
        print(
            f"| Volumetric Throughput     | >= {config.volumetric_bps_threshold / 1_000_000:.1f} MB/s  | Bandwidth byte flood fallback            |"
        )
        print(
            f"| Packet Rate Flood (Gen)   | >= {config.packet_flood_pps_threshold:.0f} pps   | Focused packet flood fallback            |"
        )
        print(
            "+---------------------------+---------------+------------------------------------------+"
        )
    elif mode_label == "ml":
        print("[*] Unsupervised Multidimensional Anomaly Profiling Active (10 features)")
    print("=" * 88 + "\n")

    total_packets_inspected = 0
    total_alerts_emitted = 0

    def _counted_packets() -> Iterable[PacketRecord]:
        nonlocal total_packets_inspected
        for pkt in packet_stream:
            total_packets_inspected += 1
            yield pkt

    for window in aggregator.aggregate(_counted_packets()):
        alerts = detector.evaluate_window(window)
        for alert in alerts:
            total_alerts_emitted += 1
            sink.emit(alert)

    print("\n" + "-" * 75)
    print(f"[+] Analysis Complete: {total_packets_inspected} packets evaluated.")
    if total_alerts_emitted > 0:
        print(f"[!] Detections: {total_alerts_emitted} suspicious event(s) flagged.")
    else:
        print("[+] Detections: No anomalies found. Traffic profile is balanced.")
    print("-" * 75 + "\n")


def cmd_demo(args: argparse.Namespace) -> None:
    """Run an educational offline synthetic traffic demonstration."""
    sample_file = Path("data/samples/demo_attack.pcap")
    print(f"[*] Generating educational sample capture at: {sample_file} ...")
    count = _generate_synthetic_demo_pcap(sample_file)
    print(f"[+] Generated {count} synthetic packets (normal web browsing + simulated SYN flood).")

    config = _build_detection_config(args)
    _process_packet_stream(
        stream_pcap(sample_file),
        config,
        str(sample_file),
        step_size=args.step,
    )


def cmd_pcap(args: argparse.Namespace) -> None:
    """Analyze a local PCAP or PCAPNG capture file."""
    pcap_path = Path(args.file)
    if not pcap_path.is_file():
        print(f"[ERROR] File not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    config = _build_detection_config(args)
    _process_packet_stream(
        stream_pcap(pcap_path),
        config,
        str(pcap_path),
        step_size=args.step,
    )


def cmd_csv(args: argparse.Namespace) -> None:
    """Analyze a local CSV traffic file."""
    csv_path = Path(args.file)
    if not csv_path.is_file():
        print(f"[ERROR] File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    config = _build_detection_config(args)
    mapping = CIC_IDS2017_CSV_MAPPING if args.cic else None
    _process_packet_stream(
        stream_csv(csv_path, mapping=mapping),
        config,
        str(csv_path),
        step_size=args.step,
    )


def cmd_evaluate(args: argparse.Namespace) -> None:
    """Evaluate detector against labeled datasets (e.g., CIC-IDS2017) or synthetic benchmarks."""
    config = _build_detection_config(args)
    detector, mode_label, model_desc = _build_detector(config, model_path=config.ml_model_path)
    evaluator = DatasetEvaluator(
        detector=detector,
        window_size=config.window_size_seconds,
        step_size=args.step,
    )

    print(f"\n[*] Running evaluation with [{mode_label}] detector engine")
    if mode_label in ("ml", "hybrid"):
        print(f"[*] ML Anomaly Model: {model_desc}")

    if args.demo:
        print("[*] Generating and evaluating on synthetic multi-vector benchmark stream...")
        stream = generate_synthetic_benchmark_stream()
        metrics = evaluator.evaluate_stream(stream)
        title = "Synthetic Multi-Vector Benchmark Evaluation Report"
    elif args.csv:
        csv_path = Path(args.csv)
        if not csv_path.is_file():
            print(f"[ERROR] CSV file not found: {csv_path}", file=sys.stderr)
            sys.exit(1)
        mapping = CIC_IDS2017_CSV_MAPPING if args.cic else None
        print(f"[*] Evaluating detector on labeled CSV: {csv_path} ...")
        metrics = evaluator.evaluate_csv(csv_path, mapping=mapping)
        title = f"Dataset Benchmark Evaluation Report: {csv_path.name}"
    elif args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.is_file():
            print(f"[ERROR] PCAP file not found: {pcap_path}", file=sys.stderr)
            sys.exit(1)
        schedule_path = Path(args.schedule) if args.schedule else None
        if schedule_path and not schedule_path.is_file():
            print(f"[ERROR] Schedule file not found: {schedule_path}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Evaluating detector on PCAP: {pcap_path} ...")
        metrics = evaluator.evaluate_pcap(pcap_path, schedule_path=schedule_path)
        title = f"PCAP Evaluation Report: {pcap_path.name}"
    else:
        print(
            "[ERROR] Specify an input source: --demo, --csv <file>, or --pcap <file>",
            file=sys.stderr,
        )
        sys.exit(1)

    print(metrics.render_ascii_report(title=title))

    if args.export_json:
        export_path = Path(args.export_json)
        metrics.export_json(export_path)
        print(f"[+] Exported evaluation metrics JSON to: {export_path}")


def cmd_train(args: argparse.Namespace) -> None:
    """Train an Isolation Forest baseline model on benign traffic."""
    model_out = Path(args.model_out)
    aggregator = SlidingWindowAggregator(
        window_size=args.window,
        step_size=args.step,
    )

    if args.demo:
        print("[*] Generating synthetic benign baseline traffic for training...")
        packets = [p for p in generate_synthetic_benchmark_stream() if p.label == "BENIGN"]
    elif args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.is_file():
            print(f"[ERROR] PCAP file not found: {pcap_path}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Streaming packets from benign PCAP: {pcap_path} ...")
        packets = list(stream_pcap(pcap_path))
    elif args.csv:
        csv_path = Path(args.csv)
        if not csv_path.is_file():
            print(f"[ERROR] CSV file not found: {csv_path}", file=sys.stderr)
            sys.exit(1)
        mapping = CIC_IDS2017_CSV_MAPPING if args.cic else None
        print(f"[*] Streaming packets from CSV: {csv_path} ...")
        raw_stream = stream_csv(csv_path, mapping=mapping)
        packets = [
            p
            for p in raw_stream
            if p.label is None or p.label.strip().upper() in {"BENIGN", "NORMAL", "0"}
        ]
    else:
        print(
            "[ERROR] Specify training input: --demo, --pcap <file>, or --csv <file>",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Aggregating {len(packets):,} packets into observation windows...")
    windows = list(aggregator.aggregate(packets))

    if len(windows) < 2:
        print(
            f"[ERROR] Insufficient observation windows generated ({len(windows)}). At least 2 required.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"[*] Training Isolation Forest on {len(windows):,} windows "
        f"(contamination={args.contamination}, estimators={args.estimators}) ..."
    )
    model = train_isolation_forest(
        windows=windows,
        contamination=args.contamination,
        n_estimators=args.estimators,
    )

    save_model(model, model_out)
    print(f"[+] Successfully trained and saved Isolation Forest model to: {model_out}\n")


def _add_common_detection_args(subparser: argparse.ArgumentParser) -> None:
    """Register common detection threshold and window flags across CLI subcommands."""
    subparser.add_argument(
        "--detector",
        choices=["hybrid", "base", "rule", "ml"],
        default="hybrid",
        help="Detection engine: 'hybrid' (rules + ML fallback, default), 'base' (rules only), 'ml' (Isolation Forest only)",
    )
    subparser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Path to custom trained Isolation Forest .joblib model (defaults to built-in baseline)",
    )
    subparser.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Time window size in seconds (default: 1.0)",
    )
    subparser.add_argument(
        "--step",
        type=float,
        default=0.2,
        help="Sliding step size in seconds (default: 0.2)",
    )
    subparser.add_argument(
        "--syn-threshold",
        type=float,
        default=100.0,
        help="SYN packets per second threshold (default: 100.0)",
    )
    subparser.add_argument(
        "--pps-threshold",
        type=float,
        default=1000.0,
        help="General packet flood threshold in pps (default: 1000.0)",
    )
    subparser.add_argument(
        "--dns-threshold",
        type=float,
        default=500.0,
        help="DNS packet flood threshold in pps (default: 500.0)",
    )
    subparser.add_argument(
        "--http-threshold",
        type=float,
        default=30.0,
        help="HTTP application request flood threshold in req/s (default: 30.0)",
    )
    subparser.add_argument(
        "--min-consecutive",
        type=int,
        default=1,
        help="Minimum consecutive violating windows before alerting (default: 1)",
    )
    subparser.add_argument(
        "--cooldown",
        type=float,
        default=1.0,
        help="Alert cooldown in seconds to suppress duplicate alerts (default: 1.0)",
    )


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
    _add_common_detection_args(parser_demo)
    parser_demo.set_defaults(func=cmd_demo)

    # Subcommand: pcap
    parser_pcap = subparsers.add_parser("pcap", help="Analyze an offline PCAP/PCAPNG file.")
    parser_pcap.add_argument("file", help="Path to PCAP capture file.")
    _add_common_detection_args(parser_pcap)
    parser_pcap.set_defaults(func=cmd_pcap)

    # Subcommand: csv
    parser_csv = subparsers.add_parser("csv", help="Analyze an offline CSV traffic file.")
    parser_csv.add_argument("file", help="Path to CSV file.")
    parser_csv.add_argument(
        "--cic",
        action="store_true",
        help="Use CIC-IDS2017 dataset column mapping format.",
    )
    _add_common_detection_args(parser_csv)
    parser_csv.set_defaults(func=cmd_csv)

    # Subcommand: evaluate
    parser_eval = subparsers.add_parser(
        "evaluate",
        help="Evaluate detector performance against labeled datasets or synthetic benchmarks.",
    )
    parser_eval.add_argument(
        "--csv",
        help="Path to labeled CSV dataset (e.g., CIC-IDS2017).",
    )
    parser_eval.add_argument(
        "--cic",
        action="store_true",
        help="Use CIC-IDS2017 dataset column mapping format.",
    )
    parser_eval.add_argument(
        "--pcap",
        help="Path to PCAP capture file.",
    )
    parser_eval.add_argument(
        "--schedule",
        help="Path to attack schedule JSON file defining ground truth intervals for PCAP.",
    )
    parser_eval.add_argument(
        "--demo",
        "--benchmark-demo",
        dest="demo",
        action="store_true",
        help="Run evaluation on built-in multi-phase benchmark stream (Benign + SYN + HTTP + UDP floods).",
    )
    parser_eval.add_argument(
        "--export-json",
        help="Path to export evaluation metrics and confusion matrix to JSON.",
    )
    _add_common_detection_args(parser_eval)
    # Default cooldown to 0.0s for evaluation so individual window classification is not suppressed
    parser_eval.set_defaults(cooldown=0.0, func=cmd_evaluate)

    # Subcommand: train
    parser_train = subparsers.add_parser(
        "train",
        help="Train an Isolation Forest anomaly detection model on benign network traffic.",
    )
    parser_train.add_argument("--pcap", help="Path to benign PCAP capture file.")
    parser_train.add_argument("--csv", help="Path to benign CSV file (e.g. CIC-IDS2017).")
    parser_train.add_argument(
        "--cic",
        action="store_true",
        help="Use CIC-IDS2017 dataset column mapping format.",
    )
    parser_train.add_argument(
        "--demo",
        action="store_true",
        help="Generate synthetic benign traffic for demo model training.",
    )
    parser_train.add_argument(
        "--model-out",
        required=True,
        help="Destination path for the trained model artifact (e.g. models/baseline.joblib).",
    )
    parser_train.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="Expected contamination / outlier ratio in training data (default: 0.01).",
    )
    parser_train.add_argument(
        "--estimators",
        type=int,
        default=100,
        help="Number of isolation trees in the forest (default: 100).",
    )
    parser_train.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Time window size in seconds (default: 1.0).",
    )
    parser_train.add_argument(
        "--step",
        type=float,
        default=0.2,
        help="Sliding step size in seconds (default: 0.2).",
    )
    parser_train.set_defaults(func=cmd_train)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
