# DoS Attack Detector

[![CI Quality Checks](https://github.com/MarceliKarman/DoS-attack-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/MarceliKarman/DoS-attack-detector/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Types: Mypy](https://img.shields.io/badge/types-mypy-blue.svg)](https://github.com/python/mypy)

A defensive, offline network traffic analysis engine built in Python for detecting Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attack patterns using configurable heuristic rules and anomaly detection.

> [!NOTE]
> **Educational & Defensive Scope**: This project is developed exclusively for defensive cybersecurity education and portfolio demonstration. It performs offline analysis on saved network capture files and synthetic test cases. It contains **no offensive capabilities** and does not generate network flood attacks.

---

## 1. Project Overview & Features

Denial-of-Service (DoS) attacks attempt to exhaust network bandwidth, server memory, or processing capacity, rendering services unavailable to legitimate users.

The **DoS Attack Detector** provides an explainable, multi-stage detection pipeline designed to inspect network traffic, compute statistical aggregations across discrete time windows, and flag anomalous signatures.

### Core Capabilities
- **Memory-Efficient Streaming**: Generator-based streaming from PCAP/PCAPNG files (via Scapy) and tabular CSV logs (supporting standard formats and CIC-IDS2017) with constant memory footprint ($O(1)$ RAM).
- **Rule-Based Heuristic Engine**:
  - **SYN Flood Detection**: Identifies disproportionate SYN packet surges lacking corresponding ACKs.
  - **Volumetric Flood Detection**: Flags bandwidth saturation exceeding configured byte thresholds.
  - **Packet-Rate Flood Detection**: Flags high-frequency packet generation threatening CPU interrupt capacity.
- **Explainable Detections**: Emits structured alerts with confidence scores and snapshot metrics rather than opaque binary alarms.
- **Interactive CLI & Demo**: Built-in demonstration runner that generates safe synthetic traffic (normal web browsing + simulated SYN flood) and displays live detection results.

---

## 2. Technology Stack

- **Runtime & Environment**: Python 3.12, managed with [uv](https://docs.astral.sh/uv/) for high-speed dependency resolution and locked virtual environments.
- **Packet & Feature Processing**: [Scapy](https://scapy.net/) (offline packet parsing), [pandas](https://pandas.pydata.org/), and [NumPy](https://numpy.org/).
- **Testing & Quality Assurance**: [pytest](https://pytest.org/) for deterministic unit/integration testing, [Ruff](https://astral.sh/ruff) for linting and formatting (including bandit security analysis), and [mypy](https://mypy-lang.org/) for strict static type checking.
- **AI-Assisted Pair Programming**: Configured with Google Antigravity and custom Agent Skills under `.agents/skills/`.

---

## 3. Installation & Setup

### Prerequisites
- Python 3.12 or newer
- [uv package manager](https://docs.astral.sh/uv/) installed:
  - **Windows (PowerShell)**:
    ```powershell
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```
  - **Linux / macOS**:
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

### Clone and Synchronize Virtual Environment
```bash
# Clone repository
git clone https://github.com/MarceliKarman/DoS-attack-detector.git
cd DoS-attack-detector

# Create virtual environment and synchronize dependencies from uv.lock
uv sync --extra dev
```

---

## 4. Usage & Quickstart

### Run the Interactive Demonstration
Generate synthetic network traffic (benign web browsing followed by an aggressive SYN flood surge) and inspect live detections:
```bash
uv run dos-detector demo
```

### Analyze an Offline PCAP/PCAPNG Capture
```bash
uv run dos-detector pcap data/raw/capture.pcap --window 1.0 --syn-threshold 100.0
```

### Analyze a Tabular CSV Log (e.g., CIC-IDS2017)
```bash
uv run dos-detector csv data/cic_ids2017/Friday-WorkingHours.csv --cic
```

---

## 5. Quality Commands & Testing

All commands are run within the managed virtual environment using `uv run`:

```bash
# Run the test suite (17 unit and integration tests)
uv run pytest -v

# Run only unit tests
uv run pytest -m unit

# Check for linting issues and security vulnerabilities (flake8-bandit)
uv run ruff check .

# Check formatting
uv run ruff format --check .

# Auto-format codebase
uv run ruff format .

# Strict static type checking
uv run mypy src
```

---

## 6. Project Architecture

The codebase follows the modern Python `src` layout:

```text
src/dos_detector/
├── __init__.py        # Package exports and version
├── alerting.py        # AlertSink protocols and console sinks
├── cli.py             # Interactive CLI entrypoint
├── config.py          # DetectionConfig thresholds
├── detector.py        # BaseDetector and RuleBasedDetector
├── features.py        # compute_window_features aggregation
├── ingestion.py       # stream_pcap and stream_csv generators
└── models.py          # Immutable PacketRecord, TrafficWindow, DetectionAlert
```

See [docs/architecture.md](docs/architecture.md) for full architectural documentation.

---

## 7. Authorized Testing Scope & Security Notice

- **No Malicious Traffic**: Do not use this repository to generate network floods, ping-of-death attacks, or spoofed TCP handshakes against external systems.
- **Untrusted Input**: Network traces must be treated as untrusted data. Avoid parsing untrusted captures on production management networks.
- **Authorized Captures Only**: Ensure any captured traffic analyzed by this engine has been obtained with authorization and scrubbed of sensitive personal identifiers.

---

## 8. License

This project is licensed under the terms of the [MIT License](LICENSE).
