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
# Default mode: hybrid engine (deterministic rules + Isolation Forest anomaly fallback)
uv run dos-detector demo

# Explicitly select detector engine: 'hybrid' (default), 'base' (rules only), or 'ml' (Isolation Forest only)
uv run dos-detector demo --detector base
uv run dos-detector demo --detector ml
uv run dos-detector demo --detector hybrid
```

### Launch the Web Monitoring Dashboard & REST API
Start the embedded dark-theme SOC monitoring dashboard and FastAPI backend:
```bash
# Start server on default http://127.0.0.1:8000
uv run dos-detector serve

# Start with custom port or detector mode
uv run dos-detector serve --port 8080 --detector hybrid
```
Once started, access:
- **Interactive SOC Dashboard**: `http://127.0.0.1:8000/` (Live PPS/BPS chart, KPI anomaly cards, 1-click educational attack simulation demo, drag-and-drop PCAP/CSV upload, and real-time alert feed with XAI feature explanations)
- **OpenAPI / Swagger Documentation**: `http://127.0.0.1:8000/docs`


### Analyze an Offline PCAP/PCAPNG Capture
```bash
# Analyze using the default hybrid detector
uv run dos-detector pcap data/raw/capture.pcap --window 1.0 --syn-threshold 100.0

# Analyze using a custom trained Isolation Forest baseline model
uv run dos-detector pcap data/raw/capture.pcap --detector ml --model models/baseline.joblib
```

### Analyze a Tabular CSV Log (e.g., CIC-IDS2017)
```bash
uv run dos-detector csv data/cic_ids2017/Friday-WorkingHours.csv --cic --detector hybrid
```

### Train a Custom Isolation Forest Anomaly Detection Baseline
Fit an Isolation Forest model on known benign network traffic to establish an environment-specific baseline:
```bash
# 1. Train on benign PCAP capture
uv run dos-detector train --pcap data/raw/benign.pcap --model-out models/custom_baseline.joblib

# 2. Train on benign CIC-IDS2017 CSV flow records
uv run dos-detector train --csv data/cic_ids2017/Monday-WorkingHours.csv --cic --model-out models/cic_baseline.joblib

# 3. Train on synthetic demo baseline
uv run dos-detector train --demo --model-out models/demo_baseline.joblib
```

### Evaluate Detection Accuracy on Labeled Datasets (e.g., CIC-IDS2017)
Run the quantitative benchmark evaluation harness to compute confusion matrices, Precision, Recall, Specificity, FPR, and F1-Scores:

```bash
# 1. Run evaluation on built-in multi-vector benchmark stream (Benign, SYN Flood, HTTP Flood, UDP Flood)
uv run dos-detector evaluate --demo

# 2. Evaluate against a labeled CIC-IDS2017 CSV file with JSON export
uv run dos-detector evaluate --csv data/cic_ids2017/Wednesday-workingHours.csv --cic --export-json results.json

# 3. Evaluate an offline PCAP capture against an attack ground-truth schedule
uv run dos-detector evaluate --pcap data/cic_ids2017/Friday.pcap --schedule data/cic_ids2017/schedule.json
```

---

## 5. Quality Commands & Testing

All commands are run within the managed virtual environment using `uv run`:

```bash
# Run the test suite (64 unit and integration tests)
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
├── detector.py        # BaseDetector, RuleBasedDetector, IsolationForest, Hybrid
├── evaluation.py      # Benchmark evaluation harness, confusion matrix, CIC-IDS2017
├── features.py        # compute_window_features and SlidingWindowAggregator
├── ingestion.py       # stream_pcap and stream_csv generators
├── ml.py              # Isolation Forest baseline training & feature extraction
├── models.py          # Immutable PacketRecord, TrafficWindow, DetectionAlert
└── server.py          # FastAPI backend and embedded SOC monitoring dashboard
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
