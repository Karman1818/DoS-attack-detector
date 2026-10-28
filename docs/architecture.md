# DoS Attack Detector: Architecture Documentation

This document outlines the software architecture, data flow, design principles, and planned extension points for the **DoS Attack Detector** project.

---

## 1. System Overview & Core Philosophy

The primary objective of this project is to analyze network traffic offline and identify patterns indicative of Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks.

### Key Architectural Principles

1. **Defensive by Design**: The tool solely inspects traffic defensively. It does not generate attack traffic, probe remote networks, or execute defensive counter-attacks.
2. **Offline-First & Unprivileged**: Analysis runs on saved PCAP and CSV files. Parsing relies on pure file decoding rather than promiscuous network driver hooks (e.g., Npcap/WinPcap), requiring no root or administrator privileges.
3. **Decoupled Pipeline**: Raw ingestion (PCAP/CSV) is strictly separated from feature computation, detection heuristics, and alert reporting:
   `strumień pakietów ➔ SlidingWindowAggregator ➔ strumień okien ➔ Detektor ➔ AlertSink`
4. **Explainable Detections**: The engine does not emit opaque boolean alarms. It emits structured alerts containing observed metrics, applied rules, Shannon entropy distribution confidence, and explanatory notes.
5. **Deterministic Immutability**: Core domain models (`PacketRecord`, `TrafficWindow`) are immutable value objects (`frozen=True`). This guarantees data integrity as records flow through multi-stage pipelines.

---

## 2. Pipeline Data Flow

The following diagram illustrates how raw network traces are transformed into defensive alerts:

```mermaid
flowchart TD
    A["Raw Input Source\n(PCAP, PCAPNG, CSV)"] --> B["Packet Ingestion / Streamer\n(stream_pcap / stream_csv)"]
    B --> C["Normalized Packet Stream\n(Iterator of PacketRecord)"]
    C --> D["Sliding Window Aggregator\n(SlidingWindowAggregator)"]
    D --> E["Sliding Window Snapshots\n(Iterator of TrafficWindow)"]
    E --> F["Detection Engine\n(RuleBasedDetector / ML Models)"]
    F --> G["Structured Alerts\n(DetectionAlert)"]
    G --> H["Alert Distribution Sink\n(InMemory / Console / SIEM)"]
```

---

## 3. Module Breakdown & Responsibilities

The codebase follows the modern Python `src` layout (`src/dos_detector/`):

### `models.py` (Domain Core)
- **`PacketRecord`**: Normalized representation of a single network packet (timestamp, IPs, protocol, ports, size, TCP flags). Shields the rest of the application from parser quirks.
- **`TrafficWindow`**: Aggregated metrics computed over an observation window (packet rates, byte rates, SYN/ACK ratios, protocol breakdowns [TCP/UDP/ICMP/DNS], victim target concentration ratios [top destination IP/port], unique IPs, Shannon entropy, top source IP metrics).
- **`Severity`**: Standardized enum (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **`DetectionAlert`**: Encapsulates a detected anomaly with metadata, confidence score, attack type (`SINGLE_SOURCE_DOS`, `COORDINATED_DOS`, `DISTRIBUTED_DOS`), and supporting metrics snapshot.

### `config.py` (Configurable Parameters)
- Defines `DetectionConfig`. Externalizes threshold configuration (window size, step size, SYN rates, volumetric bps, packet flood pps, DNS flood pps, target concentration ratio, `min_consecutive_windows` persistence, and `alert_cooldown_seconds`).

### `features.py` (Feature Engineering & Windowing)
- **`SlidingWindowAggregator`**: FIFO queue (`deque`) generating overlapping sliding windows from an input packet stream with configurable `window_size` and `step_size`. Handles chronological fast-paths, out-of-order jitter with `bisect.insort`, and large time gap jump optimizations.
- **`stream_sliding_windows`**: Generator function connecting packet iterables to sliding windows.
- **`compute_shannon_entropy`**: Shannon entropy and normalized entropy (0.0 to 1.0) calculation on IP distributions.
- **`compute_window_features`**: Pure function calculating rates, flag distributions, protocol breakdowns, victim target concentration, and entropy metrics for a batch of records.

### `ml.py` (Machine Learning & Isolation Forest Anomaly Detection)
- **`FEATURE_NAMES` & `extract_window_features`**: Transforms an immutable `TrafficWindow` into a sanitized 10-dimensional numerical feature vector for tree-based anomaly isolation.
- **`train_isolation_forest`**: Unsupervised baseline profiling fitting scikit-learn's `IsolationForest` on legitimate benign traffic.
- **Model Persistence**: Safe artifact serialization and deserialization via `joblib`.
- **`get_default_baseline_model`**: Automatic cached baseline model providing out-of-the-box ML anomaly detection without requiring prior manual model training.

### `detector.py` (Detection Logic)
- Implements `BaseDetector` (Abstract Base Class).
- **`classify_attack_distribution`**: Classifies whether an anomaly is single-source DoS, coordinated DoS, distributed DDoS, or benign multi-target transit traffic (`DISTRIBUTED_TRANSIT_TRAFFIC`) by coupling Shannon entropy with victim target concentration.
- **`RuleBasedDetector` (`base`)**: Evaluates deterministic heuristics against a `TrafficWindow` (DNS amplification/flood, UDP flood, TCP SYN flood, HTTP WebDDoS, volumetric flood, and subsumed packet flood) with sliding window persistence (`min_consecutive_windows`) and cooldown deduplication.
- **`IsolationForestDetector` (`ml`)**: Evaluates multidimensional feature divergences from the baseline, scoring anomalies and explaining which metrics triggered the alert (`_explain_anomalous_features`).
- **`HybridDetector` (`hybrid`)**: Ensemble engine combining high-precision rule heuristics with an unsupervised Isolation Forest fallback for low-rate and novel anomalies.

### `alerting.py` (Output Abstraction)
- Defines `AlertSink` protocol.
- `InMemoryAlertSink`: Stores alerts for automated testing and batch verification.
- `ConsoleAlertSink`: Formats defensive summaries safely without printing raw packet payloads.

### `evaluation.py` (Benchmark & Dataset Evaluation Harness)
- **`GroundTruthInterval` & `AttackSchedule`**: Model external attack schedules and time intervals for raw captures (e.g., CIC-IDS2017 PCAP files).
- **`EvaluationMetrics`**: Computes standard cybersecurity detection metrics: True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision, Recall, Specificity, False Positive Rate (FPR), Accuracy, and F1-Score.
- **`DatasetEvaluator`**: End-to-end evaluation runner streaming labeled CSV flows or PCAPs, tracking confusion matrices, per-attack recall breakdown, and JSON export.
- **`generate_synthetic_benchmark_stream`**: Deterministic multi-phase benchmark generator (Benign baseline + SYN flood + HTTP WebDDoS + UDP flood) for testing and educational validation without multi-gigabyte downloads.

### `server.py` (FastAPI Monitoring Backend & SOC Dashboard)
- **REST API Endpoints**:
  - `GET /`: Serves the embedded HTML5/CSS/JavaScript SOC dashboard.
  - `GET /api/health`: Provides detector health, active detection mode, telemetry counters, and version info.
  - `GET /api/config` & `POST /api/config`: Dynamic runtime inspection and reconfiguration of detection thresholds and detector modes (`hybrid`, `base`, `ml`).
  - `POST /api/model/upload` & `POST /api/model/reset`: Allows uploading custom serialized `.joblib` Isolation Forest models and dynamically hot-swapping the active engine, or resetting to the built-in reference baseline.
  - `POST /api/analyze/demo`: Evaluates synthetic multi-phase educational traffic and returns timeline series data with triggered alert tags.
  - `POST /api/analyze/upload`: Safely ingests uploaded offline capture files (`.pcap`, `.pcapng`, `.csv`), buffers them into temporary files, evaluates windows, and unlinks files immediately upon completion.
  - `GET /api/alerts` & `POST /api/alerts/clear`: Fetches historical alerts and resets state.
- **Embedded SOC Dashboard**:
  - Responsive dark-theme dashboard designed for SOC/CERT analysts.
  - Interactive Chart.js timeline showing packet rates (PPS), bandwidth (BPS), and shaded anomaly zones.
  - Drag-and-drop offline capture file upload with format validation.
  - Real-time alert feed displaying attack classification (Single-source DoS vs DDoS), severity tags, and explainable AI feature contribution badges.

---

## 4. Planned Extension Points & Roadmap

The architecture is designed to accommodate planned enhancements without requiring rewrites:

```mermaid
flowchart LR
    W["TrafficWindow"] --> R["Rule-Based Engine\n(RuleBasedDetector)"]
    W --> M["Machine Learning Engine\n(Isolation Forest)"]
    R --> S["AlertSink Protocol"]
    M --> S
    S --> C["Console Sink"]
    S --> J["JSON Telemetry Sink"]
    S --> API["FastAPI Web Dashboard"]
    S --> SIEM["SIEM Forwarder\n(CEF / Syslog RFC 5424)"]
```

1. **[Completed] Benchmark Evaluation**: Quantitative evaluation harness measuring precision, recall, and false positives on CIC-IDS2017 and multi-phase synthetic benchmarks.
2. **[Completed] Machine-Learning Anomaly Detection**: Unsupervised Isolation Forest baseline profiling with Explainable AI (XAI) feature divergence tagging.
3. **[Completed] Web Dashboard & FastAPI Backend**: Interactive single-page SOC monitoring dashboard and REST API served via Uvicorn.
4. **[Planned Final Step] SIEM Integration & Alert Sinks**: Standardized Common Event Format (CEF) and Syslog (RFC 5424) export forwarder for enterprise SIEM ingestion (e.g., Splunk, Microsoft Sentinel, Wazuh).
