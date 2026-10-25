# GEMINI Developer & Agent Instructions: DoS Attack Detector

## 1. Project Context & Architecture
- **Project Purpose**: Defensive network traffic analysis engine designed to identify Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) patterns offline.
- **Architecture & Workflow**: Modular defensive pipeline: Ingestion (PCAP/CSV streamers) -> Feature aggregation -> Detection heuristics (and future ML) -> Alert sinks.
- **Audience**: Junior software and cybersecurity developer. When writing code, explain architectural decisions, defensive implications, and why specific patterns are chosen over alternatives.

---

## 2. Technology Stack & Python Version
- **Runtime**: Python 3.12 (managed via `uv`).
- **Dependencies**:
  - Core: `scapy` (offline packet decoding), `pandas` & `numpy` (feature calculation).
  - Dev: `pytest`, `ruff`, `mypy`, `pre-commit`.
  - ML (Optional): `scikit-learn` (for anomaly detection models).
- **Package Management**: `uv` with `pyproject.toml` and locked via `uv.lock`.

---

## 3. Architecture Boundaries & Conventions
- **Layout**: Strict `src` layout (`src/dos_detector/`).
- **Data Models**: Use immutable, frozen data structures (`@dataclass(frozen=True, slots=True)`).
- **Separation of Concerns**: Ingestion parsers produce `PacketRecord` -> aggregated by `features.py` into `TrafficWindow` -> evaluated by `detector.py` -> distributed via `alerting.py`.
- **Typing & Linting**: 100% strict type annotations. Pass `mypy` without errors. Ruff line length is 100. Flake8-bandit (`S`) security checks enabled.
- **Explaining Code**: When proposing non-trivial logic, highlight the *security rationale* and *defensive trade-offs* (e.g., distinguishing legitimate traffic spikes from SYN floods).

---

## 4. Development Commands
All commands should be executed via `uv run` to ensure virtual environment consistency:

```bash
# Sync dependencies from lockfile
uv sync --extra dev

# Run full test suite
uv run pytest

# Run only unit tests
uv run pytest -m unit

# Run linter
uv run ruff check .

# Apply automatic lint fixes
uv run ruff check --fix .

# Check code formatting
uv run ruff format --check .

# Format code
uv run ruff format .

# Run static type checker
uv run mypy src
```

---

## 5. Security & Defensive Guidelines
- **Offline Only**: Default to offline analysis of saved PCAP and CSV files. Never initiate live promiscuous network packet capture without explicit authorization and isolated lab setup.
- **No Attack Code**: Never author, generate, or execute attack simulation or packet flooding scripts against external networks or internal environments.
- **Untrusted Input**: Treat all PCAPs and CSVs as untrusted binary/tabular inputs. Never pass packet metadata into shell commands or format strings unsafely.
- **Data Hygiene**: Never commit packet captures, dataset CSVs, or sensitive network identifiers to git.
- **Explainable Detections**: Reports must label patterns as "suspected" or "anomalous" with confidence levels, noting false-positive potentials.
- **Third-Party Research**: When investigating new libraries, check PyPI releases, licensing, vulnerability advisories, and maintenance status before introducing dependencies.
