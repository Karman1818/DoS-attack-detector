---
name: testing-and-validation
description: >-
  Standardizes test-driven development (TDD), pytest test design, deterministic fixtures,
  and regression testing for network traffic analysis and detection algorithms. Use when
  authoring, expanding, or running the test suite.
---

# Testing and Validation Guidelines

This skill guides the construction and maintenance of robust, deterministic tests for `dos-attack-detector`.

---

## 1. Testing Philosophy

1. **Deterministic & Isolated**:
   - Tests must never require an active internet connection or live network interface.
   - Tests must produce identical results regardless of execution order or host platform.
2. **Fast Execution**:
   - Unit tests should execute in milliseconds using in-memory synthetic objects (`PacketRecord`, `TrafficWindow`).
   - Integration tests may verify pipeline flows or small mock PCAP streams.
3. **No Attack Traffic Generation**:
   - Tests must NOT launch sockets against `localhost` or generate live flood traffic.
   - All network traffic is represented as static objects or synthetic data streams.

---

## 2. Directory Layout & Markers

```text
tests/
├── conftest.py               # Shared deterministic fixtures
├── unit/                     # Isolated unit tests (@pytest.mark.unit)
│   ├── test_config.py
│   ├── test_models.py
│   ├── test_features.py
│   └── test_detector.py
└── integration/              # Pipeline verification (@pytest.mark.integration)
    └── test_pipeline.py
```

### Pytest Markers
- `@pytest.mark.unit`: Fast unit tests covering individual functions, edge cases, and models.
- `@pytest.mark.integration`: End-to-end component tests checking multi-stage pipeline flow.

---

## 3. Designing Network Fixtures

Always build synthetic packet records in `conftest.py` with known, controlled properties:

```python
@pytest.fixture
def synthetic_syn_flood_packets() -> list[PacketRecord]:
    """Generates 150 SYN packets without ACKs to trigger SYN flood heuristics."""
    return [
        PacketRecord(
            timestamp=1000.0 + (i * 0.005),
            src_ip="192.0.2.1",
            dst_ip="198.51.100.10",
            protocol="TCP",
            src_port=40000 + i,
            dst_port=80,
            packet_size=64,
            tcp_flags=frozenset({"SYN"}),
        )
        for i in range(150)
    ]
```

---

## 4. Test Execution Runbook

Run tests using `uv`:

```bash
# Run all tests
uv run pytest

# Run only unit tests
uv run pytest -m unit

# Run with verbose output and short traceback
uv run pytest -v --tb=short

# Run a specific test file
uv run pytest tests/unit/test_detector.py
```

---

## 5. Testing Checklist
- [ ] Edge cases tested: empty packet list, single packet, zero duration window, missing TCP flags.
- [ ] Boundary tests on thresholds: values strictly below threshold, exactly at threshold, and above threshold.
- [ ] Exception handling tested: invalid configuration arguments, corrupt packet representations.
- [ ] Test names clearly describe the scenario and expected outcome (e.g., `test_syn_flood_generates_high_severity_alert`).
