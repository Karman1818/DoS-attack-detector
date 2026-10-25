---
name: security-review
description: >-
  Provides defensive cybersecurity code review standards, dependency vulnerability vetting,
  safe input handling, and secrets management rules. Use when auditing code changes,
  adding dependencies, or reviewing PRs.
---

# Defensive Cybersecurity Code Review

This skill establishes review standards and verification steps to ensure the `dos-attack-detector` project adheres to defensive security principles.

---

## 1. Security Review Priorities

1. **Defensive Scope Integrity**:
   - Verify that all changes remain purely analytical/defensive.
   - Reject any PR or code snippet that sends unauthorized packets, creates socket flooding loops, or executes port scans against remote systems.
2. **Dependency Risk & Supply Chain**:
   - Only add dependencies from reputable, actively maintained sources on PyPI.
   - Check transitive dependencies and verify pinned versions in `uv.lock`.
   - Run automated security checks via `ruff check` (flake8-bandit rules).
3. **Input Validation & Injection Prevention**:
   - PCAPs and CSVs are untrusted inputs. File paths must be validated to prevent path traversal (`../`).
   - Packet header values (e.g., DNS queries, HTTP user agents, IP strings) must never be passed to `os.system()`, `subprocess.Popen(shell=True)`, or string-interpolated database queries.
4. **Secrets & Sensitive Data Leakage**:
   - Ensure `.env` and credential files are listed in `.gitignore`.
   - Never hardcode API keys, passwords, or internal network topology maps in source code or committed fixtures.

---

## 2. Automated Security Audits

### Bandit via Ruff
The project configuration activates flake8-bandit checks under Ruff:
```bash
# Runs Ruff including S (bandit) security checks
uv run ruff check --select S src/
```

### Dependency Audit
Check installed packages against known vulnerability databases (e.g., PyPA advisory database):
```bash
# Pip-audit or uv dependency inspection
uv run pip check
```

---

## 3. Code Review Checklist

Before approving any architectural change or PR:

- [ ] **No Privileged Operations**: Code operates without requiring elevated root/administrator permissions.
- [ ] **Offline Integrity**: Default execution path does not invoke network interfaces or outbound connections.
- [ ] **Untrusted Boundary**: Any file loading mechanism (`open()`, `rdpcap()`, `pd.read_csv()`) validates paths and catches parsing errors.
- [ ] **Memory Bounds**: Packet ingestion uses iterators or chunking for files larger than a few megabytes.
- [ ] **Sanitized Output**: Alert sinks and logs do not print confidential packet payload data.
