# Data Directory Guidelines

This directory is reserved for local, offline traffic capture files (`.pcap`, `.pcapng`) and benchmark dataset CSVs (e.g., CIC-IDS2017).

> [!CAUTION]
> **Data Security & Privacy**: Never commit packet captures, dataset files, or network traces to git. PCAP and CSV files frequently contain sensitive information, internal IP addresses, or proprietary network telemetry.
> The root `.gitignore` explicitly ignores all `.pcap`, `.pcapng`, `.csv`, `.tsv`, `.parquet`, and `.jsonl` files in this directory.

---

## 1. Supported Benchmark Datasets

### CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Description**: Widely used intrusion detection benchmark containing benign traffic and common DoS/DDoS attacks (DoS Slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed, DDoS LOIC).
- **Format**: Pre-extracted feature CSV files or raw PCAPs.
- **Source**: [UNB CIC-IDS2017 Dataset Portal](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Recommended Placement**:
  ```text
  data/
  ├── cic_ids2017/
  │   ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  │   └── Wednesday-workingHours.pcap_ISCX.csv
  └── README.md
  ```
- **Evaluation Command**:
  ```bash
  uv run dos-detector evaluate --csv data/cic_ids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --cic --export-json results_friday.json
  ```

---

## 2. Using Custom Offline Captures

If you record network captures in an isolated, authorized test lab:

1. **Sanitize Captures**: Anonymize IP addresses and strip application payloads before analyzing if data originated outside an isolated testbed.
2. **Offline Only**: Place files directly in `data/raw/` or `data/samples/`.
3. **Malformed Input Warning**: All PCAP and CSV files must be treated as **untrusted user input**. Do not allow filenames or metadata to execute shell commands.

---

## 3. Directory Layout Recommendation

```text
data/
├── README.md               # This documentation file (tracked)
├── raw/                    # Untracked local PCAP captures (.gitignore)
├── processed/              # Untracked aggregated feature parquet/csv (.gitignore)
└── samples/                # Untracked small synthetic test fixtures (.gitignore)
```
