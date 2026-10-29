"""FastAPI backend server and monitoring API for DoS Attack Detector.

Provides REST endpoints for live status, threshold configuration,
on-demand analysis of synthetic demo streams, safe offline PCAP/CSV file uploads,
and serves the embedded SOC monitoring dashboard.
"""

import json
import logging
import shutil
import tempfile
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from dos_detector import __version__
from dos_detector.config import DetectionConfig
from dos_detector.detector import (
    BaseDetector,
    HybridDetector,
    IsolationForestDetector,
    RuleBasedDetector,
)
from dos_detector.evaluation import generate_synthetic_benchmark_stream
from dos_detector.features import SlidingWindowAggregator
from dos_detector.ingestion import (
    CIC_IDS2017_CSV_MAPPING,
    stream_csv,
    stream_pcap,
)
from dos_detector.ml import get_default_baseline_model, load_model
from dos_detector.models import DetectionAlert, PacketRecord
from dos_detector.siem import SiemFormat, format_alert, format_alert_json

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """System health and detector status."""

    status: str = "ok"
    version: str = __version__
    detector_mode: str
    model_description: str
    total_packets_evaluated: int
    total_alerts_emitted: int


class ConfigUpdateRequest(BaseModel):
    """Dynamic update payload for detection thresholds and engine mode."""

    detector_mode: str | None = Field(
        None, description="Detection engine mode: 'hybrid', 'base', or 'ml'"
    )
    window_size_seconds: float | None = Field(None, gt=0)
    syn_flood_pps_threshold: float | None = Field(None, gt=0)
    packet_flood_pps_threshold: float | None = Field(None, gt=0)
    dns_flood_pps_threshold: float | None = Field(None, gt=0)
    http_flood_pps_threshold: float | None = Field(None, gt=0)
    alert_cooldown_seconds: float | None = Field(None, ge=0)
    min_consecutive_windows: int | None = Field(None, ge=1)


class TimelinePoint(BaseModel):
    """Snapshot of traffic metrics and alert status for a single observation window."""

    start_time: float
    end_time: float
    packet_rate: float
    byte_rate: float
    syn_pps: float
    syn_ack_ratio: float
    entropy: float
    total_packets: int
    has_alert: bool
    alert_rule: str | None = None
    alert_severity: str | None = None
    alert_type: str | None = None


class AnalysisResult(BaseModel):
    """Comprehensive analysis report containing timeline snapshots and alerts."""

    source_name: str
    detector_mode: str
    total_packets: int
    total_windows: int
    total_alerts: int
    severity_breakdown: dict[str, int]
    attack_type_breakdown: dict[str, int]
    timeline: list[TimelinePoint]
    alerts: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------


@dataclass
class ServerState:
    """In-memory state holding the active detector, configuration, and analysis history."""

    config: DetectionConfig = field(default_factory=DetectionConfig)
    detector: BaseDetector = field(init=False)
    mode_label: str = "hybrid"
    model_desc: str = "Built-in reference baseline (Isolation Forest)"
    custom_model_path: Path | None = None
    alerts_history: list[dict[str, Any]] = field(default_factory=list)
    raw_alerts: list[DetectionAlert] = field(default_factory=list)
    total_packets_evaluated: int = 0
    total_windows_evaluated: int = 0

    def __post_init__(self) -> None:
        self.rebuild_detector()

    def rebuild_detector(self, model_path: str | Path | None = None) -> None:
        """Reconstruct detector instances based on current config and model settings."""
        if model_path is not None:
            self.custom_model_path = Path(model_path)

        mode = self.config.detector_mode.lower()
        if mode == "rule":
            mode = "base"
        self.mode_label = mode

        ml_model = None
        if mode in ("ml", "hybrid"):
            target_path = self.custom_model_path or self.config.ml_model_path
            if target_path:
                ml_model = load_model(target_path)
                self.model_desc = f"Custom model ({Path(target_path).name})"
            else:
                ml_model = get_default_baseline_model()
                self.model_desc = "Built-in reference baseline (Isolation Forest)"

        if mode == "base":
            self.detector = RuleBasedDetector(config=self.config)
            self.model_desc = "N/A (Rule-based heuristics)"
        elif mode == "ml":
            self.detector = IsolationForestDetector(model=ml_model, config=self.config)
        elif mode == "hybrid":
            rule_det = RuleBasedDetector(config=self.config)
            ml_det = IsolationForestDetector(model=ml_model, config=self.config)
            self.detector = HybridDetector(
                rule_detector=rule_det, ml_detector=ml_det, config=self.config
            )
        else:
            msg = f"Unknown detector mode: {mode}"
            raise ValueError(msg)


def _run_analysis(
    stream: Iterable[PacketRecord],
    state: ServerState,
    source_name: str,
    step_size: float = 0.2,
) -> AnalysisResult:
    """Feed packet stream through SlidingWindowAggregator and evaluate using active detector."""
    aggregator = SlidingWindowAggregator(
        window_size=state.config.window_size_seconds,
        step_size=step_size,
    )
    timeline: list[TimelinePoint] = []
    generated_alerts: list[dict[str, Any]] = []
    severity_counter: Counter[str] = Counter()
    attack_type_counter: Counter[str] = Counter()

    total_packets = 0
    total_windows = 0

    def _counting_stream() -> Iterable[PacketRecord]:
        nonlocal total_packets
        for p in stream:
            total_packets += 1
            yield p

    for window in aggregator.aggregate(_counting_stream()):
        total_windows += 1
        alerts: list[DetectionAlert] = state.detector.evaluate_window(window)

        has_alert = len(alerts) > 0
        primary_alert = alerts[0] if has_alert else None

        rule_name = primary_alert.rule_name if primary_alert else None
        severity = primary_alert.severity.value if primary_alert else None
        attack_type = primary_alert.attack_type if primary_alert else None

        if has_alert:
            for alert in alerts:
                state.raw_alerts.append(alert)
                severity_counter[alert.severity.value] += 1
                attack_type_counter[alert.attack_type] += 1
                alert_dict = {
                    "timestamp": alert.timestamp,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity.value,
                    "attack_type": alert.attack_type,
                    "confidence": round(alert.confidence, 3),
                    "description": alert.description,
                    "metrics_snapshot": alert.metrics_snapshot,
                }
                generated_alerts.append(alert_dict)
                state.alerts_history.append(alert_dict)

        syn_pps = window.syn_count / window.duration_seconds if window.duration_seconds > 0 else 0.0

        timeline.append(
            TimelinePoint(
                start_time=round(window.start_time, 2),
                end_time=round(window.end_time, 2),
                packet_rate=round(window.packet_rate, 1),
                byte_rate=round(window.byte_rate, 1),
                syn_pps=round(syn_pps, 1),
                syn_ack_ratio=round(window.syn_ack_ratio, 2),
                entropy=round(window.normalized_ip_entropy, 3),
                total_packets=window.total_packets,
                has_alert=has_alert,
                alert_rule=rule_name,
                alert_severity=severity,
                alert_type=attack_type,
            )
        )

    state.total_packets_evaluated += total_packets
    state.total_windows_evaluated += total_windows

    return AnalysisResult(
        source_name=source_name,
        detector_mode=state.mode_label,
        total_packets=total_packets,
        total_windows=total_windows,
        total_alerts=len(generated_alerts),
        severity_breakdown=dict(severity_counter),
        attack_type_breakdown=dict(attack_type_counter),
        timeline=timeline,
        alerts=generated_alerts,
    )


# ---------------------------------------------------------------------------
# Embedded HTML Dashboard Interface
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DoS Attack Detector | Defensive SOC Console</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg-dark: #0d1117;
      --card-bg: #161b22;
      --border-color: #30363d;
      --text-main: #c9d1d9;
      --text-muted: #8b949e;
      --accent-blue: #58a6ff;
      --accent-green: #3fb950;
      --accent-orange: #d29922;
      --accent-red: #f85149;
      --accent-purple: #bc8cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: var(--bg-dark); color: var(--text-main); line-height: 1.5; padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px; }
    .title-group h1 { font-size: 22px; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px; }
    .title-group p { font-size: 13px; color: var(--text-muted); }
    .badge { padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge-hybrid { background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); border: 1px solid var(--accent-purple); }
    .badge-base { background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); border: 1px solid var(--accent-blue); }
    .badge-ml { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }

    .grid-kpi { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 18px; }
    .card-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 8px; }
    .card-val { font-size: 28px; font-weight: 700; color: #fff; }
    .card-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

    .action-panel { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
    .btn { background: #21262d; border: 1px solid var(--border-color); color: #fff; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; display: inline-flex; align-items: center; gap: 8px; }
    .btn:hover { background: #30363d; border-color: #8b949e; }
    .btn-primary { background: #238636; border-color: rgba(240, 246, 252, 0.1); }
    .btn-primary:hover { background: #2ea043; }
    .upload-zone { border: 2px dashed var(--border-color); border-radius: 8px; padding: 20px; text-align: center; cursor: pointer; background: rgba(22, 27, 34, 0.5); transition: all 0.2s ease; position: relative; }
    .upload-zone:hover { border-color: var(--accent-blue); background: rgba(88, 166, 255, 0.04); }
    .upload-zone.dragover { border-color: var(--accent-green) !important; background: rgba(63, 185, 80, 0.12) !important; transform: scale(1.01); }
    .upload-zone.busy { pointer-events: none; opacity: 0.8; border-color: var(--accent-purple) !important; }
    .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: #fff; animation: spin 0.8s linear infinite; vertical-align: middle; margin-right: 6px; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .chart-container { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; margin-bottom: 24px; height: 320px; }

    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th { text-align: left; padding: 10px 14px; border-bottom: 2px solid var(--border-color); color: var(--text-muted); font-size: 11px; text-transform: uppercase; }
    td { padding: 12px 14px; border-bottom: 1px solid var(--border-color); vertical-align: top; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }

    .sev-CRITICAL { color: var(--accent-red); font-weight: 700; background: rgba(248, 81, 73, 0.15); padding: 2px 6px; border-radius: 4px; }
    .sev-HIGH { color: var(--accent-orange); font-weight: 600; background: rgba(210, 153, 34, 0.15); padding: 2px 6px; border-radius: 4px; }
    .sev-MEDIUM { color: var(--accent-blue); font-weight: 500; background: rgba(88, 166, 255, 0.15); padding: 2px 6px; border-radius: 4px; }
    .mode-select { background: #0d1117; color: #fff; border: 1px solid var(--border-color); padding: 6px 12px; border-radius: 6px; font-size: 13px; }
    .tag { display: inline-block; background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: var(--accent-blue); margin-right: 4px; margin-top: 4px; }
  </style>
</head>
<body>

  <div class="header">
    <div class="title-group">
      <h1>DoS Attack Detector <span id="engineBadge" class="badge badge-hybrid">HYBRID</span></h1>
      <p id="engineDesc">Active Model: Built-in reference baseline (Isolation Forest)</p>
    </div>
    <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
      <label style="font-size: 13px; color: var(--text-muted);">Engine Mode:</label>
      <select id="modeSelect" class="mode-select" onchange="switchMode(this.value)">
        <option value="hybrid" selected>Hybrid (Rules + ML)</option>
        <option value="base">Base (Rules Only)</option>
        <option value="ml">ML (Isolation Forest)</option>
      </select>
      <input type="file" id="customModelInput" style="display: none;" accept=".joblib" onchange="if(this.files[0]) uploadCustomModel(this.files[0]); this.value='';">
      <button class="btn" onclick="document.getElementById('customModelInput').click()" title="Load custom trained Isolation Forest (.joblib) model">📁 Custom Model</button>
      <button class="btn" id="btnResetModel" onclick="resetDefaultModel()" style="display: none;" title="Revert to built-in reference baseline">🔄 Default Model</button>
      <button class="btn" onclick="clearAlerts()">Clear</button>
    </div>
  </div>

  <div class="grid-kpi">
    <div class="card">
      <div class="card-title">Packets Evaluated</div>
      <div class="card-val" id="kpiPackets">0</div>
      <div class="card-sub" id="kpiWindows">0 time windows</div>
    </div>
    <div class="card">
      <div class="card-title">Suspicious Events</div>
      <div class="card-val" id="kpiAlerts" style="color: var(--accent-red);">0</div>
      <div class="card-sub" id="kpiCritical">0 critical / 0 high</div>
    </div>
    <div class="card">
      <div class="card-title">Distribution Ratio</div>
      <div class="card-val" id="kpiDist">--</div>
      <div class="card-sub">DDoS vs Single-Source DoS</div>
    </div>
    <div class="card">
      <div class="card-title">Engine Latency</div>
      <div class="card-val" id="kpiLatency">< 1ms</div>
      <div class="card-sub">Streaming $O(1)$ memory</div>
    </div>
  </div>

  <input type="file" id="fileInput" style="display: none;" accept=".pcap,.pcapng,.cap,.csv,.tsv" onchange="handleFileSelection(this)">

  <div class="action-panel">
    <div class="card" style="display: flex; flex-direction: column; justify-content: center; align-items: flex-start; gap: 12px;">
      <h3 style="font-size: 15px;">1-Click Synthetic Attack Demo</h3>
      <p style="font-size: 13px; color: var(--text-muted);">Generates safe educational traffic: benign web browsing followed by an aggressive SYN flood surge.</p>
      <button class="btn btn-primary" onclick="runDemo()" id="btnDemo">▶ Run Simulation Demo</button>
    </div>

    <div class="upload-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
      <div id="uploadIcon" style="font-size: 28px; margin-bottom: 6px;">📂</div>
      <h3 id="uploadTitle" style="font-size: 15px; margin-bottom: 4px; color: #fff;">Upload Offline PCAP or CSV File</h3>
      <p id="uploadDesc" style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">Drag &amp; drop capture file or click anywhere to select (.pcap, .pcapng, .csv)</p>
      <button type="button" class="btn" style="pointer-events: none; padding: 6px 14px; font-size: 13px;">Browse PCAP / CSV</button>
    </div>
  </div>

  <div class="chart-container">
    <canvas id="trafficChart"></canvas>
  </div>

  <div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
      <h3 style="font-size: 16px;">Defensive Alert Timeline &amp; Feature Deviations</h3>
      <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
        <span style="font-size: 12px; color: var(--text-muted); font-weight: 500;">SIEM Export:</span>
        <button class="btn" style="padding: 5px 10px; font-size: 12px;" onclick="exportSiem('cef')" title="Export alerts to Micro Focus ArcSight Common Event Format (.cef)">📥 CEF</button>
        <button class="btn" style="padding: 5px 10px; font-size: 12px;" onclick="exportSiem('syslog')" title="Export alerts to Syslog RFC 5424 with Structured Data (.log)">📥 Syslog</button>
        <button class="btn" style="padding: 5px 10px; font-size: 12px;" onclick="exportSiem('ndjson')" title="Export alerts to NDJSON for Splunk/Elastic (.ndjson)">📥 NDJSON</button>
      </div>
    </div>
    <table id="alertsTable">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Severity</th>
          <th>Detection Rule</th>
          <th>Attack Type</th>
          <th>Confidence</th>
          <th>Explanatory Details (XAI)</th>
        </tr>
      </thead>
      <tbody id="alertsBody">
        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No anomalies detected yet. Click "Run Simulation Demo" or upload a capture file.</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    let chart = null;

    async function initChart() {
      try {
        const canvas = document.getElementById('trafficChart');
        if (!canvas || typeof Chart === 'undefined') return;
        const ctx = canvas.getContext('2d');
        chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Packet Rate (PPS)',
              data: [],
              borderColor: '#58a6ff',
              backgroundColor: 'rgba(88, 166, 255, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.2
            },
            {
              label: 'SYN Rate (PPS)',
              data: [],
              borderColor: '#f85149',
              backgroundColor: 'rgba(248, 81, 73, 0.05)',
              borderWidth: 2,
              borderDash: [5, 5],
              tension: 0.2
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { grid: { color: '#21262d' }, ticks: { color: '#8b949e' } },
            y: { grid: { color: '#21262d' }, ticks: { color: '#8b949e' }, beginAtZero: true }
          },
          plugins: {
            legend: { labels: { color: '#c9d1d9' } }
          }
        }
      });
      } catch (err) {
        console.warn('Chart initialization skipped or deferred:', err);
      }
    }

    async function fetchHealth() {
      const res = await fetch('/api/health');
      const data = await res.json();
      document.getElementById('engineBadge').className = 'badge badge-' + data.detector_mode;
      document.getElementById('engineBadge').innerText = data.detector_mode.toUpperCase();
      document.getElementById('engineDesc').innerText = 'Active Model: ' + data.model_description;
      document.getElementById('modeSelect').value = data.detector_mode;
      const isCustom = data.model_description && data.model_description.includes('Custom');
      document.getElementById('btnResetModel').style.display = isCustom ? 'inline-flex' : 'none';
    }

    async function uploadCustomModel(file) {
      if (!file) return;
      if (!file.name.toLowerCase().endsWith('.joblib')) {
        alert('Please select a valid serialized .joblib model file.');
        return;
      }

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/model/upload', {
          method: 'POST',
          body: formData
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          alert('Failed to load custom model: ' + (errData.detail || 'Validation error'));
          return;
        }

        const data = await res.json();
        document.getElementById('engineDesc').innerText = 'Active Model: ' + data.model_description;
        document.getElementById('btnResetModel').style.display = 'inline-flex';
        alert('Custom model activated successfully:\\n' + data.model_description);
      } catch (err) {
        alert('Network error while uploading model: ' + err.message);
      }
    }

    async function resetDefaultModel() {
      try {
        const res = await fetch('/api/model/reset', { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('engineDesc').innerText = 'Active Model: ' + data.model_description;
          document.getElementById('btnResetModel').style.display = 'none';
          alert('Reverted to built-in reference baseline model.');
        }
      } catch (err) {
        alert('Failed to reset model: ' + err.message);
      }
    }

    async function switchMode(newMode) {
      await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ detector_mode: newMode })
      });
      await fetchHealth();
    }

    function handleFileSelection(input) {
      if (input && input.files && input.files[0]) {
        uploadFile(input.files[0]);
      }
    }

    async function runDemo() {
      const btn = document.getElementById('btnDemo');
      btn.innerText = 'Analyzing...';
      btn.disabled = true;
      try {
        const res = await fetch('/api/analyze/demo', { method: 'POST' });
        if (!res.ok) {
          const errText = await res.text();
          throw new Error(errText);
        }
        const data = await res.json();
        renderResults(data);
      } catch (err) {
        console.error('Demo simulation failed:', err);
        alert('Simulation demo error: ' + err.message);
      } finally {
        btn.innerText = '▶ Run Simulation Demo';
        btn.disabled = false;
      }
    }

    async function uploadFile(file) {
      if (!file) return;

      const validExts = ['.pcap', '.pcapng', '.cap', '.csv', '.tsv'];
      const fileNameLower = file.name.toLowerCase();
      const isValid = validExts.some(ext => fileNameLower.endsWith(ext));
      if (!isValid) {
        alert('Unsupported file format "' + file.name + '". Please upload a .pcap, .pcapng, or .csv file.');
        return;
      }

      const zone = document.getElementById('dropZone');
      const title = document.getElementById('uploadTitle');
      const desc = document.getElementById('uploadDesc');
      const icon = document.getElementById('uploadIcon');

      zone.classList.add('busy');
      icon.innerHTML = '<span class="spinner"></span>';
      const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
      title.innerText = `Analyzing: ${file.name} (${sizeMb} MB)...`;
      desc.innerText = 'Extracting sliding windows and evaluating heuristics. Please wait...';

      try {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/analyze/upload', {
          method: 'POST',
          body: formData
        });

        if (!res.ok) {
          const errText = await res.text();
          let detail = errText;
          try {
            const parsed = JSON.parse(errText);
            detail = parsed.detail || errText;
          } catch (_) {}
          icon.innerText = '⚠️';
          title.innerText = 'Upload / Analysis Failed';
          desc.innerText = detail;
          alert('Analysis failed: ' + detail);
          return;
        }

        const data = await res.json();
        renderResults(data);
        icon.innerText = '✅';
        title.innerText = `Completed: ${file.name}`;
        desc.innerText = `Evaluated ${data.total_packets.toLocaleString()} packets across ${data.total_windows} windows (${data.total_alerts} alerts). Click or drop another.`;
      } catch (err) {
        console.error('Upload failed:', err);
        icon.innerText = '❌';
        title.innerText = 'Connection Error';
        desc.innerText = 'Failed to communicate with detector server.';
        alert('Cannot reach detector server: ' + err.message + '\\n\\nMake sure "uv run dos-detector serve" is running in your terminal.');
      } finally {
        zone.classList.remove('busy');
        const fi = document.getElementById('fileInput');
        if (fi) fi.value = '';
      }
    }

    function initDragAndDrop() {
      const zone = document.getElementById('dropZone');
      if (!zone) return;

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        window.addEventListener(eventName, e => e.preventDefault(), false);
        zone.addEventListener(eventName, e => {
          e.preventDefault();
          e.stopPropagation();
        }, false);
      });

      ['dragenter', 'dragover'].forEach(eventName => {
        zone.addEventListener(eventName, () => {
          zone.classList.add('dragover');
          document.getElementById('uploadTitle').innerText = 'Drop PCAP / CSV file here...';
          document.getElementById('uploadIcon').innerText = '📥';
        }, false);
      });

      ['dragleave', 'dragend'].forEach(eventName => {
        zone.addEventListener(eventName, () => {
          zone.classList.remove('dragover');
          document.getElementById('uploadTitle').innerText = 'Upload Offline PCAP or CSV File';
          document.getElementById('uploadIcon').innerText = '📂';
        }, false);
      });

      zone.addEventListener('drop', (e) => {
        zone.classList.remove('dragover');
        document.getElementById('uploadTitle').innerText = 'Upload Offline PCAP or CSV File';
        document.getElementById('uploadIcon').innerText = '📂';

        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length > 0) {
          uploadFile(dt.files[0]);
        }
      }, false);
    }

    function renderResults(data) {
      document.getElementById('kpiPackets').innerText = data.total_packets.toLocaleString();
      document.getElementById('kpiWindows').innerText = data.total_windows + ' observation windows';
      document.getElementById('kpiAlerts').innerText = data.total_alerts;

      const crit = data.severity_breakdown['CRITICAL'] || 0;
      const high = data.severity_breakdown['HIGH'] || 0;
      document.getElementById('kpiCritical').innerText = `${crit} critical / ${high} high`;

      const ddos = data.attack_type_breakdown['DISTRIBUTED_DOS (DDoS)'] || 0;
      const dos = data.attack_type_breakdown['SINGLE_SOURCE_DOS'] || 0;
      if (ddos + dos > 0) {
        document.getElementById('kpiDist').innerText = `${Math.round((ddos/(ddos+dos))*100)}% DDoS`;
      } else {
        document.getElementById('kpiDist').innerText = 'Normal';
      }

      // Update Chart
      if (chart && chart.data) {
        chart.data.labels = data.timeline.map(t => t.end_time + 's');
        chart.data.datasets[0].data = data.timeline.map(t => t.packet_rate);
        chart.data.datasets[1].data = data.timeline.map(t => t.syn_pps);
        chart.update();
      }

      // Update Table
      const tbody = document.getElementById('alertsBody');
      if (data.alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--accent-green); padding: 24px;">No anomalies detected. Traffic matches legitimate baseline.</td></tr>';
        return;
      }

      tbody.innerHTML = data.alerts.map(a => `
        <tr>
          <td>${a.timestamp.toFixed(2)}s</td>
          <td><span class="sev-${a.severity}">${a.severity}</span></td>
          <td><b>${a.rule_name}</b></td>
          <td>${a.attack_type}</td>
          <td>${Math.round(a.confidence * 100)}%</td>
          <td>${a.description}</td>
        </tr>
      `).join('');
    }

    function exportSiem(format) {
      const alertCount = parseInt(document.getElementById('kpiAlerts').innerText || '0', 10);
      if (isNaN(alertCount) || alertCount === 0) {
        alert('No alerts to export yet. Please run the Simulation Demo or upload a capture file first.');
        return;
      }
      window.location.href = `/api/alerts/export?format=${encodeURIComponent(format)}`;
    }

    async function clearAlerts() {
      await fetch('/api/alerts/clear', { method: 'POST' });
      document.getElementById('alertsBody').innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">Cleared. Ready for new traffic.</td></tr>';
      document.getElementById('kpiPackets').innerText = '0';
      document.getElementById('kpiAlerts').innerText = '0';
      if (chart && chart.data) {
        chart.data.labels = [];
        chart.data.datasets[0].data = [];
        chart.data.datasets[1].data = [];
        chart.update();
      }
    }

    window.onload = async () => {
      await initChart();
      await fetchHealth();
      initDragAndDrop();
    };
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# FastAPI Application Factory
# ---------------------------------------------------------------------------


def create_app(
    config: DetectionConfig | None = None,
    detector: BaseDetector | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="DoS Attack Detector API",
        version=__version__,
        description="Defensive network traffic analysis engine and real-time monitoring dashboard.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    state = ServerState(config=config or DetectionConfig())
    if detector:
        state.detector = detector

    @app.get("/", response_class=HTMLResponse)
    def get_dashboard() -> str:
        """Serve the embedded interactive SOC monitoring dashboard."""
        return DASHBOARD_HTML

    @app.get("/api/health", response_model=HealthResponse)
    def health_check() -> HealthResponse:
        """Return system health, active detector mode, and telemetry totals."""
        return HealthResponse(
            status="ok",
            version=__version__,
            detector_mode=state.mode_label,
            model_description=state.model_desc,
            total_packets_evaluated=state.total_packets_evaluated,
            total_alerts_emitted=len(state.alerts_history),
        )

    @app.get("/api/config")
    def get_config() -> dict[str, Any]:
        """Return current detection engine threshold configuration."""
        return asdict(state.config)

    @app.post("/api/config", response_model=HealthResponse)
    def update_config(payload: ConfigUpdateRequest) -> HealthResponse:
        """Dynamically update thresholds or switch detector mode."""
        curr_dict = asdict(state.config)
        update_fields = payload.model_dump(exclude_unset=True)

        merged = {**curr_dict, **update_fields}
        try:
            new_config = DetectionConfig(**merged)
            new_config.validate()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        state.config = new_config
        state.rebuild_detector()
        return health_check()

    @app.post("/api/model/upload", response_model=HealthResponse)
    def upload_model(
        file: Annotated[
            UploadFile,
            File(description="Serialized Isolation Forest .joblib model file"),
        ],
    ) -> HealthResponse:
        """Safely upload and activate a custom Isolation Forest .joblib model."""
        suffix = Path(file.filename or "model.joblib").suffix.lower()
        if suffix != ".joblib":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported model extension '{suffix}'. Expected .joblib",
            )

        models_dir = Path("models")
        models_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = Path(file.filename or "custom_model.joblib").name
        dest_path = models_dir / safe_filename

        with dest_path.open("wb") as buffer:
            file.file.seek(0)
            shutil.copyfileobj(file.file, buffer)

        try:
            load_model(dest_path)
        except Exception as exc:
            dest_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid model artifact: {exc}",
            ) from exc

        state.custom_model_path = dest_path
        state.rebuild_detector(model_path=dest_path)
        return health_check()

    @app.post("/api/model/reset", response_model=HealthResponse)
    def reset_model() -> HealthResponse:
        """Revert active detector model to the built-in reference baseline."""
        state.custom_model_path = None
        state.rebuild_detector()
        return health_check()

    @app.post("/api/analyze/demo", response_model=AnalysisResult)
    def analyze_demo() -> AnalysisResult:
        """Generate synthetic benchmark packets and evaluate using the active detector."""
        stream = generate_synthetic_benchmark_stream()
        return _run_analysis(stream, state, source_name="Educational Simulation Demo")

    @app.post("/api/analyze/upload", response_model=AnalysisResult)
    def analyze_upload(
        file: Annotated[
            UploadFile,
            File(description="PCAP/PCAPNG or CSV capture file to inspect defensively"),
        ],
    ) -> AnalysisResult:
        """Safely upload an offline network capture file and run defensive inspection."""
        suffix = Path(file.filename or "capture.pcap").suffix.lower()
        if suffix not in (".pcap", ".pcapng", ".cap", ".csv", ".tsv"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file extension '{suffix}'. Expected .pcap, .pcapng, or .csv",
            )

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_path = Path(tmp_file.name)
            try:
                file.file.seek(0)
                shutil.copyfileobj(file.file, tmp_file)
            except Exception as exc:
                if tmp_path.is_file():
                    tmp_path.unlink()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to write uploaded file: {exc}",
                ) from exc

        try:
            if suffix in (".csv", ".tsv"):
                is_cic = "cic" in (file.filename or "").lower()
                mapping = CIC_IDS2017_CSV_MAPPING if is_cic else None
                stream = stream_csv(tmp_path, mapping=mapping)
            else:
                stream = stream_pcap(tmp_path)

            result = _run_analysis(stream, state, source_name=file.filename or "uploaded_capture")
            return result
        except Exception as exc:
            logger.exception("Error analyzing uploaded capture file: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to analyze capture '{file.filename}': {exc}",
            ) from exc
        finally:
            if tmp_path.is_file():
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError as exc:
                    logger.warning("Could not immediately remove temp file %s: %s", tmp_path, exc)

    @app.get("/api/alerts")
    def get_alerts(
        severity: str | None = Query(None, description="Filter by severity (HIGH, MEDIUM, etc.)"),
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        """Return history of emitted detection alerts."""
        alerts = state.alerts_history
        if severity:
            alerts = [a for a in alerts if a["severity"].upper() == severity.upper()]
        return alerts[-limit:]

    @app.get("/api/alerts/export")
    def export_alerts(
        format: str = Query(
            "cef",
            description="SIEM export format: 'cef', 'syslog', 'json', or 'ndjson'",
        ),
        severity: str | None = Query(
            None,
            description="Optional severity filter (e.g. HIGH, CRITICAL)",
        ),
    ) -> Response:
        """Export detection alerts formatted for SIEM ingest (CEF, Syslog RFC 5424, NDJSON)."""
        fmt_str = format.lower().strip()
        try:
            siem_fmt = SiemFormat(fmt_str)
        except ValueError as exc:
            allowed = [f.value for f in SiemFormat]
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported SIEM format '{format}'. Allowed formats: {allowed}",
            ) from exc

        alerts = state.raw_alerts
        if severity:
            alerts = [a for a in alerts if a.severity.value.upper() == severity.upper()]

        if siem_fmt == SiemFormat.JSON:
            alerts_data = [json.loads(format_alert_json(a)) for a in alerts]
            payload = json.dumps(alerts_data, indent=2) + ("\n" if alerts_data else "")
        else:
            lines = [format_alert(a, siem_fmt) for a in alerts]
            payload = "\n".join(lines) + ("\n" if lines else "")

        now_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        if siem_fmt == SiemFormat.CEF:
            media_type = "text/plain"
            ext = "cef"
        elif siem_fmt == SiemFormat.SYSLOG:
            media_type = "text/plain"
            ext = "log"
        else:
            media_type = (
                "application/x-ndjson" if siem_fmt == SiemFormat.NDJSON else "application/json"
            )
            ext = "ndjson" if siem_fmt == SiemFormat.NDJSON else "json"

        filename = f"dos_alerts_{now_str}.{ext}"
        return Response(
            content=payload,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-cache",
            },
        )

    @app.post("/api/alerts/clear")
    def clear_alerts() -> dict[str, str]:
        """Clear in-memory alert history and reset telemetry."""
        state.alerts_history.clear()
        state.raw_alerts.clear()
        state.total_packets_evaluated = 0
        state.total_windows_evaluated = 0
        state.detector.reset()
        return {"status": "cleared"}

    return app
