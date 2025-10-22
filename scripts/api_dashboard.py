# scripts/api_dashboard.py
# -----------------------------------------------------------------------------
# IoTGuard Pipeline — API + Dashboard
#
# Purpose
#   - Provide a lightweight REST API for recent events, counts and config, and
#     serve a single-page dashboard to visualize scores/blocks in real time.
#
# Where it sits in the pipeline
#   decision_loop.py → data/alerts.jsonl → [THIS FILE] → browser UI
#
# Inputs
#   - data/alerts.jsonl: append-only event log from the decision loop.
#   - configs/model.yaml: read/write of decision parameters via /api/config.
#
# Outputs
#   - HTML dashboard at `/` (Chart.js time series + recent table).
#   - JSON endpoints for other tools to consume (/api/events, /api/counts,
#     /api/latest, /api/config, /api/clear*).
#
# Operational notes
#   - Stateless: all state derived from alerts.jsonl; safe to restart anytime.
#   - Clear endpoints let you reset logs and the decision loop offset for clean
#     experiments.
# -----------------------------------------------------------------------------
import os, io, csv, json, time, threading, yaml
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, jsonify, request, Response, abort

DATA_DIR   = Path("data")
ALERT_LOG  = DATA_DIR / "alerts.jsonl"
CFG_FILE   = Path("configs/model.yaml")

app = Flask(__name__)
_lock = threading.Lock()

# ---------- helpers ----------
def _iter_alerts():
    if not ALERT_LOG.exists():
        return
    with ALERT_LOG.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def read_last_n(n=200):
    data = list(_iter_alerts() or [])
    return data[-n:]

def now_ts(): 
    return time.time()

def load_cfg():
    if not CFG_FILE.exists():
        return {}
    with CFG_FILE.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def save_cfg(cfg: dict):
    CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with CFG_FILE.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)

# ---------- APIs ----------
@app.get("/api/latest")
def api_latest():
    data = read_last_n(1)
    return jsonify({"ok": True, "latest": data[0] if data else None, "server_time": now_ts()})

@app.get("/api/counts")
def api_counts():
    """Counts in the last X minutes (default 60)."""
    mins = float(request.args.get("window_minutes", 60))
    cutoff = now_ts() - (mins * 60)
    total = attacks = blocks = 0
    class_counts = {}
    for evt in _iter_alerts() or []:
        if evt.get("ts", 0) >= cutoff:
            total += 1
            if evt.get("state") == "ATTACK":
                attacks += 1
            if evt.get("action") == "BLOCK":
                blocks += 1
            c = evt.get("pred_class")
            if c is not None:
                class_counts[c] = class_counts.get(c, 0) + 1
    return jsonify({"ok": True, "window_minutes": mins, "total": total, "attacks": attacks, "blocks": blocks, "class_counts": class_counts})

@app.get("/api/events")
def api_events():
    """Return events since a given timestamp (or last 200 if not provided)."""
    since = request.args.get("since_ts", type=float)
    if since is None:
        data = read_last_n(200)
    else:
        data = [e for e in (_iter_alerts() or []) if e.get("ts", 0) > since]
    return jsonify({"ok": True, "events": data, "server_time": now_ts()})

@app.get("/api/model")
def api_model():
    """Return model metadata like classes.json if present."""
    meta = {"classes": None, "benign_index": None}
    try:
        cj = Path("models/classes.json")
        if cj.exists():
            data = json.loads(cj.read_text(encoding="utf-8"))
            meta.update({
                "classes": data.get("classes"),
                "benign_index": data.get("benign_index")
            })
    except Exception:
        pass
    return jsonify({"ok": True, "model": meta})

@app.get("/api/config")
def api_get_config():
    cfg = load_cfg()
    decision = cfg.get("decision", {})
    return jsonify({"ok": True, "decision": {
        "threshold": float(decision.get("threshold", 0.65)),
        "grace":     int(decision.get("grace", 3)),
        "window":    int(decision.get("window", 5)),
        "cooldown_sec": int(decision.get("cooldown_sec", 30)),
    }})

@app.post("/api/config")
def api_set_config():
    body = request.get_json(silent=True) or {}
    dec   = (body.get("decision") or body)
    # validate & coerce
    try:
        new_dec = {
            "threshold": float(dec.get("threshold", 0.65)),
            "grace": int(dec.get("grace", 3)),
            "window": int(dec.get("window", 5)),
            "cooldown_sec": int(dec.get("cooldown_sec", 30)),
        }
    except Exception:
        return jsonify({"ok": False, "error": "Invalid types"}), 400

    cfg = load_cfg()
    cfg.setdefault("decision", {}).update(new_dec)
    save_cfg(cfg)
    return jsonify({"ok": True, "saved": new_dec, "note": "Restart decision loop to apply (or enable hot-reload there)."})

@app.post("/api/clear")
def api_clear():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")
    return jsonify({"ok": True})

@app.post("/api/clear_all")
def api_clear_all():
    # clear alerts
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")

    # reset offset state so the decision loop won’t re-score old rows
    (DATA_DIR / "state.json").write_text('{"offset_rows":0,"csv_mtime":0}', encoding="utf-8")

    # (optional) also reset features.csv to header for a fresh run:
    # (DATA_DIR / "features.csv").write_text(
    #   "flows,bytes_total,pkts_total,uniq_src,uniq_dst,syn_ratio,mean_bytes_flow\n", encoding="utf-8"
    # )

    return jsonify({"ok": True})

@app.get("/api/download.csv")
def api_download_csv():
    if not ALERT_LOG.exists():
        abort(404)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["ts","index","score","state","hits_in_window","action","pred_class"])
    writer.writeheader()
    for e in _iter_alerts() or []:
        writer.writerow({
            "ts": e.get("ts"),
            "index": e.get("index"),
            "score": e.get("score"),
            "state": e.get("state"),
            "hits_in_window": e.get("hits_in_window"),
            "action": e.get("action"),
            "pred_class": e.get("pred_class"),
        })
    output.seek(0)
    return Response(
        output.read(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=iotguard_alerts.csv"}
    )

@app.get("/")
def index():
    # Plain string (NOT f-string) so `${...}` in JS stays intact
    html = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>IoTGuard — Live Alerts</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<link rel="icon" href="data:,">
<style>
  :root {
    --bg:#0b0f14; --ink:#e6edf3; --muted:#9ca3af; --row:#1f2937;
    --panel: rgba(17,24,39,0.75);
    --accent:#7dd3fc; /* sky-300 */
    --accent2:#a78bfa; /* violet-400 */
    --good:#8ff2b2; --warn:#f2d28f; --bad:#f28f8f;
  }
  body {
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
    margin: 0; color:var(--ink);
    background:
      radial-gradient(1200px 600px at 80% -10%, #3b0764 0%, transparent 40%),
      radial-gradient(800px 500px at -10% 10%, #0ea5e9 0%, transparent 35%),
      linear-gradient(180deg, #0b0f14 0%, #0b1220 100%);
    min-height: 100vh;
  }
  .nav { position:sticky; top:0; z-index:10; backdrop-filter: blur(6px);
         background: linear-gradient(180deg, rgba(11,17,26,.7), rgba(11,17,26,.2));
         border-bottom: 1px solid rgba(51,65,85,.35); padding:10px 20px; }
  .brand { font-weight:800; letter-spacing:.3px; }
  .container { max-width:1100px; margin: 0 auto; padding: 18px 20px; }
  .hero h1 { margin: 8px 0 6px; font-size:38px; line-height:1.1; }
  .hero .grad { background: linear-gradient(90deg, var(--accent), var(--accent2));
                -webkit-background-clip:text; background-clip:text; color:transparent; }
  .sub { color:var(--muted); margin-top:4px; }

  .grid { display:grid; grid-template-columns: 1fr 1fr 1fr; gap:12px; }
  .card { background:var(--panel); padding:14px 16px; border-radius:14px;
          box-shadow: 0 8px 24px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.03);
          border: 1px solid rgba(148,163,184,.2); }
  .card:hover { box-shadow: 0 12px 28px rgba(0,0,0,.45); }

  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  table { width:100%; border-collapse:collapse; margin-top:12px; }
  th, td { padding:10px 12px; border-bottom:1px solid var(--row); font-size:14px; white-space:nowrap; }
  th { text-align:left; color:var(--muted); font-weight:600; }
  .tag { padding:2px 8px; border-radius:999px; font-weight:600; font-size:12px; }
  .ok { background:#0b3d1f; color:var(--good); }
  .warn { background:#3d2a0b; color:var(--warn); }
  .bad { background:#3d0b0b; color:var(--bad); }
  .footer { color:var(--muted); font-size:12px; margin-top:10px; }
  .btn { background:#0f172a; color:#cbd5e1; border:1px solid #334155; padding:8px 12px; border-radius:10px; cursor:pointer; }
  .btn:hover { filter:brightness(1.12); border-color:#475569; }
  input[type=number] { width:90px; background:#0f172a; color:#e6edf3; border:1px solid #334155; border-radius:10px; padding:8px 10px; }
  .chart-box { height:240px; }
  .chips { display:flex; gap:8px; flex-wrap:wrap; }
  .chip { background:rgba(2,6,23,.6); border:1px solid rgba(148,163,184,.25); color:#cbd5e1; padding:6px 10px; border-radius:999px; font-size:12px; }
</style>
</head>
<body>
  <div class="nav">
    <div class="container"><span class="brand">IoTGuard</span></div>
  </div>
  <div class="container hero">
    <h1><span class="grad">IoTGuard — Live Alerts</span></h1>
    <div class="sub">Realtime scoring, per-class insights, and controls.</div>
  </div>
  <div class="container grid">
    <div class="card"><div>Last 60 min — Total</div><div id="mt_total" style="font-size:24px;font-weight:700">0</div></div>
    <div class="card"><div>Last 60 min — Attacks</div><div id="mt_attacks" style="font-size:24px;font-weight:700;color:#f28f8f">0</div></div>
    <div class="card"><div>Last 60 min — Blocks</div><div id="mt_blocks" style="font-size:24px;font-weight:700;color:#f2d28f">0</div></div>
  </div>

  <div class="container" style="margin-top:12px;">
    <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div class="row">
        <div style="font-weight:700;">Controls</div>
        <div class="row" style="gap:6px;margin-left:14px;">
          <label>threshold <input id="ctl_threshold" type="number" step="0.01" min="0" max="1"/></label>
          <label>grace <input id="ctl_grace" type="number" min="1" max="20"/></label>
          <label>window <input id="ctl_window" type="number" min="1" max="50"/></label>
          <label>cooldown <input id="ctl_cool" type="number" min="0" max="3600"/></label>
          <button class="btn" id="btn_save">Save</button>
          <div id="save_msg" class="footer"></div>
        </div>
      </div>
      <div class="row">
        <button class="btn" id="btn_download">Download CSV</button>
        <button class="btn" id="btn_clear">Clear Log</button>
        <button class="btn" id="btn_clear_all">Clear All</button>
        <div id="clock" class="footer">—</div>
      </div>
    </div>
    </div>
  </div>

  <div class="container">
    <div class="card chart-box"><canvas id="scoreChart" style="width:100%;height:100%;"></canvas></div>
  </div>

  <div class="container" style="margin-top:12px;">
    <div class="card" style="margin-bottom:12px;">
      <div style="font-weight:700; margin-bottom:6px;">Per-class Counts (last 60m)</div>
      <div id="class_chips" class="chips"></div>
    </div>
    <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div style="font-weight:700;">Recent Events</div>
    </div>
    <table>
      <thead>
        <tr><th>Time (UTC)</th><th>Index</th><th>Score</th><th>State</th><th>Pred</th><th>Window Hits</th><th>Action</th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
    </div>
  </div>

  <div class="footer">Auto-refreshing every 2s. Backed by alerts.jsonl.</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
let lastTs = null;
let chart, chartData = {labels: [], scores: []};
let lastBlockTs = 0;
let modelMeta = { classes: null, benign_index: null };

// --- audio alert for BLOCK ---
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
function beep() {
  const o = audioCtx.createOscillator();
  const g = audioCtx.createGain();
  o.connect(g); g.connect(audioCtx.destination);
  o.type = 'square'; o.frequency.value = 880;
  g.gain.value = 0.05;
  o.start(); setTimeout(()=>{ o.stop(); }, 180);
}

// --- utils ---
function iso(ts){ try{ return new Date(ts*1000).toISOString(); }catch(e){ return '—'; } }
function tag(text, cls){ return '<span class="tag '+cls+'">'+text+'</span>'; }
function stateTag(s){ return s==='ATTACK' ? tag('ATTACK','bad') : tag('benign','ok'); }
function actionTag(a){ return a==='BLOCK' ? tag('BLOCK','warn') : tag('NONE','ok'); }
function rowHtml(e){
  return '<tr>'
    + '<td>'+iso(e.ts)+'</td>'
    + '<td>'+e.index+'</td>'
    + '<td>'+((e.score ?? 0).toFixed(3))+'</td>'
    + '<td>'+stateTag(e.state)+'</td>'
    + '<td>'+(e.pred_class ?? '—')+'</td>'
    + '<td>'+(e.hits_in_window ?? 0)+'</td>'
    + '<td>'+actionTag(e.action)+'</td>'
  + '</tr>';
}

function toast(msg){
  const el = document.getElementById('save_msg');
  if (!el) return;
  el.textContent = msg;
  setTimeout(()=> el.textContent = '', 2500);
}

async function refreshCounts(){
  const r = await fetch('/api/counts?window_minutes=60');
  const j = await r.json();
  document.getElementById('mt_total').innerText = j.total ?? 0;
  document.getElementById('mt_attacks').innerText = j.attacks ?? 0;
  document.getElementById('mt_blocks').innerText = j.blocks ?? 0;
  // Optionally render class counts if present
  const chips = document.getElementById('class_chips');
  if (chips) {
    let html = '';
    if (j.class_counts) {
      const entries = Object.entries(j.class_counts).sort((a,b)=> b[1]-a[1]);
      for (const [name, cnt] of entries) {
        html += `<span class="chip">${name}: ${cnt}</span>`;
      }
    }
    chips.innerHTML = html || '<span class="chip">No class data</span>';
  }
}

async function refreshEvents(){
  const q = lastTs ? ('?since_ts='+encodeURIComponent(lastTs)) : '';
  const r = await fetch('/api/events'+q);
  const j = await r.json();
  const list = j.events || [];
  if (!list.length) return;

  // table prepend
  const tbody = document.getElementById('rows');
  let html = tbody.innerHTML;
  for (const e of list) html = rowHtml(e) + html;
  tbody.innerHTML = html;

  // chart update (cap 100)
  for (const e of list){
    chartData.labels.push(iso(e.ts));
    chartData.scores.push(e.score ?? 0);
  }
  if (chartData.labels.length > 100){
    chartData.labels.splice(0, chartData.labels.length-100);
    chartData.scores.splice(0, chartData.scores.length-100);
  }
  chart.data.labels = chartData.labels;
  chart.data.datasets[0].data = chartData.scores;
  chart.update('none');

  // alerts on new BLOCK
  for (const e of list){
    if (e.action === 'BLOCK' && (e.ts > lastBlockTs)){
      lastBlockTs = e.ts;
      beep();
      document.body.style.boxShadow = 'inset 0 0 0 4px #f2d28f55';
      setTimeout(()=>document.body.style.boxShadow='none', 200);
    }
  }

  lastTs = list[list.length-1].ts;
}

async function loadConfig(){
  const r = await fetch('/api/config'); const j = await r.json();
  const d = j.decision || {};
  document.getElementById('ctl_threshold').value = d.threshold ?? 0.65;
  document.getElementById('ctl_grace').value     = d.grace ?? 3;
  document.getElementById('ctl_window').value    = d.window ?? 5;
  document.getElementById('ctl_cool').value      = d.cooldown_sec ?? 30;
  // fetch model metadata
  try { const m = await (await fetch('/api/model')).json(); modelMeta = (m.model || {}); } catch {}
}

async function saveConfig(){
  const body = {
    decision: {
      threshold: parseFloat(document.getElementById('ctl_threshold').value),
      grace: parseInt(document.getElementById('ctl_grace').value),
      window: parseInt(document.getElementById('ctl_window').value),
      cooldown_sec: parseInt(document.getElementById('ctl_cool').value),
    }
  };
  const r = await fetch('/api/config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const j = await r.json();
  const msg = document.getElementById('save_msg');
  msg.textContent = j.ok ? 'Saved (restart decision loop to apply)' : ('Error: '+(j.error||'')); 
  setTimeout(()=> msg.textContent='', 3500);
}

function tickClock(){ document.getElementById('clock').innerText = new Date().toISOString(); }

async function tick(){
  tickClock();
  await refreshCounts();
  await refreshEvents();
}

function setupChart(){
  const ctx = document.getElementById('scoreChart').getContext('2d');
  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Score',
        data: [],
        borderWidth: 2,
        pointRadius: 0
      }]
    },
    options: {
      animation: false,
      responsive: true,
      scales: {
        x: { ticks: { display:false } },
        y: { min:0, max:1 }
      },
      plugins:{ legend:{ display:false } }
    }
  });
}

document.getElementById('btn_download').onclick = ()=>{ window.location='/api/download.csv'; };

document.getElementById('btn_clear').onclick = async ()=>{
  if (!confirm('Clear alerts log? This cannot be undone.')) return;
  const r = await fetch('/api/clear', {method:'POST'});
  const j = await r.json();
  if (j.ok){
    document.getElementById('rows').innerHTML='';
    chartData.labels = []; chartData.scores = []; chart.update();
    toast('Alerts cleared');
  } else {
    toast('Error clearing alerts');
  }
};

document.getElementById('btn_clear_all').onclick = async ()=>{
  if (!confirm('Clear alerts AND reset state? The decision loop offset will reset.')) return;
  const r = await fetch('/api/clear_all', {method:'POST'});
  const j = await r.json();
  if (j.ok){
    document.getElementById('rows').innerHTML='';
    chartData.labels = []; chartData.scores = []; chart.update();
    toast('Alerts + state cleared');
  } else {
    toast('Error clearing all');
  }
};

document.getElementById('btn_save').onclick = saveConfig;

// init
setupChart();
loadConfig();
setInterval(tick, 2000);
tick();
</script>
</body>
</html>
    """
    resp = Response(html, mimetype="text/html")
    # Prevent stale cached UI — always fetch latest HTML/JS
    resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
