# scripts/api_dashboard.py
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
    for evt in _iter_alerts() or []:
        if evt.get("ts", 0) >= cutoff:
            total += 1
            if evt.get("state") == "ATTACK":
                attacks += 1
            if evt.get("action") == "BLOCK":
                blocks += 1
    return jsonify({"ok": True, "window_minutes": mins, "total": total, "attacks": attacks, "blocks": blocks})

@app.get("/api/events")
def api_events():
    """Return events since a given timestamp (or last 200 if not provided)."""
    since = request.args.get("since_ts", type=float)
    if since is None:
        data = read_last_n(200)
    else:
        data = [e for e in (_iter_alerts() or []) if e.get("ts", 0) > since]
    return jsonify({"ok": True, "events": data, "server_time": now_ts()})

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
    writer = csv.DictWriter(output, fieldnames=["ts","index","score","state","hits_in_window","action"])
    writer.writeheader()
    for e in _iter_alerts() or []:
        writer.writerow({
            "ts": e.get("ts"),
            "index": e.get("index"),
            "score": e.get("score"),
            "state": e.get("state"),
            "hits_in_window": e.get("hits_in_window"),
            "action": e.get("action"),
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
  :root { --bg:#0b0f14; --panel:#111827; --ink:#e6edf3; --muted:#9ca3af; --row:#1f2937; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 20px; background:var(--bg); color:var(--ink); }
  h1 { margin: 0 0 6px; }
  .grid { display:grid; grid-template-columns: 1fr 1fr 1fr; gap:10px; }
  .card { background:var(--panel); padding:12px 14px; border-radius:12px; box-shadow: 0 2px 8px rgba(0,0,0,.25); }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  table { width:100%; border-collapse:collapse; margin-top:12px; }
  th, td { padding:8px 10px; border-bottom:1px solid var(--row); font-size:14px; white-space:nowrap; }
  th { text-align:left; color:var(--muted); }
  .tag { padding:2px 8px; border-radius:999px; font-weight:600; font-size:12px; }
  .ok { background:#0b3d1f; color:#8ff2b2; }
  .warn { background:#3d2a0b; color:#f2d28f; }
  .bad { background:#3d0b0b; color:#f28f8f; }
  .footer { color:var(--muted); font-size:12px; margin-top:10px; }
  .btn { background:#0f172a; color:#cbd5e1; border:1px solid #334155; padding:6px 10px; border-radius:8px; cursor:pointer; }
  .btn:hover { filter:brightness(1.15); }
  input[type=number] { width:90px; background:#0f172a; color:#e6edf3; border:1px solid #334155; border-radius:8px; padding:6px 8px; }
  .chart-box { height:220px; }
</style>
</head>
<body>
  <h1>IoTGuard — Live Alerts</h1>

  <div class="grid">
    <div class="card"><div>Last 60 min — Total</div><div id="mt_total" style="font-size:24px;font-weight:700">0</div></div>
    <div class="card"><div>Last 60 min — Attacks</div><div id="mt_attacks" style="font-size:24px;font-weight:700;color:#f28f8f">0</div></div>
    <div class="card"><div>Last 60 min — Blocks</div><div id="mt_blocks" style="font-size:24px;font-weight:700;color:#f2d28f">0</div></div>
  </div>

  <div class="card" style="margin-top:12px;">
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

  <div class="card chart-box"><canvas id="scoreChart" style="width:100%;height:100%;"></canvas></div>

  <div class="card" style="margin-top:12px;">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div style="font-weight:700;">Recent Events</div>
    </div>
    <table>
      <thead>
        <tr><th>Time (UTC)</th><th>Index</th><th>Score</th><th>State</th><th>Window Hits</th><th>Action</th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>

  <div class="footer">Auto-refreshing every 2s. Backed by alerts.jsonl.</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
let lastTs = null;
let chart, chartData = {labels: [], scores: []};
let lastBlockTs = 0;

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
    return Response(html, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
