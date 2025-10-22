# scripts/console_dashboard.py
# -----------------------------------------------------------------------------
# Utility — Console dashboard (Rich)
#
# Purpose
#   - Quick terminal visualization of recent events and counters using Rich.
#   - Handy during development when a browser is not available.
#
# Inputs/Outputs
#   - Reads data/alerts.jsonl written by the decision loop.
# -----------------------------------------------------------------------------
import json, time, os
from pathlib import Path
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

ALERT_LOG = Path("data/alerts.jsonl")

def read_last_n(n=50):
    if not ALERT_LOG.exists(): return []
    lines = ALERT_LOG.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-n:]:
        try: out.append(json.loads(line))
        except: pass
    return out

def make_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=3),
        Layout(name="body"),
    )
    return layout

def header(counts):
    t = Text()
    t.append(" IoTGuard Console ", style="bold white on dark_green")
    t.append("  ")
    t.append(f"Total: {counts['total']}", style="bold cyan")
    t.append("   ")
    t.append(f"Attacks: {counts['attacks']}", style="bold red")
    t.append("   ")
    t.append(f"Blocks: {counts['blocks']}", style="bold yellow")
    return Panel(t, expand=True)

def table(events):
    tbl = Table(show_header=True, header_style="bold cyan")
    tbl.add_column("Time (UTC)", width=25)
    tbl.add_column("Idx", justify="right")
    tbl.add_column("Score", justify="right")
    tbl.add_column("State")
    tbl.add_column("Hits")
    tbl.add_column("Action")
    for e in reversed(events):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e.get("ts", 0)))
        idx = str(e.get("index", ""))
        score = f"{e.get('score', 0):.3f}"
        state = "[red]ATTACK[/red]" if e.get("state") == "ATTACK" else "[green]benign[/green]"
        hits = str(e.get("hits_in_window", 0))
        action = "[yellow]BLOCK[/yellow]" if e.get("action") == "BLOCK" else "—"
        tbl.add_row(ts, idx, score, state, hits, action)
    return tbl

def count_summary(events, window_sec=3600):
    cutoff = time.time() - window_sec
    total = attacks = blocks = 0
    for e in events:
        if e.get("ts", 0) >= cutoff:
            total += 1
            if e.get("state") == "ATTACK": attacks += 1
            if e.get("action") == "BLOCK": blocks += 1
    return {"total": total, "attacks": attacks, "blocks": blocks}

if __name__ == "__main__":
    layout = make_layout()
    with Live(layout, refresh_per_second=4, screen=False):
        while True:
            evts = read_last_n(80)
            counts = count_summary(evts, 3600)
            layout["top"].update(header(counts))
            layout["body"].update(table(evts))
            time.sleep(1)
