"""
scripts/alerts_webhook.py
-----------------------------------------------------------------------------
Optional helper: tail data/alerts.jsonl and POST selected events to a webhook.

Usage (from project root, venv active):
    python scripts/alerts_webhook.py --url https://example.com/webhook

By default it forwards only BLOCK-* events; use --all to send every alert.
-----------------------------------------------------------------------------
"""

import argparse
import json
import time
from pathlib import Path

import requests


def tail_file(path: Path, delay: float = 0.5):
    path.touch(exist_ok=True)
    with path.open("r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                time.sleep(delay)
                f.seek(pos)
                continue
            yield line


def main() -> None:
    ap = argparse.ArgumentParser(description="Forward IoTGuard alerts.jsonl to an HTTP webhook.")
    ap.add_argument("--url", required=True, help="Webhook URL to POST each event to.")
    ap.add_argument("--all", action="store_true", help="If set, send ALL alerts, not just BLOCK-*.")
    ap.add_argument("--dry-run", action="store_true", help="Print instead of sending HTTP requests.")
    args = ap.parse_args()

    alerts_path = Path("data/alerts.jsonl")
    print(f"[*] Forwarding alerts from {alerts_path} to {args.url} (all={args.all}, dry={args.dry_run})")

    for line in tail_file(alerts_path):
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue

        if not args.all:
            action = str(evt.get("action") or "")
            if not action.startswith("BLOCK"):
                continue

        if args.dry_run:
            print(json.dumps(evt))
            continue

        try:
            r = requests.post(args.url, json=evt, timeout=3.0)
            if r.status_code >= 400:
                print(f"[warn] Webhook returned {r.status_code}: {r.text[:200]}")
        except Exception as e:
            print(f"[warn] Failed to POST to webhook: {e}")


if __name__ == "__main__":
    main()





