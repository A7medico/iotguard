"""
scripts/threat_intel.py
-----------------------------------------------------------------------------
IoTGuard Component — Lightweight Threat Intelligence Enrichment

Position in pipeline
    decision_loop.py
        →  reads top_src_ip from window_meta.json
        →  [THIS FILE] (IP → country / flag / reputation tag)
        →  alerts.jsonl / dashboard ("Threat Intel" column)

High‑level responsibilities
    - Provide a simple, demo‑friendly way to attach **context** to source IPs:
        * approximate country + flag (simulated GeoIP),
        * a small reputation label if the IP is in a known‑bad list
          (e.g. "Mirai Botnet Node", "Mass Scanner").
    - Return a compact dict so the decision loop can embed it directly in each
      event, and the dashboard can render flags + labels.

Note
    - This module intentionally simulates GeoIP/threat data; in a real deployment
      you would replace this logic with calls to:
        * a GeoIP database (e.g. MaxMind / geoip2),
        * a threat‑intel API (AbuseIPDB, VirusTotal, internal feeds, etc).
-----------------------------------------------------------------------------
"""

import random

class ThreatIntel:
    def __init__(self):
        # Simulated known bad IPs for demo
        self.reputation_db = {
            "192.168.1.105": "Mirai Botnet Node",
            "10.0.0.50": "Command & Control Server",
            "45.33.22.11": "Mass Scanner",
        }
        
        # Simulated Country DB
        # We will randomly assign countries to private IPs for the demo visualization
        self.countries = ["US", "CN", "RU", "DE", "BR", "IN"]
        self.flags = {
            "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺", "DE": "🇩🇪", "BR": "🇧🇷", "IN": "🇮🇳", "Unknown": "🏳️"
        }

    def enrich_ip(self, ip):
        """
        Returns a dict with context: {country, flag, threat_tag}
        """
        if not ip:
            return {"country": "Unknown", "flag": "🏳️", "threat": None}

        # 1. Check Reputation
        threat = self.reputation_db.get(ip)

        # 2. Simulate GeoIP (Deterministic hash for consistency)
        # In real code: reader.city(ip).country.iso_code
        seed = sum(ord(c) for c in ip)
        idx = seed % len(self.countries)
        country = self.countries[idx]
        
        return {
            "country": country,
            "flag": self.flags.get(country, "🏳️"),
            "threat": threat
        }

