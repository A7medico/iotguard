"""
scripts/threat_intel.py
-----------------------------------------------------------------------------
IoTGuard Component — Lightweight Threat Intelligence Enrichment

Position in pipeline
    decision_loop.py
        →  reads top_src_ip from window_meta.json
        →  [THIS FILE] (IP → country / flag / reputation tag)
        →  alerts.jsonl / dashboard ("Threat Intel" column)

High-level responsibilities
    - Provide a simple, demo-friendly way to attach **context** to source IPs:
        * Approximate country + flag emoji (simulated GeoIP)
        * A small reputation label if the IP is in a known-bad list
          (e.g. "Mirai Botnet Node", "Mass Scanner")
    - Return a compact dict so the decision loop can embed it directly in each
      event, and the dashboard can render flags + labels.

Production Replacement
    In a real deployment, you would replace this logic with calls to:
        * A GeoIP database (e.g. MaxMind GeoLite2 / geoip2)
        * A threat-intel API (AbuseIPDB, VirusTotal, Shodan, internal feeds)
        * An IP reputation cache for performance

Demo Behavior
    This module intentionally simulates GeoIP/threat data for demonstrations:
    - Country is deterministically derived from IP hash (consistent across runs)
    - Reputation tags are from a small hardcoded list
    - Flags are emoji characters for visual appeal in the dashboard

Usage
    from threat_intel import ThreatIntel
    
    ti = ThreatIntel()
    info = ti.enrich_ip("192.168.1.100")
    # Returns: {"country": "US", "flag": "🇺🇸", "threat": None}
    
    info = ti.enrich_ip("192.168.1.105")
    # Returns: {"country": "CN", "flag": "🇨🇳", "threat": "Mirai Botnet Node"}
-----------------------------------------------------------------------------
"""

from typing import Optional, Dict, Any


class ThreatIntel:
    """
    Lightweight threat intelligence enrichment for IP addresses.
    
    This class provides IP-to-context mapping for the IoTGuard dashboard,
    including country identification and reputation tagging.
    
    Attributes:
        reputation_db: Dict mapping known-bad IPs to their threat labels.
        countries: List of country codes for simulated GeoIP.
        flags: Dict mapping country codes to flag emojis.
        
    Note:
        This is a simulation for demo purposes. In production, replace
        with actual GeoIP database and threat intelligence API calls.
    """
    
    def __init__(self):
        """
        Initialize the ThreatIntel instance with demo data.
        
        Sets up:
        - reputation_db: Known malicious IPs with their threat categories
        - countries: Pool of country codes for simulated GeoIP
        - flags: Emoji mappings for visual representation
        """
        # ---------- Reputation Database ----------
        # Simulated known-bad IPs for demo purposes.
        # In production, this would be populated from:
        # - Threat intelligence feeds (AbuseIPDB, VirusTotal, etc.)
        # - Internal blocklists from previous incidents
        # - Honeypot data and attack signatures
        self.reputation_db: Dict[str, str] = {
            "192.168.1.105": "Mirai Botnet Node",      # IoT malware
            "10.0.0.50": "Command & Control Server",   # C2 infrastructure
            "45.33.22.11": "Mass Scanner",             # Reconnaissance
        }
        
        # ---------- GeoIP Simulation ----------
        # Country codes for deterministic IP → country mapping.
        # In production, use MaxMind GeoLite2 or similar database.
        self.countries: list = ["US", "CN", "RU", "DE", "BR", "IN"]
        
        # Flag emoji mappings for visual display in dashboard.
        # Each country code maps to its corresponding flag emoji.
        self.flags: Dict[str, str] = {
            "US": "🇺🇸",  # United States
            "CN": "🇨🇳",  # China
            "RU": "🇷🇺",  # Russia
            "DE": "🇩🇪",  # Germany
            "BR": "🇧🇷",  # Brazil
            "IN": "🇮🇳",  # India
            "Unknown": "🏳️"  # Unknown/default
        }

    def enrich_ip(self, ip: Optional[str]) -> Dict[str, Any]:
        """
        Enrich an IP address with threat intelligence context.
        
        This method provides:
        1. Geographic context (country + flag) via simulated GeoIP
        2. Reputation tag if the IP is in the known-bad list
        
        Args:
            ip: The IP address to enrich. Can be None or empty.
            
        Returns:
            Dict with keys:
                - country: Two-letter country code (e.g., "US", "CN")
                - flag: Flag emoji for the country (e.g., "🇺🇸")
                - threat: Threat label if known-bad, else None
                
        Examples:
            >>> ti = ThreatIntel()
            >>> ti.enrich_ip("8.8.8.8")
            {'country': 'DE', 'flag': '🇩🇪', 'threat': None}
            
            >>> ti.enrich_ip("192.168.1.105")
            {'country': 'CN', 'flag': '🇨🇳', 'threat': 'Mirai Botnet Node'}
            
            >>> ti.enrich_ip(None)
            {'country': 'Unknown', 'flag': '🏳️', 'threat': None}
        """
        # Handle missing or empty IP
        if not ip:
            return {
                "country": "Unknown",
                "flag": "🏳️",
                "threat": None
            }

        # ---------- Step 1: Check Reputation ----------
        # Look up the IP in our known-bad database.
        # In production, this would query threat intelligence APIs.
        threat = self.reputation_db.get(ip)

        # ---------- Step 2: Simulate GeoIP Lookup ----------
        # Create a deterministic hash from the IP string.
        # This ensures the same IP always maps to the same country
        # (important for consistent demo behavior across runs).
        # 
        # In production, replace with actual GeoIP lookup:
        #   import geoip2.database
        #   reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        #   response = reader.country(ip)
        #   country = response.country.iso_code
        seed = sum(ord(c) for c in ip)  # Simple hash: sum of ASCII values
        idx = seed % len(self.countries)  # Map to country index
        country = self.countries[idx]
        
        # ---------- Step 3: Build Response ----------
        return {
            "country": country,
            "flag": self.flags.get(country, "🏳️"),
            "threat": threat
        }
    
    def add_reputation(self, ip: str, threat_label: str) -> None:
        """
        Add or update an IP's reputation in the database.
        
        This method allows dynamic updates to the threat intelligence
        database, useful for integrating with external feeds or
        learning from detected attacks.
        
        Args:
            ip: The IP address to add/update.
            threat_label: The threat category label (e.g., "Botnet Node").
        """
        self.reputation_db[ip] = threat_label
    
    def is_known_threat(self, ip: str) -> bool:
        """
        Check if an IP is in the known-bad reputation database.
        
        Args:
            ip: The IP address to check.
            
        Returns:
            True if the IP has a reputation entry, False otherwise.
        """
        return ip in self.reputation_db
