"""
scripts/6_threat_intel/threat_intel.py
-----------------------------------------------------------------------------
IoTGuard Component — Production Threat Intelligence & GeoIP Enrichment (Phase 5)

Position in pipeline:
    decision_loop.py
        → reads top_src_ip from window_meta.json
        → [THIS FILE] (IP → country / city / flag / ISP / ASN / abuse score)
        → alerts.jsonl / dashboard ("Threat Intel" column & topology map)

Capabilities:
    1. Real MaxMind GeoIP2:
       Supports official GeoLite2-City and GeoLite2-Country .mmdb readers via
       the `geoip2` library, resolving real country, city, and GPS coordinates.
       Gracefully falls back to deterministic simulation when offline or when
       no .mmdb file is present.
    2. Reputation Lookup Adapters:
       Integrated with AbuseIPDB and AlienVault OTX APIs (configured via
       environment variables IOTGUARD_ABUSEIPDB_API_KEY and IOTGUARD_OTX_API_KEY)
       to retrieve real-time abuse confidence scores, ISP, and ASN data.
    3. Thread-Safe In-Memory TTL Caching:
       Caches reputation and GeoIP results with configurable TTL
       (IOTGUARD_THREAT_CACHE_TTL, default: 3600s) to prevent redundant API
       calls and maintain high throughput in the decision loop.
    4. Asynchronous Non-Blocking Lookups:
       Provides both fast bounded synchronous lookups (with strict timeout)
       and background thread-pool lookups to avoid stalling packet processing.
-----------------------------------------------------------------------------
"""

import ipaddress
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("iotguard.threat_intel")

# ── Optional MaxMind GeoIP2 Support ──────────────────────────────────────────
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    geoip2 = None

# ── Optional HTTP Client for External APIs ───────────────────────────────────
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None


def iso_country_to_flag(code: Optional[str]) -> str:
    """Convert a two-letter ISO country code to a Unicode flag emoji."""
    if not code or len(code) != 2:
        return "🏳️"
    code = code.upper()
    try:
        # Regional Indicator Symbol Letter A is U+1F1E6
        first = chr(ord(code[0]) - 65 + 0x1F1E6)
        second = chr(ord(code[1]) - 65 + 0x1F1E6)
        return f"{first}{second}"
    except Exception:
        return "🏳️"


class ThreatIntel:
    """
    Production-ready Threat Intelligence & GeoIP Resolver.

    Provides multi-tiered IP enrichment:
      Tier 1: In-memory thread-safe TTL cache.
      Tier 2: MaxMind GeoLite2 City/Country database (.mmdb).
      Tier 3: External Threat APIs (AbuseIPDB, AlienVault OTX) if keys configured.
      Tier 4: Built-in local reputation DB + deterministic fallback.
    """

    def __init__(
        self,
        geoip_db_path: Optional[str] = None,
        abuseipdb_key: Optional[str] = None,
        otx_key: Optional[str] = None,
        cache_ttl: Optional[int] = None,
    ):
        # 1. Reputation Database (Static / Local IOCs)
        self.reputation_db: Dict[str, str] = {
            "192.168.1.105": "Mirai Botnet Node",
            "10.0.0.50": "Command & Control Server",
            "45.33.22.11": "Mass Scanner",
            "185.220.101.5": "Tor Exit Node",
            "194.26.29.112": "Mirai Loader / Brute-Forcer",
        }

        # Deterministic simulation pool (for fallback or offline mode)
        self.simulated_countries: List[str] = ["US", "CN", "RU", "DE", "BR", "IN", "GB", "NL", "FR", "JP"]

        # 2. TTL Cache Setup
        env_ttl = os.getenv("IOTGUARD_THREAT_CACHE_TTL")
        self.cache_ttl = int(cache_ttl or env_ttl or 3600)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # 3. External API Credentials
        self.abuseipdb_key = abuseipdb_key or os.getenv("IOTGUARD_ABUSEIPDB_API_KEY")
        self.otx_key = otx_key or os.getenv("IOTGUARD_OTX_API_KEY")

        # 4. MaxMind GeoIP2 Reader Setup
        self.geoip_reader = None
        self.geoip_db_path = None
        self._init_geoip_reader(geoip_db_path)

        # 5. Background Thread Pool for Async Lookups
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="threat_intel")

    def _init_geoip_reader(self, db_path: Optional[str] = None) -> None:
        """Initialize MaxMind GeoIP2 database reader if file is present."""
        if not GEOIP2_AVAILABLE:
            logger.info("geoip2 package not available; using deterministic resolver")
            return

        candidates = [
            db_path,
            os.getenv("IOTGUARD_GEOIP_DB"),
            "data/GeoLite2-City.mmdb",
            "data/GeoLite2-Country.mmdb",
            "models/GeoLite2-City.mmdb",
            "models/GeoLite2-Country.mmdb",
        ]

        for p in candidates:
            if p and Path(p).exists():
                try:
                    self.geoip_reader = geoip2.database.Reader(str(p))
                    self.geoip_db_path = str(p)
                    logger.info(f"Loaded MaxMind GeoIP2 database from {p}")
                    return
                except Exception as e:
                    logger.warning(f"Failed to open GeoIP2 database at {p}: {e}")

        logger.debug("No MaxMind .mmdb file found; fallback enabled")

    # ── Utility Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if an IP address belongs to private/loopback/link-local ranges."""
        try:
            obj = ipaddress.ip_address(ip.strip())
            return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved
        except Exception:
            return False

    # ── GeoIP Resolution ─────────────────────────────────────────────────────

    def _resolve_geoip(self, ip: str) -> Dict[str, Any]:
        """Resolve country, city, and coordinates via MaxMind or deterministic fallback."""
        if self.is_private_ip(ip):
            return {
                "country": "LAN",
                "country_name": "Private Network",
                "city": "Internal Gateway",
                "flag": "🏠",
                "source": "private",
            }

        # 1. Query MaxMind GeoLite2
        if self.geoip_reader is not None:
            try:
                # Try City lookup first, fallback to Country
                if hasattr(self.geoip_reader, "city"):
                    res = self.geoip_reader.city(ip)
                    iso = res.country.iso_code or res.registered_country.iso_code or "Unknown"
                    name = res.country.name or "Unknown"
                    city = res.city.name if res.city and res.city.name else None
                    lat = res.location.latitude
                    lon = res.location.longitude
                else:
                    res = self.geoip_reader.country(ip)
                    iso = res.country.iso_code or "Unknown"
                    name = res.country.name or "Unknown"
                    city = None
                    lat, lon = None, None

                return {
                    "country": iso,
                    "country_name": name,
                    "city": city,
                    "latitude": lat,
                    "longitude": lon,
                    "flag": iso_country_to_flag(iso),
                    "source": "geoip2",
                }
            except Exception as e:
                logger.debug(f"GeoIP2 lookup miss for {ip}: {e}")

        # 2. Deterministic Hash Fallback (Consistent across runs)
        seed = sum(ord(c) for c in ip)
        idx = seed % len(self.simulated_countries)
        country_code = self.simulated_countries[idx]
        country_names = {
            "US": "United States", "CN": "China", "RU": "Russia", "DE": "Germany",
            "BR": "Brazil", "IN": "India", "GB": "United Kingdom", "NL": "Netherlands",
            "FR": "France", "JP": "Japan",
        }

        return {
            "country": country_code,
            "country_name": country_names.get(country_code, "Unknown"),
            "city": None,
            "latitude": None,
            "longitude": None,
            "flag": iso_country_to_flag(country_code),
            "source": "simulated",
        }

    # ── Reputation Resolvers (AbuseIPDB & OTX) ────────────────────────────────

    def _query_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API for abuse confidence score, ISP, and domain."""
        if not self.abuseipdb_key or not REQUESTS_AVAILABLE or self.is_private_ip(ip):
            return None

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Key": self.abuseipdb_key,
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            }
            resp = requests.get(url, headers=headers, params=params, timeout=1.5)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                isp = data.get("isp")
                domain = data.get("domain")
                total_reports = data.get("totalReports", 0)

                threat_tag = None
                if score >= 75:
                    threat_tag = f"High Abuse Risk ({score}%)"
                elif score >= 25:
                    threat_tag = f"Suspicious Host ({score}%)"

                return {
                    "abuse_confidence_score": score,
                    "isp": isp,
                    "domain": domain,
                    "total_reports": total_reports,
                    "threat": threat_tag,
                    "source": "abuseipdb",
                }
        except Exception as e:
            logger.debug(f"AbuseIPDB API request failed for {ip}: {e}")

        return None

    def _query_alienvault_otx(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX for indicator pulses and ASN details."""
        if not self.otx_key or not REQUESTS_AVAILABLE or self.is_private_ip(ip):
            return None

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.otx_key}
            resp = requests.get(url, headers=headers, timeout=1.5)
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                asn = data.get("asn")
                threat_tag = f"OTX Threat ({pulse_count} pulses)" if pulse_count > 0 else None
                return {
                    "asn": asn,
                    "pulse_count": pulse_count,
                    "threat": threat_tag,
                    "source": "alienvault_otx",
                }
        except Exception as e:
            logger.debug(f"AlienVault OTX API request failed for {ip}: {e}")

        return None

    # ── Main Enrichment API ──────────────────────────────────────────────────

    def enrich_ip(self, ip: Optional[str]) -> Dict[str, Any]:
        """
        Enrich an IP address with GeoIP, reputation, and threat tags.

        Args:
            ip: IPv4/IPv6 address string.

        Returns:
            Dict containing:
                - country: 2-letter ISO code
                - country_name: Full country name
                - flag: Flag emoji
                - city: City name (if resolved)
                - threat: Threat label (or None)
                - isp: Internet Service Provider (if resolved)
                - asn: Autonomous System Number (if resolved)
                - abuse_confidence_score: 0-100 score (if resolved)
                - is_malicious: boolean flag
                - source: Detection metadata source
        """
        if not ip or not isinstance(ip, str):
            return {
                "ip": "unknown",
                "country": "Unknown",
                "country_name": "Unknown",
                "flag": "🏳️",
                "city": None,
                "threat": None,
                "isp": None,
                "asn": None,
                "abuse_confidence_score": 0,
                "abuse_score": 0,
                "is_malicious": False,
                "is_private": False,
                "source": "none",
            }

        clean_ip = ip.strip()

        # 1. Check TTL Cache
        now = time.time()
        with self._lock:
            cached = self._cache.get(clean_ip)
            if cached and cached.get("expires_at", 0) > now:
                return cached["data"].copy()

        # 2. Check Static Reputation Database
        local_threat = self.reputation_db.get(clean_ip)

        # 3. Resolve GeoIP
        geo_info = self._resolve_geoip(clean_ip)

        # 4. Query External Reputation (AbuseIPDB / OTX) if keys configured
        ext_rep = None
        if self.abuseipdb_key:
            ext_rep = self._query_abuseipdb(clean_ip)
        elif self.otx_key:
            ext_rep = self._query_alienvault_otx(clean_ip)

        # 5. Assemble Payload
        threat_label = local_threat
        isp = None
        asn = None
        abuse_score = 0
        source = geo_info.get("source", "simulated")

        if ext_rep:
            threat_label = threat_label or ext_rep.get("threat")
            isp = ext_rep.get("isp")
            asn = ext_rep.get("asn")
            abuse_score = ext_rep.get("abuse_confidence_score", 0)
            source = f"{source}+{ext_rep.get('source', 'api')}"

        is_malicious = bool(threat_label or abuse_score >= 50)

        result = {
            "ip": clean_ip,
            "country": geo_info.get("country", "Unknown"),
            "country_name": geo_info.get("country_name", "Unknown"),
            "flag": geo_info.get("flag", "🏳️"),
            "city": geo_info.get("city"),
            "latitude": geo_info.get("latitude"),
            "longitude": geo_info.get("longitude"),
            "threat": threat_label,
            "isp": isp,
            "asn": asn,
            "abuse_confidence_score": abuse_score,
            "abuse_score": abuse_score,
            "is_malicious": is_malicious,
            "is_private": self.is_private_ip(clean_ip),
            "source": source,
        }

        # 6. Store in TTL Cache
        with self._lock:
            self._cache[clean_ip] = {
                "data": result.copy(),
                "expires_at": now + self.cache_ttl,
            }

        return result

    def enrich_ip_async(
        self,
        ip: str,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        """Asynchronously enrich an IP in the background pool."""
        def _task():
            res = self.enrich_ip(ip)
            if callback:
                try:
                    callback(res)
                except Exception as e:
                    logger.warning(f"Error in async enrich callback for {ip}: {e}")
            return res

        return self._executor.submit(_task)

    def add_reputation(self, ip: str, threat_label: str) -> None:
        """Add or update an IP's reputation in the database and invalidate cache."""
        clean_ip = ip.strip()
        self.reputation_db[clean_ip] = threat_label
        with self._lock:
            if clean_ip in self._cache:
                del self._cache[clean_ip]

    def is_known_threat(self, ip: str) -> bool:
        """Check if an IP has a known malicious reputation."""
        clean_ip = ip.strip() if ip else ""
        if clean_ip in self.reputation_db:
            return True
        with self._lock:
            cached = self._cache.get(clean_ip)
            if cached and cached.get("data", {}).get("is_malicious"):
                return True
        return False

    def clear_cache(self) -> None:
        """Clear the in-memory threat intelligence TTL cache."""
        with self._lock:
            self._cache.clear()
