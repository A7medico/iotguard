"""
scripts/9_utilities/rate_limiter.py
-----------------------------------------------------------------------------
IoTGuard — Rate Limiting and Access Control Module

Purpose:
    - Rate limit API requests to prevent abuse
    - Manage IP allowlist/blocklist for manual overrides
    - Provide decorators for Flask routes

Configuration:
    Loaded from configs/access_control.yaml

Usage:
    from rate_limiter import RateLimiter, AccessControl

    # Rate limiting
    limiter = RateLimiter()

    @app.before_request
    def check_rate_limit():
        if not limiter.is_allowed(request.remote_addr):
            return jsonify({"error": "Rate limit exceeded"}), 429

    # Access control
    access = AccessControl()
    if access.is_blocklisted(ip):
        block_immediately(ip)
    if access.is_allowlisted(ip):
        skip_ml_detection(ip)
-----------------------------------------------------------------------------
"""
import os
import time
import ipaddress
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# =============================================================================
# CONFIGURATION
# =============================================================================
CONFIG_PATH = Path("configs/access_control.yaml")


def _load_config() -> dict:
    """Load access control configuration from YAML file."""
    if not YAML_AVAILABLE:
        return {}

    if not CONFIG_PATH.exists():
        return {}

    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


# =============================================================================
# IP NETWORK UTILITIES
# =============================================================================
def _parse_ip_list(ip_list: List[str]) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse a list of IP addresses/CIDR ranges into network objects.

    Handles:
        - Single IPs: "192.168.1.1" -> 192.168.1.1/32
        - CIDR ranges: "10.0.0.0/24"
        - IPv6: "2001:db8::1"
    """
    networks = set()

    for entry in ip_list or []:
        try:
            entry = str(entry).strip()
            if not entry:
                continue

            # Parse as network (handles both single IPs and CIDR)
            if "/" in entry:
                networks.add(ipaddress.ip_network(entry, strict=False))
            else:
                # Single IP - convert to /32 or /128 network
                ip = ipaddress.ip_address(entry)
                prefix = 32 if ip.version == 4 else 128
                networks.add(ipaddress.ip_network(f"{entry}/{prefix}", strict=False))
        except ValueError:
            # Invalid IP format - skip silently
            continue

    return networks


def _ip_in_networks(
    ip: str,
    networks: Set[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    """Check if an IP address is within any of the given networks."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        for network in networks:
            if addr in network:
                return True
    except ValueError:
        pass
    return False


# =============================================================================
# ACCESS CONTROL (ALLOWLIST / BLOCKLIST)
# =============================================================================
@dataclass
class AccessControl:
    """
    Manages IP allowlist and blocklist for manual override of ML detection.

    Allowlist: IPs that bypass ML detection (never blocked)
    Blocklist: IPs that are always blocked (bypass ML detection)

    Blocklist takes precedence over allowlist.

    Usage:
        access = AccessControl()

        # In decision loop
        if access.is_blocklisted(src_ip):
            block_immediately(src_ip)
        elif access.is_allowlisted(src_ip):
            skip_ml_check(src_ip)
        else:
            run_ml_detection(src_ip)
    """

    _allowlist: Set = field(default_factory=set)
    _blocklist: Set = field(default_factory=set)
    _config_mtime: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        """Load configuration on initialization."""
        self._reload_config()

    def _reload_config(self) -> None:
        """Reload configuration from file if changed."""
        try:
            if CONFIG_PATH.exists():
                mtime = CONFIG_PATH.stat().st_mtime
                if mtime > self._config_mtime:
                    config = _load_config()
                    self._allowlist = _parse_ip_list(config.get("allowlist", []))
                    self._blocklist = _parse_ip_list(config.get("blocklist", []))
                    self._config_mtime = mtime
        except Exception:
            pass

    def is_allowlisted(self, ip: str) -> bool:
        """
        Check if an IP is on the allowlist.

        Allowlisted IPs bypass ML detection and are never blocked
        by the automated system.

        Args:
            ip: IP address to check

        Returns:
            True if IP is allowlisted
        """
        with self._lock:
            self._reload_config()
            return _ip_in_networks(ip, self._allowlist)

    def is_blocklisted(self, ip: str) -> bool:
        """
        Check if an IP is on the blocklist.

        Blocklisted IPs are immediately blocked without ML detection.
        Blocklist takes precedence over allowlist.

        Args:
            ip: IP address to check

        Returns:
            True if IP is blocklisted
        """
        with self._lock:
            self._reload_config()
            return _ip_in_networks(ip, self._blocklist)

    def check_access(self, ip: str) -> Tuple[str, bool]:
        """
        Comprehensive access check for an IP.

        Returns:
            Tuple of (action, should_skip_ml) where:
            - action: "block" | "allow" | "check"
            - should_skip_ml: True if ML detection should be skipped
        """
        with self._lock:
            self._reload_config()

            # Blocklist takes precedence
            if _ip_in_networks(ip, self._blocklist):
                return ("block", True)

            if _ip_in_networks(ip, self._allowlist):
                return ("allow", True)

            return ("check", False)

    def get_stats(self) -> dict:
        """Get current allowlist/blocklist statistics."""
        with self._lock:
            self._reload_config()
            return {
                "allowlist_count": len(self._allowlist),
                "blocklist_count": len(self._blocklist),
                "config_loaded": self._config_mtime > 0,
            }


# =============================================================================
# RATE LIMITER
# =============================================================================
@dataclass
class RateLimiter:
    """
    Token bucket rate limiter for API endpoints.

    Tracks request counts per IP address and enforces configurable
    rate limits to prevent abuse.

    Configuration (from access_control.yaml):
        rate_limiting:
          enabled: true
          default_limit: 100
          window_seconds: 60
          exempt_ips: ["127.0.0.1"]

    Usage:
        limiter = RateLimiter()

        @app.before_request
        def check_rate():
            if not limiter.is_allowed(request.remote_addr):
                return "Rate limit exceeded", 429
    """

    _requests: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _config_mtime: float = 0.0

    # Configuration (loaded from YAML)
    enabled: bool = True
    default_limit: int = 100
    window_seconds: int = 60
    exempt_ips: Set[str] = field(default_factory=set)

    # Per-endpoint limits
    login_limit: int = 5
    config_limit: int = 10

    def __post_init__(self):
        """Load configuration on initialization."""
        self._reload_config()

    def _reload_config(self) -> None:
        """Reload rate limiting configuration from file."""
        try:
            if CONFIG_PATH.exists():
                mtime = CONFIG_PATH.stat().st_mtime
                if mtime > self._config_mtime:
                    config = _load_config()
                    rate_cfg = config.get("rate_limiting", {})

                    self.enabled = bool(rate_cfg.get("enabled", True))
                    self.default_limit = int(rate_cfg.get("default_limit", 100))
                    self.window_seconds = int(rate_cfg.get("window_seconds", 60))
                    self.login_limit = int(rate_cfg.get("login_limit", 5))
                    self.config_limit = int(rate_cfg.get("config_limit", 10))

                    exempt = rate_cfg.get("exempt_ips", [])
                    self.exempt_ips = set(str(ip).strip() for ip in exempt)

                    self._config_mtime = mtime
        except Exception:
            pass

    def _cleanup_old_requests(self, ip: str, window: float) -> None:
        """Remove request timestamps older than the window."""
        cutoff = time.time() - window
        self._requests[ip] = [ts for ts in self._requests[ip] if ts > cutoff]

    def is_allowed(
        self,
        ip: str,
        endpoint: Optional[str] = None,
        limit: Optional[int] = None
    ) -> bool:
        """
        Check if a request from an IP is allowed under rate limits.

        Args:
            ip: Client IP address
            endpoint: Optional endpoint name for per-endpoint limits
            limit: Optional override for the rate limit

        Returns:
            True if request is allowed, False if rate limited
        """
        with self._lock:
            self._reload_config()

            # Rate limiting disabled
            if not self.enabled:
                return True

            # Check exempt IPs
            ip_clean = ip.strip() if ip else ""
            if ip_clean in self.exempt_ips:
                return True

            # Determine limit based on endpoint
            if limit is None:
                if endpoint == "login":
                    limit = self.login_limit
                elif endpoint == "config":
                    limit = self.config_limit
                else:
                    limit = self.default_limit

            # Clean up old requests
            self._cleanup_old_requests(ip_clean, self.window_seconds)

            # Check current count
            current_count = len(self._requests[ip_clean])

            if current_count >= limit:
                return False

            # Record this request
            self._requests[ip_clean].append(time.time())
            return True

    def get_remaining(self, ip: str, limit: Optional[int] = None) -> int:
        """Get remaining requests for an IP in the current window."""
        with self._lock:
            self._reload_config()

            if limit is None:
                limit = self.default_limit

            ip_clean = ip.strip() if ip else ""
            self._cleanup_old_requests(ip_clean, self.window_seconds)

            current = len(self._requests[ip_clean])
            return max(0, limit - current)

    def reset(self, ip: Optional[str] = None) -> None:
        """Reset rate limit counters for an IP or all IPs."""
        with self._lock:
            if ip:
                self._requests.pop(ip.strip(), None)
            else:
                self._requests.clear()

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "default_limit": self.default_limit,
                "window_seconds": self.window_seconds,
                "tracked_ips": len(self._requests),
                "exempt_ips_count": len(self.exempt_ips),
            }


# =============================================================================
# SINGLETON INSTANCES
# =============================================================================
_access_control: Optional[AccessControl] = None
_rate_limiter: Optional[RateLimiter] = None


def get_access_control() -> AccessControl:
    """Get the singleton AccessControl instance."""
    global _access_control
    if _access_control is None:
        _access_control = AccessControl()
    return _access_control


def get_rate_limiter() -> RateLimiter:
    """Get the singleton RateLimiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# =============================================================================
# FLASK INTEGRATION HELPERS
# =============================================================================
def check_rate_limit(ip: str, endpoint: Optional[str] = None) -> Tuple[bool, dict]:
    """
    Check if request should be rate limited.

    Returns:
        Tuple of (is_allowed, headers) where headers contains
        X-RateLimit-* headers for the response.
    """
    limiter = get_rate_limiter()
    allowed = limiter.is_allowed(ip, endpoint)
    remaining = limiter.get_remaining(ip)

    headers = {
        "X-RateLimit-Limit": str(limiter.default_limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Window": str(limiter.window_seconds),
    }

    if not allowed:
        headers["Retry-After"] = str(limiter.window_seconds)

    return allowed, headers
