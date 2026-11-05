"""
scripts/auth.py
=============================================================================
IoTGuard — JWT Authentication & Rate Limiting System
=============================================================================

PIPELINE POSITION:
    ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
    │   API Request   │ --> │    auth.py      │ --> │ Protected Route │
    │   (from user)   │     │ (this file)     │     │ (data returned) │
    └─────────────────┘     └─────────────────┘     └─────────────────┘

WHAT THIS MODULE DOES:
    1. JWT AUTHENTICATION
       - Generate tokens when users login with valid credentials
       - Validate tokens on subsequent requests
       - Tokens expire after configurable hours (default: 24)
    
    2. RATE LIMITING
       - Prevent brute force attacks
       - Limit requests per IP per minute
       - Returns 429 when limit exceeded

AUTHENTICATION FLOW:
    ┌──────────────────────────────────────────────────────────────────────┐
    │  1. User POSTs to /api/v1/login with {username, password}            │
    │  2. authenticate_user() checks credentials against env vars          │
    │  3. If valid, create_token() generates JWT with expiry               │
    │  4. Token returned to user                                           │
    │  5. User includes token in future requests: Authorization: Bearer X  │
    │  6. @require_auth decorator validates token on protected routes      │
    └──────────────────────────────────────────────────────────────────────┘

CONFIGURATION (Environment Variables):
    IOTGUARD_JWT_SECRET    : Secret key for signing tokens
                             (auto-generated if not set, but won't persist!)
    IOTGUARD_JWT_EXPIRY    : Token lifetime in hours (default: 24)
    IOTGUARD_USER          : Valid username for login
    IOTGUARD_PASS          : Valid password for login

USAGE EXAMPLES:
    # In api_dashboard.py - protect a route:
    from auth import require_auth
    
    @app.route("/api/v1/protected")
    @require_auth
    def protected():
        return {"user": g.current_user}
    
    # Login to get a token:
    curl -X POST http://localhost:5001/api/v1/login \
         -H "Content-Type: application/json" \
         -d '{"username": "admin", "password": "secret"}'
    
    # Use token in requests:
    curl http://localhost:5001/api/v1/protected \
         -H "Authorization: Bearer <your-token>"

SECURITY NOTES:
    - ALWAYS set IOTGUARD_JWT_SECRET in production!
    - Use strong passwords (min 12 characters, mixed case, numbers, symbols)
    - Tokens are stateless - to revoke, change the JWT_SECRET
    - Rate limiting is in-memory only (resets on restart)
=============================================================================
"""

import os
import time
import secrets
import hashlib
import hmac
import base64
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any, Tuple, Union, List

from flask import request, jsonify, g

def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_decode(data: str) -> bytes:
    """Decode base64url string with padding tolerance."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))

# ============================================================================
# OPTIONAL DEPENDENCY: PyJWT
# If not installed, zero-dependency HMAC-SHA256 JWT engine is used.
# ============================================================================
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

logger = logging.getLogger("iotguard.auth")


# ============================================================================
# CONFIGURATION
# All sensitive values come from environment variables
# ============================================================================

def _get_jwt_secret() -> str:
    """
    Get or generate JWT secret key.
    
    SECURITY WARNING:
        If IOTGUARD_JWT_SECRET is not set, a random secret is generated.
        This means tokens won't survive a server restart!
        Always set this in production.
    
    EXAMPLE:
        # Generate a secure secret:
        python -c "import secrets; print(secrets.token_hex(32))"
        
        # Then set it:
        export IOTGUARD_JWT_SECRET="your-64-character-hex-string"
    
    Returns:
        64-character hex string
    """
    secret = os.getenv("IOTGUARD_JWT_SECRET", "")
    if not secret:
        # Generate random secret (WARNING: won't persist!)
        secret = secrets.token_hex(32)
        logger.warning(
            "⚠️ No IOTGUARD_JWT_SECRET set, using random secret "
            "(tokens won't persist across restarts)"
        )
    return secret


# JWT Configuration
JWT_SECRET = _get_jwt_secret()          # The signing key
JWT_ALGORITHM = "HS256"                  # HMAC-SHA256 algorithm
JWT_EXPIRY_HOURS = int(os.getenv("IOTGUARD_JWT_EXPIRY", "24"))

# Login Credentials from environment
AUTH_USER = os.getenv("IOTGUARD_USER", "admin")  # Default username
AUTH_PASS = os.getenv("IOTGUARD_PASS", "")       # No default password!

# Enterprise Roles
ROLE_ADMIN = "ADMIN"
ROLE_SOC_ANALYST = "SOC_ANALYST"
ROLE_AUDITOR = "AUDITOR"
ROLE_EDGE_SENSOR = "EDGE_SENSOR"
ALL_ROLES = {ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_AUDITOR, ROLE_EDGE_SENSOR}

# API Keys In-Memory Store
_API_KEYS: Dict[str, Dict[str, Any]] = {}
_api_keys_lock = threading.Lock()

# Auto-register default admin key if set via environment
_env_key = os.getenv("IOTGUARD_API_KEY", "")
if _env_key:
    _API_KEYS[_env_key] = {
        "name": "env_admin",
        "role": ROLE_ADMIN,
        "created_at": time.time(),
    }


def register_api_key(
    name: str,
    role: str = ROLE_SOC_ANALYST,
    key: Optional[str] = None,
    created_by: str = "admin",
    rate_limit: Optional[int] = None,
    **kwargs,
) -> str:
    """Register an enterprise API key with scoped role privileges."""
    role_clean = str(role).upper()
    if role_clean not in ALL_ROLES:
        role_clean = ROLE_SOC_ANALYST
    with _api_keys_lock:
        actual_key = key or f"iotguard_{secrets.token_hex(24)}"
        _API_KEYS[actual_key] = {
            "name": name,
            "role": role_clean,
            "created_by": created_by,
            "rate_limit": rate_limit,
            "created_at": time.time(),
        }
        return actual_key


def validate_api_key(key: str) -> Optional[Dict[str, Any]]:
    """Validate an API key and return metadata if active."""
    if not key:
        return None
    with _api_keys_lock:
        return _API_KEYS.get(key)


def list_api_keys() -> List[Dict[str, Any]]:
    """List active registered API keys."""
    with _api_keys_lock:
        return [
            {
                "name": v["name"],
                "role": v["role"],
                "created_at": v["created_at"],
                "key_prefix": k[:8] + "...",
            }
            for k, v in _API_KEYS.items()
        ]


def revoke_api_key(key: str) -> bool:
    """Revoke an API key."""
    with _api_keys_lock:
        if key in _API_KEYS:
            del _API_KEYS[key]
            return True
        return False


# ============================================================================
# PASSWORD HASHING
# Optional: Store hashed passwords instead of plain text
# ============================================================================

def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256 with salt.
    
    WHY HASH:
        - Plain text passwords in env vars are visible in process listings
        - Hashing adds a layer of protection
    
    HOW TO USE:
        1. Generate hash: python -c "from auth import hash_password; print(hash_password('mypass'))"
        2. Set env var: export IOTGUARD_PASS="<64-char-hash>"
    
    Args:
        password: Plain text password
        
    Returns:
        64-character SHA-256 hash
    """
    # Salt prevents rainbow table attacks
    salt = os.getenv("IOTGUARD_SALT", "iotguard_default_salt")
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def verify_password(password: str, expected: str) -> bool:
    """
    Verify password against expected value.
    
    SUPPORTS BOTH:
        - Plain text passwords (legacy/simple setup)
        - SHA-256 hashed passwords (more secure)
    
    DETECTION:
        If expected is exactly 64 hex chars, treat as hash.
        Otherwise, direct comparison.
    
    Args:
        password: User-provided password attempt
        expected: Expected value from IOTGUARD_PASS
        
    Returns:
        True if password matches
    """
    if not expected:
        return False
    
    # 64-character string = likely a SHA-256 hash
    if len(expected) == 64:
        return hash_password(password) == expected
    
    # Otherwise, plain text comparison
    return password == expected


# ============================================================================
# JWT TOKEN MANAGEMENT
# Create, validate, and refresh JSON Web Tokens
# ============================================================================

def create_token(
    username: str,
    role: Union[str, Dict] = ROLE_ADMIN,
    extra_claims: Optional[Dict] = None
) -> str:
    """
    Create a JWT token for an authenticated user with enterprise role scope.
    """
    # Backward compatibility if extra_claims was passed as 2nd positional argument
    if isinstance(role, dict):
        extra_claims = role
        role = ROLE_ADMIN
        
    role_clean = str(role).upper()
    if role_clean not in ALL_ROLES:
        role_clean = ROLE_ADMIN

    now = datetime.now(timezone.utc)
    
    # Standard JWT claims with role
    payload = {
        "sub": username,
        "role": role_clean,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=JWT_EXPIRY_HOURS)).timestamp()),
        "iss": "iotguard"
    }
    
    # Add any custom claims
    if extra_claims:
        payload.update(extra_claims)

    if JWT_AVAILABLE:
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Built-in zero-dependency fallback (HMAC-SHA256)
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    sig = hmac.new(JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def validate_token(token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """
    Validate a JWT token.
    """
    if JWT_AVAILABLE:
        try:
            # Decode and validate in one step
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            if "role" not in payload:
                payload["role"] = ROLE_ADMIN
            return True, payload, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
            
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {e}"

    # Built-in zero-dependency fallback (HMAC-SHA256)
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, None, "Invalid token format"
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = _b64url_encode(hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest())
        if not hmac.compare_digest(sig_b64, expected_sig):
            return False, None, "Invalid token signature"
        
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if "exp" in payload:
            exp_ts = payload["exp"]
            if isinstance(exp_ts, (int, float)) and time.time() > exp_ts:
                return False, None, "Token has expired"
        if "role" not in payload:
            payload["role"] = ROLE_ADMIN
        return True, payload, None
    except Exception as e:
        return False, None, f"Invalid token: {e}"


def refresh_token(token: str) -> Optional[str]:
    """
    Refresh a valid token with extended expiry.
    
    USE CASE:
        Allow users to stay logged in without re-entering credentials.
        Call this periodically to keep the session alive.
    
    Args:
        token: Current valid JWT token
        
    Returns:
        New token with fresh expiry, or None if current token is invalid
        
    EXAMPLE:
        new_token = refresh_token(current_token)
        if new_token:
            # Update client's stored token
            pass
        else:
            # Force re-login
            pass
    """
    valid, payload, _ = validate_token(token)
    if not valid or not payload:
        return None
    
    # Create fresh token for same user
    return create_token(payload["sub"])


# ============================================================================
# FLASK REQUEST HANDLING
# Extract tokens from HTTP requests
# ============================================================================

def get_api_key_from_request() -> Optional[str]:
    """Extract API key from X-IoTGuard-API-Key or X-API-Key header."""
    return request.headers.get("X-IoTGuard-API-Key") or request.headers.get("X-API-Key")


def get_token_from_request() -> Optional[str]:
    """
    Extract JWT token from current Flask request.
    
    LOOKS IN (order):
        1. Authorization header: "Authorization: Bearer <token>"
        2. Query parameter: "?token=<token>" (for WebSocket compatibility)
    
    WHY QUERY PARAMETER:
        WebSocket connections can't set custom headers in browsers,
        so we allow passing the token as a query parameter.
    
    Returns:
        Token string if found, None otherwise
    """
    # Check Authorization header first (preferred method)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer " prefix
    
    # Fall back to query parameter (for WebSocket)
    token = request.args.get("token")
    if token:
        return token
    
    return None


def require_auth(f):
    """
    Flask decorator to require authentication (JWT or API Key).
    Sets g.current_user and g.current_role.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check API Key header
        api_key = get_api_key_from_request()
        if api_key:
            key_info = validate_api_key(api_key)
            if key_info:
                g.current_user = key_info["name"]
                g.current_role = key_info["role"]
                g.auth_type = "api_key"
                return f(*args, **kwargs)
            return jsonify({"error": "Invalid API Key"}), 401

        # 2. Skip auth if no password configured (dev/test mode)
        if not AUTH_PASS and not get_token_from_request():
            g.current_user = "anonymous"
            g.current_role = ROLE_ADMIN
            g.auth_type = "anonymous"
            return f(*args, **kwargs)
        
        # 3. Validate JWT token
        token = get_token_from_request()
        if not token:
            return jsonify({"error": "Missing authentication credentials"}), 401
        
        valid, payload, error = validate_token(token)
        if not valid:
            return jsonify({"error": error}), 401
        
        g.current_user = payload.get("sub", "unknown")
        g.current_role = payload.get("role", ROLE_ADMIN)
        g.auth_type = "jwt"
        return f(*args, **kwargs)
    
    return decorated


def require_role(allowed_roles: Union[str, List[str], set, Tuple[str, ...]]):
    """
    Flask decorator to enforce enterprise Role-Based Access Control (RBAC).
    Supported roles: ADMIN, SOC_ANALYST, AUDITOR, EDGE_SENSOR.
    """
    if isinstance(allowed_roles, str):
        roles_set = {allowed_roles.upper()}
    else:
        roles_set = {str(r).upper() for r in allowed_roles}

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # 1. Check API Key
            api_key = get_api_key_from_request()
            if api_key:
                key_info = validate_api_key(api_key)
                if not key_info:
                    return jsonify({"error": "Invalid API Key"}), 401
                g.current_user = key_info["name"]
                g.current_role = key_info["role"]
                g.auth_type = "api_key"
                if g.current_role not in roles_set:
                    return jsonify({
                        "error": "Forbidden: Insufficient privileges",
                        "required_roles": sorted(list(roles_set)),
                        "user_role": g.current_role,
                    }), 403
                return f(*args, **kwargs)

            # 2. Dev mode: skip if no password configured AND no token provided
            if not AUTH_PASS and not get_token_from_request():
                g.current_user = "anonymous"
                g.current_role = ROLE_ADMIN
                g.auth_type = "anonymous"
                return f(*args, **kwargs)

            # 3. Validate JWT Token
            token = get_token_from_request()
            if not token:
                return jsonify({"error": "Missing authentication credentials"}), 401

            valid, payload, error = validate_token(token)
            if not valid:
                return jsonify({"error": error}), 401

            g.current_user = payload.get("sub", "unknown")
            g.current_role = payload.get("role", ROLE_ADMIN)
            g.auth_type = "jwt"

            if g.current_role not in roles_set:
                return jsonify({
                    "error": "Forbidden: Insufficient privileges",
                    "required_roles": sorted(list(roles_set)),
                    "user_role": g.current_role,
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator
    
    return decorated


def optional_auth(f):
    """
    Flask decorator for optional authentication.
    
    Unlike @require_auth, this doesn't reject unauthenticated requests.
    Instead, it sets g.current_user to either the verified user or None.
    
    USE CASE:
        Routes that behave differently for logged-in vs anonymous users.
    
    EXAMPLE:
        @app.route("/api/v1/data")
        @optional_auth
        def get_data():
            if g.current_user:
                return {"data": "full data", "user": g.current_user}
            else:
                return {"data": "limited data"}
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        
        if token:
            valid, payload, _ = validate_token(token)
            if valid and payload:
                g.current_user = payload.get("sub")
            else:
                g.current_user = None
        else:
            g.current_user = None
        
        return f(*args, **kwargs)
    
    return decorated


# ============================================================================
# LOGIN HANDLER
# Authenticate user credentials and issue token
# ============================================================================

def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Authenticate user credentials and return JWT token.
    
    WORKFLOW:
        1. Check username matches IOTGUARD_USER
        2. Check password matches IOTGUARD_PASS (plain or hashed)
        3. If valid, generate and return token
        4. Log the authentication attempt
    
    Args:
        username: Provided username
        password: Provided password
        
    Returns:
        Tuple of (success, token_or_none, error_or_none)
        
    EXAMPLES:
        # Successful login
        success, token, error = authenticate_user("admin", "correct")
        # (True, "eyJ...", None)
        
        # Bad password
        success, token, error = authenticate_user("admin", "wrong")
        # (False, None, "Invalid password")
    """
    # Check username
    if username != AUTH_USER:
        return False, None, "Invalid username"
    
    # Check password
    if not verify_password(password, AUTH_PASS):
        return False, None, "Invalid password"
    
    # Generate token
    try:
        token = create_token(username)
        logger.info(f"🔐 User '{username}' authenticated successfully")
        return True, token, None
    except Exception as e:
        logger.error(f"Token generation failed: {e}")
        return False, None, str(e)


# ============================================================================
# RATE LIMITING
# Prevent brute force and DoS attacks
# ============================================================================

class RateLimiter:
    """
    Simple in-memory rate limiter.
    
    HOW IT WORKS:
        - Tracks request timestamps per key (usually client IP)
        - Sliding window: only counts requests in last N seconds
        - Rejects requests when count exceeds max
    
    LIMITATIONS:
        - In-memory only (resets on restart)
        - Not shared across workers/instances
        - For production, use Redis-based solution
    
    EXAMPLE:
        limiter = RateLimiter(max_requests=100, window_seconds=60)
        
        if limiter.is_allowed(client_ip):
            # Process request
        else:
            # Return 429 Too Many Requests
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, list] = {}  # key -> [timestamps]
    
    def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed for the given key.
        
        Args:
            key: Identifier (usually IP address)
            
        Returns:
            True if under limit, False if rate exceeded
        """
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - self.window_seconds
        
        # Initialize if new key
        if key not in self._requests:
            self._requests[key] = []
        
        # Remove old requests (outside window)
        self._requests[key] = [t for t in self._requests[key] if t > window_start]
        
        # Check limit
        if len(self._requests[key]) >= self.max_requests:
            return False
        
        # Record this request
        self._requests[key].append(now)
        return True
    
    def get_remaining(self, key: str) -> int:
        """
        Get remaining requests for the key.
        
        Useful for X-RateLimit-Remaining header.
        """
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - self.window_seconds
        
        if key not in self._requests:
            return self.max_requests
        
        current = len([t for t in self._requests[key] if t > window_start])
        return max(0, self.max_requests - current)


# Global rate limiter (100 requests per minute per IP)
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


def rate_limit(f):
    """
    Flask decorator for rate limiting based on client IP.
    
    USAGE:
        @app.route("/api/v1/expensive")
        @rate_limit
        def expensive_operation():
            # Only 100 calls per minute allowed
            return {"result": "data"}
    
    RESPONSE ON LIMIT:
        HTTP 429 Too Many Requests
        {"error": "Rate limit exceeded", "retry_after": 60}
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr or "unknown"
        
        if not rate_limiter.is_allowed(client_ip):
            remaining = rate_limiter.get_remaining(client_ip)
            return jsonify({
                "error": "Rate limit exceeded",
                "retry_after": rate_limiter.window_seconds
            }), 429
        
        return f(*args, **kwargs)
    
    return decorated


# ============================================================================
# STANDALONE TESTING
# ============================================================================
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 60)
    print("IoTGuard JWT Authentication Test")
    print("=" * 60)
    
    if JWT_AVAILABLE:
        print("\n✅ PyJWT is installed")
        
        # Create a test token
        token = create_token("testuser")
        print(f"\nCreated token: {token[:50]}...")
        
        # Validate it
        valid, payload, error = validate_token(token)
        print(f"Validation: valid={valid}, user={payload.get('sub') if payload else None}")
        
        # Test rate limiter
        print("\nTesting rate limiter...")
        for i in range(5):
            allowed = rate_limiter.is_allowed("test_ip")
            remaining = rate_limiter.get_remaining("test_ip")
            print(f"  Request {i+1}: allowed={allowed}, remaining={remaining}")
    else:
        print("\n❌ PyJWT not installed - JWT features unavailable")
        print("   Install with: pip install PyJWT")
