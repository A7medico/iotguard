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
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any, Tuple

from flask import request, jsonify, g

# ============================================================================
# OPTIONAL DEPENDENCY: PyJWT
# If not installed, JWT features will be disabled but basic auth still works
# Install with: pip install PyJWT
# ============================================================================
try:
    import jwt
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

def create_token(username: str, extra_claims: Optional[Dict] = None) -> str:
    """
    Create a JWT token for an authenticated user.
    
    TOKEN STRUCTURE:
        Header:  {"alg": "HS256", "typ": "JWT"}
        Payload: {
            "sub": "username",        # Subject (who the token is for)
            "iat": 1234567890,        # Issued at (timestamp)
            "exp": 1234567890,        # Expires at (timestamp)
            "iss": "iotguard"         # Issuer
        }
        Signature: HMAC-SHA256(header + payload, secret)
    
    Args:
        username: The authenticated user's name
        extra_claims: Optional dict of additional claims
        
    Returns:
        Encoded JWT token string
        
    Raises:
        RuntimeError: If PyJWT is not installed
        
    EXAMPLE:
        token = create_token("admin")
        # Returns: "eyJhbGciOiJIUzI1NiI..."
    """
    if not JWT_AVAILABLE:
        raise RuntimeError("PyJWT not installed. Run: pip install PyJWT")
    
    now = datetime.now(timezone.utc)
    
    # Standard JWT claims
    payload = {
        "sub": username,                                    # Subject
        "iat": now,                                         # Issued at
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),    # Expiration
        "iss": "iotguard"                                   # Issuer
    }
    
    # Add any custom claims
    if extra_claims:
        payload.update(extra_claims)
    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def validate_token(token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """
    Validate a JWT token.
    
    CHECKS PERFORMED:
        1. Signature is valid (not tampered)
        2. Token is not expired
        3. Token structure is correct
    
    Args:
        token: The JWT token string to validate
        
    Returns:
        Tuple of (is_valid, payload_dict, error_message)
        
    EXAMPLES:
        # Valid token
        valid, payload, err = validate_token(good_token)
        # valid=True, payload={"sub": "admin", ...}, err=None
        
        # Expired token
        valid, payload, err = validate_token(old_token)
        # valid=False, payload=None, err="Token has expired"
        
        # Tampered token
        valid, payload, err = validate_token(bad_token)
        # valid=False, payload=None, err="Invalid token: ..."
    """
    if not JWT_AVAILABLE:
        return False, None, "PyJWT not installed"
    
    try:
        # Decode and validate in one step
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True, payload, None
        
    except jwt.ExpiredSignatureError:
        return False, None, "Token has expired"
        
    except jwt.InvalidTokenError as e:
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
    Flask decorator to require JWT authentication.
    
    USAGE:
        @app.route("/api/v1/secret")
        @require_auth
        def secret_data():
            # g.current_user is set automatically
            return {"message": f"Hello, {g.current_user}!"}
    
    BEHAVIOR:
        - If no password configured (IOTGUARD_PASS=""), auth is skipped
          (development mode)
        - If token missing, returns 401 with {"error": "Missing..."}
        - If token invalid/expired, returns 401 with error details
        - If token valid, sets g.current_user and continues
    
    Args:
        f: The Flask view function to protect
        
    Returns:
        Decorated function
    """
    @wraps(f)  # Preserve function metadata
    def decorated(*args, **kwargs):
        # Skip auth if no password configured (dev mode)
        if not AUTH_PASS:
            g.current_user = "anonymous"
            return f(*args, **kwargs)
        
        # Get token from request
        token = get_token_from_request()
        
        if not token:
            return jsonify({"error": "Missing authentication token"}), 401
        
        # Validate token
        valid, payload, error = validate_token(token)
        
        if not valid:
            return jsonify({"error": error}), 401
        
        # Set current user for the request context
        g.current_user = payload.get("sub", "unknown")
        
        return f(*args, **kwargs)
    
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
