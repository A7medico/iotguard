"""
scripts/9_utilities/validators.py
-----------------------------------------------------------------------------
IoTGuard — Input Validation and Sanitization Utilities

Purpose:
    Centralized validation functions for input sanitization across the system.
    All external inputs should be validated before use.

Security:
    - Prevents injection attacks
    - Validates data types and ranges
    - Provides safe defaults

Usage:
    from validators import validate_ip, validate_threshold, sanitize_string

    # Validate IP address
    is_valid, error = validate_ip("192.168.1.100")

    # Validate threshold
    threshold = validate_threshold(value, default=0.7)
-----------------------------------------------------------------------------
"""
import re
import ipaddress
from typing import Any, Optional, Tuple, List, Union
from pathlib import Path


# =============================================================================
# IP ADDRESS VALIDATION
# =============================================================================

# Dangerous characters that could enable shell injection
DANGEROUS_CHARS = [';', '&', '|', '$', '`', '\n', '\r', '\\', '"', "'", '<', '>', '(', ')', '{', '}']


def validate_ip(ip: Any) -> Tuple[bool, str]:
    """
    Validate an IP address for security and correctness.

    Checks:
        1. Type and emptiness
        2. Dangerous characters (command injection prevention)
        3. Valid IPv4/IPv6 format
        4. Not loopback or link-local (safety)

    Args:
        ip: The value to validate as an IP address

    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is empty string
    """
    # Check type
    if ip is None:
        return False, "IP address is None"

    if not isinstance(ip, str):
        return False, f"IP address must be string, got {type(ip).__name__}"

    ip = ip.strip()

    if not ip:
        return False, "IP address is empty"

    # Security: Check for dangerous characters
    for char in DANGEROUS_CHARS:
        if char in ip:
            return False, f"IP contains dangerous character: {repr(char)}"

    # Parse and validate
    try:
        parsed = ipaddress.ip_address(ip)

        # Safety: Don't allow blocking loopback
        if parsed.is_loopback:
            return False, "Cannot use loopback address"

        # Safety: Don't allow link-local
        if parsed.is_link_local:
            return False, "Cannot use link-local address"

        return True, ""

    except ValueError as e:
        return False, f"Invalid IP format: {e}"


def validate_ip_or_cidr(value: Any) -> Tuple[bool, str]:
    """
    Validate an IP address or CIDR network.

    Args:
        value: IP address or CIDR notation (e.g., "192.168.1.0/24")

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not value or not isinstance(value, str):
        return False, "Value must be a non-empty string"

    value = value.strip()

    for char in DANGEROUS_CHARS:
        if char in value:
            return False, f"Contains dangerous character: {repr(char)}"

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True, ""
    except ValueError as e:
        return False, f"Invalid IP/CIDR format: {e}"


# =============================================================================
# NUMERIC VALIDATION
# =============================================================================

def validate_threshold(
    value: Any,
    default: float = 0.7,
    min_val: float = 0.0,
    max_val: float = 1.0
) -> float:
    """
    Validate and sanitize a threshold value.

    Args:
        value: The value to validate
        default: Default value if invalid
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Validated float within bounds, or default if invalid
    """
    try:
        result = float(value)
        if min_val <= result <= max_val:
            return round(result, 4)
        return default
    except (TypeError, ValueError):
        return default


def validate_int(
    value: Any,
    default: int = 0,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None
) -> int:
    """
    Validate and sanitize an integer value.

    Args:
        value: The value to validate
        default: Default value if invalid
        min_val: Minimum allowed value (optional)
        max_val: Maximum allowed value (optional)

    Returns:
        Validated int within bounds, or default if invalid
    """
    try:
        result = int(value)

        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return default

        return result
    except (TypeError, ValueError):
        return default


def validate_positive_int(value: Any, default: int = 1) -> int:
    """Validate a positive integer (>= 1)."""
    return validate_int(value, default=default, min_val=1)


def validate_non_negative_int(value: Any, default: int = 0) -> int:
    """Validate a non-negative integer (>= 0)."""
    return validate_int(value, default=default, min_val=0)


# =============================================================================
# STRING VALIDATION
# =============================================================================

# Pattern for safe strings (alphanumeric, dash, underscore, dot)
SAFE_STRING_PATTERN = re.compile(r'^[\w\-\.]+$')


def sanitize_string(
    value: Any,
    max_length: int = 256,
    default: str = ""
) -> str:
    """
    Sanitize a string value for safe use.

    Removes or escapes dangerous characters and enforces length limits.

    Args:
        value: The value to sanitize
        max_length: Maximum allowed length
        default: Default value if invalid

    Returns:
        Sanitized string
    """
    if value is None:
        return default

    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return default

    # Strip whitespace
    value = value.strip()

    # Enforce length limit
    if len(value) > max_length:
        value = value[:max_length]

    # Remove null bytes and other dangerous chars
    value = value.replace('\x00', '')

    return value


def validate_safe_string(value: Any, max_length: int = 256) -> Tuple[bool, str]:
    """
    Validate that a string contains only safe characters.

    Safe characters: alphanumeric, dash, underscore, dot

    Args:
        value: The value to validate
        max_length: Maximum allowed length

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(value, str):
        return False, "Value must be a string"

    if len(value) > max_length:
        return False, f"String too long (max {max_length})"

    if not SAFE_STRING_PATTERN.match(value):
        return False, "String contains invalid characters"

    return True, ""


# =============================================================================
# PATH VALIDATION
# =============================================================================

def validate_path(
    value: Any,
    must_exist: bool = False,
    must_be_file: bool = False,
    must_be_dir: bool = False
) -> Tuple[bool, Optional[Path]]:
    """
    Validate a file path.

    Args:
        value: The path to validate
        must_exist: If True, path must exist
        must_be_file: If True, path must be a file
        must_be_dir: If True, path must be a directory

    Returns:
        Tuple of (is_valid, Path object or None)
    """
    if not value:
        return False, None

    try:
        path = Path(value)

        # Check for path traversal attempts
        resolved = path.resolve()
        if ".." in str(path):
            return False, None

        if must_exist and not path.exists():
            return False, None

        if must_be_file and not path.is_file():
            return False, None

        if must_be_dir and not path.is_dir():
            return False, None

        return True, path

    except Exception:
        return False, None


# =============================================================================
# CONFIG VALIDATION
# =============================================================================

def validate_config_value(
    config: dict,
    key: str,
    expected_type: type,
    default: Any = None,
    min_val: Any = None,
    max_val: Any = None
) -> Any:
    """
    Safely extract and validate a value from a config dictionary.

    Args:
        config: The configuration dictionary
        key: The key to extract
        expected_type: Expected type (int, float, str, bool, list, dict)
        default: Default value if missing or invalid
        min_val: Minimum value for numeric types
        max_val: Maximum value for numeric types

    Returns:
        Validated value or default
    """
    if not isinstance(config, dict):
        return default

    value = config.get(key)

    if value is None:
        return default

    # Type conversion
    try:
        if expected_type == bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            return bool(value)

        if expected_type == int:
            result = int(value)
            if min_val is not None and result < min_val:
                return default
            if max_val is not None and result > max_val:
                return default
            return result

        if expected_type == float:
            result = float(value)
            if min_val is not None and result < min_val:
                return default
            if max_val is not None and result > max_val:
                return default
            return result

        if expected_type == str:
            return str(value)

        if expected_type == list:
            return list(value) if isinstance(value, (list, tuple)) else default

        if expected_type == dict:
            return dict(value) if isinstance(value, dict) else default

        return default

    except (TypeError, ValueError):
        return default


# =============================================================================
# FEATURE VECTOR VALIDATION
# =============================================================================

def validate_feature_vector(
    features: Any,
    expected_length: int = 13
) -> Tuple[bool, str, Optional[List[float]]]:
    """
    Validate a feature vector for ML model input.

    Args:
        features: The feature vector (list, tuple, or array-like)
        expected_length: Expected number of features

    Returns:
        Tuple of (is_valid, error_message, validated_features)
    """
    if features is None:
        return False, "Features are None", None

    try:
        # Convert to list
        if hasattr(features, 'tolist'):
            features = features.tolist()
        else:
            features = list(features)

        # Check length
        if len(features) != expected_length:
            return False, f"Expected {expected_length} features, got {len(features)}", None

        # Convert to floats and check for NaN/Inf
        validated = []
        for i, val in enumerate(features):
            f_val = float(val)
            if f_val != f_val:  # NaN check
                return False, f"Feature {i} is NaN", None
            if abs(f_val) == float('inf'):
                return False, f"Feature {i} is Inf", None
            validated.append(f_val)

        return True, "", validated

    except (TypeError, ValueError) as e:
        return False, f"Invalid feature format: {e}", None
