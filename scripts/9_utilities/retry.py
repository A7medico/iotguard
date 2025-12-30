"""
scripts/9_utilities/retry.py
-----------------------------------------------------------------------------
IoTGuard — Retry and Resilience Utilities

Purpose:
    Provide retry logic for operations that may fail transiently:
    - Network operations (API calls, HTTP requests)
    - File operations (temporary locks, I/O errors)
    - Database operations

Usage:
    from retry import retry, with_retry

    # As decorator
    @retry(max_attempts=3, delay=1.0)
    def fetch_threat_intel(ip):
        return requests.get(f"https://api.example.com/{ip}")

    # As function wrapper
    result = with_retry(lambda: risky_operation(), max_attempts=3)
-----------------------------------------------------------------------------
"""
import time
import functools
import logging
from typing import Callable, Any, Optional, Tuple, Type, Union


logger = logging.getLogger("iotguard.retry")


# =============================================================================
# RETRY DECORATOR
# =============================================================================

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    max_delay: float = 30.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable[[Exception, int], None]] = None,
    reraise: bool = True
):
    """
    Decorator that retries a function on failure.

    Features:
        - Configurable retry attempts
        - Exponential backoff
        - Exception filtering
        - Callback on retry

    Args:
        max_attempts: Maximum number of attempts (default: 3)
        delay: Initial delay between retries in seconds (default: 1.0)
        backoff: Multiplier for delay after each retry (default: 2.0)
        max_delay: Maximum delay cap in seconds (default: 30.0)
        exceptions: Tuple of exception types to catch (default: all)
        on_retry: Callback function(exception, attempt) called on each retry
        reraise: If True, raise the last exception after all retries fail

    Returns:
        Decorated function

    Example:
        @retry(max_attempts=3, delay=1.0, backoff=2.0)
        def fetch_data():
            return requests.get("https://api.example.com/data")

        # This will retry up to 3 times with delays of 1s, 2s, 4s
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            current_delay = delay

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)

                except exceptions as e:
                    last_exception = e

                    if attempt < max_attempts:
                        # Log the retry
                        logger.warning(
                            f"Retry {attempt}/{max_attempts} for {func.__name__}: {e}"
                        )

                        # Call retry callback if provided
                        if on_retry:
                            try:
                                on_retry(e, attempt)
                            except Exception:
                                pass

                        # Wait before next attempt
                        time.sleep(current_delay)

                        # Apply exponential backoff
                        current_delay = min(current_delay * backoff, max_delay)

                    else:
                        # All retries exhausted
                        logger.error(
                            f"All {max_attempts} attempts failed for {func.__name__}: {e}"
                        )

            # Raise or return None after all retries
            if reraise and last_exception:
                raise last_exception
            return None

        return wrapper
    return decorator


# =============================================================================
# FUNCTIONAL RETRY
# =============================================================================

def with_retry(
    func: Callable,
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    default: Any = None
) -> Any:
    """
    Execute a function with retry logic.

    Unlike the decorator, this is used for one-off retry operations.

    Args:
        func: The function to execute (no arguments)
        max_attempts: Maximum retry attempts
        delay: Initial delay between retries
        backoff: Backoff multiplier
        exceptions: Exceptions to catch
        default: Default value if all retries fail

    Returns:
        Function result or default value

    Example:
        result = with_retry(
            lambda: requests.get(url).json(),
            max_attempts=3,
            default={}
        )
    """
    current_delay = delay

    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except exceptions as e:
            if attempt < max_attempts:
                logger.debug(f"Retry {attempt}/{max_attempts}: {e}")
                time.sleep(current_delay)
                current_delay *= backoff
            else:
                logger.warning(f"All retries failed: {e}")

    return default


# =============================================================================
# CIRCUIT BREAKER
# =============================================================================

class CircuitBreaker:
    """
    Circuit breaker pattern for failing-fast on repeated failures.

    States:
        - CLOSED: Normal operation, requests pass through
        - OPEN: Failing fast, requests are rejected immediately
        - HALF_OPEN: Testing if service recovered

    Usage:
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

        @breaker
        def call_external_api():
            return requests.get("https://api.example.com")

        # Or manual usage:
        if breaker.allow_request():
            try:
                result = call_api()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
    """

    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 1
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Failures before opening circuit
            recovery_timeout: Seconds to wait before half-open
            half_open_max_calls: Test calls allowed in half-open state
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = self.STATE_CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0

    @property
    def state(self) -> str:
        """Current circuit state."""
        return self._state

    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        if self._state == self.STATE_CLOSED:
            return True

        if self._state == self.STATE_OPEN:
            # Check if recovery timeout elapsed
            if self._last_failure_time:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = self.STATE_HALF_OPEN
                    self._half_open_calls = 0
                    logger.info("Circuit breaker: OPEN -> HALF_OPEN")
                    return True
            return False

        if self._state == self.STATE_HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

        return True

    def record_success(self) -> None:
        """Record a successful operation."""
        if self._state == self.STATE_HALF_OPEN:
            # Service recovered
            self._state = self.STATE_CLOSED
            self._failure_count = 0
            logger.info("Circuit breaker: HALF_OPEN -> CLOSED (recovered)")
        elif self._state == self.STATE_CLOSED:
            self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed operation."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._state == self.STATE_HALF_OPEN:
            # Still failing, back to open
            self._state = self.STATE_OPEN
            logger.warning("Circuit breaker: HALF_OPEN -> OPEN (still failing)")

        elif self._state == self.STATE_CLOSED:
            if self._failure_count >= self.failure_threshold:
                self._state = self.STATE_OPEN
                logger.warning(
                    f"Circuit breaker: CLOSED -> OPEN "
                    f"(threshold {self.failure_threshold} reached)"
                )

    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        self._state = self.STATE_CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self._half_open_calls = 0

    def __call__(self, func: Callable) -> Callable:
        """Use as decorator."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.allow_request():
                raise RuntimeError(
                    f"Circuit breaker is OPEN for {func.__name__}"
                )

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure()
                raise

        return wrapper


# =============================================================================
# TIMEOUT UTILITIES
# =============================================================================

class TimeoutError(Exception):
    """Raised when an operation times out."""
    pass


def with_timeout(
    func: Callable,
    timeout_seconds: float,
    default: Any = None
) -> Any:
    """
    Execute a function with a soft timeout (checks between operations).

    Note: This is a cooperative timeout - the function must yield control.
    For hard timeouts, use threading or multiprocessing.

    Args:
        func: Function to execute
        timeout_seconds: Maximum seconds to wait
        default: Value to return on timeout

    Returns:
        Function result or default
    """
    import threading

    result = [default]
    exception = [None]

    def target():
        try:
            result[0] = func()
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        logger.warning(f"Operation timed out after {timeout_seconds}s")
        return default

    if exception[0]:
        raise exception[0]

    return result[0]
