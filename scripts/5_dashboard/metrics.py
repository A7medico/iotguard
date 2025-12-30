"""
scripts/metrics.py
=============================================================================
IoTGuard — Prometheus Metrics & Monitoring System
=============================================================================

PIPELINE POSITION:
    ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
    │ All IoTGuard    │ --> │   metrics.py    │ --> │   Prometheus    │
    │ Components      │     │  (this file)    │     │   + Grafana     │
    └─────────────────┘     └─────────────────┘     └─────────────────┘

WHAT THIS MODULE DOES:
    Collects and exposes operational metrics for monitoring:
    
    1. DETECTION METRICS
       - Total detections (by severity, attack type)
       - IP blocks (success/failure counts)
       
    2. PERFORMANCE METRICS  
       - Model inference latency
       - Score distributions
       
    3. HEALTH METRICS
       - Active WebSocket connections
       - Model drift indicator

PROMETHEUS INTEGRATION:
    Prometheus scrapes the /metrics endpoint periodically and stores
    time-series data. Grafana then visualizes this data in dashboards.
    
    Scrape Flow:
    ┌─────────────┐        ┌─────────────┐        ┌─────────────┐
    │ Prometheus  │ GET    │ /metrics    │ text   │ Time-Series │
    │   Scraper   │ -----> │  endpoint   │ -----> │   Database  │
    └─────────────┘        └─────────────┘        └─────────────┘

METRIC TYPES:
    COUNTER   : Only increases (e.g., total requests)
    GAUGE     : Can go up or down (e.g., active connections)
    HISTOGRAM : Distribution of values (e.g., latency percentiles)

USAGE EXAMPLES:
    # Record a detection
    from metrics import record_detection
    record_detection(severity="high", attack_type="SYN_Flood")
    
    # Record model inference time
    from metrics import record_inference_time
    with record_inference_time("supervised"):
        prediction = model.predict(features)
    
    # Get metrics for Prometheus
    from metrics import get_metrics_text
    text = get_metrics_text()  # Prometheus exposition format

EXPOSED METRICS:
    iotguard_detections_total{severity, attack_type}
    iotguard_blocks_total{success}
    iotguard_inference_seconds{model_type}
    iotguard_score_distribution{model_type}
    iotguard_api_requests_total{endpoint, method, status}
    iotguard_model_drift{model_type}
    iotguard_active_connections
    iotguard_last_detection_timestamp
    iotguard_info{version}
=============================================================================
"""

import time
import threading
from typing import Optional, Dict, Any
from contextlib import contextmanager
from collections import defaultdict
from datetime import datetime


# ============================================================================
# METRIC TYPE IMPLEMENTATIONS
# These classes implement Prometheus-style metrics without external libraries
# ============================================================================

class Counter:
    """
    A Prometheus-style counter metric.
    
    CHARACTERISTICS:
        - Only increases (or resets to 0)
        - Never decreases
        - Tracks cumulative totals
    
    USE CASES:
        - Total HTTP requests
        - Total detections
        - Total errors
    
    EXAMPLE:
        requests = Counter("http_requests_total", "Total HTTP requests", ("method", "path"))
        requests.inc(method="GET", path="/api")
        requests.inc(method="POST", path="/api", value=5)  # Can increment by more than 1
    """
    
    def __init__(self, name: str, description: str, labels: tuple = ()):
        """
        Initialize a counter.
        
        Args:
            name: Metric name (snake_case, e.g., "http_requests_total")
            description: Human-readable description
            labels: Tuple of label names for multi-dimensional metrics
        """
        self.name = name
        self.description = description
        self.labels = labels
        # Store values per label combination
        # Key = tuple of label values, Value = count
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()  # Thread safety
    
    def inc(self, value: float = 1, **label_values) -> None:
        """
        Increment the counter.
        
        Args:
            value: Amount to increment (default 1)
            **label_values: Label key=value pairs
            
        EXAMPLE:
            counter.inc(method="GET", status="200")
            counter.inc(value=10, method="POST")  # Increment by 10
        """
        # Build key from label values in order
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] += value
    
    def get(self, **label_values) -> float:
        """Get current counter value for specific labels."""
        key = tuple(label_values.get(l, "") for l in self.labels)
        return self._values.get(key, 0)
    
    def to_prometheus(self) -> str:
        """
        Export to Prometheus text exposition format.
        
        FORMAT:
            # HELP metric_name description
            # TYPE metric_name counter
            metric_name{label1="value1", label2="value2"} 123
        """
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} counter"
        ]
        for key, value in self._values.items():
            if self.labels:
                # Format: metric{l1="v1",l2="v2"} value
                label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key))
                lines.append(f"{self.name}{{{label_str}}} {value}")
            else:
                lines.append(f"{self.name} {value}")
        return "\n".join(lines)


class Gauge:
    """
    A Prometheus-style gauge metric.
    
    CHARACTERISTICS:
        - Can increase or decrease
        - Represents current state
        - Point-in-time value
    
    USE CASES:
        - Current temperature
        - Active connections
        - Memory usage
    
    EXAMPLE:
        connections = Gauge("active_connections", "Current connections")
        connections.set(10)
        connections.inc()      # Now 11
        connections.dec(5)     # Now 6
    """
    
    def __init__(self, name: str, description: str, labels: tuple = ()):
        self.name = name
        self.description = description
        self.labels = labels
        self._values: Dict[tuple, float] = {}
        self._lock = threading.Lock()
    
    def set(self, value: float, **label_values) -> None:
        """Set gauge to specific value."""
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] = value
    
    def inc(self, value: float = 1, **label_values) -> None:
        """Increment gauge by value."""
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0) + value
    
    def dec(self, value: float = 1, **label_values) -> None:
        """Decrement gauge by value."""
        self.inc(-value, **label_values)
    
    def get(self, **label_values) -> float:
        """Get current gauge value."""
        key = tuple(label_values.get(l, "") for l in self.labels)
        return self._values.get(key, 0)
    
    def to_prometheus(self) -> str:
        """Export to Prometheus text format."""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} gauge"
        ]
        for key, value in self._values.items():
            if self.labels:
                label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key))
                lines.append(f"{self.name}{{{label_str}}} {value}")
            else:
                lines.append(f"{self.name} {value}")
        return "\n".join(lines)


class Histogram:
    """
    A Prometheus-style histogram metric.
    
    CHARACTERISTICS:
        - Tracks distribution of values
        - Uses predefined buckets
        - Calculates percentiles efficiently
    
    USE CASES:
        - Request latency (p50, p95, p99)
        - Response sizes
        - Score distributions
    
    HOW IT WORKS:
        Values are observed and counted into buckets.
        Buckets are cumulative (le = less than or equal).
        
        Example with buckets [0.1, 0.5, 1.0]:
        If we observe values [0.05, 0.3, 0.8]:
          bucket{le="0.1"} = 1  (0.05 <= 0.1)
          bucket{le="0.5"} = 2  (0.05, 0.3 <= 0.5)
          bucket{le="1.0"} = 3  (all <= 1.0)
          bucket{le="+Inf"} = 3 (all values)
    
    EXAMPLE:
        latency = Histogram("request_latency_seconds", "Latency")
        latency.observe(0.15)
        latency.observe(0.42)
    """
    
    # Default buckets suitable for latency in seconds
    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
    
    def __init__(self, name: str, description: str, labels: tuple = (), buckets: tuple = None):
        self.name = name
        self.description = description
        self.labels = labels
        self.buckets = buckets or self.DEFAULT_BUCKETS
        
        # Per label combination:
        # - _counts: bucket -> count of values <= bucket
        # - _sums: total sum of all observed values
        # - _totals: total count of observations
        self._counts: Dict[tuple, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._sums: Dict[tuple, float] = defaultdict(float)
        self._totals: Dict[tuple, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def observe(self, value: float, **label_values) -> None:
        """
        Record an observation.
        
        Args:
            value: The value to record
            **label_values: Label key=value pairs
            
        EXAMPLE:
            histogram.observe(0.25, method="GET")
        """
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._sums[key] += value
            self._totals[key] += 1
            # Increment all buckets where value <= bucket
            for bucket in self.buckets:
                if value <= bucket:
                    self._counts[key][bucket] += 1
    
    def to_prometheus(self) -> str:
        """
        Export to Prometheus text format.
        
        OUTPUT FORMAT:
            metric_bucket{le="0.1"} 10
            metric_bucket{le="0.5"} 25
            metric_bucket{le="+Inf"} 30
            metric_sum 45.67
            metric_count 30
        """
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} histogram"
        ]
        
        for key in set(list(self._counts.keys()) + list(self._sums.keys())):
            if self.labels:
                base_labels = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key))
            else:
                base_labels = ""
            
            # Output bucket counts (cumulative)
            cumulative = 0
            for bucket in self.buckets:
                cumulative += self._counts[key].get(bucket, 0)
                if base_labels:
                    lines.append(f'{self.name}_bucket{{{base_labels},le="{bucket}"}} {cumulative}')
                else:
                    lines.append(f'{self.name}_bucket{{le="{bucket}"}} {cumulative}')
            
            # +Inf bucket (all values)
            total = self._totals.get(key, 0)
            if base_labels:
                lines.append(f'{self.name}_bucket{{{base_labels},le="+Inf"}} {total}')
                lines.append(f'{self.name}_sum{{{base_labels}}} {self._sums.get(key, 0)}')
                lines.append(f'{self.name}_count{{{base_labels}}} {total}')
            else:
                lines.append(f'{self.name}_bucket{{le="+Inf"}} {total}')
                lines.append(f'{self.name}_sum {self._sums.get(key, 0)}')
                lines.append(f'{self.name}_count {total}')
        
        return "\n".join(lines)


# ============================================================================
# IOTGUARD METRICS DEFINITIONS
# Pre-defined metrics for the IoTGuard application
# ============================================================================

# ---------------------------------------------------------------------------
# DETECTION METRICS
# Track threat detections and actions taken
# ---------------------------------------------------------------------------
detections_total = Counter(
    "iotguard_detections_total",
    "Total number of threat detections",
    labels=("severity", "attack_type")
)

blocks_total = Counter(
    "iotguard_blocks_total", 
    "Total number of IP blocks",
    labels=("success",)  # "true" or "false"
)

# ---------------------------------------------------------------------------
# PERFORMANCE METRICS
# Track model inference performance
# ---------------------------------------------------------------------------
inference_seconds = Histogram(
    "iotguard_inference_seconds",
    "Model inference latency in seconds",
    labels=("model_type",),  # "supervised", "unsupervised", "ensemble"
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1)
)

score_distribution = Histogram(
    "iotguard_score_distribution",
    "Distribution of detection scores",
    labels=("model_type",),
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
)

# ---------------------------------------------------------------------------
# API METRICS
# Track API usage
# ---------------------------------------------------------------------------
api_requests_total = Counter(
    "iotguard_api_requests_total",
    "Total API requests",
    labels=("endpoint", "method", "status")
)

# ---------------------------------------------------------------------------
# HEALTH / STATUS METRICS
# Track system health
# ---------------------------------------------------------------------------
model_drift = Gauge(
    "iotguard_model_drift",
    "Model drift indicator (0-1, higher = more drift)",
    labels=("model_type",)
)

active_connections = Gauge(
    "iotguard_active_connections",
    "Number of active WebSocket connections"
)

last_detection_timestamp = Gauge(
    "iotguard_last_detection_timestamp",
    "Timestamp of last detection"
)

# ---------------------------------------------------------------------------
# INFO METRIC
# Static information about the service
# ---------------------------------------------------------------------------
info = Gauge(
    "iotguard_info",
    "IoTGuard version information",
    labels=("version",)
)
info.set(1, version="1.0.0")


# ============================================================================
# CONVENIENCE FUNCTIONS
# Easy-to-use wrappers for recording metrics
# ============================================================================

def record_detection(severity: str, attack_type: str = "unknown") -> None:
    """
    Record a threat detection.
    
    WHEN TO CALL:
        In decision_loop.py when a threat is detected.
    
    EXAMPLE:
        record_detection("high", "SYN_Flood")
    
    Args:
        severity: low, medium, high, or critical
        attack_type: Type of attack detected
    """
    detections_total.inc(severity=severity, attack_type=attack_type)
    last_detection_timestamp.set(time.time())


def record_block(success: bool = True) -> None:
    """
    Record an IP block attempt.
    
    WHEN TO CALL:
        In blocker.py after attempting to block an IP.
    
    EXAMPLE:
        result = block_ip("192.168.1.100")
        record_block(success=result)
    
    Args:
        success: Whether the block succeeded
    """
    blocks_total.inc(success=str(success).lower())


def record_score(score: float, model_type: str = "supervised") -> None:
    """
    Record a detection score for distribution analysis.
    
    WHEN TO CALL:
        After getting a prediction from any model.
    
    EXAMPLE:
        score = model.predict_proba(features)[0][1]
        record_score(score, "supervised")
    
    Args:
        score: Detection score (0.0 to 1.0)
        model_type: Which model produced the score
    """
    score_distribution.observe(score, model_type=model_type)


@contextmanager
def record_inference_time(model_type: str = "supervised"):
    """
    Context manager to record model inference latency.
    
    WHEN TO CALL:
        Wrap model prediction calls.
    
    EXAMPLE:
        with record_inference_time("supervised"):
            prediction = model.predict(features)
        
        # Or for ensemble:
        with record_inference_time("ensemble"):
            result = ensemble.predict(features)
    
    Args:
        model_type: Type of model being timed
        
    HOW IT WORKS:
        1. Records start time on entry
        2. Runs the wrapped code
        3. Records duration on exit
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        inference_seconds.observe(duration, model_type=model_type)


def record_api_request(endpoint: str, method: str, status: int) -> None:
    """
    Record an API request.
    
    WHEN TO CALL:
        In Flask after_request hook.
    
    EXAMPLE:
        @app.after_request
        def track_request(response):
            record_api_request(
                endpoint=request.path,
                method=request.method,
                status=response.status_code
            )
            return response
    """
    api_requests_total.inc(endpoint=endpoint, method=method, status=str(status))


def update_model_drift(drift_score: float, model_type: str = "supervised") -> None:
    """
    Update the model drift indicator.
    
    WHAT IS MODEL DRIFT:
        Over time, the distribution of real data may change from
        what the model was trained on. High drift suggests the
        model may need retraining.
    
    HOW TO CALCULATE:
        Compare recent prediction distributions to training baseline.
        Common approaches: KL divergence, PSI (Population Stability Index)
    
    Args:
        drift_score: 0.0 (no drift) to 1.0 (severe drift)
        model_type: Which model
    """
    model_drift.set(drift_score, model_type=model_type)


# ============================================================================
# EXPORT FUNCTIONS
# Get metrics in various formats
# ============================================================================

def get_metrics_text() -> str:
    """
    Get all metrics in Prometheus text exposition format.
    
    WHEN TO CALL:
        Handler for GET /metrics endpoint.
    
    EXAMPLE:
        @app.get("/metrics")
        def prometheus_metrics():
            return Response(get_metrics_text(), mimetype="text/plain")
    
    Returns:
        Multi-line string in Prometheus format
    """
    metrics = [
        detections_total,
        blocks_total,
        inference_seconds,
        score_distribution,
        api_requests_total,
        model_drift,
        active_connections,
        last_detection_timestamp,
        info
    ]
    
    parts = []
    for metric in metrics:
        text = metric.to_prometheus()
        if text.strip():
            parts.append(text)
    
    return "\n\n".join(parts) + "\n"


def get_metrics_json() -> Dict[str, Any]:
    """
    Get metrics summary as JSON for the dashboard.
    
    WHEN TO CALL:
        Handler for GET /api/v1/metrics endpoint.
    
    Returns:
        Dict with summarized metrics
    """
    return {
        "detections": {
            "total": sum(detections_total._values.values()),
            "by_severity": {
                k[0]: v for k, v in detections_total._values.items()
            }
        },
        "blocks": {
            "total": sum(blocks_total._values.values()),
            "success_rate": (
                blocks_total.get(success="true") / 
                max(1, sum(blocks_total._values.values()))
            )
        },
        "inference": {
            "total_count": sum(inference_seconds._totals.values()),
            "avg_latency_ms": (
                sum(inference_seconds._sums.values()) / 
                max(1, sum(inference_seconds._totals.values())) * 1000
            )
        },
        "last_detection": last_detection_timestamp.get(),
        "active_connections": active_connections.get()
    }


# ============================================================================
# STANDALONE TESTING
# ============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("IoTGuard Metrics Test")
    print("=" * 60)
    
    # Simulate some activity
    print("\nSimulating metrics collection...")
    
    record_detection("high", "SYN_Flood")
    record_detection("medium", "Port_Scan")
    record_detection("high", "SYN_Flood")  # Same type again
    
    record_block(True)
    record_block(True)
    record_block(False)  # One failed block
    
    record_score(0.85, "supervised")
    record_score(0.45, "supervised")
    record_score(0.92, "ensemble")
    
    # Simulate inference timing
    with record_inference_time("supervised"):
        time.sleep(0.01)  # 10ms
    
    with record_inference_time("ensemble"):
        time.sleep(0.025)  # 25ms
    
    # Print Prometheus format
    print("\n=== Prometheus Format ===")
    print(get_metrics_text())
    
    # Print JSON summary
    print("\n=== JSON Summary ===")
    import json
    print(json.dumps(get_metrics_json(), indent=2))
