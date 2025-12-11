"""
scripts/device_fingerprinting.py
=============================================================================
IoTGuard — Automatic Device Type Detection

PURPOSE:
    Automatically identify IoT vs IT devices based on traffic patterns,
    instead of requiring manual configuration in devices.yaml.

HOW IT WORKS:
    IoT devices typically have:
    - Lower traffic diversity (fewer unique destinations)
    - More predictable packet patterns
    - Lower protocol diversity
    - Smaller average packet sizes
    - Regular/periodic traffic patterns

    IT devices typically have:
    - High traffic diversity
    - Many different protocols
    - Larger packets (file transfers, web browsing)
    - Irregular traffic patterns

USAGE:
    from device_fingerprinting import DeviceFingerprinter

    fingerprinter = DeviceFingerprinter()
    device_type = fingerprinter.classify(features_row)
    # Returns: "iot" or "it"
=============================================================================
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from collections import defaultdict
import numpy as np

logger = logging.getLogger("iotguard.fingerprinting")


class DeviceFingerprinter:
    """
    Classify devices as IoT or IT based on traffic characteristics.
    
    ARCHITECTURE:
        DeviceFingerprinter
        ├── classify(features)           - Main classification method
        ├── _compute_iot_score()         - Calculate IoT likelihood
        ├── update_profile(ip, features) - Build per-IP profiles
        └── get_device_type(ip)          - Get cached device type
    
    FEATURE WEIGHTS:
        Features that strongly indicate IoT:
        - Low protocol diversity (1-2 protocols)
        - Small average packet sizes
        - Low HTTP ratio (not web browsing)
        - Regular IAT patterns
        
        Features that strongly indicate IT:
        - High protocol diversity (5+ protocols)
        - Large packets (file transfers)
        - High HTTP ratio (web browsing)
        - Variable traffic patterns
    """
    
    # Weight for each feature in IoT score calculation
    # Positive = more IoT-like, Negative = more IT-like
    FEATURE_WEIGHTS = {
        "protocol_diversity": -0.15,   # Lower diversity = IoT
        "http_ratio": -0.20,           # Lower HTTP = IoT
        "mean_bytes_flow": -0.10,      # Smaller packets = IoT
        "std_bytes": -0.10,            # Less variation = IoT
        "flows": -0.05,                # Fewer flows = IoT
    }
    
    # Thresholds for IoT characteristics
    IOT_THRESHOLDS = {
        "protocol_diversity": 3,   # IoT typically < 3 protocols
        "http_ratio": 0.3,         # IoT typically < 30% HTTP
        "mean_bytes_flow": 500,    # IoT typically < 500 bytes/flow
        "std_bytes": 200,          # IoT typically low variance
        "flows": 50,               # IoT typically fewer flows per window
    }
    
    def __init__(self):
        """Initialize the fingerprinter with empty device profiles."""
        # Per-IP accumulated statistics
        self.device_profiles: Dict[str, Dict] = defaultdict(lambda: {
            "samples": 0,
            "iot_score_sum": 0.0,
            "last_seen": 0,
        })
        
        # Cache of final classifications
        self.device_cache: Dict[str, str] = {}
        
        # Load existing cache if available
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load cached device classifications."""
        cache_path = Path("data/device_fingerprints.json")
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                self.device_cache = data.get("cache", {})
                logger.info(f"Loaded {len(self.device_cache)} cached device types")
            except Exception:
                pass
    
    def _save_cache(self) -> None:
        """Save device classifications to cache."""
        cache_path = Path("data/device_fingerprints.json")
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps({"cache": self.device_cache}, indent=2),
                encoding="utf-8"
            )
        except Exception:
            pass
    
    def _compute_iot_score(self, features: Dict[str, float]) -> float:
        """
        Compute an IoT likelihood score based on traffic features.
        
        Score interpretation:
            > 0.6: Likely IoT
            0.4-0.6: Uncertain
            < 0.4: Likely IT
        
        Args:
            features: Dict with feature values
        
        Returns:
            IoT score between 0 and 1
        """
        score = 0.5  # Start neutral
        
        for feature, threshold in self.IOT_THRESHOLDS.items():
            value = features.get(feature, threshold)
            
            if feature in ("protocol_diversity", "http_ratio", "mean_bytes_flow", 
                          "std_bytes", "flows"):
                # For these features, lower values = more IoT-like
                if value < threshold:
                    score += 0.1
                elif value > threshold * 2:
                    score -= 0.1
        
        # Additional heuristics
        
        # Very regular IAT suggests IoT (sensor polling)
        iat = features.get("iat_mean", 0.5)
        if 0.1 < iat < 2.0:  # Regular timing
            score += 0.05
        
        # High TCP ratio without HTTP suggests IoT (MQTT, CoAP)
        tcp_ratio = features.get("tcp_ratio", 0.5)
        http_ratio = features.get("http_ratio", 0)
        if tcp_ratio > 0.8 and http_ratio < 0.1:
            score += 0.1
        
        # High SYN ratio might indicate scanning (IT behavior)
        syn_ratio = features.get("syn_ratio", 0)
        if syn_ratio > 0.5:
            score -= 0.1
        
        return float(np.clip(score, 0, 1))
    
    def classify(
        self, 
        features: Dict[str, float],
        ip: Optional[str] = None
    ) -> Tuple[str, float]:
        """
        Classify traffic as IoT or IT.
        
        Args:
            features: Traffic feature dict
            ip: Optional source IP (for caching)
        
        Returns:
            Tuple of (device_type, confidence)
            device_type: "iot" or "it"
            confidence: 0.5 (uncertain) to 1.0 (very confident)
        """
        iot_score = self._compute_iot_score(features)
        
        # Update profile if IP provided
        if ip:
            self.update_profile(ip, features, iot_score)
            
            # Use averaged score from profile if enough samples
            profile = self.device_profiles[ip]
            if profile["samples"] >= 5:
                avg_score = profile["iot_score_sum"] / profile["samples"]
                iot_score = avg_score
        
        # Determine type and confidence
        if iot_score > 0.55:
            device_type = "iot"
            confidence = min(1.0, 0.5 + (iot_score - 0.5) * 2)
        elif iot_score < 0.45:
            device_type = "it"
            confidence = min(1.0, 0.5 + (0.5 - iot_score) * 2)
        else:
            # Uncertain - default to IoT
            device_type = "iot"
            confidence = 0.5
        
        # Cache result if confident enough
        if ip and confidence > 0.7:
            self.device_cache[ip] = device_type
            self._save_cache()
        
        return device_type, confidence
    
    def update_profile(
        self, 
        ip: str, 
        features: Dict[str, float],
        iot_score: Optional[float] = None
    ) -> None:
        """
        Update the traffic profile for an IP address.
        
        Accumulates statistics over time for more accurate classification.
        
        Args:
            ip: IP address
            features: Traffic features
            iot_score: Pre-computed IoT score (optional)
        """
        import time
        
        if iot_score is None:
            iot_score = self._compute_iot_score(features)
        
        profile = self.device_profiles[ip]
        profile["samples"] += 1
        profile["iot_score_sum"] += iot_score
        profile["last_seen"] = time.time()
    
    def get_device_type(self, ip: str) -> Optional[str]:
        """
        Get the cached device type for an IP.
        
        Args:
            ip: IP address
        
        Returns:
            "iot", "it", or None if not cached
        """
        return self.device_cache.get(ip)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fingerprinting statistics."""
        return {
            "cached_devices": len(self.device_cache),
            "active_profiles": len(self.device_profiles),
            "iot_count": sum(1 for v in self.device_cache.values() if v == "iot"),
            "it_count": sum(1 for v in self.device_cache.values() if v == "it"),
        }


# =============================================================================
# Singleton
# =============================================================================

_fingerprinter: Optional[DeviceFingerprinter] = None


def get_fingerprinter() -> DeviceFingerprinter:
    """Get or create the global fingerprinter instance."""
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = DeviceFingerprinter()
    return _fingerprinter


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("IoTGuard Device Fingerprinting")
    print("=" * 40)
    
    fp = DeviceFingerprinter()
    
    # Test IoT-like traffic
    iot_features = {
        "flows": 10,
        "bytes_total": 5000,
        "pkts_total": 50,
        "syn_ratio": 0.1,
        "mean_bytes_flow": 200,
        "ack_ratio": 0.8,
        "fin_ratio": 0.1,
        "rst_ratio": 0.0,
        "http_ratio": 0.0,
        "tcp_ratio": 0.9,
        "protocol_diversity": 2,
        "std_bytes": 50,
        "iat_mean": 1.0,
    }
    
    device_type, confidence = fp.classify(iot_features, ip="192.168.1.50")
    print(f"\nIoT-like traffic: {device_type} (confidence: {confidence:.2%})")
    
    # Test IT-like traffic
    it_features = {
        "flows": 200,
        "bytes_total": 500000,
        "pkts_total": 2000,
        "syn_ratio": 0.3,
        "mean_bytes_flow": 2500,
        "ack_ratio": 0.6,
        "fin_ratio": 0.2,
        "rst_ratio": 0.05,
        "http_ratio": 0.7,
        "tcp_ratio": 0.8,
        "protocol_diversity": 8,
        "std_bytes": 5000,
        "iat_mean": 0.05,
    }
    
    device_type, confidence = fp.classify(it_features, ip="192.168.1.100")
    print(f"IT-like traffic: {device_type} (confidence: {confidence:.2%})")
    
    print(f"\nStats: {fp.get_stats()}")
