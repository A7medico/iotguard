"""
tests/test_device_fingerprinting.py
-----------------------------------------------------------------------------
Unit tests for the device fingerprinting module
-----------------------------------------------------------------------------
"""
import pytest
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from device_fingerprinting import DeviceFingerprinter, get_fingerprinter


class TestDeviceFingerprinter:
    """Test the DeviceFingerprinter class"""
    
    @pytest.fixture
    def fingerprinter(self):
        """Create a new fingerprinter for testing"""
        return DeviceFingerprinter()
    
    def test_init(self, fingerprinter):
        """Fingerprinter should initialize with empty profiles"""
        assert len(fingerprinter.device_profiles) == 0
    
    def test_iot_traffic_classified_as_iot(self, fingerprinter):
        """IoT-like traffic should be classified as IoT"""
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
        
        device_type, confidence = fingerprinter.classify(iot_features)
        
        assert device_type == "iot"
        assert confidence >= 0.5  # At least somewhat confident
    
    def test_it_traffic_classified_as_it(self, fingerprinter):
        """IT-like traffic should be classified as IT"""
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
        
        device_type, confidence = fingerprinter.classify(it_features)
        
        assert device_type == "it"
        assert confidence >= 0.5
    
    def test_profile_accumulation(self, fingerprinter):
        """Multiple samples should improve classification"""
        iot_features = {
            "flows": 10,
            "bytes_total": 5000,
            "protocol_diversity": 2,
            "http_ratio": 0.0,
            "mean_bytes_flow": 200,
            "std_bytes": 50,
            "tcp_ratio": 0.9,
            "iat_mean": 1.0,
        }
        
        # Add multiple samples
        for _ in range(10):
            fingerprinter.classify(iot_features, ip="192.168.1.50")
        
        # Profile should have accumulated
        profile = fingerprinter.device_profiles["192.168.1.50"]
        assert profile["samples"] == 10
    
    def test_get_device_type_cached(self, fingerprinter):
        """Cached device types should be retrievable"""
        # Manually cache a device
        fingerprinter.device_cache["192.168.1.100"] = "iot"
        
        result = fingerprinter.get_device_type("192.168.1.100")
        
        assert result == "iot"
    
    def test_get_device_type_uncached(self, fingerprinter):
        """Uncached devices should return None"""
        result = fingerprinter.get_device_type("10.0.0.1")
        
        assert result is None
    
    def test_get_stats(self, fingerprinter):
        """Stats should return correct counts"""
        # Clear any existing cache
        fingerprinter.device_cache.clear()
        
        fingerprinter.device_cache["1.1.1.1"] = "iot"
        fingerprinter.device_cache["2.2.2.2"] = "it"
        fingerprinter.device_cache["3.3.3.3"] = "iot"
        
        stats = fingerprinter.get_stats()
        
        assert stats["cached_devices"] == 3
        assert stats["iot_count"] == 2
        assert stats["it_count"] == 1
    
    def test_iot_score_in_valid_range(self, fingerprinter):
        """IoT score should always be between 0 and 1"""
        # Extreme IoT features
        extreme_iot = {
            "flows": 1,
            "protocol_diversity": 1,
            "http_ratio": 0.0,
            "mean_bytes_flow": 10,
            "std_bytes": 5,
        }
        
        score = fingerprinter._compute_iot_score(extreme_iot)
        assert 0 <= score <= 1
        
        # Extreme IT features
        extreme_it = {
            "flows": 10000,
            "protocol_diversity": 20,
            "http_ratio": 1.0,
            "mean_bytes_flow": 100000,
            "std_bytes": 50000,
        }
        
        score = fingerprinter._compute_iot_score(extreme_it)
        assert 0 <= score <= 1


class TestGetFingerprinter:
    """Test the singleton pattern"""
    
    def test_returns_singleton(self):
        """get_fingerprinter should return the same instance"""
        fp1 = get_fingerprinter()
        fp2 = get_fingerprinter()
        
        assert fp1 is fp2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
