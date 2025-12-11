"""
tests/test_ensemble.py
-----------------------------------------------------------------------------
Unit tests for the ensemble prediction module (ensemble.py)
-----------------------------------------------------------------------------
"""
import pytest
import numpy as np
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))


class TestEnsemblePredictor:
    """Test the EnsemblePredictor class"""
    
    @pytest.fixture
    def ensemble(self):
        """Create an ensemble predictor for testing"""
        from ensemble import EnsemblePredictor
        return EnsemblePredictor()
    
    def test_init_loads_models(self, ensemble):
        """Ensemble should load at least one model"""
        # At least supervised should be available
        assert ensemble.supervised_model is not None or ensemble.unsupervised_model is not None
    
    def test_predict_returns_dict(self, ensemble):
        """predict() should return a dictionary with required keys"""
        # Sample feature vector (13 features)
        features = np.array([[
            100, 50000, 100, 0.2, 500, 0.5, 0.1, 0.0, 0.3, 0.8, 5, 1000, 0.5
        ]])
        
        result = ensemble.predict(features)
        
        assert isinstance(result, dict)
        assert "score" in result
        assert "is_attack" in result
        assert "threshold" in result
        assert "confidence" in result
    
    def test_score_in_valid_range(self, ensemble):
        """Scores should be between 0 and 1"""
        features = np.array([[
            100, 50000, 100, 0.2, 500, 0.5, 0.1, 0.0, 0.3, 0.8, 5, 1000, 0.5
        ]])
        
        result = ensemble.predict(features)
        
        assert 0 <= result["score"] <= 1
        assert 0 <= result["confidence"] <= 1
    
    def test_is_attack_is_boolean(self, ensemble):
        """is_attack should be a boolean"""
        features = np.array([[
            100, 50000, 100, 0.2, 500, 0.5, 0.1, 0.0, 0.3, 0.8, 5, 1000, 0.5
        ]])
        
        result = ensemble.predict(features)
        
        assert isinstance(result["is_attack"], (bool, np.bool_))
    
    def test_batch_predict(self, ensemble):
        """predict_batch() should handle multiple samples"""
        features = np.array([
            [100, 50000, 100, 0.2, 500, 0.5, 0.1, 0.0, 0.3, 0.8, 5, 1000, 0.5],
            [200, 100000, 200, 0.8, 1000, 0.2, 0.3, 0.1, 0.1, 0.9, 3, 2000, 0.3],
        ])
        
        results = ensemble.predict_batch(features)
        
        assert isinstance(results, list)
        assert len(results) == 2
    
    def test_high_syn_ratio_detected(self, ensemble):
        """High SYN ratio traffic should likely be flagged"""
        # Traffic pattern suggesting SYN flood
        syn_flood_features = np.array([[
            1000,      # many flows
            100000,    # moderate bytes
            5000,      # many packets
            0.95,      # very high SYN ratio
            100,       # small mean bytes
            0.05,      # low ACK (not completing handshakes)
            0.0,       # no FIN
            0.0,       # no RST
            0.0,       # no HTTP
            1.0,       # all TCP
            1,         # low diversity
            50,        # low std
            0.01       # fast IAT
        ]])
        
        result = ensemble.predict(syn_flood_features)
        # This should have a high score (attack-like)
        assert result["score"] > 0.3  # At least somewhat suspicious
    
    def test_explain_prediction(self, ensemble):
        """explain_prediction() should return readable string"""
        features = np.array([[
            100, 50000, 100, 0.2, 500, 0.5, 0.1, 0.0, 0.3, 0.8, 5, 1000, 0.5
        ]])
        
        result = ensemble.predict(features)
        explanation = ensemble.explain_prediction(result)
        
        assert isinstance(explanation, str)
        assert len(explanation) > 0


class TestGetEnsemble:
    """Test the singleton pattern"""
    
    def test_get_ensemble_returns_same_instance(self):
        """get_ensemble() should return the same instance"""
        from ensemble import get_ensemble
        
        e1 = get_ensemble()
        e2 = get_ensemble()
        
        assert e1 is e2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
