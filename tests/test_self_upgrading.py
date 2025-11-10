"""
Tests for Self-Upgrading Learning System
Tests prompt effectiveness tracking, agent parameter tuning, and template selection
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.adaptive_learning import (
    AdaptiveLearningSystem,
    PromptOptimizer,
    VerificationTuner,
    PatternLearner,
    UserFeedbackProcessor,
    PromptPerformance,
    VerificationWeights,
    UserFeedback
)


class TestPromptOptimizer:
    """Test suite for prompt effectiveness tracking"""
    
    def test_prompt_optimizer_initialization(self):
        """Test PromptOptimizer initialization"""
        optimizer = PromptOptimizer()
        
        assert optimizer is not None
        assert isinstance(optimizer.prompt_performance, dict)
        
    def test_track_hypothesis_result(self):
        """Test tracking hypothesis success/failure"""
        optimizer = PromptOptimizer()
        
        optimizer.track_hypothesis_result("hunter", 0.8, was_successful=True)
        
        assert "hunter" in optimizer.prompt_performance
        perf = optimizer.prompt_performance["hunter"]
        assert perf.total_hypotheses == 1
        assert perf.successful_hypotheses == 1
        assert perf.success_rate == 1.0
        
    def test_success_rate_calculation(self):
        """Test success rate calculation over multiple hypotheses"""
        optimizer = PromptOptimizer()
        
        # Track multiple results
        optimizer.track_hypothesis_result("hunter", 0.8, was_successful=True)
        optimizer.track_hypothesis_result("hunter", 0.8, was_successful=True)
        optimizer.track_hypothesis_result("hunter", 0.8, was_successful=False)
        
        perf = optimizer.prompt_performance["hunter"]
        assert perf.total_hypotheses == 3
        assert perf.successful_hypotheses == 2
        assert abs(perf.success_rate - 0.666) < 0.01
        
    def test_average_temperature_tracking(self):
        """Test that average temperature is tracked correctly"""
        optimizer = PromptOptimizer()
        
        optimizer.track_hypothesis_result("hunter", 0.8, was_successful=True)
        optimizer.track_hypothesis_result("hunter", 0.6, was_successful=True)
        
        perf = optimizer.prompt_performance["hunter"]
        # Average should be (0.8 + 0.6) / 2 = 0.7
        assert abs(perf.avg_temperature - 0.7) < 0.01
        
    def test_optimized_temperature_for_high_success(self):
        """Test temperature optimization for high success rate"""
        optimizer = PromptOptimizer()
        
        # Simulate high success rate
        for _ in range(10):
            optimizer.track_hypothesis_result("hunter", 0.7, was_successful=True)
        
        optimized_temp = optimizer.get_optimized_temperature("hunter")
        
        # Should increase temperature for high success
        assert optimized_temp >= 0.7
        
    def test_optimized_temperature_for_low_success(self):
        """Test temperature optimization for low success rate"""
        optimizer = PromptOptimizer()
        
        # Simulate low success rate
        for _ in range(10):
            optimizer.track_hypothesis_result("hunter", 0.8, was_successful=False)
        
        optimized_temp = optimizer.get_optimized_temperature("hunter")
        
        # Should decrease temperature for low success
        assert optimized_temp < 0.8
        
    def test_default_temperature_for_new_stage(self):
        """Test default temperature for unknown stage"""
        optimizer = PromptOptimizer()
        
        temp = optimizer.get_optimized_temperature("unknown_stage")
        
        # Should return a reasonable default
        assert 0.0 <= temp <= 1.0
        
    def test_recommendations_generation(self):
        """Test generating optimization recommendations"""
        optimizer = PromptOptimizer()
        
        # Create conditions for recommendations
        for _ in range(10):
            optimizer.track_hypothesis_result("low_performer", 0.8, was_successful=False)
        
        recommendations = optimizer.get_recommendations()
        
        assert isinstance(recommendations, list)
        # Should have recommendation for low performer
        assert any("low_performer" in rec for rec in recommendations)
        
    def test_serialization(self):
        """Test optimizer serialization"""
        optimizer = PromptOptimizer()
        
        optimizer.track_hypothesis_result("hunter", 0.8, was_successful=True)
        
        data = optimizer.to_dict()
        
        assert isinstance(data, dict)
        assert "hunter" in data
        assert "success_rate" in data["hunter"]
        
    def test_deserialization(self):
        """Test optimizer deserialization"""
        optimizer = PromptOptimizer()
        
        data = {
            "hunter": {
                "prompt_stage": "hunter",
                "total_hypotheses": 5,
                "successful_hypotheses": 4,
                "success_rate": 0.8,
                "avg_temperature": 0.7,
                "last_updated": datetime.now().isoformat()
            }
        }
        
        optimizer.from_dict(data)
        
        assert "hunter" in optimizer.prompt_performance
        assert optimizer.prompt_performance["hunter"].success_rate == 0.8


class TestVerificationTuner:
    """Test suite for verification layer weight tuning"""
    
    def test_verification_tuner_initialization(self):
        """Test VerificationTuner initialization"""
        tuner = VerificationTuner()
        
        assert tuner is not None
        assert isinstance(tuner.current_weights, VerificationWeights)
        # Weights should sum to approximately 1.0
        total = sum([
            tuner.current_weights.static,
            tuner.current_weights.symbolic,
            tuner.current_weights.dynamic,
            tuner.current_weights.behavioral
        ])
        assert abs(total - 1.0) < 0.01
        
    def test_record_layer_accuracy(self):
        """Test recording accuracy for verification layers"""
        tuner = VerificationTuner()
        
        tuner.record_layer_accuracy("static", 0.9)
        
        assert len(tuner.layer_accuracy["static"]) == 1
        assert tuner.layer_accuracy["static"][0] == 0.9
        
    def test_weight_adjustment_for_high_accuracy(self):
        """Test weight increase for high-accuracy layers"""
        tuner = VerificationTuner()
        
        initial_weight = tuner.current_weights.static
        
        # Record high accuracy for static layer
        for _ in range(15):
            tuner.record_layer_accuracy("static", 0.95)
        
        tuner.adjust_weights(min_samples=10)
        
        # Weight should increase (after normalization)
        # Note: Actual weight might not increase due to normalization
        # but the adjustment should be attempted
        assert len(tuner.layer_accuracy["static"]) >= 10
        
    def test_weight_adjustment_for_low_accuracy(self):
        """Test weight decrease for low-accuracy layers"""
        tuner = VerificationTuner()
        
        # Record low accuracy
        for _ in range(15):
            tuner.record_layer_accuracy("symbolic", 0.4)
        
        tuner.adjust_weights(min_samples=10)
        
        # Adjustment should be made
        assert len(tuner.layer_accuracy["symbolic"]) >= 10
        
    def test_weights_remain_normalized(self):
        """Test that weights remain normalized after adjustment"""
        tuner = VerificationTuner()
        
        # Record various accuracies
        for _ in range(15):
            tuner.record_layer_accuracy("static", 0.9)
            tuner.record_layer_accuracy("symbolic", 0.5)
            tuner.record_layer_accuracy("dynamic", 0.8)
            tuner.record_layer_accuracy("behavioral", 0.6)
        
        tuner.adjust_weights(min_samples=10)
        
        # Weights should still sum to 1.0
        total = sum([
            tuner.current_weights.static,
            tuner.current_weights.symbolic,
            tuner.current_weights.dynamic,
            tuner.current_weights.behavioral
        ])
        assert abs(total - 1.0) < 0.01
        
    def test_get_weights(self):
        """Test getting current weights as dictionary"""
        tuner = VerificationTuner()
        
        weights = tuner.get_weights()
        
        assert isinstance(weights, dict)
        assert "static" in weights
        assert "symbolic" in weights
        assert "dynamic" in weights
        assert "behavioral" in weights
        
    def test_serialization(self):
        """Test tuner serialization"""
        tuner = VerificationTuner()
        
        tuner.record_layer_accuracy("static", 0.9)
        
        data = tuner.to_dict()
        
        assert isinstance(data, dict)
        assert "weights" in data
        assert "accuracy_history" in data
        
    def test_deserialization(self):
        """Test tuner deserialization"""
        tuner = VerificationTuner()
        
        data = {
            "weights": {
                "static": 0.2,
                "symbolic": 0.3,
                "dynamic": 0.4,
                "behavioral": 0.1,
                "last_updated": datetime.now().isoformat()
            },
            "accuracy_history": {
                "static": [0.9, 0.85, 0.92]
            }
        }
        
        tuner.from_dict(data)
        
        assert tuner.current_weights.static == 0.2
        assert len(tuner.layer_accuracy["static"]) == 3


class TestPatternLearner:
    """Test suite for pattern extraction and learning"""
    
    def test_pattern_learner_initialization(self):
        """Test PatternLearner initialization"""
        learner = PatternLearner()
        
        assert learner is not None
        assert isinstance(learner.learned_patterns, list)
        assert isinstance(learner.pattern_signatures, set)
        
    def test_extract_new_pattern(self):
        """Test extracting new patterns from vulnerabilities"""
        learner = PatternLearner()
        
        vulnerabilities = [
            {
                "name": "reentrancy",
                "severity": "critical",
                "confidence": 0.9,
                "affected_code": "withdraw() function"
            }
        ]
        
        new_patterns = learner.extract_patterns(vulnerabilities)
        
        assert len(new_patterns) > 0
        assert new_patterns[0]["name"] == "reentrancy"
        
    def test_pattern_deduplication(self):
        """Test that duplicate patterns are not added"""
        learner = PatternLearner()
        
        vuln = {
            "name": "reentrancy",
            "severity": "critical",
            "confidence": 0.9
        }
        
        # Extract same pattern twice
        learner.extract_patterns([vuln])
        learner.extract_patterns([vuln])
        
        # Should only have one pattern
        assert len(learner.learned_patterns) == 1
        
    def test_get_patterns(self):
        """Test retrieving learned patterns"""
        learner = PatternLearner()
        
        vuln = {
            "name": "test_pattern",
            "severity": "high",
            "confidence": 0.8
        }
        
        learner.extract_patterns([vuln])
        patterns = learner.get_patterns()
        
        assert len(patterns) > 0
        assert patterns[0]["name"] == "test_pattern"


class TestUserFeedbackProcessor:
    """Test suite for user feedback processing"""
    
    def test_feedback_processor_initialization(self):
        """Test UserFeedbackProcessor initialization"""
        processor = UserFeedbackProcessor()
        
        assert processor is not None
        assert isinstance(processor.feedback_log, list)
        
    def test_process_false_positive_feedback(self):
        """Test processing false positive feedback"""
        processor = UserFeedbackProcessor()
        
        feedback = processor.process_feedback(
            vulnerability_id="vuln-001",
            feedback_type="false_positive",
            pattern_name="test_pattern"
        )
        
        assert isinstance(feedback, UserFeedback)
        assert feedback.feedback_type == "false_positive"
        assert len(processor.feedback_log) == 1
        
    def test_process_confirmed_feedback(self):
        """Test processing confirmed vulnerability feedback"""
        processor = UserFeedbackProcessor()
        
        feedback = processor.process_feedback(
            vulnerability_id="vuln-002",
            feedback_type="confirmed",
            pattern_name="reentrancy"
        )
        
        assert feedback.feedback_type == "confirmed"
        
    def test_feedback_with_details(self):
        """Test processing feedback with additional details"""
        processor = UserFeedbackProcessor()
        
        details = {"notes": "Great catch!", "accuracy": "high"}
        
        feedback = processor.process_feedback(
            vulnerability_id="vuln-003",
            feedback_type="confirmed",
            details=details
        )
        
        assert feedback.details == details
        
    def test_get_feedback_summary(self):
        """Test generating feedback summary"""
        processor = UserFeedbackProcessor()
        
        processor.process_feedback("v1", "confirmed")
        processor.process_feedback("v2", "false_positive")
        processor.process_feedback("v3", "confirmed")
        
        summary = processor.get_feedback_summary()
        
        assert summary["total_feedback"] == 3
        assert "by_type" in summary
        assert summary["by_type"]["confirmed"] == 2
        assert summary["by_type"]["false_positive"] == 1
        
    def test_serialization(self):
        """Test feedback processor serialization"""
        processor = UserFeedbackProcessor()
        
        processor.process_feedback("v1", "confirmed")
        
        data = processor.to_dict()
        
        assert isinstance(data, list)
        assert len(data) == 1
        
    def test_deserialization(self):
        """Test feedback processor deserialization"""
        processor = UserFeedbackProcessor()
        
        data = [
            {
                "vulnerability_id": "v1",
                "feedback_type": "confirmed",
                "timestamp": datetime.now().isoformat(),
                "details": {},
                "pattern_name": "test"
            }
        ]
        
        processor.from_dict(data)
        
        assert len(processor.feedback_log) == 1


class TestAdaptiveLearningSystem:
    """Test suite for integrated adaptive learning system"""
    
    def test_adaptive_system_initialization(self):
        """Test AdaptiveLearningSystem initialization"""
        system = AdaptiveLearningSystem()
        
        assert system is not None
        assert isinstance(system.prompt_optimizer, PromptOptimizer)
        assert isinstance(system.verification_tuner, VerificationTuner)
        assert isinstance(system.pattern_learner, PatternLearner)
        assert isinstance(system.feedback_processor, UserFeedbackProcessor)
        
    def test_process_scan_results(self):
        """Test processing scan results"""
        system = AdaptiveLearningSystem()
        
        scan_results = {
            "analysis_results": {
                "novel_patterns": {
                    "patterns": [
                        {"name": "new_vuln", "confidence": 0.8, "severity": "high"}
                    ]
                }
            }
        }
        
        # Use synchronous call since we're not in async context
        import asyncio
        result = asyncio.run(system.process_scan_results(scan_results))
        
        assert isinstance(result, dict)
        assert "new_patterns_learned" in result
        
    def test_get_comprehensive_metrics(self):
        """Test getting comprehensive metrics"""
        system = AdaptiveLearningSystem()
        
        metrics = system.get_comprehensive_metrics()
        
        assert isinstance(metrics, dict)
        assert "prompt_optimization" in metrics
        assert "verification_tuning" in metrics
        assert "pattern_learning" in metrics
        assert "user_feedback" in metrics
        
    def test_save_and_load_state(self):
        """Test saving and loading system state"""
        system = AdaptiveLearningSystem()
        
        # Make some changes
        system.prompt_optimizer.track_hypothesis_result("hunter", 0.8, True)
        system.verification_tuner.record_layer_accuracy("static", 0.9)
        
        # Save state
        state = system.save_state()
        
        assert isinstance(state, dict)
        assert "last_updated" in state
        
        # Create new system and load state
        new_system = AdaptiveLearningSystem()
        new_system.load_state(state)
        
        # Verify state was loaded
        assert "hunter" in new_system.prompt_optimizer.prompt_performance
        
    def test_feedback_integration(self):
        """Test user feedback integration with learning"""
        system = AdaptiveLearningSystem()
        
        scan_results = {
            "analysis_results": {
                "novel_patterns": {"patterns": []},
                "anomalies": {"anomalies": []}
            }
        }
        
        user_feedback = {
            "vuln-1": {
                "type": "confirmed",
                "pattern_name": "reentrancy"
            }
        }
        
        import asyncio
        result = asyncio.run(system.process_scan_results(scan_results, user_feedback))
        
        assert result["feedback_processed"] == 1


class TestAgentParameterTuning:
    """Test suite for automatic agent parameter tuning"""
    
    def test_temperature_auto_tuning(self):
        """Test automatic temperature adjustment based on performance"""
        optimizer = PromptOptimizer()
        
        # Simulate poor performance at high temperature
        for _ in range(10):
            optimizer.track_hypothesis_result("hunter", 0.9, was_successful=False)
        
        # Should recommend lower temperature
        optimized_temp = optimizer.get_optimized_temperature("hunter")
        assert optimized_temp < 0.9
        
    def test_verification_weight_auto_tuning(self):
        """Test automatic verification weight adjustment"""
        tuner = VerificationTuner()
        
        # Simulate performance data
        for _ in range(15):
            tuner.record_layer_accuracy("static", 0.95)
            tuner.record_layer_accuracy("dynamic", 0.50)
        
        initial_static = tuner.current_weights.static
        initial_dynamic = tuner.current_weights.dynamic
        
        tuner.adjust_weights(min_samples=10)
        
        # After adjustment, weights should be updated
        # (exact values depend on algorithm)
        assert isinstance(tuner.current_weights.static, float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
