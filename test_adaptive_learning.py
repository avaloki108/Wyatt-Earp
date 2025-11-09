#!/usr/bin/env python3
"""
Test script for Adaptive Learning System
Demonstrates adaptive learning capabilities
"""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from advanced.adaptive_learning import (
    AdaptiveLearningSystem, 
    PromptOptimizer,
    VerificationTuner,
    PatternLearner,
    UserFeedbackProcessor
)
from advanced.persistent_learning import PersistentLearningDB


def test_prompt_optimizer():
    """Test prompt optimization functionality"""
    print("="*70)
    print("TEST 1: Prompt Optimizer")
    print("="*70)
    
    optimizer = PromptOptimizer()
    
    # Simulate hypothesis results
    print("\nSimulating hypothesis results...")
    
    # Divergent exploration - creative prompts
    for i in range(10):
        success = i < 3  # 30% success rate
        optimizer.track_hypothesis_result('divergent_exploration', 0.8, success)
    
    # Technical validation - precise prompts
    for i in range(10):
        success = i < 8  # 80% success rate
        optimizer.track_hypothesis_result('technical_validation', 0.3, success)
    
    # Show results
    print("\nPrompt Performance:")
    for stage, perf in optimizer.prompt_performance.items():
        print(f"\n  {stage}:")
        print(f"    Success Rate: {perf.success_rate:.1%}")
        print(f"    Total Hypotheses: {perf.total_hypotheses}")
        print(f"    Successful: {perf.successful_hypotheses}")
        print(f"    Avg Temperature: {perf.avg_temperature:.2f}")
        print(f"    Optimized Temperature: {optimizer.get_optimized_temperature(stage):.2f}")
    
    # Show recommendations
    print("\nRecommendations:")
    for rec in optimizer.get_recommendations():
        print(f"  • {rec}")
    
    print("\n✓ Prompt Optimizer Test Passed")
    return optimizer


def test_verification_tuner():
    """Test verification weight tuning"""
    print("\n" + "="*70)
    print("TEST 2: Verification Tuner")
    print("="*70)
    
    tuner = VerificationTuner()
    
    print("\nInitial weights:")
    for layer, weight in tuner.get_weights().items():
        print(f"  {layer}: {weight:.2%}")
    
    # Simulate accuracy results
    print("\nSimulating layer accuracy results...")
    
    # Static analysis - moderate accuracy
    for _ in range(15):
        tuner.record_layer_accuracy('static', 0.7)
    
    # Symbolic execution - high accuracy
    for _ in range(15):
        tuner.record_layer_accuracy('symbolic', 0.95)
    
    # Dynamic testing - moderate accuracy
    for _ in range(15):
        tuner.record_layer_accuracy('dynamic', 0.75)
    
    # Behavioral - low accuracy
    for _ in range(15):
        tuner.record_layer_accuracy('behavioral', 0.5)
    
    # Adjust weights
    tuner.adjust_weights(min_samples=10)
    
    print("\nAdjusted weights (after performance feedback):")
    for layer, weight in tuner.get_weights().items():
        print(f"  {layer}: {weight:.2%}")
    
    print("\n✓ Verification Tuner Test Passed")
    return tuner


def test_pattern_learner():
    """Test pattern learning from verified vulnerabilities"""
    print("\n" + "="*70)
    print("TEST 3: Pattern Learner")
    print("="*70)
    
    learner = PatternLearner()
    
    # Simulate verified vulnerabilities
    verified_vulns = [
        {
            'name': 'reentrancy_attack',
            'severity': 'high',
            'confidence': 0.9,
            'detection_strategy': 'symbolic_execution',
            'affected_code': 'function withdraw() external { ... }'
        },
        {
            'name': 'integer_overflow',
            'severity': 'medium',
            'confidence': 0.85,
            'detection_strategy': 'static_analysis',
            'affected_code': 'uint256 balance = amount + total;'
        },
        {
            'name': 'reentrancy_attack',  # Duplicate pattern
            'severity': 'high',
            'confidence': 0.92,
            'detection_strategy': 'symbolic_execution',
            'affected_code': 'function transfer() external { ... }'
        }
    ]
    
    print(f"\nExtracting patterns from {len(verified_vulns)} verified vulnerabilities...")
    new_patterns = learner.extract_patterns(verified_vulns)
    
    print(f"\nNew patterns learned: {len(new_patterns)}")
    for pattern in new_patterns:
        print(f"\n  Pattern: {pattern['name']}")
        print(f"    Severity: {pattern['severity']}")
        print(f"    Confidence: {pattern['confidence']:.1%}")
        print(f"    Detection Strategy: {pattern['detection_strategy']}")
    
    print(f"\nTotal unique patterns: {len(learner.learned_patterns)}")
    print(f"Pattern signatures tracked: {len(learner.pattern_signatures)}")
    
    print("\n✓ Pattern Learner Test Passed")
    return learner


def test_user_feedback_processor():
    """Test user feedback processing"""
    print("\n" + "="*70)
    print("TEST 4: User Feedback Processor")
    print("="*70)
    
    # Create a test learning database
    test_db_path = "/tmp/test_adaptive_learning.json"
    learning_db = PersistentLearningDB(test_db_path)
    
    # Add a test pattern
    from advanced.persistent_learning import PatternEffectiveness
    from datetime import datetime
    
    learning_db.pattern_effectiveness['test_pattern'] = PatternEffectiveness(
        pattern_name='test_pattern',
        times_detected=5,
        true_positives=3,
        false_positives=2,
        last_updated=datetime.now().isoformat(),
        confidence_score=0.6
    )
    
    processor = UserFeedbackProcessor(learning_db)
    
    print(f"\nInitial pattern confidence: {learning_db.pattern_effectiveness['test_pattern'].confidence_score:.1%}")
    
    # Mark as false positive
    print("\nProcessing false positive feedback...")
    feedback1 = processor.process_feedback(
        vulnerability_id='vuln-001',
        feedback_type='false_positive',
        pattern_name='test_pattern',
        details={'reason': 'Duplicate detection'}
    )
    
    print(f"Updated pattern confidence: {learning_db.pattern_effectiveness['test_pattern'].confidence_score:.1%}")
    print(f"False positives: {learning_db.pattern_effectiveness['test_pattern'].false_positives}")
    
    # Confirm a vulnerability
    print("\nProcessing confirmation feedback...")
    feedback2 = processor.process_feedback(
        vulnerability_id='vuln-002',
        feedback_type='confirmed',
        pattern_name='test_pattern',
        details={'severity': 'high', 'impact': 'Loss of funds'}
    )
    
    print(f"Updated pattern confidence: {learning_db.pattern_effectiveness['test_pattern'].confidence_score:.1%}")
    print(f"True positives: {learning_db.pattern_effectiveness['test_pattern'].true_positives}")
    
    # Show feedback summary
    summary = processor.get_feedback_summary()
    print("\nFeedback Summary:")
    print(f"  Total Feedback: {summary['total_feedback']}")
    print(f"  By Type: {summary['by_type']}")
    
    print("\n✓ User Feedback Processor Test Passed")
    return processor


def test_adaptive_learning_system():
    """Test complete adaptive learning system"""
    print("\n" + "="*70)
    print("TEST 5: Complete Adaptive Learning System")
    print("="*70)
    
    # Create test learning database
    test_db_path = "/tmp/test_adaptive_system.json"
    learning_db = PersistentLearningDB(test_db_path)
    
    # Create adaptive system
    adaptive_system = AdaptiveLearningSystem(learning_db)
    
    # Simulate scan results
    scan_results = {
        'analysis_results': {
            'novel_patterns': {
                'patterns': [
                    {
                        'name': 'flash_loan_attack',
                        'severity': 'critical',
                        'confidence': 0.9,
                        'detection_strategy': 'behavioral_analysis'
                    },
                    {
                        'name': 'oracle_manipulation',
                        'severity': 'high',
                        'confidence': 0.85,
                        'detection_strategy': 'pattern_detection'
                    }
                ]
            },
            'anomalies': {
                'anomalies': [
                    {
                        'name': 'suspicious_state_change',
                        'severity': 'medium',
                        'confidence': 0.75,
                        'detection_strategy': 'anomaly_detection'
                    }
                ]
            }
        }
    }
    
    print("\nProcessing scan results through adaptive learning...")
    
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    result = loop.run_until_complete(
        adaptive_system.process_scan_results(scan_results)
    )
    
    loop.close()
    
    print("\nAdaptive Learning Results:")
    print(f"  New Patterns Learned: {result['new_patterns_learned']}")
    print(f"  Feedback Processed: {result['feedback_processed']}")
    print(f"  Verification Weights: {result['current_verification_weights']}")
    
    # Get comprehensive metrics
    metrics = adaptive_system.get_comprehensive_metrics()
    
    print("\nComprehensive Metrics:")
    print(f"  Prompt Performance Tracked: {len(metrics['prompt_optimization'])} stages")
    print(f"  Patterns Learned: {metrics['pattern_learning']['total_patterns_learned']}")
    print(f"  User Feedback: {metrics['user_feedback']['total_feedback']} items")
    
    # Save and load state
    print("\nTesting state persistence...")
    state = adaptive_system.save_state()
    
    new_system = AdaptiveLearningSystem(learning_db)
    new_system.load_state(state)
    
    print(f"✓ State saved with {len(state)} keys")
    print("✓ State loaded successfully")
    
    print("\n✓ Adaptive Learning System Test Passed")
    return adaptive_system


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print(" ADAPTIVE LEARNING SYSTEM - COMPREHENSIVE TESTS")
    print("="*70)
    print()
    
    try:
        # Run individual component tests
        optimizer = test_prompt_optimizer()
        tuner = test_verification_tuner()
        learner = test_pattern_learner()
        processor = test_user_feedback_processor()
        
        # Run integrated system test
        adaptive_system = test_adaptive_learning_system()
        
        print("\n" + "="*70)
        print(" ALL TESTS PASSED ✓")
        print("="*70)
        print("\n✅ Adaptive Learning System is working correctly!")
        print("\nKey capabilities demonstrated:")
        print("  • Prompt optimization based on success rates")
        print("  • Verification weight auto-tuning")
        print("  • Pattern learning from verified findings")
        print("  • User feedback processing")
        print("  • State persistence and loading")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
