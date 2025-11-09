#!/usr/bin/env python3
"""
Demonstration of Multi-Stage LLM Prompt Chaining for Creative Hypothesis Generation
Shows the full workflow from contract analysis to exploit scenario generation
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.persistent_learning import PersistentLearningDB
from advanced.prompt_chaining import PromptOptimizer


# Sample vulnerable contract for demonstration
VULNERABLE_VAULT = """
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // VULNERABILITY 1: Classic reentrancy - external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update - REENTRANCY VULNERABILITY!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;  // State updated AFTER external call
        totalSupply -= amount;
        emit Withdrawal(msg.sender, amount);
    }
    
    // VULNERABILITY 2: No access control on emergency function
    function emergencyWithdraw() public {
        uint256 contractBalance = address(this).balance;
        (bool success, ) = msg.sender.call{value: contractBalance}("");
        require(success, "Emergency withdrawal failed");
    }
    
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}
"""


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def demonstrate_prompt_chaining():
    """Main demonstration function"""
    
    print_section("Multi-Stage LLM Prompt Chaining Demonstration")
    
    print("This demo shows how the prompt chain orchestrator generates creative")
    print("vulnerability hypotheses through multiple stages of refinement.\n")
    
    # Initialize components
    print("🔧 Initializing components...")
    reasoner = AdvancedLLMReasoner()
    learning_db = PersistentLearningDB()
    optimizer = PromptOptimizer(learning_db)
    
    # Get learned patterns for context
    learned_patterns = learning_db.get_learned_patterns_text(max_patterns=5)
    print(f"✓ Loaded {len(learned_patterns)} learned patterns from database\n")
    
    # Execute prompt chain
    print_section("Executing Multi-Stage Prompt Chain")
    
    result = reasoner.execute_prompt_chain(
        contract_code=VULNERABLE_VAULT,
        contract_type="vault",
        static_analysis_results={
            "detectors": {
                "reentrancy": ["withdraw"],
                "unprotected_function": ["emergencyWithdraw"],
                "external_calls": ["withdraw", "emergencyWithdraw"]
            }
        },
        learned_patterns=learned_patterns,
        creativity_level="balanced"
    )
    
    # Display results
    print_section("Results Summary")
    
    print("📊 Execution Statistics:")
    print(f"  • Total hypotheses generated: {result.hypotheses_generated}")
    print(f"  • Hypotheses validated: {result.hypotheses_validated}")
    print(f"  • Hypotheses rejected: {result.hypotheses_rejected}")
    print(f"  • Exploit scenarios created: {len(result.exploit_scenarios)}")
    print(f"  • Execution time: {result.execution_time:.2f}s")
    print(f"  • Estimated tokens used: {result.tokens_used}\n")
    
    # Show stage-by-stage results
    print_section("Stage-by-Stage Breakdown")
    
    for stage_name, stage_stats in result.stage_results.items():
        print(f"📌 {stage_name.replace('_', ' ').title()}:")
        for key, value in stage_stats.items():
            print(f"  • {key}: {value}")
        print()
    
    # Display hypotheses
    if result.all_hypotheses:
        print_section("Generated Hypotheses")
        
        for i, hypothesis in enumerate(result.all_hypotheses[:10], 1):
            print(f"{i}. {hypothesis.name}")
            print(f"   Description: {hypothesis.description}")
            print(f"   Plausibility: {hypothesis.plausibility}")
            print(f"   Confidence: {hypothesis.confidence:.2f}")
            print(f"   Status: {hypothesis.status}")
            
            if hypothesis.historical_reference:
                print(f"   Historical Ref: {hypothesis.historical_reference}")
            
            if hypothesis.preconditions:
                print(f"   Preconditions: {', '.join(hypothesis.preconditions)}")
            
            if hypothesis.code_evidence:
                print(f"   Code Evidence: {', '.join(hypothesis.code_evidence)}")
            
            print()
    
    # Display exploit scenarios
    if result.exploit_scenarios:
        print_section("Synthesized Exploit Scenarios")
        
        for i, scenario in enumerate(result.exploit_scenarios, 1):
            print(f"🎯 Exploit Scenario {i}: {scenario.name}")
            print(f"   Type: {scenario.vulnerability_type}")
            print(f"   Severity: {scenario.severity.upper()}")
            print(f"   Confidence: {scenario.confidence:.2f}")
            print(f"   Difficulty: {scenario.difficulty}")
            print(f"   Estimated Profit: {scenario.estimated_profit}")
            print("\n   Conditions Required:")
            for cond in scenario.conditions:
                print(f"     • {cond}")
            
            print("\n   Attacker Capabilities:")
            for cap in scenario.attacker_capabilities:
                print(f"     • {cap}")
            
            print("\n   Attack Sequence:")
            for step in scenario.attack_sequence:
                print(f"     {step['step']}. {step['action']} [{step.get('function', 'N/A')}]")
            
            print(f"\n   Impact: {scenario.impact}\n")
    
    # Record quality metrics
    if result.hypotheses_generated > 0:
        print_section("Recording Quality Metrics")
        
        # Calculate average confidences
        initial_confidences = [h.confidence for h in result.all_hypotheses if h.stage == 'divergent_exploration']
        final_confidences = [h.confidence for h in result.all_hypotheses if h.status == 'validated']
        
        avg_initial = sum(initial_confidences) / len(initial_confidences) if initial_confidences else 0.5
        avg_final = sum(final_confidences) / len(final_confidences) if final_confidences else 0.7
        
        learning_db.record_hypothesis_quality(
            hypothesis_type="reentrancy",
            generated_count=result.hypotheses_generated,
            verified_count=result.hypotheses_validated,
            rejected_count=result.hypotheses_rejected,
            avg_initial_confidence=avg_initial,
            avg_final_confidence=avg_final
        )
        
        print("✓ Recorded hypothesis quality metrics to learning database")
        print(f"  • Average initial confidence: {avg_initial:.2f}")
        print(f"  • Average final confidence: {avg_final:.2f}")
        print(f"  • Confidence improvement: {(avg_final - avg_initial):+.2f}\n")
    
    # Optimization recommendations
    print_section("Prompt Optimization Recommendations")
    
    for stage_name in ['divergent_exploration', 'technical_validation', 'exploit_synthesis']:
        # Simulate feedback for demonstration
        optimizer.optimize_based_on_feedback(
            stage_name=stage_name,
            hypotheses=result.all_hypotheses,
            verified_count=result.hypotheses_validated,
            false_positive_count=max(0, result.hypotheses_validated - 1)
        )
        
        recommendations = optimizer.get_optimization_recommendations(stage_name)
        
        if recommendations['status'] == 'analyzed':
            print(f"📈 {stage_name.replace('_', ' ').title()}:")
            print(f"  • Success rate: {recommendations['avg_success_rate']:.1%}")
            print(f"  • False positive rate: {recommendations['avg_fp_rate']:.1%}")
            
            if recommendations['suggestions']:
                print("  • Suggestions:")
                for suggestion in recommendations['suggestions']:
                    print(f"    - {suggestion}")
            print()
    
    print_section("Demonstration Complete")
    
    print("✅ The prompt chaining system successfully:")
    print("  1. Generated diverse vulnerability hypotheses (divergent exploration)")
    print("  2. Enhanced them with historical context (analogical reasoning)")
    print("  3. Validated technical feasibility (technical validation)")
    print("  4. Synthesized actionable exploit scenarios (exploit synthesis)")
    print("  5. Recorded quality metrics for continuous improvement")
    print("\n💡 The system will improve over time as it learns from more scans!\n")
    
    # Display learning database summary
    metrics = learning_db.get_improvement_metrics()
    
    if metrics.get('total_scans', 0) > 0:
        print("📚 Learning Database Summary:")
        print(f"  • Total scans: {metrics.get('total_scans', 0)}")
        print(f"  • Patterns learned: {metrics.get('total_patterns_learned', 0)}")
        
        if 'hypothesis_metrics' in metrics:
            h_metrics = metrics['hypothesis_metrics']
            if isinstance(h_metrics, dict) and h_metrics.get('total_hypotheses_generated', 0) > 0:
                print(f"  • Total hypotheses generated: {h_metrics.get('total_hypotheses_generated', 0)}")
                print(f"  • Overall success rate: {h_metrics.get('overall_success_rate', 0):.1%}")


def demonstrate_creativity_levels():
    """Demonstrate different creativity levels"""
    
    print_section("Comparing Creativity Levels")
    
    reasoner = AdvancedLLMReasoner()
    
    for creativity_level in ['conservative', 'balanced', 'aggressive']:
        print(f"\n🎨 Testing {creativity_level.upper()} creativity level...")
        
        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT,
            contract_type="vault",
            creativity_level=creativity_level
        )
        
        print(f"  Hypotheses: {result.hypotheses_generated}")
        print(f"  Validated: {result.hypotheses_validated}")
        print(f"  Scenarios: {len(result.exploit_scenarios)}")
        print(f"  Time: {result.execution_time:.2f}s")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("  ADVANCED WEB3 BUG HUNTER - PROMPT CHAINING DEMO")
    print("="*80 + "\n")
    
    # Main demonstration
    demonstrate_prompt_chaining()
    
    # Creativity levels comparison
    demonstrate_creativity_levels()
    
    print("\n" + "="*80)
    print("  Demo completed successfully!")
    print("="*80 + "\n")
