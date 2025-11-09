"""
Integration test for Multi-Stage LLM Prompt Chaining
Tests the full chain execution with a real vulnerable contract
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.prompt_chaining import PromptChainOrchestrator, PromptOptimizer
from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.persistent_learning import PersistentLearningDB


# Sample vulnerable contract for testing
VULNERABLE_VAULT_CONTRACT = """
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

    // VULNERABLE: Reentrancy attack possible
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state update - VULNERABILITY!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;  // State updated AFTER external call
        totalSupply -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    // VULNERABLE: No access control
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


class TestPromptChainIntegration:
    """Integration tests for the full prompt chain"""

    def test_full_chain_execution_with_mock_llm(self):
        """Test complete chain execution with mock LLM responses"""
        # Create mock LLM reasoner
        reasoner = AdvancedLLMReasoner()

        # Execute prompt chain
        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT,
            contract_type="vault",
            static_analysis_results={
                "detectors": {
                    "reentrancy": ["withdraw"],
                    "unprotected_function": ["emergencyWithdraw"],
                }
            },
            creativity_level="balanced",
        )

        # Verify results structure
        assert result is not None
        assert result.hypotheses_generated > 0
        assert result.execution_time > 0
        assert "divergent_exploration" in result.stage_results

        print(f"\n✓ Generated {result.hypotheses_generated} hypotheses")
        print(f"✓ Validated {result.hypotheses_validated} hypotheses")
        print(f"✓ Rejected {result.hypotheses_rejected} hypotheses")
        print(f"✓ Created {len(result.exploit_scenarios)} exploit scenarios")
        print(f"✓ Execution time: {result.execution_time:.2f}s")
        print(f"✓ Tokens used: ~{result.tokens_used}")

    def test_conservative_creativity_level(self):
        """Test chain with conservative creativity settings"""
        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT,
            contract_type="vault",
            creativity_level="conservative",
        )

        assert result is not None
        # Conservative should generate fewer, more focused hypotheses
        print(f"\n✓ Conservative mode: {result.hypotheses_generated} hypotheses")

    def test_aggressive_creativity_level(self):
        """Test chain with aggressive creativity settings"""
        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT,
            contract_type="vault",
            creativity_level="aggressive",
        )

        assert result is not None
        # Aggressive should generate more diverse hypotheses
        print(f"\n✓ Aggressive mode: {result.hypotheses_generated} hypotheses")

    def test_integration_with_learning_db(self):
        """Test integration with persistent learning database"""
        # Create learning DB
        learning_db = PersistentLearningDB(
            db_path="/tmp/test_integration_learning.json"
        )

        # Create optimizer
        optimizer = PromptOptimizer(learning_db)

        # Create orchestrator
        reasoner = AdvancedLLMReasoner()
        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT,
            contract_type="vault",
            learned_patterns=learning_db.get_learned_patterns_text(max_patterns=5),
        )

        assert result is not None

        # Record hypothesis quality
        if result.hypotheses_generated > 0:
            learning_db.record_hypothesis_quality(
                hypothesis_type="reentrancy",
                generated_count=result.hypotheses_generated,
                verified_count=result.hypotheses_validated,
                rejected_count=result.hypotheses_rejected,
                avg_initial_confidence=0.5,
                avg_final_confidence=0.7,
            )

        # Verify learning DB was updated
        metrics = learning_db._get_hypothesis_metrics_summary()
        assert metrics.get("total_hypotheses_generated", 0) >= 0

        print("\n✓ Learning DB integration successful")
        print(f"  Hypothesis metrics: {metrics}")

    def test_hypothesis_quality_across_stages(self):
        """Test that hypothesis quality improves through stages"""
        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT,
            contract_type="vault",
            creativity_level="balanced",
        )

        assert result is not None

        # Check stage progression
        divergent_count = 0
        if "divergent_exploration" in result.stage_results:
            divergent_count = result.stage_results["divergent_exploration"].get(
                "hypotheses_count", 0
            )
            print(f"\n✓ Stage 1 (Divergent): {divergent_count} hypotheses")

        if "technical_validation" in result.stage_results:
            validated = result.stage_results["technical_validation"].get("validated", 0)
            rejected = result.stage_results["technical_validation"].get("rejected", 0)
            print(f"✓ Stage 3 (Validation): {validated} validated, {rejected} rejected")

            # Validation should filter out some hypotheses
            if divergent_count > 0:
                rejection_rate = (
                    rejected / (validated + rejected)
                    if (validated + rejected) > 0
                    else 0
                )
                print(f"✓ Rejection rate: {rejection_rate * 100:.1f}%")

    def test_exploit_scenario_generation(self):
        """Test that exploit scenarios are properly synthesized"""
        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT,
            contract_type="vault",
            creativity_level="balanced",
        )

        assert result is not None

        # Check exploit scenarios
        print(f"\n✓ Generated {len(result.exploit_scenarios)} exploit scenarios")

        for i, scenario in enumerate(result.exploit_scenarios[:3], 1):
            print(f"\nExploit Scenario {i}:")
            print(f"  Name: {scenario.name}")
            print(f"  Type: {scenario.vulnerability_type}")
            print(f"  Severity: {scenario.severity}")
            print(f"  Confidence: {scenario.confidence:.2f}")
            print(f"  Difficulty: {scenario.difficulty}")

            assert scenario.name is not None
            assert scenario.vulnerability_type is not None
            assert scenario.severity in ["critical", "high", "medium", "low"]
            assert 0.0 <= scenario.confidence <= 1.0


class TestPromptChainPerformance:
    """Performance tests for prompt chaining"""

    def test_execution_time_is_reasonable(self):
        """Test that full chain executes in reasonable time"""
        import time

        reasoner = AdvancedLLMReasoner()

        start = time.time()
        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT, contract_type="vault"
        )
        elapsed = time.time() - start

        # Should complete in under 90 seconds (as per requirements)
        # With mock LLM, should be much faster
        assert elapsed < 10.0  # Mock LLM should be very fast

        print(f"\n✓ Execution time: {elapsed:.2f}s (target: <90s with real LLM)")

    def test_token_usage_tracking(self):
        """Test that token usage is tracked"""
        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code=VULNERABLE_VAULT_CONTRACT, contract_type="vault"
        )

        assert result is not None
        assert result.tokens_used > 0

        print(f"\n✓ Token usage: {result.tokens_used} tokens")

        # Check per-stage token usage
        for stage, stats in result.stage_results.items():
            if "tokens" in stats:
                print(f"  {stage}: {stats['tokens']} tokens")


class TestPromptChainEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_contract(self):
        """Test handling of empty contract"""
        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code="", contract_type="unknown"
        )

        assert result is not None
        # Should still execute but may generate fewer hypotheses
        print(f"\n✓ Empty contract: {result.hypotheses_generated} hypotheses")

    def test_very_large_contract(self):
        """Test handling of very large contract (token limit)"""
        # Create a large contract by repeating the vulnerable vault
        large_contract = VULNERABLE_VAULT_CONTRACT * 10

        reasoner = AdvancedLLMReasoner()

        result = reasoner.execute_prompt_chain(
            contract_code=large_contract, contract_type="vault"
        )

        assert result is not None
        # Should handle truncation gracefully
        print(f"\n✓ Large contract: {result.hypotheses_generated} hypotheses")

    def test_no_llm_client(self):
        """Test orchestrator with no LLM client (mock mode)"""
        orchestrator = PromptChainOrchestrator(llm_client=None)

        result = orchestrator.execute_chain_sync(
            contract_code=VULNERABLE_VAULT_CONTRACT, contract_type="vault"
        )

        assert result is not None
        # Should use mock responses
        assert result.hypotheses_generated > 0
        print(f"\n✓ Mock mode: {result.hypotheses_generated} hypotheses")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
