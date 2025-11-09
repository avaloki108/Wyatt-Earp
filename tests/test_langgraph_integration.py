"""
Integration tests for LangGraph multi-agent orchestration workflow
Tests the complete DAG execution with all 5 specialized agents
"""

import pytest
import sys
from pathlib import Path
from typing import Any, Dict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.langgraph_orchestrator import LangGraphOrchestrator, LangGraphExecutionResult


# Sample vulnerable contract for testing
VULNERABLE_CONTRACT = """
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: Reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"""


class MockLLMClient:
    """Mock LLM client for testing without real API calls"""
    
    def __init__(self):
        self.call_count = 0
        self.responses = {
            "hunter": {
                "hypotheses": [
                    {
                        "name": "reentrancy_attack",
                        "severity": "critical",
                        "confidence": 0.9,
                        "description": "Withdraw function vulnerable to reentrancy"
                    }
                ]
            },
            "analogical_reasoner": {
                "enhancements": [
                    {
                        "name": "reentrancy_attack",
                        "severity": "critical",
                        "confidence": 0.95,
                        "description": "Similar to DAO hack pattern",
                        "historical_reference": "DAO 2016"
                    }
                ]
            },
            "skeptical_validator": {
                "validated": [
                    {
                        "name": "reentrancy_attack",
                        "severity": "critical",
                        "confidence": 0.9
                    }
                ],
                "rejected": [],
                "decision": "continue",
                "feedback": "Hypothesis appears valid"
            },
            "exploit_synthesizer": {
                "scenarios": [
                    {
                        "name": "reentrancy_exploit",
                        "steps": ["Deploy attacker contract", "Call withdraw", "Reenter"],
                        "expected_impact": "Drain all funds"
                    }
                ]
            },
            "self_evaluation": {
                "decision": "approve",
                "confidence": 0.85,
                "feedback": "Exploit scenario is complete and valid"
            }
        }
    
    def query_llm(self, prompt: str, model: str = "gpt-4", temperature: float = 0.7) -> Any:
        """Mock LLM query that returns appropriate responses based on agent type"""
        self.call_count += 1
        
        # Determine which agent is calling based on prompt content
        if "Hunt for vulnerabilities" in prompt or "identify" in prompt.lower():
            return self.responses["hunter"]
        elif "analogical" in prompt.lower() or "similar" in prompt.lower():
            return self.responses["analogical_reasoner"]
        elif "validate" in prompt.lower() or "skeptical" in prompt.lower():
            return self.responses["skeptical_validator"]
        elif "exploit" in prompt.lower() and "synthesize" in prompt.lower():
            return self.responses["exploit_synthesizer"]
        elif "evaluate" in prompt.lower() or "self-evaluation" in prompt.lower():
            return self.responses["self_evaluation"]
        else:
            return {"message": "Generic response"}


class TestLangGraphMultiAgentOrchestration:
    """Test suite for multi-agent LangGraph DAG workflow"""
    
    def test_orchestrator_initialization(self):
        """Test that orchestrator initializes correctly"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        assert orchestrator is not None
        assert orchestrator.llm_client == mock_client
        assert orchestrator.max_rewrites >= 0
        
    def test_full_dag_execution(self):
        """Test complete DAG execution with all agents"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        result = orchestrator.run(
            contract_code=VULNERABLE_CONTRACT,
            static_analysis_results={"detectors": {"reentrancy": ["withdraw"]}},
            contract_type="vault"
        )
        
        # Verify result structure
        assert isinstance(result, LangGraphExecutionResult)
        assert len(result.agent_runs) > 0
        assert result.final_decision in ["approved", "terminated", "undetermined"]
        
        # Verify all agents executed
        agent_names = {run.name for run in result.agent_runs}
        assert "hunter" in agent_names
        assert "analogical_reasoner" in agent_names
        assert "skeptical_validator" in agent_names
        
    def test_agent_sequence_execution(self):
        """Test that agents execute in correct sequence"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        result = orchestrator.run(
            contract_code=VULNERABLE_CONTRACT,
            static_analysis_results={},
            contract_type="vault"
        )
        
        # Extract agent execution order
        agent_sequence = [run.name for run in result.agent_runs]
        
        # Verify hunter runs first
        assert agent_sequence[0] == "hunter"
        
        # Verify analogical_reasoner runs after hunter
        hunter_idx = agent_sequence.index("hunter")
        analogical_idx = agent_sequence.index("analogical_reasoner")
        assert analogical_idx > hunter_idx
        
    def test_shared_memory_propagation(self):
        """Test that shared memory is propagated between agents"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        result = orchestrator.run(
            contract_code=VULNERABLE_CONTRACT,
            static_analysis_results={},
            contract_type="vault"
        )
        
        # Verify shared state contains expected fields
        assert "hypotheses" in result.shared_state or "validated_hypotheses" in result.shared_state
        assert "final_assessment" in result.shared_state
        
    def test_conditional_routing_from_skeptic(self):
        """Test conditional routing based on skeptical validator decision"""
        mock_client = MockLLMClient()
        
        # Test "continue" path
        mock_client.responses["skeptical_validator"]["decision"] = "continue"
        orchestrator = LangGraphOrchestrator(mock_client)
        result = orchestrator.run(VULNERABLE_CONTRACT, {}, "vault")
        
        # Should have exploit_synthesizer in execution
        agent_names = {run.name for run in result.agent_runs}
        assert "exploit_synthesizer" in agent_names
        
    def test_rewrite_loop_termination(self):
        """Test that rewrite loops terminate after max recursion"""
        mock_client = MockLLMClient()
        
        # Force rewrite decisions
        mock_client.responses["skeptical_validator"]["decision"] = "rewrite"
        mock_client.responses["self_evaluation"]["decision"] = "rewrite"
        
        orchestrator = LangGraphOrchestrator(mock_client)
        
        # Should raise recursion error when stuck in rewrite loop
        from langgraph.errors import GraphRecursionError
        with pytest.raises(GraphRecursionError):
            result = orchestrator.run(VULNERABLE_CONTRACT, {}, "vault")
        
    def test_agent_temperature_settings(self):
        """Test that each agent has appropriate temperature settings"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        result = orchestrator.run(VULNERABLE_CONTRACT, {}, "vault")
        
        # Verify temperature ranges for different agents
        for run in result.agent_runs:
            if run.name == "hunter":
                assert run.temperature >= 0.7  # Higher creativity
            elif run.name == "skeptical_validator":
                assert run.temperature <= 0.4  # Lower creativity, more strict
            elif run.name == "self_evaluation":
                assert run.temperature <= 0.3  # Most conservative
                
    def test_empty_contract_handling(self):
        """Test handling of empty/invalid contracts"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        result = orchestrator.run(
            contract_code="",
            static_analysis_results=None,
            contract_type="unknown"
        )
        
        # Should still complete without errors
        assert isinstance(result, LangGraphExecutionResult)
        
    def test_static_analysis_integration(self):
        """Test integration with static analysis results"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        static_results = {
            "detectors": {
                "reentrancy": ["withdraw"],
                "unprotected": ["emergencyWithdraw"]
            },
            "warnings": ["Missing access control"]
        }
        
        result = orchestrator.run(VULNERABLE_CONTRACT, static_results, "vault")
        
        # Verify static analysis is used
        assert len(result.agent_runs) > 0
        # At least one agent should reference static analysis in prompt
        assert any("static_analysis" in str(run.prompt).lower() or "detectors" in str(run.prompt).lower() 
                  for run in result.agent_runs)


class TestLangGraphEdgeCases:
    """Test edge cases and error handling"""
    
    def test_missing_config_file(self, tmp_path):
        """Test handling when config file is missing"""
        mock_client = MockLLMClient()
        
        # Create orchestrator with non-existent config path
        config_path = str(tmp_path / "nonexistent.yaml")
        orchestrator = LangGraphOrchestrator(mock_client, config_path=config_path)
        
        # Should initialize with default config
        assert orchestrator is not None
        
    def test_malformed_llm_responses(self):
        """Test handling of malformed LLM responses"""
        mock_client = MockLLMClient()
        
        # Provide malformed responses
        mock_client.responses["hunter"] = "Not a valid JSON response"
        
        orchestrator = LangGraphOrchestrator(mock_client)
        result = orchestrator.run(VULNERABLE_CONTRACT, {}, "vault")
        
        # Should handle gracefully
        assert isinstance(result, LangGraphExecutionResult)
        
    def test_large_contract_handling(self):
        """Test handling of very large contracts"""
        mock_client = MockLLMClient()
        orchestrator = LangGraphOrchestrator(mock_client)
        
        # Create a large contract
        large_contract = "contract Large {\n" + "\n".join([
            f"    uint256 public var{i};" for i in range(1000)
        ]) + "\n}"
        
        result = orchestrator.run(large_contract, {}, "vault")
        
        # Should complete without timeout
        assert isinstance(result, LangGraphExecutionResult)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
