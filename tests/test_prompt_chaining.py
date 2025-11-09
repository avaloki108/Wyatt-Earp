"""
Unit tests for Multi-Stage LLM Prompt Chaining
Tests each stage independently and the full chain orchestration
"""

import pytest
import json
from pathlib import Path
import sys
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.prompt_chaining import (
    PromptChainOrchestrator,
    HypothesisItem,
    ExploitScenario,
    PromptChainResult,
    PromptOptimizer,
)
from advanced.persistent_learning import PersistentLearningDB


class MockLLMClient:
    """Mock LLM client for testing"""

    def __init__(self, mock_responses=None):
        self.mock_responses = mock_responses or {}
        self.call_count = 0
        self.last_prompt: Optional[str] = None
        self.last_temperature: Optional[float] = None

    def query_llm(self, prompt: str, temperature: float = 0.7, **kwargs) -> str:
        """Mock query_llm method"""
        self.call_count += 1
        self.last_prompt = prompt
        self.last_temperature = temperature

        # Return stage-specific mock response
        if "divergent_exploration" in prompt.lower():
            return json.dumps(
                [
                    {
                        "name": "Flash Loan Reentrancy",
                        "description": "Use flash loan to trigger reentrancy",
                        "plausibility": "high",
                        "preconditions": [
                            "Flash loan available",
                            "Reentrancy possible",
                        ],
                    },
                    {
                        "name": "Oracle Manipulation",
                        "description": "Manipulate price oracle via large swap",
                        "plausibility": "medium",
                        "preconditions": ["Spot price oracle", "Low liquidity"],
                    },
                ]
            )
        elif "analogical_reasoning" in prompt.lower():
            return json.dumps(
                [
                    {
                        "hypothesis_id": "hyp-001",
                        "historical_reference": "Cream Finance Attack",
                        "manifestation": "Similar reentrancy pattern",
                        "confidence_adjustment": "+0.2",
                        "variations": ["Via fallback", "Via callback"],
                    }
                ]
            )
        elif "technical_validation" in prompt.lower():
            return json.dumps(
                [
                    {
                        "hypothesis_id": "hyp-001",
                        "status": "KEEP",
                        "reasoning": "Missing reentrancy guard",
                        "code_evidence": ["withdraw function"],
                        "confidence": 0.85,
                        "missing_safeguards": ["nonReentrant modifier"],
                    },
                    {
                        "hypothesis_id": "hyp-002",
                        "status": "REJECT",
                        "reasoning": "Oracle has TWAP protection",
                        "code_evidence": [],
                        "confidence": 0.2,
                        "missing_safeguards": [],
                    },
                ]
            )
        elif "exploit_synthesis" in prompt.lower():
            return json.dumps(
                [
                    {
                        "name": "Flash Loan Reentrancy Exploit",
                        "vulnerability_type": "reentrancy",
                        "severity": "critical",
                        "conditions": ["ETH balance > 0", "withdraw() public"],
                        "attacker_capabilities": ["Flash loan", "Malicious contract"],
                        "attack_sequence": [
                            {"step": 1, "action": "Get flash loan", "function": "N/A"},
                            {
                                "step": 2,
                                "action": "Call withdraw",
                                "function": "withdraw",
                            },
                            {
                                "step": 3,
                                "action": "Reenter via fallback",
                                "function": "receive",
                            },
                        ],
                        "impact": "All ETH drained",
                        "estimated_profit": "$1M+",
                        "difficulty": "easy",
                        "confidence": 0.85,
                    }
                ]
            )

        return "Mock response"


class TestPromptChainOrchestrator:
    """Test the PromptChainOrchestrator class"""

    def test_initialization(self):
        """Test orchestrator initialization"""
        mock_llm = MockLLMClient()
        orchestrator = PromptChainOrchestrator(llm_client=mock_llm)

        assert orchestrator.llm_client == mock_llm
        assert orchestrator.config is not None
        assert len(orchestrator.hypotheses) == 0
        assert len(orchestrator.exploit_scenarios) == 0

    def test_config_loading(self):
        """Test configuration loading from YAML"""
        orchestrator = PromptChainOrchestrator()

        assert "stages" in orchestrator.config
        assert "divergent_exploration" in orchestrator.config["stages"]
        assert "analogical_reasoning" in orchestrator.config["stages"]
        assert "technical_validation" in orchestrator.config["stages"]
        assert "exploit_synthesis" in orchestrator.config["stages"]

    def test_stage_enabled_check(self):
        """Test stage enabled/disabled check"""
        orchestrator = PromptChainOrchestrator()

        # All stages should be enabled by default
        assert orchestrator._is_stage_enabled("divergent_exploration")
        assert orchestrator._is_stage_enabled("analogical_reasoning")
        assert orchestrator._is_stage_enabled("technical_validation")
        assert orchestrator._is_stage_enabled("exploit_synthesis")

    def test_parse_divergent_response(self):
        """Test parsing divergent exploration response"""
        orchestrator = PromptChainOrchestrator()

        response = json.dumps(
            [
                {
                    "name": "Test Attack",
                    "description": "Test description",
                    "plausibility": "high",
                    "preconditions": ["condition1", "condition2"],
                }
            ]
        )

        hypotheses = orchestrator._parse_divergent_response(response)

        assert len(hypotheses) == 1
        assert hypotheses[0].name == "Test Attack"
        assert hypotheses[0].plausibility == "high"
        assert len(hypotheses[0].preconditions) == 2
        assert hypotheses[0].confidence > 0

    def test_parse_validation_response(self):
        """Test parsing technical validation response"""
        orchestrator = PromptChainOrchestrator()

        response = json.dumps(
            [
                {
                    "hypothesis_id": "hyp-001",
                    "status": "KEEP",
                    "reasoning": "Valid vulnerability",
                    "code_evidence": ["function1"],
                    "confidence": 0.8,
                    "missing_safeguards": ["guard1"],
                }
            ]
        )

        validations = orchestrator._parse_validation_response(response)

        assert len(validations) == 1
        assert validations[0]["status"] == "KEEP"
        assert validations[0]["confidence"] == 0.8

    def test_parse_exploit_scenarios(self):
        """Test parsing exploit synthesis response"""
        orchestrator = PromptChainOrchestrator()

        response = json.dumps(
            [
                {
                    "name": "Test Exploit",
                    "vulnerability_type": "reentrancy",
                    "severity": "high",
                    "conditions": ["cond1"],
                    "attacker_capabilities": ["cap1"],
                    "attack_sequence": [{"step": 1, "action": "test"}],
                    "impact": "Test impact",
                    "estimated_profit": "$100K",
                    "difficulty": "medium",
                    "confidence": 0.7,
                }
            ]
        )

        scenarios = orchestrator._parse_exploit_scenarios(response)

        assert len(scenarios) == 1
        assert scenarios[0].name == "Test Exploit"
        assert scenarios[0].severity == "high"
        assert scenarios[0].confidence == 0.7

    def test_apply_enhancements(self):
        """Test applying analogical reasoning enhancements"""
        orchestrator = PromptChainOrchestrator()

        hypotheses = [
            HypothesisItem(
                id="hyp-001",
                name="Test Hypothesis",
                description="Test",
                plausibility="medium",
                preconditions=[],
            )
        ]

        enhancements = [
            {
                "hypothesis_id": "hyp-001",
                "historical_reference": "Historic Attack",
                "manifestation": "Similar pattern",
                "confidence_adjustment": "+0.2",
                "variations": ["var1", "var2"],
            }
        ]

        enhanced = orchestrator._apply_enhancements(hypotheses, enhancements)

        assert enhanced[0].historical_reference == "Historic Attack"
        assert len(enhanced[0].variations) == 2
        assert enhanced[0].confidence > 0.5  # Should be increased

    def test_apply_validations(self):
        """Test applying technical validation results"""
        orchestrator = PromptChainOrchestrator()

        hypotheses = [
            HypothesisItem(
                id="hyp-001",
                name="H1",
                description="D1",
                plausibility="high",
                preconditions=[],
            ),
            HypothesisItem(
                id="hyp-002",
                name="H2",
                description="D2",
                plausibility="low",
                preconditions=[],
            ),
        ]

        validations = [
            {
                "hypothesis_id": "hyp-001",
                "status": "KEEP",
                "reasoning": "Valid",
                "code_evidence": ["func1"],
                "confidence": 0.8,
                "missing_safeguards": ["guard1"],
            },
            {
                "hypothesis_id": "hyp-002",
                "status": "REJECT",
                "reasoning": "Invalid",
                "code_evidence": [],
                "confidence": 0.2,
                "missing_safeguards": [],
            },
        ]

        validated, rejected = orchestrator._apply_validations(hypotheses, validations)

        assert len(validated) == 1
        assert len(rejected) == 1
        assert validated[0].status == "validated"
        assert rejected[0].status == "rejected"

    def test_plausibility_to_confidence(self):
        """Test plausibility to confidence conversion"""
        orchestrator = PromptChainOrchestrator()

        assert orchestrator._plausibility_to_confidence("low") == 0.3
        assert orchestrator._plausibility_to_confidence("medium") == 0.5
        assert orchestrator._plausibility_to_confidence("high") == 0.7
        assert orchestrator._plausibility_to_confidence("unknown") == 0.5

    def test_creativity_level_application(self):
        """Test applying creativity level presets"""
        orchestrator = PromptChainOrchestrator()

        # Apply aggressive creativity
        orchestrator._apply_creativity_level("aggressive")

        # Check temperatures were updated
        assert (
            orchestrator.config["stages"]["divergent_exploration"]["temperature"]
            == 0.95
        )
        assert (
            orchestrator.config["stages"]["technical_validation"]["temperature"] == 0.4
        )

    def test_contract_summary_creation(self):
        """Test contract summary generation"""
        orchestrator = PromptChainOrchestrator()

        contract_code = """
        contract Test {
            function deposit() public payable { }
            function withdraw(uint amount) public { }
        }
        """

        summary = orchestrator._create_contract_summary(contract_code)

        assert "deposit" in summary
        assert "withdraw" in summary

    def test_synchronous_execution(self):
        """Test synchronous chain execution"""
        mock_llm = MockLLMClient()
        orchestrator = PromptChainOrchestrator(llm_client=mock_llm)

        contract_code = """
        contract VulnerableVault {
            mapping(address => uint) balances;

            function withdraw(uint amount) public {
                require(balances[msg.sender] >= amount);
                msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """

        result = orchestrator.execute_chain_sync(
            contract_code=contract_code,
            contract_type="vault",
            creativity_level="balanced",
        )

        assert result is not None
        assert isinstance(result, PromptChainResult)
        assert result.hypotheses_generated >= 0
        assert result.execution_time > 0
        assert mock_llm.call_count > 0


class TestPromptOptimizer:
    """Test the PromptOptimizer class"""

    def test_initialization(self):
        """Test optimizer initialization"""
        learning_db = PersistentLearningDB(db_path="/tmp/test_learning.json")
        optimizer = PromptOptimizer(learning_db)

        assert optimizer.learning_db == learning_db
        assert len(optimizer.prompt_effectiveness) == 0

    def test_optimize_based_on_feedback(self):
        """Test optimization based on feedback"""
        learning_db = PersistentLearningDB(db_path="/tmp/test_learning.json")
        optimizer = PromptOptimizer(learning_db)

        hypotheses = [
            HypothesisItem(
                id="h1",
                name="H1",
                description="D1",
                plausibility="high",
                preconditions=[],
            ),
            HypothesisItem(
                id="h2",
                name="H2",
                description="D2",
                plausibility="medium",
                preconditions=[],
            ),
            HypothesisItem(
                id="h3",
                name="H3",
                description="D3",
                plausibility="low",
                preconditions=[],
            ),
        ]

        optimizer.optimize_based_on_feedback(
            stage_name="divergent_exploration",
            hypotheses=hypotheses,
            verified_count=2,
            false_positive_count=1,
        )

        assert "divergent_exploration" in optimizer.prompt_effectiveness
        assert (
            optimizer.prompt_effectiveness["divergent_exploration"]["total_runs"] == 1
        )
        assert (
            len(optimizer.prompt_effectiveness["divergent_exploration"]["success_rate"])
            == 1
        )

    def test_get_optimization_recommendations(self):
        """Test getting optimization recommendations"""
        learning_db = PersistentLearningDB(db_path="/tmp/test_learning.json")
        optimizer = PromptOptimizer(learning_db)

        # No data initially
        recommendations = optimizer.get_optimization_recommendations("test_stage")
        assert recommendations["status"] == "insufficient_data"

        # Add some data
        hypotheses = [
            HypothesisItem(
                id=f"h{i}",
                name=f"H{i}",
                description=f"D{i}",
                plausibility="medium",
                preconditions=[],
            )
            for i in range(10)
        ]

        optimizer.optimize_based_on_feedback("test_stage", hypotheses, 2, 5)

        recommendations = optimizer.get_optimization_recommendations("test_stage")
        assert recommendations["status"] == "analyzed"
        assert "avg_success_rate" in recommendations
        assert "suggestions" in recommendations


class TestHypothesisItem:
    """Test HypothesisItem dataclass"""

    def test_creation(self):
        """Test creating a hypothesis item"""
        hypothesis = HypothesisItem(
            id="test-001",
            name="Test Hypothesis",
            description="Test description",
            plausibility="high",
            preconditions=["cond1", "cond2"],
            confidence=0.8,
        )

        assert hypothesis.id == "test-001"
        assert hypothesis.name == "Test Hypothesis"
        assert hypothesis.confidence == 0.8
        assert len(hypothesis.preconditions) == 2
        assert hypothesis.status == "pending"


class TestExploitScenario:
    """Test ExploitScenario dataclass"""

    def test_creation(self):
        """Test creating an exploit scenario"""
        scenario = ExploitScenario(
            name="Test Exploit",
            vulnerability_type="reentrancy",
            severity="high",
            conditions=["condition1"],
            attacker_capabilities=["flash loan"],
            attack_sequence=[{"step": 1, "action": "test"}],
            impact="Test impact",
            estimated_profit="$100K",
            difficulty="medium",
            confidence=0.75,
        )

        assert scenario.name == "Test Exploit"
        assert scenario.severity == "high"
        assert scenario.confidence == 0.75
        assert len(scenario.attack_sequence) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
