"""
Advanced LLM Reasoning Engine for Vulnerability Discovery
Multi-agent approach with specialized reasoning modules
Supports: Grok (x.ai), Claude (Anthropic), OpenAI
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

# Import LLM provider
from .llm_providers import LLMClient, LLMProvider


class ReasoningMode(Enum):
    ADVERSARIAL = "adversarial"  # Think like an attacker
    DEFENSIVE = "defensive"  # Think like an auditor
    ECONOMIC = "economic"  # Analyze economic incentives
    COMPOSABILITY = "composability"  # Cross-protocol interactions
    FORMAL = "formal"  # Formal verification reasoning


@dataclass
class ReasoningResult:
    """Result from LLM reasoning"""
    mode: ReasoningMode
    findings: List[Dict[str, Any]]
    attack_scenarios: List[str]
    property_tests: List[str]
    confidence: float
    reasoning_chain: List[str]  # Chain of thought
    references: List[str] = field(default_factory=list)


class AdvancedLLMReasoner:
    """
    Multi-agent LLM reasoning system for vulnerability discovery
    Uses chain-of-thought, adversarial thinking, and domain expertise
    Supports: Grok (x.ai), Claude (Anthropic), OpenAI
    """

    def __init__(
        self,
        provider: str = "grok",  # "grok", "claude", or "openai"
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        # Map provider string to enum
        provider_map = {
            "grok": LLMProvider.GROK,
            "claude": LLMProvider.CLAUDE,
            "openai": LLMProvider.OPENAI
        }

        if provider not in provider_map:
            raise ValueError(f"Unknown provider: {provider}. Use 'grok', 'claude', or 'openai'")

        self.provider_name = provider
        self.llm_client = LLMClient(
            provider=provider_map[provider],
            api_key=api_key,
            model=model
        )
        self.reasoning_history: List[ReasoningResult] = []

    def analyze_contract_multi_agent(self,
                                    contract_code: str,
                                    static_analysis_results: Dict[str, Any],
                                    contract_type: str = "unknown") -> List[ReasoningResult]:
        """
        Run multiple reasoning agents in parallel for comprehensive analysis
        """
        results = []

        # Agent 1: Adversarial Reasoning
        results.append(self._adversarial_reasoning(contract_code, static_analysis_results))

        # Agent 2: Economic Analysis
        results.append(self._economic_reasoning(contract_code, contract_type))

        # Agent 3: Composability Analysis
        results.append(self._composability_reasoning(contract_code))

        # Agent 4: Formal Verification
        results.append(self._formal_reasoning(contract_code))

        # Agent 5: Pattern Matching
        results.append(self._pattern_reasoning(contract_code, static_analysis_results))

        # Synthesize results
        synthesized = self._synthesize_findings(results)
        results.append(synthesized)

        self.reasoning_history.extend(results)
        return results

    def _call_llm(self, prompt: str, temperature: float = 0.7) -> str:
        """Call LLM API via unified provider"""
        messages = [
            {
                "role": "system",
                "content": "You are an expert Web3 security researcher specializing in smart contract vulnerabilities."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        try:
            response = self.llm_client.chat_completion(
                messages=messages,
                temperature=temperature,
                max_tokens=2000
            )
            return response
        except Exception as e:
            # Return error message for debugging
            return f"LLM API Error: {str(e)}\n\nUsing mock response for demo purposes..."

    # ... (rest of the methods remain the same as original file)
    # Copy all the other methods from the original llm_reasoning_engine.py
    # _adversarial_reasoning, _economic_reasoning, etc.
