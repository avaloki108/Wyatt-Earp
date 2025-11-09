"""
Multi-Stage LLM Prompt Chaining for Creative Hypothesis Generation
Sequential prompt stages with different objectives for discovering novel vulnerabilities
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import yaml
import re
import time
from pathlib import Path


class PromptStage(Enum):
    """Stages in the prompt chain"""

    DIVERGENT_EXPLORATION = "divergent_exploration"
    ANALOGICAL_REASONING = "analogical_reasoning"
    TECHNICAL_VALIDATION = "technical_validation"
    EXPLOIT_SYNTHESIS = "exploit_synthesis"


@dataclass
class HypothesisItem:
    """Single vulnerability hypothesis"""

    id: str
    name: str
    description: str
    plausibility: str
    preconditions: List[str]
    confidence: float = 0.5
    stage: str = "divergent_exploration"
    historical_reference: Optional[str] = None
    manifestation: Optional[str] = None
    variations: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, validated, rejected
    reasoning: str = ""
    code_evidence: List[str] = field(default_factory=list)
    missing_safeguards: List[str] = field(default_factory=list)


@dataclass
class ExploitScenario:
    """Complete exploit scenario from synthesis stage"""

    name: str
    vulnerability_type: str
    severity: str
    conditions: List[str]
    attacker_capabilities: List[str]
    attack_sequence: List[Dict[str, Any]]
    impact: str
    estimated_profit: str
    difficulty: str
    confidence: float
    source_hypothesis_id: Optional[str] = None


@dataclass
class PromptChainResult:
    """Result from executing the full prompt chain"""

    hypotheses_generated: int
    hypotheses_validated: int
    hypotheses_rejected: int
    exploit_scenarios: List[ExploitScenario]
    all_hypotheses: List[HypothesisItem]
    execution_time: float
    tokens_used: int
    stage_results: Dict[str, Any] = field(default_factory=dict)


class PromptChainOrchestrator:
    """
    Orchestrates multi-stage prompt chaining for creative vulnerability discovery
    Each stage has different creativity level and objective
    """

    def __init__(self, llm_client=None, config_path: Optional[str] = None):
        """
        Initialize orchestrator

        Args:
            llm_client: LLM client with query_llm method (e.g., AdvancedLLMReasoner)
            config_path: Path to YAML configuration file
        """
        self.llm_client = llm_client
        self.config = self._load_config(config_path)
        self.hypotheses: List[HypothesisItem] = []
        self.exploit_scenarios: List[ExploitScenario] = []
        self._hypothesis_id_counter = 0

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_path_obj: Path
        if config_path is None:
            config_path_obj = Path(__file__).parent / "prompt_chain_config.yaml"
        else:
            config_path_obj = Path(config_path)

        try:
            with open(config_path_obj, "r") as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            print(f"Warning: Could not load config from {config_path}: {e}")
            # Return minimal default config
            return {
                "enabled": True,
                "stages": {
                    "divergent_exploration": {
                        "temperature": 0.85,
                        "enabled": True,
                        "order": 1,
                    },
                    "analogical_reasoning": {
                        "temperature": 0.65,
                        "enabled": True,
                        "order": 2,
                    },
                    "technical_validation": {
                        "temperature": 0.35,
                        "enabled": True,
                        "order": 3,
                    },
                    "exploit_synthesis": {
                        "temperature": 0.3,
                        "enabled": True,
                        "order": 4,
                    },
                },
                "prompt_templates": {},
            }

    async def execute_chain(
        self,
        contract_code: str,
        contract_type: str = "unknown",
        static_analysis_results: Optional[Dict[str, Any]] = None,
        learned_patterns: Optional[List[str]] = None,
        creativity_level: str = "balanced",
    ) -> PromptChainResult:
        """
        Execute the full multi-stage prompt chain

        Args:
            contract_code: Solidity contract code
            contract_type: Type of contract (vault, AMM, bridge, etc.)
            static_analysis_results: Results from static analysis tools
            learned_patterns: Patterns from learning database
            creativity_level: conservative, balanced, or aggressive

        Returns:
            PromptChainResult with all hypotheses and exploit scenarios
        """
        start_time = time.time()
        tokens_used = 0
        stage_results = {}

        # Apply creativity level to temperatures
        self._apply_creativity_level(creativity_level)

        # Stage 1: Divergent Exploration
        if self._is_stage_enabled("divergent_exploration"):
            print("🔍 Stage 1: Divergent Exploration...")
            hypotheses, tokens = await self._execute_divergent_exploration(
                contract_code, contract_type, static_analysis_results
            )
            self.hypotheses.extend(hypotheses)
            tokens_used += tokens
            stage_results["divergent_exploration"] = {
                "hypotheses_count": len(hypotheses),
                "tokens": tokens,
            }
            print(f"   Generated {len(hypotheses)} hypotheses")

        # Stage 2: Analogical Reasoning
        if self._is_stage_enabled("analogical_reasoning"):
            print("🔗 Stage 2: Analogical Reasoning...")
            enhanced_hypotheses, tokens = await self._execute_analogical_reasoning(
                contract_code, contract_type, self.hypotheses, learned_patterns
            )
            self.hypotheses = enhanced_hypotheses
            tokens_used += tokens
            stage_results["analogical_reasoning"] = {
                "hypotheses_enhanced": len(enhanced_hypotheses),
                "tokens": tokens,
            }
            print(
                f"   Enhanced {len(enhanced_hypotheses)} hypotheses with historical context"
            )

        # Stage 3: Technical Validation
        if self._is_stage_enabled("technical_validation"):
            print("✅ Stage 3: Technical Validation...")
            validated, rejected, tokens = await self._execute_technical_validation(
                contract_code, self.hypotheses
            )
            tokens_used += tokens
            stage_results["technical_validation"] = {
                "validated": len(validated),
                "rejected": len(rejected),
                "tokens": tokens,
            }
            print(f"   Validated {len(validated)} hypotheses, rejected {len(rejected)}")

        # Stage 4: Exploit Synthesis
        if self._is_stage_enabled("exploit_synthesis"):
            print("⚔️  Stage 4: Exploit Synthesis...")
            validated_hypotheses = [
                h for h in self.hypotheses if h.status == "validated"
            ]
            exploit_scenarios, tokens = await self._execute_exploit_synthesis(
                contract_code, validated_hypotheses
            )
            self.exploit_scenarios = exploit_scenarios
            tokens_used += tokens
            stage_results["exploit_synthesis"] = {
                "scenarios_count": len(exploit_scenarios),
                "tokens": tokens,
            }
            print(f"   Synthesized {len(exploit_scenarios)} exploit scenarios")

        execution_time = time.time() - start_time

        # Count final statistics
        validated_count = len([h for h in self.hypotheses if h.status == "validated"])
        rejected_count = len([h for h in self.hypotheses if h.status == "rejected"])

        return PromptChainResult(
            hypotheses_generated=len(self.hypotheses),
            hypotheses_validated=validated_count,
            hypotheses_rejected=rejected_count,
            exploit_scenarios=self.exploit_scenarios,
            all_hypotheses=self.hypotheses,
            execution_time=execution_time,
            tokens_used=tokens_used,
            stage_results=stage_results,
        )

    def execute_chain_sync(self, *args, **kwargs) -> PromptChainResult:
        """Synchronous wrapper for execute_chain"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.execute_chain(*args, **kwargs))

    async def _execute_divergent_exploration(
        self,
        contract_code: str,
        contract_type: str,
        static_analysis_results: Optional[Dict[str, Any]],
    ) -> Tuple[List[HypothesisItem], int]:
        """Stage 1: Generate diverse, creative hypotheses"""
        stage_config = self.config["stages"]["divergent_exploration"]
        prompt_template = self.config.get("prompt_templates", {}).get(
            "divergent_exploration", ""
        )

        # Prepare context
        static_summary = self._summarize_static_analysis(static_analysis_results)

        # Render prompt template
        prompt = prompt_template.replace("{{contract_type}}", contract_type)
        prompt = prompt.replace(
            "{{contract_code}}", contract_code[:3000]
        )  # Truncate for tokens
        prompt = prompt.replace("{{static_analysis_summary}}", static_summary)

        # Query LLM
        temperature = stage_config.get("temperature", 0.85)
        response = await self._query_llm_async(prompt, temperature)

        # Parse response
        hypotheses = self._parse_divergent_response(response)

        # Estimate tokens (rough approximation)
        tokens = len(prompt.split()) + len(response.split())

        return hypotheses, tokens

    async def _execute_analogical_reasoning(
        self,
        contract_code: str,
        contract_type: str,
        hypotheses: List[HypothesisItem],
        learned_patterns: Optional[List[str]],
    ) -> Tuple[List[HypothesisItem], int]:
        """Stage 2: Enhance hypotheses with historical patterns"""
        stage_config = self.config["stages"]["analogical_reasoning"]
        prompt_template = self.config.get("prompt_templates", {}).get(
            "analogical_reasoning", ""
        )

        # Prepare context
        contract_summary = self._create_contract_summary(contract_code)
        previous_hypotheses_json = json.dumps(
            [
                {"id": h.id, "name": h.name, "description": h.description}
                for h in hypotheses[:20]  # Limit to avoid token overflow
            ],
            indent=2,
        )

        learned_patterns_text = "\n".join(
            learned_patterns or ["No learned patterns available"]
        )

        # Render prompt
        prompt = prompt_template.replace("{{contract_type}}", contract_type)
        prompt = prompt.replace("{{contract_summary}}", contract_summary)
        prompt = prompt.replace("{{previous_hypotheses}}", previous_hypotheses_json)
        prompt = prompt.replace("{{learned_patterns}}", learned_patterns_text)

        # Query LLM
        temperature = stage_config.get("temperature", 0.65)
        response = await self._query_llm_async(prompt, temperature)

        # Parse and enhance hypotheses
        enhancements = self._parse_analogical_response(response)
        enhanced_hypotheses = self._apply_enhancements(hypotheses, enhancements)

        tokens = len(prompt.split()) + len(response.split())
        return enhanced_hypotheses, tokens

    async def _execute_technical_validation(
        self, contract_code: str, hypotheses: List[HypothesisItem]
    ) -> Tuple[List[HypothesisItem], List[HypothesisItem], int]:
        """Stage 3: Validate technical feasibility"""
        stage_config = self.config["stages"]["technical_validation"]
        prompt_template = self.config.get("prompt_templates", {}).get(
            "technical_validation", ""
        )

        # Prepare hypotheses JSON
        hypotheses_json = json.dumps(
            [
                {
                    "id": h.id,
                    "name": h.name,
                    "description": h.description,
                    "confidence": h.confidence,
                }
                for h in hypotheses[:30]  # Validate top hypotheses
            ],
            indent=2,
        )

        # Render prompt
        prompt = prompt_template.replace("{{contract_code}}", contract_code[:3000])
        prompt = prompt.replace("{{hypotheses}}", hypotheses_json)

        # Query LLM
        temperature = stage_config.get("temperature", 0.35)
        response = await self._query_llm_async(prompt, temperature)

        # Parse validation results
        validations = self._parse_validation_response(response)
        validated, rejected = self._apply_validations(hypotheses, validations)

        tokens = len(prompt.split()) + len(response.split())
        return validated, rejected, tokens

    async def _execute_exploit_synthesis(
        self, contract_code: str, validated_hypotheses: List[HypothesisItem]
    ) -> Tuple[List[ExploitScenario], int]:
        """Stage 4: Synthesize exploit scenarios"""
        stage_config = self.config["stages"]["exploit_synthesis"]
        prompt_template = self.config.get("prompt_templates", {}).get(
            "exploit_synthesis", ""
        )

        # Prepare validated hypotheses
        validated_json = json.dumps(
            [
                {
                    "id": h.id,
                    "name": h.name,
                    "description": h.description,
                    "confidence": h.confidence,
                    "code_evidence": h.code_evidence,
                }
                for h in validated_hypotheses[:20]  # Top 20
            ],
            indent=2,
        )

        # Render prompt
        prompt = prompt_template.replace("{{contract_code}}", contract_code[:3000])
        prompt = prompt.replace("{{validated_hypotheses}}", validated_json)

        # Query LLM
        temperature = stage_config.get("temperature", 0.3)
        response = await self._query_llm_async(prompt, temperature)

        # Parse exploit scenarios
        scenarios = self._parse_exploit_scenarios(response)

        tokens = len(prompt.split()) + len(response.split())
        return scenarios, tokens

    async def _query_llm_async(self, prompt: str, temperature: float) -> str:
        """Async wrapper for LLM query with retry logic"""
        if self.llm_client is None:
            return self._mock_llm_response(prompt)

        retry_attempts = self.config.get("retry_attempts", 3)
        retry_delay = self.config.get("retry_delay", 2)

        for attempt in range(retry_attempts):
            try:
                # Check if LLM client has async method
                if hasattr(self.llm_client, "query_llm_async"):
                    response = await self.llm_client.query_llm_async(
                        prompt, temperature=temperature
                    )
                else:
                    # Fallback to sync method
                    response = self.llm_client.query_llm(
                        prompt, temperature=temperature
                    )

                # If response indicates LLM is not available, use mock
                if "LLM API key not configured" in response or "LLM Error:" in response:
                    return self._mock_llm_response(prompt)

                return response
            except Exception as e:
                if attempt < retry_attempts - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    print(f"LLM query failed after {retry_attempts} attempts: {e}")
                    return self._mock_llm_response(prompt)

        return self._mock_llm_response(prompt)

    def _mock_llm_response(self, prompt: str) -> str:
        """Generate mock response when LLM is not available"""
        prompt_lower = prompt.lower()

        # Detect stage based on prompt content
        if any(
            keyword in prompt_lower
            for keyword in [
                "unconventional attack",
                "brainstorm",
                "creative",
                "diverse attack",
            ]
        ):
            # Divergent exploration stage
            return json.dumps(
                [
                    {
                        "name": "Flash Loan Price Manipulation",
                        "description": "Attacker uses flash loan to manipulate oracle price and drain funds",
                        "plausibility": "high",
                        "preconditions": [
                            "Flash loan available",
                            "Price oracle vulnerable",
                        ],
                    },
                    {
                        "name": "Cross-Function Reentrancy",
                        "description": "Exploit state inconsistency between multiple external calls",
                        "plausibility": "medium",
                        "preconditions": [
                            "Multiple external functions",
                            "Shared state",
                        ],
                    },
                ]
            )
        elif any(
            keyword in prompt_lower
            for keyword in ["similar protocols", "historical exploit", "transferable"]
        ):
            # Analogical reasoning stage
            return json.dumps(
                [
                    {
                        "hypothesis_id": "hyp-001",
                        "historical_reference": "Cream Finance Reentrancy Attack",
                        "manifestation": "Similar pattern in withdraw function",
                        "confidence_adjustment": "+0.2",
                        "variations": ["Via callback", "Via fallback"],
                    }
                ]
            )
        elif any(
            keyword in prompt_lower
            for keyword in ["critically evaluate", "validate", "technical feasibility"]
        ):
            # Technical validation stage
            return json.dumps(
                [
                    {
                        "hypothesis_id": "hyp-001",
                        "status": "KEEP",
                        "reasoning": "Missing reentrancy guard in withdraw",
                        "code_evidence": [
                            "withdraw function",
                            "missing nonReentrant modifier",
                        ],
                        "confidence": 0.8,
                        "missing_safeguards": ["reentrancy guard"],
                    }
                ]
            )
        elif any(
            keyword in prompt_lower
            for keyword in ["synthesize", "exploit scenario", "step-by-step attack"]
        ):
            # Exploit synthesis stage
            return json.dumps(
                [
                    {
                        "name": "Flash Loan Reentrancy Exploit",
                        "vulnerability_type": "reentrancy",
                        "severity": "critical",
                        "conditions": [
                            "Contract has ETH balance",
                            "withdraw() is public",
                        ],
                        "attacker_capabilities": ["Deploy malicious contract"],
                        "attack_sequence": [
                            {
                                "step": 1,
                                "action": "Call withdraw()",
                                "function": "withdraw",
                            },
                            {
                                "step": 2,
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

        # Default fallback
        return json.dumps(
            [
                {
                    "name": "Generic Vulnerability",
                    "description": "Mock vulnerability for testing",
                    "plausibility": "medium",
                    "preconditions": ["Test condition"],
                }
            ]
        )

    def _parse_divergent_response(self, response: str) -> List[HypothesisItem]:
        """Parse divergent exploration response into HypothesisItem objects"""
        hypotheses = []

        try:
            # Try to parse the entire response as JSON first
            if response.strip().startswith("["):
                data = json.loads(response)
            else:
                # Try to extract JSON array
                json_match = re.search(r"\[\s*\{.*\}\s*\]", response, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(0))
                else:
                    return hypotheses

            for item in data:
                self._hypothesis_id_counter += 1
                hypotheses.append(
                    HypothesisItem(
                        id=f"hyp-{self._hypothesis_id_counter:03d}",
                        name=item.get("name", "Unknown"),
                        description=item.get("description", ""),
                        plausibility=item.get("plausibility", "medium"),
                        preconditions=item.get("preconditions", []),
                        confidence=self._plausibility_to_confidence(
                            item.get("plausibility", "medium")
                        ),
                        stage="divergent_exploration",
                    )
                )
        except Exception as e:
            print(f"Error parsing divergent response: {e}")

        return hypotheses

    def _parse_analogical_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse analogical reasoning response"""
        enhancements = []

        try:
            # Try to parse the entire response as JSON first
            if response.strip().startswith("["):
                enhancements = json.loads(response)
            else:
                # Try to extract JSON array
                json_match = re.search(r"\[\s*\{.*\}\s*\]", response, re.DOTALL)
                if json_match:
                    enhancements = json.loads(json_match.group(0))
        except Exception as e:
            print(f"Error parsing analogical response: {e}")

        return enhancements

    def _parse_validation_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse technical validation response"""
        validations = []

        try:
            # Try to parse the entire response as JSON first
            if response.strip().startswith("["):
                validations = json.loads(response)
            else:
                # Try to extract JSON array
                json_match = re.search(r"\[\s*\{.*\}\s*\]", response, re.DOTALL)
                if json_match:
                    validations = json.loads(json_match.group(0))
        except Exception as e:
            print(f"Error parsing validation response: {e}")

        return validations

    def _parse_exploit_scenarios(self, response: str) -> List[ExploitScenario]:
        """Parse exploit synthesis response into ExploitScenario objects"""
        scenarios = []

        try:
            # Try to parse the entire response as JSON first
            if response.strip().startswith("["):
                data = json.loads(response)
            else:
                # Try to extract JSON array with better regex
                json_match = re.search(r"\[\s*\{.*\}\s*\]", response, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(0))
                else:
                    return scenarios

            for item in data:
                scenarios.append(
                    ExploitScenario(
                        name=item.get("name", "Unknown Exploit"),
                        vulnerability_type=item.get("vulnerability_type", "unknown"),
                        severity=item.get("severity", "medium"),
                        conditions=item.get("conditions", []),
                        attacker_capabilities=item.get("attacker_capabilities", []),
                        attack_sequence=item.get("attack_sequence", []),
                        impact=item.get("impact", ""),
                        estimated_profit=item.get("estimated_profit", "N/A"),
                        difficulty=item.get("difficulty", "unknown"),
                        confidence=item.get("confidence", 0.5),
                    )
                )
        except Exception as e:
            print(f"Error parsing exploit scenarios: {e}")

        return scenarios

    def _apply_enhancements(
        self, hypotheses: List[HypothesisItem], enhancements: List[Dict[str, Any]]
    ) -> List[HypothesisItem]:
        """Apply analogical reasoning enhancements to hypotheses"""
        enhancement_map = {e.get("hypothesis_id", ""): e for e in enhancements}

        for hypothesis in hypotheses:
            if hypothesis.id in enhancement_map:
                enhancement = enhancement_map[hypothesis.id]
                hypothesis.historical_reference = enhancement.get(
                    "historical_reference"
                )
                hypothesis.manifestation = enhancement.get("manifestation")
                hypothesis.variations = enhancement.get("variations", [])

                # Apply confidence adjustment
                adjustment = enhancement.get("confidence_adjustment", "+0.0")
                try:
                    adj_value = float(adjustment)
                    hypothesis.confidence = max(
                        0.0, min(1.0, hypothesis.confidence + adj_value)
                    )
                except (ValueError, TypeError):
                    pass

                hypothesis.stage = "analogical_reasoning"

        return hypotheses

    def _apply_validations(
        self, hypotheses: List[HypothesisItem], validations: List[Dict[str, Any]]
    ) -> Tuple[List[HypothesisItem], List[HypothesisItem]]:
        """Apply technical validation results"""
        validation_map = {v.get("hypothesis_id", ""): v for v in validations}

        validated = []
        rejected = []

        for hypothesis in hypotheses:
            if hypothesis.id in validation_map:
                validation = validation_map[hypothesis.id]
                status = validation.get("status", "REJECT")

                hypothesis.status = "validated" if status == "KEEP" else "rejected"
                hypothesis.reasoning = validation.get("reasoning", "")
                hypothesis.code_evidence = validation.get("code_evidence", [])
                hypothesis.missing_safeguards = validation.get("missing_safeguards", [])
                hypothesis.confidence = validation.get(
                    "confidence", hypothesis.confidence
                )
                hypothesis.stage = "technical_validation"

                if hypothesis.status == "validated":
                    validated.append(hypothesis)
                else:
                    rejected.append(hypothesis)
            else:
                # Default to rejected if not explicitly validated
                hypothesis.status = "rejected"
                hypothesis.reasoning = "Not validated by LLM"
                rejected.append(hypothesis)

        return validated, rejected

    def _summarize_static_analysis(
        self, static_results: Optional[Dict[str, Any]]
    ) -> str:
        """Create concise summary of static analysis results"""
        if not static_results:
            return "No static analysis results available"

        summary_lines = []
        if "detectors" in static_results:
            for detector, findings in static_results["detectors"].items():
                if findings:
                    summary_lines.append(f"- {detector}: {len(findings)} findings")

        return "\n".join(summary_lines) if summary_lines else "No significant findings"

    def _create_contract_summary(self, contract_code: str) -> str:
        """Create brief summary of contract structure"""
        # Extract functions
        func_pattern = r"function\s+(\w+)\s*\("
        functions = re.findall(func_pattern, contract_code)

        # Extract key modifiers
        has_reentrancy_guard = "nonReentrant" in contract_code
        has_access_control = any(
            word in contract_code
            for word in ["onlyOwner", "onlyRole", "require(msg.sender"]
        )

        summary = f"Functions: {', '.join(functions[:10])}\n"
        summary += f"Reentrancy guard: {'Yes' if has_reentrancy_guard else 'No'}\n"
        summary += f"Access control: {'Yes' if has_access_control else 'No'}"

        return summary

    def _plausibility_to_confidence(self, plausibility: str) -> float:
        """Convert plausibility string to confidence score"""
        mapping = {"low": 0.3, "medium": 0.5, "high": 0.7}
        return mapping.get(plausibility.lower(), 0.5)

    def _is_stage_enabled(self, stage_name: str) -> bool:
        """Check if a stage is enabled in configuration"""
        return self.config.get("stages", {}).get(stage_name, {}).get("enabled", True)

    def _apply_creativity_level(self, creativity_level: str):
        """Apply creativity level preset to stage temperatures"""
        if creativity_level in self.config.get("creativity_levels", {}):
            levels = self.config["creativity_levels"][creativity_level]
            for stage_name, temperature in levels.items():
                if stage_name in self.config["stages"]:
                    self.config["stages"][stage_name]["temperature"] = temperature


class PromptOptimizer:
    """
    Optimize prompt strategies based on historical success
    Integrates with PersistentLearningDB
    """

    def __init__(self, learning_db):
        """
        Args:
            learning_db: Instance of PersistentLearningDB
        """
        self.learning_db = learning_db
        self.prompt_effectiveness = {}

    def optimize_based_on_feedback(
        self,
        stage_name: str,
        hypotheses: List[HypothesisItem],
        verified_count: int,
        false_positive_count: int,
    ):
        """
        Adjust prompt strategies based on historical success

        Args:
            stage_name: Name of the prompt stage
            hypotheses: List of hypotheses from this stage
            verified_count: Number of verified hypotheses
            false_positive_count: Number of false positives
        """
        total = len(hypotheses)
        if total == 0:
            return

        # Calculate success rate
        success_rate = verified_count / total
        fp_rate = false_positive_count / total

        # Update effectiveness tracking
        if stage_name not in self.prompt_effectiveness:
            self.prompt_effectiveness[stage_name] = {
                "success_rate": [],
                "fp_rate": [],
                "total_runs": 0,
            }

        self.prompt_effectiveness[stage_name]["success_rate"].append(success_rate)
        self.prompt_effectiveness[stage_name]["fp_rate"].append(fp_rate)
        self.prompt_effectiveness[stage_name]["total_runs"] += 1

        # Store in learning DB if available
        if hasattr(self.learning_db, "prompt_effectiveness"):
            self.learning_db.prompt_effectiveness[stage_name] = {
                "avg_success_rate": sum(
                    self.prompt_effectiveness[stage_name]["success_rate"]
                )
                / len(self.prompt_effectiveness[stage_name]["success_rate"]),
                "avg_fp_rate": sum(self.prompt_effectiveness[stage_name]["fp_rate"])
                / len(self.prompt_effectiveness[stage_name]["fp_rate"]),
                "runs": self.prompt_effectiveness[stage_name]["total_runs"],
            }
            self.learning_db.save_database()

    def get_optimization_recommendations(self, stage_name: str) -> Dict[str, Any]:
        """Get recommendations for improving a prompt stage"""
        if stage_name not in self.prompt_effectiveness:
            return {"status": "insufficient_data"}

        stats = self.prompt_effectiveness[stage_name]
        avg_success = sum(stats["success_rate"]) / len(stats["success_rate"])
        avg_fp = sum(stats["fp_rate"]) / len(stats["fp_rate"])

        recommendations = {
            "status": "analyzed",
            "avg_success_rate": avg_success,
            "avg_fp_rate": avg_fp,
            "suggestions": [],
        }

        # Generate suggestions
        if avg_success < 0.3:
            recommendations["suggestions"].append(
                "Increase creativity/temperature to generate more diverse hypotheses"
            )
        elif avg_success > 0.8:
            recommendations["suggestions"].append(
                "Consider tightening criteria to improve precision"
            )

        if avg_fp > 0.5:
            recommendations["suggestions"].append(
                "Add more validation constraints to reduce false positives"
            )

        return recommendations


# Asyncio compatibility
try:
    import asyncio
except ImportError:
    print("Warning: asyncio not available, async features disabled")
