"""
Advanced LLM Reasoning Engine for Vulnerability Discovery
Multi-agent approach with specialized reasoning modules
Combines GPT-4, Claude, and local models for comprehensive analysis

Enhanced with AI Hypothesis System integration for improved vulnerability discovery
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
import os

# Import AI hypothesis system components (optional)
try:
    from .ai_hypothesis_system import AIHypothesisSystem

    HAS_AI_HYPOTHESIS = True
except ImportError:
    HAS_AI_HYPOTHESIS = False

# Import prompt chaining components (optional)
try:
    from .prompt_chaining import PromptChainOrchestrator, PromptChainResult

    HAS_PROMPT_CHAINING = True
except ImportError:
    HAS_PROMPT_CHAINING = False

try:
    from .langgraph_orchestrator import (
        LangGraphOrchestrator,
        LangGraphExecutionResult,
        AgentRun,
    )

    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

    class AgentRun:
        """Minimal stub for AgentRun when LangGraph is unavailable."""

        pass


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
    """

    def __init__(
        self, openai_key: Optional[str] = None, anthropic_key: Optional[str] = None
    ):
        self.openai_key = openai_key or os.getenv("OPENAI_API_KEY")
        self.anthropic_key = anthropic_key or os.getenv("ANTHROPIC_API_KEY")
        self.reasoning_history: List[ReasoningResult] = []

        # Initialize AI hypothesis system if available
        self.ai_hypothesis_system: Optional[AIHypothesisSystem] = None
        if HAS_AI_HYPOTHESIS:
            self.ai_hypothesis_system = AIHypothesisSystem(
                llm_client=self,
                enable_poc_generation=False,  # Disable for compatibility
                enable_learning=True,
            )

        # Initialize prompt chain orchestrator if available
        self.prompt_chain_orchestrator: Optional[PromptChainOrchestrator] = None
        if HAS_PROMPT_CHAINING:
            self.prompt_chain_orchestrator = PromptChainOrchestrator(llm_client=self)

        # Initialize LangGraph orchestrator for DAG-based reasoning if available
        self.langgraph_orchestrator: Optional[LangGraphOrchestrator] = None
        if HAS_LANGGRAPH:
            try:
                self.langgraph_orchestrator = LangGraphOrchestrator(llm_client=self)
            except Exception as exc:
                print(f"LangGraph orchestrator initialization failed: {exc}")

    def analyze_contract_multi_agent(
        self,
        contract_code: str,
        static_analysis_results: Dict[str, Any],
        contract_type: str = "unknown",
        use_ai_hypothesis: bool = True,
    ) -> List[ReasoningResult]:
        """
        Run multiple reasoning agents in parallel for comprehensive analysis

        Args:
            use_ai_hypothesis: If True and available, use AI hypothesis system for enhanced analysis
        """
        results: List[ReasoningResult] = []

        # Enhanced: AI Hypothesis System (if available)
        if use_ai_hypothesis and self.ai_hypothesis_system:
            try:
                hypothesis_report = self.ai_hypothesis_system.analyze_contract(
                    contract_code=contract_code,
                    contract_name=contract_type,
                    contract_type=contract_type,
                    static_analysis_results=static_analysis_results,
                    generate_pocs=False,
                )

                # Convert hypothesis findings to reasoning results
                hypothesis_result = self._convert_hypothesis_to_reasoning(
                    hypothesis_report
                )
                results.append(hypothesis_result)
            except Exception as e:
                print(f"AI Hypothesis System error: {e}")

        if self.langgraph_orchestrator:
            try:
                execution: LangGraphExecutionResult = self.langgraph_orchestrator.run(
                    contract_code=contract_code,
                    static_analysis_results=static_analysis_results,
                    contract_type=contract_type,
                )
                results.extend(self._convert_langgraph_execution(execution))
                self.reasoning_history.extend(results)
                return results
            except Exception as exc:
                print(
                    f"LangGraph orchestrator error: {exc}. Falling back to legacy pipeline."
                )

        # Fallback to the legacy sequential pipeline if LangGraph is unavailable or fails
        legacy_results = self._legacy_multi_agent(
            contract_code,
            static_analysis_results,
            contract_type,
            prior_results=results,
        )
        results.extend(legacy_results)

        self.reasoning_history.extend(results)
        return results

    def _legacy_multi_agent(
        self,
        contract_code: str,
        static_analysis_results: Dict[str, Any],
        contract_type: str,
        prior_results: Optional[List[ReasoningResult]] = None,
    ) -> List[ReasoningResult]:
        """Retain the legacy sequential pipeline as a fallback path."""

        legacy_results: List[ReasoningResult] = []

        legacy_results.append(
            self._adversarial_reasoning(contract_code, static_analysis_results)
        )
        legacy_results.append(self._economic_reasoning(contract_code, contract_type))
        legacy_results.append(self._composability_reasoning(contract_code))
        legacy_results.append(self._formal_reasoning(contract_code))
        legacy_results.append(
            self._pattern_reasoning(contract_code, static_analysis_results)
        )

        synthesis_inputs = (prior_results or []) + legacy_results
        legacy_results.append(self._synthesize_findings(synthesis_inputs))

        return legacy_results

    def _convert_langgraph_execution(
        self, execution: LangGraphExecutionResult
    ) -> List[ReasoningResult]:
        """Convert the LangGraph execution artefacts into ReasoningResult entries."""

        mode_map = {
            "hunter": ReasoningMode.ADVERSARIAL,
            "analogical_reasoner": ReasoningMode.COMPOSABILITY,
            "skeptical_validator": ReasoningMode.DEFENSIVE,
            "exploit_synthesizer": ReasoningMode.ADVERSARIAL,
            "self_evaluation": ReasoningMode.FORMAL,
        }

        results: List[ReasoningResult] = []

        for run in execution.agent_runs:
            mode = mode_map.get(run.name, ReasoningMode.ADVERSARIAL)
            findings = self._normalize_findings_from_parsed(
                run.parsed_response, run.raw_response
            )
            attack_scenarios = self._extract_attack_scenarios_from_run(run)
            confidence = self._extract_confidence_from_parsed(run.parsed_response)
            reasoning_chain = [run.role]
            if isinstance(run.raw_response, str):
                stripped_response = run.raw_response.strip()
                if stripped_response:
                    reasoning_chain.append(stripped_response)

            result = ReasoningResult(
                mode=mode,
                findings=findings,
                attack_scenarios=attack_scenarios,
                property_tests=self._extract_property_tests_from_parsed(
                    run.parsed_response
                ),
                confidence=confidence,
                reasoning_chain=reasoning_chain,
                references=[],
            )
            results.append(result)

        final_assessment = execution.shared_state.get("final_assessment")
        if isinstance(final_assessment, dict) and final_assessment:
            results.append(
                ReasoningResult(
                    mode=ReasoningMode.DEFENSIVE,
                    findings=[final_assessment],
                    attack_scenarios=self._stringify_attack_scenarios(
                        execution.shared_state.get("exploit_scenarios", [])
                    ),
                    property_tests=[],
                    confidence=float(final_assessment.get("confidence", 0.5)),
                    reasoning_chain=[final_assessment.get("summary", "").strip()],
                    references=[],
                )
            )

        return results

    def _normalize_findings_from_parsed(
        self, parsed: Any, raw: Any
    ) -> List[Dict[str, Any]]:
        """Normalize parsed agent payloads into a list of findings dictionaries."""

        if isinstance(parsed, list):
            return [
                item if isinstance(item, dict) else {"summary": item} for item in parsed
            ]
        if isinstance(parsed, dict):
            for key in ["hypotheses", "validated", "findings", "analysis"]:
                value = parsed.get(key)
                if isinstance(value, list):
                    return [
                        item if isinstance(item, dict) else {"summary": item}
                        for item in value
                    ]
            return [parsed]
        if isinstance(raw, str) and raw.strip():
            return [{"summary": raw.strip()}]
        return []

    def _extract_attack_scenarios_from_run(self, run: AgentRun) -> List[str]:
        parsed = run.parsed_response
        if isinstance(parsed, dict):
            for key in ["scenarios", "exploits", "results"]:
                value = parsed.get(key)
                if isinstance(value, list):
                    return self._stringify_attack_scenarios(value)
        if isinstance(parsed, list) and run.name == "exploit_synthesizer":
            return self._stringify_attack_scenarios(parsed)
        return []

    def _extract_property_tests_from_parsed(self, parsed: Any) -> List[str]:
        if isinstance(parsed, dict):
            tests = parsed.get("property_tests") or parsed.get("tests")
            if isinstance(tests, list):
                return [str(item) for item in tests]
        return []

    def _extract_confidence_from_parsed(self, parsed: Any) -> float:
        if isinstance(parsed, dict):
            confidence = parsed.get("confidence")
            if isinstance(confidence, (int, float)):
                return float(confidence)
        return 0.6

    def _stringify_attack_scenarios(self, scenarios: List[Any]) -> List[str]:
        stringified: List[str] = []
        for scenario in scenarios:
            if isinstance(scenario, str):
                stringified.append(scenario)
            else:
                try:
                    stringified.append(json.dumps(scenario))
                except (TypeError, ValueError):
                    stringified.append(str(scenario))
        return stringified

    def _adversarial_reasoning(
        self, contract_code: str, static_results: Dict[str, Any]
    ) -> ReasoningResult:
        """
        Think like an attacker - find novel exploit paths
        """
        prompt = self._build_adversarial_prompt(contract_code, static_results)

        # This would call GPT-4/Claude in production
        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.7)

        findings = self._parse_adversarial_response(response)

        return ReasoningResult(
            mode=ReasoningMode.ADVERSARIAL,
            findings=findings,
            attack_scenarios=self._extract_attack_scenarios(response),
            property_tests=[],
            confidence=0.75,
            reasoning_chain=self._extract_reasoning_chain(response),
        )

    def query_llm(
        self, prompt: str, model: str = "gpt-4", temperature: float = 0.7
    ) -> str:
        """
        Query LLM with proper error handling
        Supports OpenAI, Anthropic (Claude), and XAI (Grok)
        """
        try:
            # Try OpenAI first
            if self.openai_key:
                from openai import OpenAI

                client = OpenAI(api_key=self.openai_key)
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000,
                    temperature=temperature,
                )
                return response.choices[0].message.content

            # Try Anthropic/Claude
            elif self.anthropic_key:
                import anthropic

                client = anthropic.Anthropic(api_key=self.anthropic_key)
                message = client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}],
                )
                return message.content[0].text

            # Try XAI/Grok
            elif os.getenv("XAI_API_KEY"):
                from openai import OpenAI

                client = OpenAI(
                    api_key=os.getenv("XAI_API_KEY"), base_url="https://api.x.ai/v1"
                )
                response = client.chat.completions.create(
                    model="grok-3",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000,
                    temperature=temperature,
                )
                return response.choices[0].message.content
            else:
                return "LLM API key not configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or XAI_API_KEY."

        except Exception as e:
            return f"LLM Error: {str(e)}"

    def _build_adversarial_prompt(
        self, contract_code: str, static_results: Dict[str, Any]
    ) -> str:
        """Build prompt for adversarial reasoning"""
        return f"""You are an expert Web3 security researcher and ethical hacker.
Your goal is to find novel vulnerabilities by thinking like an attacker.

CONTRACT CODE:
```solidity
{contract_code[:3000]}  # Truncate for token limits
```

STATIC ANALYSIS RESULTS:
{json.dumps(static_results, indent=2)[:1000]}

ADVERSARIAL REASONING FRAMEWORK:
1. Identify all attack surfaces (external functions, state variables, etc.)
2. Map trust boundaries and privilege levels
3. Trace data flow from user inputs to critical operations
4. Identify composability risks with external protocols
5. Consider multi-transaction attack sequences
6. Think about economic incentives and game theory

SPECIFIC ATTACK VECTORS TO CONSIDER:
- Flash loan attacks (manipulate state with borrowed capital)
- Oracle manipulation (exploit price feeds)
- Governance attacks (flash loan voting, proposal griefing)
- MEV extraction (sandwich attacks, front-running)
- Cross-function reentrancy (exploit state inconsistencies)
- ERC-4626 share inflation
- First depositor attacks
- Donation attacks
- Time-based exploits
- Cross-chain bridge attacks
- Reward calculation manipulations

For each potential vulnerability, provide:
1. Vulnerability type and location
2. Attack scenario (step-by-step)
3. Preconditions needed
4. Expected profit/impact
5. Difficulty of exploitation
6. Remediation suggestion

Think deeply and creatively. Focus on logic flaws that automated tools miss.
"""

    def _economic_reasoning(
        self, contract_code: str, contract_type: str
    ) -> ReasoningResult:
        """Analyze economic incentives and game theory"""
        prompt = f"""You are a Web3 economic security expert.
Analyze this {contract_type} contract for economic vulnerabilities and misaligned incentives.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

ECONOMIC ANALYSIS FRAMEWORK:
1. Identify all economic actors and their incentives
2. Map value flows (tokens, fees, rewards)
3. Find misaligned incentives
4. Consider game-theoretic equilibria
5. Analyze attack profitability

KEY QUESTIONS:
- Can an attacker profit risk-free?
- Are there scenarios where attacking is more profitable than honest participation?
- Can economic parameters be manipulated?
- Are there economic feedback loops that could spiral?
- What happens at economic extremes (very high/low prices, liquidity, etc.)?

SPECIFIC ECONOMIC ATTACKS:
- Flash loan attacks (zero-risk capital)
- Liquidity manipulation
- Price oracle manipulation
- Reward gaming
- Fee extraction
- Governance token manipulation
- Collateral attacks

Provide:
1. Economic vulnerabilities found
2. Profit calculation for attacks
3. Risk/reward analysis for attacker
4. Economic parameter recommendations
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.5)

        return ReasoningResult(
            mode=ReasoningMode.ECONOMIC,
            findings=self._parse_economic_response(response),
            attack_scenarios=self._extract_attack_scenarios(response),
            property_tests=[],
            confidence=0.70,
            reasoning_chain=self._extract_reasoning_chain(response),
        )

    def _composability_reasoning(self, contract_code: str) -> ReasoningResult:
        """Analyze cross-protocol composability risks"""
        prompt = f"""You are an expert in DeFi composability and protocol interactions.
Analyze how this contract interacts with external protocols and identify composability risks.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

COMPOSABILITY ANALYSIS:
1. Identify all external protocol dependencies
2. Map protocol interaction patterns
3. Find assumptions about external protocol behavior
4. Identify shared state or resources
5. Consider multi-protocol attack sequences

COMPOSABILITY RISKS:
- Read-only reentrancy across protocols
- Price oracle inconsistencies
- Liquidity assumptions
- Protocol upgrade risks
- Cross-protocol MEV
- Shared collateral risks
- Circular dependencies

For each risk:
1. External protocols involved
2. Interaction pattern
3. Failure scenarios
4. Attack scenarios
5. Mitigation strategies
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.6)

        return ReasoningResult(
            mode=ReasoningMode.COMPOSABILITY,
            findings=self._parse_composability_response(response),
            attack_scenarios=self._extract_attack_scenarios(response),
            property_tests=[],
            confidence=0.65,
            reasoning_chain=self._extract_reasoning_chain(response),
        )

    def _formal_reasoning(self, contract_code: str) -> ReasoningResult:
        """Generate formal properties and invariants"""
        prompt = f"""You are a formal verification expert.
Analyze this contract and suggest formal properties that should hold.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

FORMAL PROPERTY GENERATION:
1. Identify state invariants (must always be true)
2. Define preconditions and postconditions for functions
3. Specify temporal properties
4. Define conservation laws
5. Identify safety and liveness properties

PROPERTY CATEGORIES:
- Balance conservation (sum of balances = total supply)
- Access control (only authorized can execute)
- State transitions (valid state machine)
- Arithmetic safety (no overflow/underflow)
- Economic invariants (collateral >= debt)

For each property, provide:
1. Property description (English)
2. Formal specification (Solidity/Certora)
3. Importance/criticality
4. How to test it

Output formal properties suitable for Echidna, Certora, or manual testing.
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.3)

        return ReasoningResult(
            mode=ReasoningMode.FORMAL,
            findings=[],
            attack_scenarios=[],
            property_tests=self._extract_property_tests(response),
            confidence=0.80,
            reasoning_chain=self._extract_reasoning_chain(response),
        )

    def _pattern_reasoning(
        self, contract_code: str, static_results: Dict[str, Any]
    ) -> ReasoningResult:
        """Match against known vulnerability patterns"""
        prompt = f"""You are a vulnerability pattern expert.
Compare this contract against known vulnerability patterns and historical exploits.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

STATIC ANALYSIS FINDINGS:
{json.dumps(static_results, indent=2)[:1000]}

KNOWN PATTERNS TO CHECK:
1. Historical DeFi Hacks:
   - Poly Network (access control)
   - Wormhole (signature verification)
   - Ronin Bridge (validator compromise)
   - Nomad Bridge (initialization bug)
   - Cream Finance (reentrancy)

2. Common Patterns:
   - Unchecked external calls
   - Integer overflow/underflow
   - Reentrancy (classic, cross-function, read-only)
   - Front-running
   - Access control issues
   - Oracle manipulation

3. DeFi-Specific:
   - ERC-4626 inflation
   - AMM manipulation
   - Flash loan attacks
   - Governance exploits

For each pattern match:
1. Pattern name and reference
2. How it manifests in this code
3. Severity and exploitability
4. Historical precedent
5. Recommended fix
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.4)

        return ReasoningResult(
            mode=ReasoningMode.DEFENSIVE,
            findings=self._parse_pattern_response(response),
            attack_scenarios=[],
            property_tests=[],
            confidence=0.85,
            reasoning_chain=self._extract_reasoning_chain(response),
            references=self._extract_references(response),
        )

    def _synthesize_findings(self, results: List[ReasoningResult]) -> ReasoningResult:
        """Synthesize findings from all agents"""
        all_findings = []
        all_scenarios = []
        all_properties = []

        for result in results:
            all_findings.extend(result.findings)
            all_scenarios.extend(result.attack_scenarios)
            all_properties.extend(result.property_tests)

        # Remove duplicates and rank by confidence
        unique_findings = self._deduplicate_findings(all_findings)
        ranked_findings = sorted(
            unique_findings, key=lambda x: x.get("confidence", 0), reverse=True
        )

        return ReasoningResult(
            mode=ReasoningMode.DEFENSIVE,
            findings=ranked_findings[:20],  # Top 20
            attack_scenarios=list(set(all_scenarios)),
            property_tests=list(set(all_properties)),
            confidence=0.80,
            reasoning_chain=["Synthesized from multiple reasoning agents"],
        )

    def _call_llm(
        self, prompt: str, model: str = "gpt-4-turbo", temperature: float = 0.7
    ) -> str:
        """
        Call LLM API (OpenAI, Anthropic, or local)
        In production, this would make actual API calls
        """
        try:
            # Try XAI/Grok first (preferred)
            if os.getenv("XAI_API_KEY"):
                from openai import OpenAI
                
                client = OpenAI(
                    api_key=os.getenv("XAI_API_KEY"), 
                    base_url="https://api.x.ai/v1"
                )
                response = client.chat.completions.create(
                    model="grok-3",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000,
                    temperature=temperature,
                )
                return response.choices[0].message.content
            
            # Try OpenAI
            elif self.openai_key:
                from openai import OpenAI
                
                client = OpenAI(api_key=self.openai_key)
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000,
                    temperature=temperature,
                )
                return response.choices[0].message.content
            
            # Try Anthropic/Claude
            elif self.anthropic_key:
                import anthropic
                
                client = anthropic.Anthropic(api_key=self.anthropic_key)
                message = client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}],
                )
                return message.content[0].text
            
            else:
                return "LLM API key not configured. Set XAI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY."
        
        except Exception as e:
            return f"LLM Error: {str(e)}"

    def _parse_adversarial_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response for adversarial findings"""
        # In production, use more sophisticated parsing
        findings = []

        # Extract findings from response (simplified)
        if "reentrancy" in response.lower():
            findings.append(
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "confidence": 0.8,
                    "description": "Potential reentrancy vulnerability",
                    "location": "withdraw function",
                }
            )

        if "slippage" in response.lower():
            findings.append(
                {
                    "type": "slippage_missing",
                    "severity": "medium",
                    "confidence": 0.7,
                    "description": "Missing slippage protection",
                    "location": "swap function",
                }
            )

        return findings

    def _parse_economic_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse economic analysis response"""
        return []  # Simplified for demo

    def _parse_composability_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse composability analysis response"""
        return []  # Simplified for demo

    def _parse_pattern_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse pattern matching response"""
        return []  # Simplified for demo

    def _extract_attack_scenarios(self, response: str) -> List[str]:
        """Extract attack scenarios from response"""
        scenarios = []

        # Simple extraction
        lines = response.split("\n")
        for i, line in enumerate(lines):
            if "attack" in line.lower() and "scenario" in line.lower():
                # Collect next few lines
                scenario = "\n".join(lines[i : i + 5])
                scenarios.append(scenario)

        return scenarios

    def _extract_property_tests(self, response: str) -> List[str]:
        """Extract property test specifications"""
        properties = []

        # Extract echidna-style properties
        import re

        echidna_pattern = r"echidna_\w+.*"
        properties = re.findall(echidna_pattern, response)

        return properties

    def _extract_reasoning_chain(self, response: str) -> List[str]:
        """Extract chain of thought reasoning"""
        chains = []

        lines = response.split("\n")
        for line in lines:
            if line.strip() and (
                "because" in line.lower()
                or "therefore" in line.lower()
                or "this means" in line.lower()
            ):
                chains.append(line.strip())

        return chains

    def _extract_references(self, response: str) -> List[str]:
        """Extract references to known vulnerabilities"""
        import re

        url_pattern = r"https?://[^\s]+"
        refs = re.findall(url_pattern, response)
        return refs

    def _deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for finding in findings:
            # Create fingerprint
            fingerprint = (finding.get("type", ""), finding.get("location", ""))

            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(finding)

        return unique

    def _convert_hypothesis_to_reasoning(self, hypothesis_report) -> ReasoningResult:
        """
        Convert AI hypothesis system report to ReasoningResult format
        Enables integration with existing multi-agent system
        """
        findings = []
        attack_scenarios = []

        # Extract verified vulnerabilities
        for vuln in hypothesis_report.verified_vulnerabilities:
            findings.append(
                {
                    "type": vuln["type"],
                    "severity": vuln["severity"],
                    "confidence": vuln["confidence"],
                    "description": vuln["description"],
                    "location": ", ".join(vuln.get("affected_functions", [])),
                }
            )

            if vuln.get("attack_scenario"):
                attack_scenarios.append(vuln["attack_scenario"])

        # Extract uncertain findings with lower confidence
        for uncertain in hypothesis_report.uncertain_findings:
            findings.append(
                {
                    "type": uncertain["type"],
                    "severity": "medium",
                    "confidence": uncertain["confidence"],
                    "description": uncertain["description"],
                    "location": "unknown",
                }
            )

        # Determine overall confidence
        confidences = [f["confidence"] for f in findings]
        overall_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return ReasoningResult(
            mode=ReasoningMode.ADVERSARIAL,  # AI hypotheses are adversarial in nature
            findings=findings,
            attack_scenarios=attack_scenarios,
            property_tests=[],
            confidence=overall_confidence,
            reasoning_chain=[
                f"Generated {hypothesis_report.hypotheses_generated} hypotheses",
                f"Verified {len(hypothesis_report.verified_vulnerabilities)} vulnerabilities",
                f"Confidence improvement: {hypothesis_report.confidence_improvement:+.2f}",
            ],
            references=[],
        )

    def generate_fuzzing_harness(
        self, contract_code: str, vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Generate targeted fuzzing harness based on LLM findings"""
        prompt = f"""Generate Echidna fuzzing properties to test the following vulnerabilities:

CONTRACT:
{contract_code[:2000]}

SUSPECTED VULNERABILITIES:
{json.dumps(vulnerabilities, indent=2)}

Generate:
1. Property functions (echidna_*) that would detect these vulnerabilities
2. Helper functions to set up test conditions
3. Custom test cases for edge cases

Make properties specific and targeted to the suspected vulnerabilities.
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.2)
        return response

    def explain_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """Generate detailed explanation of vulnerability for report"""
        prompt = f"""Explain this vulnerability in detail for a security report:

VULNERABILITY:
{json.dumps(vulnerability, indent=2)}

Provide:
1. Technical explanation
2. Proof-of-concept code
3. Impact assessment
4. Remediation steps
5. Similar historical vulnerabilities

Write for a technical audience (developers and auditors).
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.3)
        return response

    def execute_prompt_chain(
        self,
        contract_code: str,
        contract_type: str = "unknown",
        static_analysis_results: Optional[Dict[str, Any]] = None,
        learned_patterns: Optional[List[str]] = None,
        creativity_level: str = "balanced",
        use_async: bool = False,
    ) -> Optional["PromptChainResult"]:
        """
        Execute multi-stage prompt chaining for creative hypothesis generation

        Args:
            contract_code: Solidity contract code
            contract_type: Type of contract (vault, AMM, bridge, etc.)
            static_analysis_results: Results from static analysis
            learned_patterns: Patterns from learning database
            creativity_level: conservative, balanced, or aggressive
            use_async: Whether to use async execution (default: False for compatibility)

        Returns:
            PromptChainResult with hypotheses and exploit scenarios, or None if not available
        """
        if not self.prompt_chain_orchestrator:
            print("Warning: Prompt chain orchestrator not available")
            return None

        try:
            # Use synchronous wrapper by default for compatibility
            result = self.prompt_chain_orchestrator.execute_chain_sync(
                contract_code=contract_code,
                contract_type=contract_type,
                static_analysis_results=static_analysis_results,
                learned_patterns=learned_patterns,
                creativity_level=creativity_level,
            )

            return result
        except Exception as e:
            print(f"Error executing prompt chain: {e}")
            return None

    def get_enhanced_llm_prompt(
        self,
        base_prompt: str,
        learned_patterns: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Enhance LLM prompt with learned patterns from persistent learning DB

        Args:
            base_prompt: Original prompt
            learned_patterns: Patterns from learning database
            context: Additional context

        Returns:
            Enhanced prompt with learning context
        """
        if not learned_patterns:
            return base_prompt

        enhancement = "\n\nLEARNED PATTERNS FROM PREVIOUS SCANS:\n"
        enhancement += "\n".join(f"- {pattern}" for pattern in learned_patterns[:10])
        enhancement += "\n\nConsider these patterns when analyzing the contract.\n"

        return base_prompt + enhancement


def demonstrate_llm_reasoning():
    """Demonstrate advanced LLM reasoning"""

    reasoner = AdvancedLLMReasoner()

    sample_contract = """
    contract VulnerableVault {
        mapping(address => uint256) public balances;
        uint256 public totalSupply;

        function deposit() public payable {
            balances[msg.sender] += msg.value;
            totalSupply += msg.value;
        }

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            msg.sender.call{value: amount}("");  // Reentrancy!
            balances[msg.sender] -= amount;  // State update after call
            totalSupply -= amount;
        }

        function getPrice() public view returns (uint256) {
            // Using spot price - vulnerable to manipulation!
            return dex.getReserves();
        }
    }
    """

    static_results = {
        "detectors": {"reentrancy": ["withdraw"], "unprotected_call": ["withdraw"]}
    }

    print("=== Advanced LLM Reasoning Analysis ===\n")

    results = reasoner.analyze_contract_multi_agent(
        sample_contract, static_results, "vault"
    )

    for result in results:
        print(f"\n{'=' * 60}")
        print(f"REASONING MODE: {result.mode.value}")
        print(f"Confidence: {result.confidence}")
        print(f"{'=' * 60}")

        if result.findings:
            print(f"\nFindings ({len(result.findings)}):")
            for finding in result.findings:
                print(f"  - {finding}")

        if result.attack_scenarios:
            print(f"\nAttack Scenarios ({len(result.attack_scenarios)}):")
            for scenario in result.attack_scenarios[:3]:
                print(f"  {scenario}")

        if result.property_tests:
            print(f"\nProperty Tests ({len(result.property_tests)}):")
            for prop in result.property_tests[:5]:
                print(f"  {prop}")

    # Generate fuzzing harness
    print("\n" + "=" * 60)
    print("FUZZING HARNESS GENERATION")
    print("=" * 60)

    harness = reasoner.generate_fuzzing_harness(sample_contract, results[0].findings)
    print(harness[:500])

    return results


if __name__ == "__main__":
    results = demonstrate_llm_reasoning()
    print(f"\n\nTotal reasoning modes: {len(results)}")
