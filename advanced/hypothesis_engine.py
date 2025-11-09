"""
Hypothesis Engine - Creative Vulnerability Hypothesis Generation
Generates novel vulnerability hypotheses using multi-temperature LLM prompting
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib
import json


class HypothesisType(Enum):
    """Types of vulnerability hypotheses"""
    LOGIC_FLAW = "logic_flaw"
    ECONOMIC_EXPLOIT = "economic_exploit"
    CROSS_CONTRACT = "cross_contract"
    BRIDGE_VULNERABILITY = "bridge_vulnerability"
    ORACLE_MANIPULATION = "oracle_manipulation"
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    EDGE_CASE = "edge_case"


@dataclass
class VulnerabilityHypothesis:
    """A generated hypothesis about a potential vulnerability"""
    id: str
    type: HypothesisType
    description: str
    confidence: float  # Initial confidence (0-1)
    attack_scenario: str
    affected_functions: List[str]
    severity: str  # critical, high, medium, low
    creativity_score: float  # How novel is this hypothesis
    generated_by: str  # Which prompt/model generated it
    timestamp: str
    verification_status: str = "pending"  # pending, verified, rejected
    verification_layers: Dict[str, Any] = field(default_factory=dict)
    poc_generated: bool = False
    final_confidence: float = 0.0
    
    
@dataclass
class HypothesisGenerationConfig:
    """Configuration for hypothesis generation"""
    creative_temperature: float = 0.9  # High for creative exploration
    refinement_temperature: float = 0.3  # Low for technical validation
    max_hypotheses_per_stage: int = 10
    min_confidence_threshold: float = 0.3
    enable_cross_contract: bool = True
    enable_bridge_analysis: bool = True
    enable_edge_cases: bool = True


class HypothesisEngine:
    """
    Generates creative vulnerability hypotheses using multi-stage LLM prompting
    Focuses on discovering novel vulnerabilities beyond known patterns
    """
    
    def __init__(self, llm_client=None, config: Optional[HypothesisGenerationConfig] = None):
        self.llm_client = llm_client
        self.config = config or HypothesisGenerationConfig()
        self.generated_hypotheses: List[VulnerabilityHypothesis] = []
        self.hypothesis_history: Dict[str, List[VulnerabilityHypothesis]] = {}
        
    def generate_hypotheses(self, 
                           contract_code: str,
                           contract_type: str = "unknown",
                           static_analysis_results: Optional[Dict[str, Any]] = None) -> List[VulnerabilityHypothesis]:
        """
        Generate vulnerability hypotheses through multi-stage prompting
        
        Stage 1: Creative exploration (high temperature)
        Stage 2: Technical refinement (low temperature)
        Stage 3: Cross-contract analysis (if enabled)
        """
        hypotheses = []
        
        # Stage 1: Creative Exploration
        creative_hypotheses = self._creative_exploration_stage(
            contract_code, 
            contract_type,
            static_analysis_results
        )
        hypotheses.extend(creative_hypotheses)
        
        # Stage 2: Refinement Stage
        refined_hypotheses = self._refinement_stage(
            contract_code,
            creative_hypotheses,
            static_analysis_results
        )
        hypotheses.extend(refined_hypotheses)
        
        # Stage 3: Cross-Contract Analysis
        if self.config.enable_cross_contract:
            cross_contract_hypotheses = self._cross_contract_analysis_stage(
                contract_code,
                contract_type
            )
            hypotheses.extend(cross_contract_hypotheses)
            
        # Stage 4: Edge Case Discovery
        if self.config.enable_edge_cases:
            edge_case_hypotheses = self._edge_case_discovery_stage(
                contract_code,
                static_analysis_results
            )
            hypotheses.extend(edge_case_hypotheses)
        
        # Filter by confidence threshold
        hypotheses = [h for h in hypotheses if h.confidence >= self.config.min_confidence_threshold]
        
        # Store generated hypotheses
        self.generated_hypotheses.extend(hypotheses)
        contract_hash = self._hash_contract(contract_code)
        self.hypothesis_history[contract_hash] = hypotheses
        
        return hypotheses
    
    def _creative_exploration_stage(self,
                                   contract_code: str,
                                   contract_type: str,
                                   static_results: Optional[Dict[str, Any]]) -> List[VulnerabilityHypothesis]:
        """
        Stage 1: Creative exploration with high temperature
        Generates unconventional attack vectors
        """
        prompt = self._build_creative_prompt(contract_code, contract_type, static_results)
        
        hypotheses = []
        
        # Call LLM with high temperature for creativity
        if self.llm_client:
            response = self._call_llm(
                prompt, 
                temperature=self.config.creative_temperature,
                model_type="creative"
            )
            hypotheses = self._parse_hypothesis_response(response, "creative_exploration")
        else:
            # Fallback: Generate pattern-based hypotheses
            hypotheses = self._generate_pattern_based_hypotheses(contract_code, "creative")
            
        return hypotheses[:self.config.max_hypotheses_per_stage]
    
    def _refinement_stage(self,
                         contract_code: str,
                         creative_hypotheses: List[VulnerabilityHypothesis],
                         static_results: Optional[Dict[str, Any]]) -> List[VulnerabilityHypothesis]:
        """
        Stage 2: Refine and validate creative hypotheses with lower temperature
        """
        prompt = self._build_refinement_prompt(contract_code, creative_hypotheses, static_results)
        
        hypotheses = []
        
        if self.llm_client and creative_hypotheses:
            response = self._call_llm(
                prompt,
                temperature=self.config.refinement_temperature,
                model_type="refinement"
            )
            hypotheses = self._parse_hypothesis_response(response, "refinement")
        else:
            # Fallback: Analyze creative hypotheses with pattern matching
            hypotheses = self._refine_hypotheses_pattern_based(creative_hypotheses, contract_code)
            
        return hypotheses[:self.config.max_hypotheses_per_stage]
    
    def _cross_contract_analysis_stage(self,
                                      contract_code: str,
                                      contract_type: str) -> List[VulnerabilityHypothesis]:
        """
        Stage 3: Explore cross-contract and protocol interaction vulnerabilities
        """
        prompt = self._build_cross_contract_prompt(contract_code, contract_type)
        
        hypotheses = []
        
        if self.llm_client:
            response = self._call_llm(
                prompt,
                temperature=0.7,
                model_type="cross_contract"
            )
            hypotheses = self._parse_hypothesis_response(response, "cross_contract")
        else:
            # Fallback: Pattern-based cross-contract analysis
            hypotheses = self._generate_cross_contract_hypotheses(contract_code)
            
        return hypotheses[:self.config.max_hypotheses_per_stage]
    
    def _edge_case_discovery_stage(self,
                                  contract_code: str,
                                  static_results: Optional[Dict[str, Any]]) -> List[VulnerabilityHypothesis]:
        """
        Stage 4: Discover edge cases and boundary conditions
        """
        prompt = self._build_edge_case_prompt(contract_code, static_results)
        
        hypotheses = []
        
        if self.llm_client:
            response = self._call_llm(
                prompt,
                temperature=0.6,
                model_type="edge_case"
            )
            hypotheses = self._parse_hypothesis_response(response, "edge_case")
        else:
            # Fallback: Pattern-based edge case detection
            hypotheses = self._generate_edge_case_hypotheses(contract_code)
            
        return hypotheses[:self.config.max_hypotheses_per_stage]
    
    def _build_creative_prompt(self, 
                              contract_code: str,
                              contract_type: str,
                              static_results: Optional[Dict[str, Any]]) -> str:
        """Build prompt for creative exploration stage"""
        static_info = ""
        if static_results:
            static_info = f"\nKnown issues: {json.dumps(static_results, indent=2)}"
            
        return f"""You are a creative Web3 security researcher discovering novel vulnerabilities.
Think beyond standard patterns. Explore unconventional attack vectors.

Contract Type: {contract_type}
{static_info}

Contract Code:
```solidity
{contract_code[:2000]}  # Limit for prompt size
```

Generate 5-10 NOVEL vulnerability hypotheses. Think creatively:
- Logic flaws in state transitions
- Economic exploits through incentive manipulation
- Cross-contract interaction vulnerabilities
- Edge cases in mathematical operations
- Unusual oracle manipulation techniques
- Novel reentrancy patterns

For each hypothesis, provide:
1. Type (logic_flaw, economic_exploit, cross_contract, etc.)
2. Description (what is the vulnerability)
3. Attack scenario (how would it be exploited)
4. Affected functions
5. Severity (critical/high/medium/low)
6. Confidence (0.0-1.0)

Output as JSON array of hypotheses."""
    
    def _build_refinement_prompt(self,
                                contract_code: str,
                                creative_hypotheses: List[VulnerabilityHypothesis],
                                static_results: Optional[Dict[str, Any]]) -> str:
        """Build prompt for refinement stage"""
        hypotheses_summary = "\n".join([
            f"- {h.type.value}: {h.description[:100]}" 
            for h in creative_hypotheses[:5]
        ])
        
        return f"""You are a technical security auditor validating vulnerability hypotheses.

Initial Hypotheses:
{hypotheses_summary}

Contract Code:
```solidity
{contract_code[:2000]}
```

For each hypothesis, provide technical validation:
1. Is it technically feasible in this code?
2. What specific code patterns enable it?
3. What conditions must be met?
4. Updated confidence score (0.0-1.0)
5. Specific function names involved

Output validated and refined hypotheses as JSON array."""
    
    def _build_cross_contract_prompt(self, contract_code: str, contract_type: str) -> str:
        """Build prompt for cross-contract analysis"""
        return f"""Analyze this contract for cross-contract and protocol interaction vulnerabilities.

Contract Type: {contract_type}

Contract Code:
```solidity
{contract_code[:2000]}
```

Look for:
1. External call vulnerabilities
2. Bridge and cross-chain issues
3. Oracle dependencies
4. Composability risks
5. Protocol integration flaws

Output as JSON array of cross-contract hypotheses."""
    
    def _build_edge_case_prompt(self, contract_code: str, static_results: Optional[Dict[str, Any]]) -> str:
        """Build prompt for edge case discovery"""
        return f"""Discover edge cases and boundary condition vulnerabilities.

Contract Code:
```solidity
{contract_code[:2000]}
```

Look for:
1. Integer overflow/underflow edge cases
2. Division by zero scenarios
3. Empty array/mapping access
4. Extreme value handling
5. State transition edge cases

Output as JSON array of edge case hypotheses."""
    
    def _call_llm(self, prompt: str, temperature: float, model_type: str) -> str:
        """Call LLM with error handling and timeout"""
        if not self.llm_client:
            return "{}"
            
        try:
            # Call the LLM client with appropriate parameters
            response = self.llm_client.query_llm(prompt, temperature=temperature)
            return response
        except Exception as e:
            print(f"LLM call error ({model_type}): {e}")
            return "{}"
    
    def _parse_hypothesis_response(self, response: str, generated_by: str) -> List[VulnerabilityHypothesis]:
        """Parse LLM response into hypothesis objects"""
        hypotheses = []
        
        try:
            # Try to parse JSON response
            data = json.loads(response) if isinstance(response, str) else response
            
            if isinstance(data, list):
                for item in data:
                    hypothesis = self._create_hypothesis_from_dict(item, generated_by)
                    if hypothesis:
                        hypotheses.append(hypothesis)
            elif isinstance(data, dict) and 'hypotheses' in data:
                for item in data['hypotheses']:
                    hypothesis = self._create_hypothesis_from_dict(item, generated_by)
                    if hypothesis:
                        hypotheses.append(hypothesis)
        except json.JSONDecodeError:
            # Fallback: Try to extract information from text
            hypotheses = self._parse_text_response(response, generated_by)
        except Exception as e:
            print(f"Error parsing hypothesis response: {e}")
            
        return hypotheses
    
    def _create_hypothesis_from_dict(self, data: Dict[str, Any], generated_by: str) -> Optional[VulnerabilityHypothesis]:
        """Create hypothesis object from dictionary"""
        try:
            hypothesis_id = hashlib.sha256(
                f"{data.get('description', '')}{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16]
            
            # Parse hypothesis type
            type_str = data.get('type', 'logic_flaw')
            try:
                hyp_type = HypothesisType(type_str.lower())
            except ValueError:
                hyp_type = HypothesisType.LOGIC_FLAW
                
            return VulnerabilityHypothesis(
                id=hypothesis_id,
                type=hyp_type,
                description=data.get('description', ''),
                confidence=float(data.get('confidence', 0.5)),
                attack_scenario=data.get('attack_scenario', data.get('scenario', '')),
                affected_functions=data.get('affected_functions', data.get('functions', [])),
                severity=data.get('severity', 'medium'),
                creativity_score=float(data.get('creativity_score', 0.5)),
                generated_by=generated_by,
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            print(f"Error creating hypothesis: {e}")
            return None
    
    def _parse_text_response(self, text: str, generated_by: str) -> List[VulnerabilityHypothesis]:
        """Fallback: Parse text response when JSON parsing fails"""
        # Simple text parsing - extract key information
        hypotheses = []
        # This is a simplified fallback - in production would be more sophisticated
        return hypotheses
    
    def _generate_pattern_based_hypotheses(self, contract_code: str, stage: str) -> List[VulnerabilityHypothesis]:
        """Fallback: Generate hypotheses using pattern matching when LLM unavailable"""
        hypotheses = []
        
        # Reentrancy patterns
        if "call" in contract_code.lower() and "balance" in contract_code.lower():
            hypotheses.append(VulnerabilityHypothesis(
                id=self._generate_id("reentrancy"),
                type=HypothesisType.REENTRANCY,
                description="Potential reentrancy vulnerability through external calls",
                confidence=0.6,
                attack_scenario="Attacker could re-enter contract before state updates",
                affected_functions=self._extract_function_names(contract_code),
                severity="high",
                creativity_score=0.3,
                generated_by=f"pattern_{stage}",
                timestamp=datetime.now().isoformat()
            ))
            
        # Oracle manipulation
        if any(word in contract_code.lower() for word in ["oracle", "price", "twap"]):
            hypotheses.append(VulnerabilityHypothesis(
                id=self._generate_id("oracle"),
                type=HypothesisType.ORACLE_MANIPULATION,
                description="Potential oracle manipulation vulnerability",
                confidence=0.5,
                attack_scenario="Attacker could manipulate oracle price feeds",
                affected_functions=self._extract_function_names(contract_code),
                severity="high",
                creativity_score=0.4,
                generated_by=f"pattern_{stage}",
                timestamp=datetime.now().isoformat()
            ))
            
        return hypotheses
    
    def _refine_hypotheses_pattern_based(self, 
                                        creative_hypotheses: List[VulnerabilityHypothesis],
                                        contract_code: str) -> List[VulnerabilityHypothesis]:
        """Refine hypotheses using pattern matching"""
        refined = []
        
        for hypothesis in creative_hypotheses:
            # Boost confidence if we find supporting patterns
            confidence_boost = 0.0
            
            # Check for supporting code patterns
            if hypothesis.type == HypothesisType.REENTRANCY:
                if "nonReentrant" not in contract_code and "call" in contract_code:
                    confidence_boost = 0.2
            elif hypothesis.type == HypothesisType.ORACLE_MANIPULATION:
                if "latestAnswer" in contract_code and "timestamp" not in contract_code:
                    confidence_boost = 0.3
                    
            if confidence_boost > 0:
                hypothesis.confidence = min(1.0, hypothesis.confidence + confidence_boost)
                refined.append(hypothesis)
                
        return refined
    
    def _generate_cross_contract_hypotheses(self, contract_code: str) -> List[VulnerabilityHypothesis]:
        """Generate cross-contract hypotheses using pattern matching"""
        hypotheses = []
        
        if any(word in contract_code for word in ["interface", "IERC", "external"]):
            hypotheses.append(VulnerabilityHypothesis(
                id=self._generate_id("cross_contract"),
                type=HypothesisType.CROSS_CONTRACT,
                description="Potential cross-contract interaction vulnerability",
                confidence=0.5,
                attack_scenario="Malicious contract could exploit external interactions",
                affected_functions=self._extract_function_names(contract_code),
                severity="medium",
                creativity_score=0.5,
                generated_by="pattern_cross_contract",
                timestamp=datetime.now().isoformat()
            ))
            
        return hypotheses
    
    def _generate_edge_case_hypotheses(self, contract_code: str) -> List[VulnerabilityHypothesis]:
        """Generate edge case hypotheses using pattern matching"""
        hypotheses = []
        
        # Division operations without zero check
        if "/" in contract_code and "require" not in contract_code.lower():
            hypotheses.append(VulnerabilityHypothesis(
                id=self._generate_id("edge_division"),
                type=HypothesisType.EDGE_CASE,
                description="Potential division by zero edge case",
                confidence=0.4,
                attack_scenario="Division by zero could cause transaction revert",
                affected_functions=self._extract_function_names(contract_code),
                severity="medium",
                creativity_score=0.3,
                generated_by="pattern_edge_case",
                timestamp=datetime.now().isoformat()
            ))
            
        return hypotheses
    
    def _extract_function_names(self, contract_code: str) -> List[str]:
        """Extract function names from contract code"""
        import re
        pattern = r'function\s+(\w+)\s*\('
        matches = re.findall(pattern, contract_code)
        return matches[:10]  # Limit to avoid too many
    
    def _generate_id(self, prefix: str) -> str:
        """Generate unique hypothesis ID"""
        return hashlib.sha256(
            f"{prefix}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
    
    def _hash_contract(self, contract_code: str) -> str:
        """Generate hash for contract code"""
        return hashlib.sha256(contract_code.encode()).hexdigest()[:16]
    
    def get_hypothesis_stats(self) -> Dict[str, Any]:
        """Get statistics about generated hypotheses"""
        if not self.generated_hypotheses:
            return {}
            
        return {
            "total_hypotheses": len(self.generated_hypotheses),
            "by_type": self._count_by_type(),
            "by_severity": self._count_by_severity(),
            "average_confidence": sum(h.confidence for h in self.generated_hypotheses) / len(self.generated_hypotheses),
            "average_creativity": sum(h.creativity_score for h in self.generated_hypotheses) / len(self.generated_hypotheses),
            "verified_count": len([h for h in self.generated_hypotheses if h.verification_status == "verified"]),
            "rejected_count": len([h for h in self.generated_hypotheses if h.verification_status == "rejected"])
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count hypotheses by type"""
        counts = {}
        for h in self.generated_hypotheses:
            counts[h.type.value] = counts.get(h.type.value, 0) + 1
        return counts
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count hypotheses by severity"""
        counts = {}
        for h in self.generated_hypotheses:
            counts[h.severity] = counts.get(h.severity, 0) + 1
        return counts
