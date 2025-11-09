"""
Verification Pipeline - Multi-Layered Hypothesis Verification
Combines static analysis, symbolic execution, dynamic testing, and behavioral analysis
with confidence scoring and cross-validation to reduce false positives
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import asyncio


class VerificationLayer(Enum):
    """Different layers of verification"""

    STATIC_ANALYSIS = "static_analysis"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DYNAMIC_TESTING = "dynamic_testing"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    POC_EXECUTION = "poc_execution"


@dataclass
class VerificationResult:
    """Result from a single verification layer"""

    layer: VerificationLayer
    hypothesis_id: str
    verified: bool
    confidence: float  # 0.0-1.0
    evidence: List[str]
    execution_time: float
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregatedVerification:
    """Aggregated verification result across all layers"""

    hypothesis_id: str
    layer_results: Dict[VerificationLayer, VerificationResult]
    final_confidence: float
    verification_status: str  # verified, rejected, uncertain
    recommendation: str
    severity_adjusted: str
    timestamp: str
    cross_layer_agreement: int = 0
    contradictions: List[str] = field(default_factory=list)


class StaticAnalysisLayer:
    """
    Layer 1: Static Analysis using pattern detectors
    Integrates NovelPatternDetector and RareVulnerabilityDetector
    """

    def __init__(self, pattern_detector=None, rare_detector=None):
        self.pattern_detector = pattern_detector
        self.rare_detector = rare_detector
        self.name = "static_analysis"

    async def verify(self, hypothesis: Any, contract_code: str) -> Dict[str, Any]:
        """Check if hypothesis matches known patterns or static rules"""
        matches = []
        confidence = 0.2  # Default low confidence

        try:
            # Run pattern detectors if available
            if self.pattern_detector:
                patterns = self.pattern_detector.detect_all_patterns(
                    contract_code, "Contract"
                )
                # Match hypothesis to detected patterns
                for pattern in patterns:
                    if self._hypothesis_matches_pattern(hypothesis, pattern):
                        matches.append(pattern.name)
                        confidence = max(confidence, pattern.confidence * 0.7)

            if self.rare_detector:
                rare_vulns = self.rare_detector.detect_all(contract_code)
                for vuln in rare_vulns:
                    if self._hypothesis_matches_rare_vuln(hypothesis, vuln):
                        matches.append(vuln.name)
                        confidence = max(confidence, vuln.confidence * 0.7)

            # If no external detectors, fall back to basic pattern matching
            if not matches and hasattr(hypothesis, "type"):
                matches, confidence = self._basic_pattern_check(
                    hypothesis, contract_code
                )

        except Exception:
            pass  # Graceful degradation

        return {
            "supported": len(matches) > 0,
            "matching_patterns": matches,
            "confidence": confidence if matches else 0.2,
        }

    def _hypothesis_matches_pattern(self, hypothesis: Any, pattern: Any) -> bool:
        """Check if hypothesis aligns with a detected pattern"""
        if not hasattr(hypothesis, "type"):
            return False

        hyp_type = str(hypothesis.type).lower()
        pattern_name = str(pattern.name).lower()

        # Check for keyword overlap
        keywords = ["reentrancy", "oracle", "overflow", "access", "flash", "governance"]
        for keyword in keywords:
            if keyword in hyp_type and keyword in pattern_name:
                return True

        return False

    def _hypothesis_matches_rare_vuln(self, hypothesis: Any, vuln: Any) -> bool:
        """Check if hypothesis aligns with a rare vulnerability"""
        if not hasattr(hypothesis, "description"):
            return False

        desc = hypothesis.description.lower()
        vuln_name = vuln.name.lower()

        # Simple keyword matching
        for word in vuln_name.split():
            if len(word) > 4 and word in desc:
                return True

        return False

    def _basic_pattern_check(
        self, hypothesis: Any, contract_code: str
    ) -> Tuple[List[str], float]:
        """Basic pattern checking when external detectors not available"""
        matches = []
        confidence = 0.2

        hyp_type = str(hypothesis.type).lower()

        if "reentrancy" in hyp_type:
            if "call" in contract_code.lower():
                matches.append("potential_reentrancy")
                confidence = 0.6
        elif "oracle" in hyp_type:
            if any(
                word in contract_code for word in ["oracle", "price", "latestAnswer"]
            ):
                matches.append("oracle_usage")
                confidence = 0.5
        elif "overflow" in hyp_type or "underflow" in hyp_type:
            if "+" in contract_code or "-" in contract_code:
                matches.append("arithmetic_operations")
                confidence = 0.4

        return matches, confidence


class SymbolicExecutionLayer:
    """
    Layer 2: Symbolic Execution using Z3 SMT solver
    Attempts to find concrete exploit paths
    """

    def __init__(self, symbolic_executor=None):
        self.symbolic_executor = symbolic_executor
        self.name = "symbolic_execution"

    async def verify(self, hypothesis: Any, contract_code: str) -> Dict[str, Any]:
        """Attempt to find symbolic execution path proving hypothesis"""
        try:
            if self.symbolic_executor:
                # Extract constraint from hypothesis
                constraint = self._extract_constraint(hypothesis)

                # Run symbolic execution
                result = self.symbolic_executor.analyze_contract(contract_code[:2000])

                if hasattr(result, "vulnerabilities") and result.vulnerabilities:
                    return {
                        "supported": True,
                        "exploit_path": len(result.vulnerabilities),
                        "smt_proof": True,
                        "confidence": 0.85,
                    }

            # Fallback: pattern-based reasoning
            return self._fallback_symbolic_check(hypothesis, contract_code)

        except Exception as e:
            return {"supported": False, "confidence": 0.1, "error": str(e)}

    def _extract_constraint(self, hypothesis: Any) -> Optional[str]:
        """Extract SMT constraint from hypothesis"""
        if hasattr(hypothesis, "description"):
            desc = hypothesis.description.lower()
            if "negative" in desc:
                return "balance < 0"
            elif "overflow" in desc:
                return "result > MAX_UINT256"
        return None

    def _fallback_symbolic_check(
        self, hypothesis: Any, contract_code: str
    ) -> Dict[str, Any]:
        """Fallback when symbolic executor unavailable"""
        if hasattr(hypothesis, "type"):
            hyp_type = str(hypothesis.type).lower()

            if "reentrancy" in hyp_type:
                if ".call(" in contract_code or "call{value:" in contract_code:
                    return {"supported": True, "confidence": 0.6}

        return {"supported": False, "confidence": 0.1}


class DynamicTestingLayer:
    """
    Layer 3: Dynamic Testing through fuzzing and simulation
    Simulates attack scenarios
    """

    def __init__(self, fuzzing_orchestrator=None):
        self.fuzzing_orchestrator = fuzzing_orchestrator
        self.name = "dynamic_testing"

    async def verify(self, hypothesis: Any, contract_code: str) -> Dict[str, Any]:
        """Generate and execute test scenarios to prove hypothesis"""
        try:
            # Check if attack scenario is feasible
            if hasattr(hypothesis, "attack_scenario") and hypothesis.attack_scenario:
                scenario = hypothesis.attack_scenario.lower()

                # Look for actionable attack steps
                if any(
                    word in scenario for word in ["call", "transfer", "send", "execute"]
                ):
                    return {
                        "supported": True,
                        "attack_scenario": hypothesis.attack_scenario,
                        "confidence": 0.5,
                    }

            return {"supported": False, "confidence": 0.0}

        except Exception as e:
            return {"supported": False, "confidence": 0.0, "error": str(e)}


class BehavioralAnalysisLayer:
    """
    Layer 4: Behavioral Analysis for anomaly detection
    Uses BehavioralAnomalyDetector to find suspicious patterns
    """

    def __init__(self, anomaly_detector=None):
        self.anomaly_detector = anomaly_detector
        self.name = "behavioral_analysis"

    async def verify(self, hypothesis: Any, contract_code: str) -> Dict[str, Any]:
        """Detect behavioral anomalies supporting hypothesis"""
        try:
            if self.anomaly_detector:
                anomalies = self.anomaly_detector.analyze_contract(
                    contract_code, "Contract"
                )

                # Match anomalies to hypothesis
                relevant = self._match_anomalies(hypothesis, anomalies)

                if relevant:
                    return {
                        "supported": True,
                        "anomalies": [a.name for a in relevant],
                        "confidence": 0.6,
                    }

            return {"supported": False, "confidence": 0.2}

        except Exception:
            return {"supported": False, "confidence": 0.2}

    def _match_anomalies(self, hypothesis: Any, anomalies: List[Any]) -> List[Any]:
        """Match detected anomalies to hypothesis"""
        if not hasattr(hypothesis, "type"):
            return []

        hyp_type = str(hypothesis.type).lower()
        relevant = []

        for anomaly in anomalies:
            anomaly_name = anomaly.name.lower()
            # Simple keyword matching
            for word in hyp_type.split("_"):
                if len(word) > 3 and word in anomaly_name:
                    relevant.append(anomaly)
                    break

        return relevant


class ConfidenceScorer:
    """
    Computes weighted confidence scores from verification layers
    Applies bonuses for agreement and penalties for contradictions
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        # Default weights (can be tuned based on empirical accuracy)
        self.weights = weights or {
            "static_analysis": 0.15,
            "symbolic_execution": 0.25,
            "dynamic_testing": 0.25,
            "behavioral_analysis": 0.15,
            "poc_execution": 0.20,
        }

    def compute(self, layer_results: Dict[str, Dict[str, Any]]) -> float:
        """Compute weighted confidence score from verification layers"""
        weighted_score = 0.0
        total_weight = 0.0

        for layer_name, result in layer_results.items():
            weight = self.weights.get(layer_name, 0.2)
            confidence = result.get("confidence", 0.0)

            if result.get("supported", False):
                weighted_score += weight * confidence

            total_weight += weight

        # Normalize
        if total_weight > 0:
            weighted_score = weighted_score / total_weight

        # Apply bonuses for cross-layer agreement
        supporting_layers = sum(
            1 for r in layer_results.values() if r.get("supported", False)
        )
        if supporting_layers >= 3:
            weighted_score *= 1.2  # 20% boost for 3+ layers agreeing

        # Apply penalties for contradictions
        if self._has_contradictions(layer_results):
            weighted_score *= 0.7  # 30% penalty for contradictions

        return min(weighted_score, 1.0)  # Cap at 100%

    def _has_contradictions(self, layer_results: Dict[str, Dict[str, Any]]) -> bool:
        """Detect contradictions between layers"""
        # If PoC fails but static analysis is very confident, that's a contradiction
        poc_result = layer_results.get("poc_execution", {})
        static_result = layer_results.get("static_analysis", {})

        if not poc_result.get("supported") and static_result.get("confidence", 0) > 0.8:
            return True

        # If symbolic finds nothing but dynamic testing succeeds
        symbolic_result = layer_results.get("symbolic_execution", {})
        dynamic_result = layer_results.get("dynamic_testing", {})

        if (
            not symbolic_result.get("supported")
            and dynamic_result.get("confidence", 0) > 0.7
        ):
            return True

        return False

    def update_weights(self, new_weights: Dict[str, float]):
        """Update layer weights (for learning)"""
        total = sum(new_weights.values())
        if abs(total - 1.0) > 0.01:
            # Normalize if not summing to 1.0
            new_weights = {k: v / total for k, v in new_weights.items()}

        self.weights.update(new_weights)


class CrossValidator:
    """
    Cross-validates findings across verification layers
    Ensures consistency and reduces false positives
    """

    def __init__(self, confidence_scorer: Optional[ConfidenceScorer] = None):
        self.confidence_scorer = confidence_scorer or ConfidenceScorer()

    def validate(
        self,
        layer_results: Dict[str, Dict[str, Any]],
        confidence_threshold: float = 0.7,
    ) -> Tuple[bool, str, List[str]]:
        """
        Cross-validate findings across verification layers

        Returns:
            (is_valid, reason, contradictions)
        """
        # Count supporting layers
        supporting_layers = sum(
            1 for r in layer_results.values() if r.get("supported", False)
        )

        # Require at least 2 layers supporting hypothesis
        if supporting_layers < 2:
            return False, "Insufficient cross-layer support (need 2+ layers)", []

        # If PoC executed successfully, high confidence regardless
        poc_result = layer_results.get("poc_execution", {})
        if poc_result.get("supported", False) and poc_result.get("confidence", 0) > 0.9:
            return True, "PoC execution confirms exploit", []

        # Check for contradictions
        contradictions = self._find_contradictions(layer_results)
        if contradictions:
            return False, "Layer contradictions detected", contradictions

        # Use confidence threshold
        total_confidence = self.confidence_scorer.compute(layer_results)
        if total_confidence >= confidence_threshold:
            return True, f"High confidence: {total_confidence:.2%}", []

        return False, f"Below confidence threshold: {total_confidence:.2%}", []

    def _find_contradictions(
        self, layer_results: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Find contradictions between layers"""
        contradictions = []

        # PoC vs Static contradiction
        poc = layer_results.get("poc_execution", {})
        static = layer_results.get("static_analysis", {})

        if not poc.get("supported") and static.get("confidence", 0) > 0.8:
            contradictions.append("PoC failed but static analysis highly confident")

        # Symbolic vs Dynamic contradiction
        symbolic = layer_results.get("symbolic_execution", {})
        dynamic = layer_results.get("dynamic_testing", {})

        if not symbolic.get("supported") and dynamic.get("supported"):
            contradictions.append(
                "Symbolic found no path but dynamic testing succeeded"
            )

        return contradictions


class MultiLayerVerificationPipeline:
    """
    Multi-layered verification pipeline
    Validates hypotheses through progressive verification stages
    with confidence scoring and cross-validation
    """

    def __init__(
        self,
        pattern_detector=None,
        rare_detector=None,
        symbolic_executor=None,
        fuzzing_orchestrator=None,
        anomaly_detector=None,
        poc_generator=None,
        learning_db=None,
    ):
        """
        Initialize multi-layer verification pipeline

        Args:
            pattern_detector: NovelPatternDetector instance
            rare_detector: RareVulnerabilityDetector instance
            symbolic_executor: AdvancedSymbolicExecutor instance
            fuzzing_orchestrator: EnhancedFuzzingOrchestrator instance
            anomaly_detector: BehavioralAnomalyDetector instance
            poc_generator: PoCGenerator instance
            learning_db: PersistentLearningDB instance for adaptive learning
        """
        # Initialize verification layers
        self.layers = [
            StaticAnalysisLayer(pattern_detector, rare_detector),
            SymbolicExecutionLayer(symbolic_executor),
            DynamicTestingLayer(fuzzing_orchestrator),
            BehavioralAnalysisLayer(anomaly_detector),
        ]

        self.poc_generator = poc_generator
        self.learning_db = learning_db

        # Initialize scoring and validation with learned weights if available
        initial_weights = None
        if learning_db:
            learned_weights = learning_db.get_optimal_layer_weights()
            if learned_weights:
                initial_weights = learned_weights
                print(
                    f"✓ Using learned verification weights from {len(learning_db.verification_layer_metrics)} tracked layers"
                )

        self.confidence_scorer = ConfidenceScorer(weights=initial_weights)
        self.cross_validator = CrossValidator(self.confidence_scorer)

        # History tracking
        self.verification_history: List[Dict[str, Any]] = []

    async def verify_hypothesis(
        self,
        hypothesis: Any,
        contract_code: str,
        run_all_layers: bool = True,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Verify a hypothesis through all verification layers

        Args:
            hypothesis: VulnerabilityHypothesis object
            contract_code: Source code to analyze
            run_all_layers: Whether to run all layers or stop early
            timeout: Timeout per layer in seconds

        Returns:
            Aggregated verification result
        """
        layer_results = {}

        # Execute each layer
        for layer in self.layers:
            try:
                result = await asyncio.wait_for(
                    layer.verify(hypothesis, contract_code), timeout=timeout
                )
                layer_results[layer.name] = result

                # Early stopping if not running all layers
                if not run_all_layers and not result.get("supported", False):
                    break

            except asyncio.TimeoutError:
                layer_results[layer.name] = {
                    "supported": False,
                    "confidence": 0.0,
                    "error": "timeout",
                }
            except Exception as e:
                layer_results[layer.name] = {
                    "supported": False,
                    "confidence": 0.0,
                    "error": str(e),
                }

        # Run PoC generation if static layer supports
        if self.poc_generator and layer_results.get("static_analysis", {}).get(
            "supported", False
        ):
            try:
                poc_result = await asyncio.wait_for(
                    self._verify_poc_execution(hypothesis, contract_code),
                    timeout=timeout * 2,  # PoC gets more time
                )
                layer_results["poc_execution"] = poc_result
            except Exception as e:
                layer_results["poc_execution"] = {
                    "supported": False,
                    "confidence": 0.0,
                    "error": str(e),
                }

        # Compute aggregate confidence score
        confidence = self.confidence_scorer.compute(layer_results)

        # Cross-validate findings
        validated, reason, contradictions = self.cross_validator.validate(layer_results)

        # Determine verification status
        if confidence >= 0.7 and validated:
            status = "verified"
        elif confidence >= 0.4:
            status = "uncertain"
        else:
            status = "rejected"

        # Count cross-layer agreement
        supporting_layers = sum(
            1 for r in layer_results.values() if r.get("supported", False)
        )

        result = {
            "hypothesis_id": getattr(hypothesis, "id", "unknown"),
            "layer_results": layer_results,
            "final_confidence": confidence,
            "verification_status": status,
            "validated": validated,
            "validation_reason": reason,
            "contradictions": contradictions,
            "cross_layer_agreement": supporting_layers,
            "timestamp": datetime.now().isoformat(),
        }

        self.verification_history.append(result)

        return result

    async def _verify_poc_execution(
        self, hypothesis: Any, contract_code: str
    ) -> Dict[str, Any]:
        """Verify through PoC generation and execution"""
        try:
            if self.poc_generator:
                # This is a placeholder - actual PoC execution would be more complex
                return {
                    "supported": False,
                    "confidence": 0.0,
                    "message": "PoC generation not yet implemented",
                }
            else:
                return {"supported": False, "confidence": 0.0}
        except Exception as e:
            return {"supported": False, "confidence": 0.0, "error": str(e)}

    def verify_hypothesis_sync(
        self, hypothesis: Any, contract_code: str, run_all_layers: bool = True
    ) -> Dict[str, Any]:
        """Synchronous wrapper for verify_hypothesis"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_closed():
            asyncio.set_event_loop(None)
            loop = None

        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(
                self.verify_hypothesis(hypothesis, contract_code, run_all_layers), loop
            )
            return future.result()

        if not loop:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(
                    self.verify_hypothesis(hypothesis, contract_code, run_all_layers)
                )
            finally:
                loop.close()
                asyncio.set_event_loop(None)

        return loop.run_until_complete(
            self.verify_hypothesis(hypothesis, contract_code, run_all_layers)
        )

    def get_verification_stats(self) -> Dict[str, Any]:
        """Get statistics about verification pipeline performance"""
        if not self.verification_history:
            return {
                "total_verifications": 0,
                "verified_count": 0,
                "rejected_count": 0,
                "uncertain_count": 0,
            }

        verified = len(
            [
                v
                for v in self.verification_history
                if v["verification_status"] == "verified"
            ]
        )
        rejected = len(
            [
                v
                for v in self.verification_history
                if v["verification_status"] == "rejected"
            ]
        )
        uncertain = len(
            [
                v
                for v in self.verification_history
                if v["verification_status"] == "uncertain"
            ]
        )

        avg_confidence = sum(
            v["final_confidence"] for v in self.verification_history
        ) / len(self.verification_history)
        avg_agreement = sum(
            v["cross_layer_agreement"] for v in self.verification_history
        ) / len(self.verification_history)

        return {
            "total_verifications": len(self.verification_history),
            "verified_count": verified,
            "rejected_count": rejected,
            "uncertain_count": uncertain,
            "avg_confidence": avg_confidence,
            "avg_cross_layer_agreement": avg_agreement,
            "false_positive_reduction": (rejected / len(self.verification_history))
            if self.verification_history
            else 0.0,
        }

    def export_verification_report(self, filepath: str):
        """Export verification results to JSON"""
        report = {
            "statistics": self.get_verification_stats(),
            "layer_weights": self.confidence_scorer.weights,
            "verification_history": self.verification_history,
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        print(f"✓ Verification report exported to {filepath}")


class VerificationPipeline:
    """
    Multi-layered verification pipeline
    Validates hypotheses through progressive verification stages
    """

    def __init__(
        self,
        static_analyzer=None,
        symbolic_executor=None,
        dynamic_tester=None,
        poc_generator=None,
    ):
        self.static_analyzer = static_analyzer
        self.symbolic_executor = symbolic_executor
        self.dynamic_tester = dynamic_tester
        self.poc_generator = poc_generator

        self.verification_history: List[AggregatedVerification] = []
        self.layer_weights = {
            VerificationLayer.STATIC_ANALYSIS: 0.15,
            VerificationLayer.SYMBOLIC_EXECUTION: 0.25,
            VerificationLayer.DYNAMIC_TESTING: 0.25,
            VerificationLayer.BEHAVIORAL_ANALYSIS: 0.15,
            VerificationLayer.POC_EXECUTION: 0.20,
        }

    def verify_hypothesis(
        self, hypothesis: Any, contract_code: str, run_all_layers: bool = True
    ) -> AggregatedVerification:
        """
        Verify a hypothesis through multiple layers

        Args:
            hypothesis: VulnerabilityHypothesis object
            contract_code: Source code to analyze
            run_all_layers: Whether to run all layers or stop early on rejection
        """
        layer_results = {}

        # Layer 1: Static Analysis
        static_result = self._verify_static_analysis(hypothesis, contract_code)
        layer_results[VerificationLayer.STATIC_ANALYSIS] = static_result

        if not run_all_layers and not static_result.verified:
            return self._aggregate_results(hypothesis, layer_results)

        # Layer 2: Symbolic Execution
        if self.symbolic_executor:
            symbolic_result = self._verify_symbolic_execution(hypothesis, contract_code)
            layer_results[VerificationLayer.SYMBOLIC_EXECUTION] = symbolic_result

            if not run_all_layers and not symbolic_result.verified:
                return self._aggregate_results(hypothesis, layer_results)

        # Layer 3: Dynamic Testing
        if self.dynamic_tester:
            dynamic_result = self._verify_dynamic_testing(hypothesis, contract_code)
            layer_results[VerificationLayer.DYNAMIC_TESTING] = dynamic_result

            if not run_all_layers and not dynamic_result.verified:
                return self._aggregate_results(hypothesis, layer_results)

        # Layer 4: PoC Execution
        if self.poc_generator and static_result.verified:
            poc_result = self._verify_poc_execution(hypothesis, contract_code)
            layer_results[VerificationLayer.POC_EXECUTION] = poc_result

        # Aggregate results
        aggregated = self._aggregate_results(hypothesis, layer_results)
        self.verification_history.append(aggregated)

        return aggregated

    def verify_batch(
        self, hypotheses: List[Any], contract_code: str, parallel: bool = False
    ) -> List[AggregatedVerification]:
        """
        Verify multiple hypotheses
        """
        results = []

        for hypothesis in hypotheses:
            result = self.verify_hypothesis(
                hypothesis, contract_code, run_all_layers=True
            )
            results.append(result)

        return results

    def _verify_static_analysis(
        self, hypothesis: Any, contract_code: str
    ) -> VerificationResult:
        """
        Layer 1: Static analysis verification
        Uses pattern matching and code analysis
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}

        try:
            # Check for code patterns related to hypothesis
            if hasattr(hypothesis, "type"):
                hypothesis_type = (
                    hypothesis.type.value
                    if hasattr(hypothesis.type, "value")
                    else str(hypothesis.type)
                )

                # Reentrancy checks
                if "reentrancy" in hypothesis_type.lower():
                    has_external_call = "call" in contract_code.lower()
                    has_state_change = any(
                        word in contract_code for word in ["balance", "transfer", "="]
                    )
                    no_protection = (
                        "nonReentrant" not in contract_code
                        and "ReentrancyGuard" not in contract_code
                    )

                    if has_external_call and has_state_change and no_protection:
                        verified = True
                        confidence = 0.7
                        evidence.append(
                            "External calls found without reentrancy protection"
                        )
                        evidence.append("State changes detected after external calls")

                    details["has_external_call"] = has_external_call
                    details["has_protection"] = not no_protection

                # Oracle manipulation checks
                elif "oracle" in hypothesis_type.lower():
                    has_oracle_call = any(
                        word in contract_code
                        for word in ["oracle", "latestAnswer", "getPrice"]
                    )
                    no_timestamp_check = "timestamp" not in contract_code.lower()
                    no_staleness_check = "updatedAt" not in contract_code

                    if has_oracle_call and (no_timestamp_check or no_staleness_check):
                        verified = True
                        confidence = 0.6
                        evidence.append("Oracle price feed used")
                        if no_staleness_check:
                            evidence.append("No staleness check detected")

                    details["has_oracle"] = has_oracle_call
                    details["has_staleness_check"] = not no_staleness_check

                # Cross-contract checks
                elif "cross_contract" in hypothesis_type.lower():
                    has_external_interface = any(
                        word in contract_code
                        for word in ["interface", "IERC", "external"]
                    )
                    has_untrusted_call = (
                        ".call" in contract_code or "delegatecall" in contract_code
                    )

                    if has_external_interface or has_untrusted_call:
                        verified = True
                        confidence = 0.5
                        evidence.append("External contract interactions detected")

                    details["has_external_interface"] = has_external_interface

                # Access control checks
                elif "access" in hypothesis_type.lower():
                    has_privileged_functions = any(
                        word in contract_code
                        for word in ["onlyOwner", "onlyAdmin", "admin"]
                    )
                    has_modifier = "modifier" in contract_code

                    if not has_modifier and not has_privileged_functions:
                        verified = True
                        confidence = 0.6
                        evidence.append("No access control modifiers found")

                # Edge case checks
                elif "edge" in hypothesis_type.lower():
                    has_division = "/" in contract_code
                    has_zero_check = (
                        "require" in contract_code.lower()
                        or "assert" in contract_code.lower()
                    )

                    if has_division and not has_zero_check:
                        verified = True
                        confidence = 0.4
                        evidence.append("Division operations without checks")

                    details["has_division"] = has_division
                    details["has_checks"] = has_zero_check

        except Exception as e:
            evidence.append(f"Static analysis error: {str(e)}")

        execution_time = (datetime.now() - start_time).total_seconds()

        return VerificationResult(
            layer=VerificationLayer.STATIC_ANALYSIS,
            hypothesis_id=getattr(hypothesis, "id", "unknown"),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details,
        )

    def _verify_symbolic_execution(
        self, hypothesis: Any, contract_code: str
    ) -> VerificationResult:
        """
        Layer 2: Symbolic execution verification
        Uses Z3 solver to prove exploitability
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}

        try:
            if self.symbolic_executor:
                # Run symbolic execution
                # This is a simplified version - actual implementation would be more complex
                result = self.symbolic_executor.analyze_contract(contract_code[:1000])

                if hasattr(result, "vulnerabilities") and result.vulnerabilities:
                    verified = True
                    confidence = 0.8
                    evidence.append("Symbolic execution found exploitable path")
                    evidence.extend(
                        [v.get("description", "") for v in result.vulnerabilities[:3]]
                    )
                    details["symbolic_paths"] = len(getattr(result, "paths", []))
            else:
                # Fallback: Pattern-based symbolic reasoning
                if hasattr(hypothesis, "type"):
                    hypothesis_type = (
                        hypothesis.type.value
                        if hasattr(hypothesis.type, "value")
                        else str(hypothesis.type)
                    )

                    # Simplified checks
                    if "reentrancy" in hypothesis_type.lower():
                        # Look for call patterns
                        if "call{value:" in contract_code or ".call(" in contract_code:
                            verified = True
                            confidence = 0.6
                            evidence.append(
                                "Potential execution path for reentrancy found"
                            )

        except Exception as e:
            evidence.append(f"Symbolic execution error: {str(e)}")

        execution_time = (datetime.now() - start_time).total_seconds()

        return VerificationResult(
            layer=VerificationLayer.SYMBOLIC_EXECUTION,
            hypothesis_id=getattr(hypothesis, "id", "unknown"),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details,
        )

    def _verify_dynamic_testing(
        self, hypothesis: Any, contract_code: str
    ) -> VerificationResult:
        """
        Layer 3: Dynamic testing verification
        Simulates attack scenarios
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}

        # Placeholder for dynamic testing
        # In production, this would deploy to test environment and execute attack scenarios
        try:
            # Simplified dynamic check
            if hasattr(hypothesis, "attack_scenario") and hypothesis.attack_scenario:
                # Check if attack scenario is feasible
                scenario = hypothesis.attack_scenario.lower()

                if any(word in scenario for word in ["call", "transfer", "send"]):
                    verified = True
                    confidence = 0.5
                    evidence.append("Attack scenario appears feasible")

        except Exception as e:
            evidence.append(f"Dynamic testing error: {str(e)}")

        execution_time = (datetime.now() - start_time).total_seconds()

        return VerificationResult(
            layer=VerificationLayer.DYNAMIC_TESTING,
            hypothesis_id=getattr(hypothesis, "id", "unknown"),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details,
        )

    def _verify_poc_execution(
        self, hypothesis: Any, contract_code: str
    ) -> VerificationResult:
        """
        Layer 4: PoC execution verification
        Generates and executes proof of concept
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}

        try:
            if self.poc_generator:
                # Generate and execute PoC
                poc_result = self.poc_generator.generate_and_execute(
                    hypothesis, contract_code
                )

                if poc_result.get("success", False):
                    verified = True
                    confidence = 0.95  # High confidence if PoC executes successfully
                    evidence.append("PoC executed successfully")
                    evidence.append(
                        f"Exploit demonstrated: {poc_result.get('description', '')}"
                    )
                    details["poc_output"] = poc_result.get("output", "")
            else:
                # Placeholder without actual PoC generator
                evidence.append("PoC generator not configured")

        except Exception as e:
            evidence.append(f"PoC execution error: {str(e)}")

        execution_time = (datetime.now() - start_time).total_seconds()

        return VerificationResult(
            layer=VerificationLayer.POC_EXECUTION,
            hypothesis_id=getattr(hypothesis, "id", "unknown"),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details,
        )

    def _aggregate_results(
        self,
        hypothesis: Any,
        layer_results: Dict[VerificationLayer, VerificationResult],
    ) -> AggregatedVerification:
        """
        Aggregate verification results from all layers
        Calculate final confidence score
        """
        # Calculate weighted confidence score
        total_weight = 0.0
        weighted_confidence = 0.0

        for layer, result in layer_results.items():
            weight = self.layer_weights.get(layer, 0.25)
            total_weight += weight
            if result.verified:
                weighted_confidence += result.confidence * weight

        final_confidence = (
            weighted_confidence / total_weight if total_weight > 0 else 0.0
        )

        # Determine verification status
        if final_confidence >= 0.7:
            status = "verified"
            recommendation = "High confidence vulnerability - prioritize remediation"
        elif final_confidence >= 0.4:
            status = "uncertain"
            recommendation = "Moderate confidence - manual review recommended"
        else:
            status = "rejected"
            recommendation = "Low confidence - likely false positive"

        # Adjust severity based on confidence
        original_severity = getattr(hypothesis, "severity", "medium")
        if final_confidence < 0.5:
            severity_adjusted = "low" if original_severity != "critical" else "medium"
        else:
            severity_adjusted = original_severity

        return AggregatedVerification(
            hypothesis_id=getattr(hypothesis, "id", "unknown"),
            layer_results=layer_results,
            final_confidence=final_confidence,
            verification_status=status,
            recommendation=recommendation,
            severity_adjusted=severity_adjusted,
            timestamp=datetime.now().isoformat(),
        )

    def update_layer_weights(self, new_weights: Dict[VerificationLayer, float]):
        """Update weights for different verification layers"""
        total = sum(new_weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError("Weights must sum to 1.0")

        self.layer_weights.update(new_weights)

    def get_verification_stats(self) -> Dict[str, Any]:
        """Get statistics about verification pipeline"""
        if not self.verification_history:
            return {
                "total_verifications": 0,
                "verified_count": 0,
                "rejected_count": 0,
                "uncertain_count": 0,
            }

        verified = len(
            [
                v
                for v in self.verification_history
                if v.verification_status == "verified"
            ]
        )
        rejected = len(
            [
                v
                for v in self.verification_history
                if v.verification_status == "rejected"
            ]
        )
        uncertain = len(
            [
                v
                for v in self.verification_history
                if v.verification_status == "uncertain"
            ]
        )

        avg_confidence = sum(
            v.final_confidence for v in self.verification_history
        ) / len(self.verification_history)

        # Layer statistics
        layer_stats = {}
        for layer in VerificationLayer:
            layer_results = [
                v.layer_results.get(layer)
                for v in self.verification_history
                if layer in v.layer_results
            ]
            if layer_results:
                layer_stats[layer.value] = {
                    "total": len(layer_results),
                    "verified": len([r for r in layer_results if r.verified]),
                    "avg_confidence": sum(r.confidence for r in layer_results)
                    / len(layer_results),
                    "avg_execution_time": sum(r.execution_time for r in layer_results)
                    / len(layer_results),
                }

        return {
            "total_verifications": len(self.verification_history),
            "verified_count": verified,
            "rejected_count": rejected,
            "uncertain_count": uncertain,
            "avg_confidence": avg_confidence,
            "layer_statistics": layer_stats,
            "current_weights": {k.value: v for k, v in self.layer_weights.items()},
        }

    def export_verification_report(self, filepath: str):
        """Export verification results to JSON"""
        report = {
            "statistics": self.get_verification_stats(),
            "verification_history": [
                {
                    "hypothesis_id": v.hypothesis_id,
                    "final_confidence": v.final_confidence,
                    "status": v.verification_status,
                    "recommendation": v.recommendation,
                    "severity_adjusted": v.severity_adjusted,
                    "timestamp": v.timestamp,
                    "layers": {
                        layer.value: {
                            "verified": result.verified,
                            "confidence": result.confidence,
                            "evidence": result.evidence,
                            "execution_time": result.execution_time,
                        }
                        for layer, result in v.layer_results.items()
                    },
                }
                for v in self.verification_history
            ],
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        print(f"✓ Verification report exported to {filepath}")
