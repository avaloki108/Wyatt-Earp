"""
Persistent Learning System - True incremental learning from every analysis
Tracks what the tool learns, improves accuracy over time, and persists knowledge
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class LearningRecord:
    """Record of what was learned from an analysis"""

    id: str
    timestamp: str
    contract_hash: str
    vulnerabilities_found: List[str]
    false_positives_marked: List[str]
    patterns_extracted: List[Dict[str, Any]]
    accuracy_score: float
    processing_time: float
    llm_insights: List[str]


@dataclass
class PatternEffectiveness:
    """Track how effective each vulnerability pattern is"""

    pattern_name: str
    times_detected: int
    true_positives: int
    false_positives: int
    last_updated: str
    confidence_score: float


@dataclass
class HypothesisQualityMetrics:
    """Track quality of AI-generated hypotheses"""

    hypothesis_type: str
    total_generated: int
    verified_count: int
    rejected_count: int
    avg_initial_confidence: float
    avg_final_confidence: float
    success_rate: float
    last_updated: str


@dataclass
class VerificationLayerMetrics:
    """Track performance of verification layers"""

    layer_name: str
    total_verifications: int
    true_positives: int
    false_positives: int
    false_negatives: int
    avg_confidence: float
    avg_execution_time: float
    accuracy: float
    last_updated: str


class PersistentLearningDB:
    """
    Persistent learning database that improves with each scan
    Stores all learnings and uses them to improve future scans
    """

    def __init__(self, db_path: str = "learned_knowledge.json"):
        self.db_path = Path(db_path)
        self.learning_records: List[LearningRecord] = []
        self.pattern_effectiveness: Dict[str, PatternEffectiveness] = {}
        self.vulnerability_corpus: Dict[str, List[str]] = {}  # Type -> examples
        self.accuracy_history: List[float] = []
        self.hypothesis_metrics: Dict[
            str, HypothesisQualityMetrics
        ] = {}  # Track hypothesis quality
        self.prompt_effectiveness: Dict[str, float] = {}  # Track prompt effectiveness

        # NEW: Adaptive learning fields
        self.prompt_performance: Dict[
            str, Any
        ] = {}  # Detailed prompt performance tracking
        self.verification_weights: Dict[str, Any] = {}  # Verification layer weights
        self.hypothesis_quality_trends: Dict[
            str, List[float]
        ] = {}  # Quality trends over time
        self.user_feedback_log: List[Dict[str, Any]] = []  # User feedback history

        self.verification_layer_metrics: Dict[
            str, VerificationLayerMetrics
        ] = {}  # NEW: Track verification layers
        self._load_database()

    def _load_database(self):
        """Load existing learning database"""
        if self.db_path.exists():
            try:
                with open(self.db_path, "r") as f:
                    data = json.load(f)

                # Load learning records
                if "learning_records" in data:
                    self.learning_records = [
                        LearningRecord(**record) for record in data["learning_records"]
                    ]

                # Load pattern effectiveness
                if "pattern_effectiveness" in data:
                    self.pattern_effectiveness = {
                        name: PatternEffectiveness(**stats)
                        for name, stats in data["pattern_effectiveness"].items()
                    }

                # Load vulnerability corpus
                if "vulnerability_corpus" in data:
                    self.vulnerability_corpus = data["vulnerability_corpus"]

                # Load accuracy history
                if "accuracy_history" in data:
                    self.accuracy_history = data["accuracy_history"]

                # Load hypothesis metrics
                if "hypothesis_metrics" in data:
                    self.hypothesis_metrics = {
                        name: HypothesisQualityMetrics(**metrics)
                        for name, metrics in data["hypothesis_metrics"].items()
                    }

                # Load prompt effectiveness
                if "prompt_effectiveness" in data:
                    self.prompt_effectiveness = data["prompt_effectiveness"]

                # Load adaptive learning fields (NEW)
                if "prompt_performance" in data:
                    self.prompt_performance = data["prompt_performance"]

                if "verification_weights" in data:
                    self.verification_weights = data["verification_weights"]

                if "hypothesis_quality_trends" in data:
                    self.hypothesis_quality_trends = data["hypothesis_quality_trends"]

                if "user_feedback_log" in data:
                    self.user_feedback_log = data["user_feedback_log"]
                # Load verification layer metrics
                if "verification_layer_metrics" in data:
                    self.verification_layer_metrics = {
                        name: VerificationLayerMetrics(**metrics)
                        for name, metrics in data["verification_layer_metrics"].items()
                    }

                print(
                    f"✓ Loaded learning database: {len(self.learning_records)} records"
                )
            except Exception as e:
                print(f"Warning: Could not load learning database: {e}")

    def save_database(self):
        """Persist all learning data"""
        try:
            data = {
                "learning_records": [asdict(r) for r in self.learning_records],
                "pattern_effectiveness": {
                    name: asdict(stats)
                    for name, stats in self.pattern_effectiveness.items()
                },
                "vulnerability_corpus": self.vulnerability_corpus,
                "accuracy_history": self.accuracy_history,
                "hypothesis_metrics": {
                    name: asdict(metrics)
                    for name, metrics in self.hypothesis_metrics.items()
                },
                "prompt_effectiveness": self.prompt_effectiveness,
                # NEW: Adaptive learning fields
                "prompt_performance": self.prompt_performance,
                "verification_weights": self.verification_weights,
                "hypothesis_quality_trends": self.hypothesis_quality_trends,
                "user_feedback_log": self.user_feedback_log,
                "verification_layer_metrics": {
                    name: asdict(metrics)
                    for name, metrics in self.verification_layer_metrics.items()
                },
                "last_updated": datetime.now().isoformat(),
                "total_scans": len(self.learning_records),
            }

            with open(self.db_path, "w") as f:
                json.dump(data, f, indent=2)

            print(f"✓ Saved learning database: {len(self.learning_records)} records")
        except Exception as e:
            print(f"Error saving database: {e}")

    def record_analysis(
        self,
        contract_code: str,
        vulnerabilities_found: List[Dict[str, Any]],
        llm_insights: List[str],
        processing_time: float,
        user_feedback: Optional[Dict[str, Any]] = None,
    ) -> LearningRecord:
        """
        Record what was learned from this analysis
        This is called after EVERY scan to improve the system
        """
        # Generate unique ID for this analysis
        contract_hash = hashlib.sha256(contract_code.encode()).hexdigest()[:16]
        record_id = (
            f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{contract_hash[:8]}"
        )

        # Extract vulnerability types
        vuln_types = [
            v.get("name", v.get("type", "unknown")) for v in vulnerabilities_found
        ]

        # Calculate accuracy if user provided feedback
        accuracy = 1.0  # Default if no feedback
        false_positives = []

        if user_feedback:
            false_positives = user_feedback.get("false_positives", [])
            confirmed = user_feedback.get("confirmed", len(vulnerabilities_found))
            total = len(vulnerabilities_found)
            accuracy = confirmed / total if total > 0 else 1.0

        # Extract patterns from findings
        patterns_extracted = self._extract_patterns_from_findings(vulnerabilities_found)

        # Create learning record
        record = LearningRecord(
            id=record_id,
            timestamp=datetime.now().isoformat(),
            contract_hash=contract_hash,
            vulnerabilities_found=vuln_types,
            false_positives_marked=false_positives,
            patterns_extracted=patterns_extracted,
            accuracy_score=accuracy,
            processing_time=processing_time,
            llm_insights=llm_insights,
        )

        # Store record
        self.learning_records.append(record)
        self.accuracy_history.append(accuracy)

        # Update pattern effectiveness
        self._update_pattern_effectiveness(vuln_types, false_positives)

        # Add to vulnerability corpus
        for vuln_type in vuln_types:
            if vuln_type not in self.vulnerability_corpus:
                self.vulnerability_corpus[vuln_type] = []
            # Store code snippet for this vulnerability type
            snippet = contract_code[:200]  # First 200 chars as example
            if snippet not in self.vulnerability_corpus[vuln_type]:
                self.vulnerability_corpus[vuln_type].append(snippet)

        # Save to disk
        self.save_database()

        return record

    def _extract_patterns_from_findings(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract reusable patterns from vulnerability findings"""
        patterns = []

        for vuln in vulnerabilities:
            pattern = {
                "type": vuln.get("name", vuln.get("type", "unknown")),
                "severity": vuln.get("severity", "medium"),
                "indicators": [],
                "detection_strategy": vuln.get("detection_strategy", "static_analysis"),
            }

            # Extract code patterns if available
            if "affected_code" in vuln:
                pattern["code_signature"] = vuln["affected_code"][:100]

            # Extract function patterns
            if "affected_functions" in vuln:
                pattern["function_signatures"] = vuln["affected_functions"]

            patterns.append(pattern)

        return patterns

    def _update_pattern_effectiveness(
        self, detected: List[str], false_positives: List[str]
    ):
        """Update effectiveness tracking for each detection pattern"""
        for pattern_name in detected:
            if pattern_name not in self.pattern_effectiveness:
                self.pattern_effectiveness[pattern_name] = PatternEffectiveness(
                    pattern_name=pattern_name,
                    times_detected=0,
                    true_positives=0,
                    false_positives=0,
                    last_updated=datetime.now().isoformat(),
                    confidence_score=0.5,
                )

            stats = self.pattern_effectiveness[pattern_name]
            stats.times_detected += 1

            if pattern_name in false_positives:
                stats.false_positives += 1
            else:
                stats.true_positives += 1

            # Update confidence score based on accuracy
            total = stats.true_positives + stats.false_positives
            stats.confidence_score = stats.true_positives / total if total > 0 else 0.5
            stats.last_updated = datetime.now().isoformat()

    def get_learned_patterns_for_analysis(self) -> List[Dict[str, Any]]:
        """
        Get all learned patterns to use in next analysis
        Returns patterns sorted by effectiveness
        """
        patterns = []

        for pattern_name, stats in self.pattern_effectiveness.items():
            if stats.confidence_score >= 0.5:  # Only include effective patterns
                patterns.append(
                    {
                        "name": pattern_name,
                        "confidence": stats.confidence_score,
                        "examples": self.vulnerability_corpus.get(pattern_name, [])[:3],
                        "times_detected": stats.times_detected,
                    }
                )

        # Sort by confidence
        patterns.sort(key=lambda x: x["confidence"], reverse=True)
        return patterns

    def get_improvement_metrics(self) -> Dict[str, Any]:
        """Get metrics showing how the tool has improved over time"""
        if len(self.accuracy_history) < 2:
            return {
                "scans_completed": len(self.learning_records),
                "improvement": "insufficient_data",
            }

        # Calculate improvement over time
        recent_accuracy = sum(self.accuracy_history[-10:]) / min(
            10, len(self.accuracy_history)
        )
        initial_accuracy = sum(self.accuracy_history[:10]) / min(
            10, len(self.accuracy_history)
        )
        improvement = recent_accuracy - initial_accuracy

        # Find most effective patterns
        top_patterns = sorted(
            self.pattern_effectiveness.values(),
            key=lambda x: x.confidence_score,
            reverse=True,
        )[:5]

        return {
            "total_scans": len(self.learning_records),
            "average_accuracy": sum(self.accuracy_history) / len(self.accuracy_history),
            "recent_accuracy": recent_accuracy,
            "initial_accuracy": initial_accuracy,
            "improvement_percentage": improvement * 100,
            "total_patterns_learned": len(self.pattern_effectiveness),
            "top_patterns": [p.pattern_name for p in top_patterns],
            "hypothesis_metrics": self._get_hypothesis_metrics_summary(),
        }

    def record_hypothesis_quality(
        self,
        hypothesis_type: str,
        generated_count: int,
        verified_count: int,
        rejected_count: int,
        avg_initial_confidence: float,
        avg_final_confidence: float,
    ):
        """
        Record quality metrics for AI-generated hypotheses
        Used by prompt chain orchestrator

        Args:
            hypothesis_type: Type of hypothesis (e.g., 'flash_loan_attack', 'reentrancy')
            generated_count: Total hypotheses generated
            verified_count: Number verified as plausible
            rejected_count: Number rejected as implausible
            avg_initial_confidence: Average initial confidence score
            avg_final_confidence: Average final confidence after validation
        """
        if hypothesis_type not in self.hypothesis_metrics:
            self.hypothesis_metrics[hypothesis_type] = HypothesisQualityMetrics(
                hypothesis_type=hypothesis_type,
                total_generated=0,
                verified_count=0,
                rejected_count=0,
                avg_initial_confidence=0.0,
                avg_final_confidence=0.0,
                success_rate=0.0,
                last_updated=datetime.now().isoformat(),
            )

        metrics = self.hypothesis_metrics[hypothesis_type]

        # Update counts
        metrics.total_generated += generated_count
        metrics.verified_count += verified_count
        metrics.rejected_count += rejected_count

        # Update confidence averages (weighted)
        total_prev = metrics.total_generated - generated_count
        if total_prev > 0:
            metrics.avg_initial_confidence = (
                metrics.avg_initial_confidence * total_prev
                + avg_initial_confidence * generated_count
            ) / metrics.total_generated
            metrics.avg_final_confidence = (
                metrics.avg_final_confidence * total_prev
                + avg_final_confidence * generated_count
            ) / metrics.total_generated
        else:
            metrics.avg_initial_confidence = avg_initial_confidence
            metrics.avg_final_confidence = avg_final_confidence

        # Calculate success rate
        total_processed = metrics.verified_count + metrics.rejected_count
        metrics.success_rate = (
            metrics.verified_count / total_processed if total_processed > 0 else 0.0
        )
        metrics.last_updated = datetime.now().isoformat()

        # Save to disk
        self.save_database()

    def get_learned_patterns_text(self, max_patterns: int = 10) -> List[str]:
        """
        Get learned patterns as text descriptions for prompt enhancement

        Args:
            max_patterns: Maximum number of patterns to return

        Returns:
            List of pattern descriptions
        """
        patterns = self.get_learned_patterns_for_analysis()
        pattern_texts = []

        for pattern in patterns[:max_patterns]:
            text = f"{pattern['name']} (confidence: {pattern['confidence']:.2f}, detected {pattern['times_detected']} times)"
            pattern_texts.append(text)

        return pattern_texts

    def _get_hypothesis_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of hypothesis quality metrics"""
        if not self.hypothesis_metrics:
            return {"status": "no_data"}

        total_generated = sum(
            m.total_generated for m in self.hypothesis_metrics.values()
        )
        total_verified = sum(m.verified_count for m in self.hypothesis_metrics.values())
        total_rejected = sum(m.rejected_count for m in self.hypothesis_metrics.values())

        avg_success_rate = sum(
            m.success_rate for m in self.hypothesis_metrics.values()
        ) / len(self.hypothesis_metrics)

        return {
            "total_hypotheses_generated": total_generated,
            "total_verified": total_verified,
            "total_rejected": total_rejected,
            "overall_success_rate": avg_success_rate,
            "hypothesis_types_tracked": len(self.hypothesis_metrics),
        }

    def get_enhanced_llm_prompt(self) -> str:
        """
        Generate enhanced LLM prompt with all learned patterns
        This makes the LLM smarter with each scan
        """
        prompt = """You are an advanced smart contract auditor with continuously learning capabilities.

Based on previous analyses, pay special attention to these vulnerability patterns:

"""

        patterns = self.get_learned_patterns_for_analysis()

        for i, pattern in enumerate(patterns[:10], 1):  # Top 10 patterns
            prompt += (
                f"\n{i}. {pattern['name']} (Confidence: {pattern['confidence']:.2f})"
            )
            if pattern["examples"]:
                prompt += f"\n   Example indicators: {pattern['examples'][0][:100]}..."

        prompt += """

Use these learned patterns to:
1. Detect similar vulnerabilities in the current contract
2. Identify variations of known patterns
3. Look for novel vulnerabilities that match these categories
4. Consider edge cases based on past findings

Provide detailed analysis with specific code references.
"""

        return prompt

    def track_hypothesis_quality(
        self,
        hypothesis_type: str,
        initial_confidence: float,
        final_confidence: float,
        verified: bool,
    ):
        """
        Track quality metrics for AI-generated hypotheses
        Helps improve prompt strategies over time
        """
        if hypothesis_type not in self.hypothesis_metrics:
            self.hypothesis_metrics[hypothesis_type] = HypothesisQualityMetrics(
                hypothesis_type=hypothesis_type,
                total_generated=0,
                verified_count=0,
                rejected_count=0,
                avg_initial_confidence=0.0,
                avg_final_confidence=0.0,
                success_rate=0.0,
                last_updated=datetime.now().isoformat(),
            )

        metrics = self.hypothesis_metrics[hypothesis_type]

        # Update counts
        metrics.total_generated += 1
        if verified:
            metrics.verified_count += 1
        else:
            metrics.rejected_count += 1

        # Update averages (running average)
        total = metrics.total_generated
        metrics.avg_initial_confidence = (
            metrics.avg_initial_confidence * (total - 1) + initial_confidence
        ) / total
        metrics.avg_final_confidence = (
            metrics.avg_final_confidence * (total - 1) + final_confidence
        ) / total

        # Update success rate
        metrics.success_rate = metrics.verified_count / metrics.total_generated
        metrics.last_updated = datetime.now().isoformat()

    def update_prompt_effectiveness(self, prompt_id: str, effectiveness_score: float):
        """
        Track effectiveness of specific prompts
        Helps identify which prompts generate best hypotheses
        """
        self.prompt_effectiveness[prompt_id] = effectiveness_score

    def get_hypothesis_quality_report(self) -> Dict[str, Any]:
        """Get report on hypothesis generation quality"""
        if not self.hypothesis_metrics:
            return {
                "total_hypotheses": 0,
                "message": "No hypothesis data available yet",
            }

        total_hypotheses = sum(
            m.total_generated for m in self.hypothesis_metrics.values()
        )
        total_verified = sum(m.verified_count for m in self.hypothesis_metrics.values())

        return {
            "total_hypotheses_generated": total_hypotheses,
            "total_verified": total_verified,
            "overall_success_rate": total_verified / total_hypotheses
            if total_hypotheses > 0
            else 0.0,
            "by_type": {
                name: {
                    "total": m.total_generated,
                    "verified": m.verified_count,
                    "success_rate": m.success_rate,
                    "avg_initial_confidence": m.avg_initial_confidence,
                    "avg_final_confidence": m.avg_final_confidence,
                    "confidence_improvement": m.avg_final_confidence
                    - m.avg_initial_confidence,
                }
                for name, m in self.hypothesis_metrics.items()
            },
            "best_performing_types": sorted(
                [(name, m.success_rate) for name, m in self.hypothesis_metrics.items()],
                key=lambda x: x[1],
                reverse=True,
            )[:5],
        }

    def get_prompt_recommendations(self) -> Dict[str, Any]:
        """Get recommendations for prompt optimization"""
        if not self.hypothesis_metrics:
            return {"message": "Insufficient data for recommendations"}

        recommendations = []

        # Analyze hypothesis types
        for name, metrics in self.hypothesis_metrics.items():
            if metrics.total_generated < 5:
                continue

            # Low success rate - adjust temperature/prompt
            if metrics.success_rate < 0.3:
                recommendations.append(
                    {
                        "type": name,
                        "issue": "low_success_rate",
                        "current_rate": metrics.success_rate,
                        "recommendation": "Lower temperature for more precise hypotheses",
                    }
                )

            # High false positive rate
            elif metrics.success_rate > 0.8 and metrics.avg_initial_confidence < 0.5:
                recommendations.append(
                    {
                        "type": name,
                        "issue": "low_initial_confidence",
                        "recommendation": "Increase creative temperature to explore more",
                    }
                )

            # Good performance - confidence improving
            elif (
                metrics.success_rate > 0.6
                and (metrics.avg_final_confidence - metrics.avg_initial_confidence)
                > 0.2
            ):
                recommendations.append(
                    {
                        "type": name,
                        "issue": "good_performance",
                        "recommendation": "Current prompt strategy working well",
                    }
                )

        return {
            "recommendations": recommendations,
            "best_prompts": sorted(
                self.prompt_effectiveness.items(),
                key=lambda item: (
                    item[1].get("avg_success_rate", 0.0)
                    if isinstance(item[1], dict)
                    else float(item[1])
                    if isinstance(item[1], (int, float))
                    else 0.0
                ),
                reverse=True,
            )[:5],
        }

    def record_verification_layer_performance(
        self,
        layer_name: str,
        verified: bool,
        confidence: float,
        execution_time: float,
        is_true_positive: Optional[bool] = None,
    ):
        """
        Record performance of a verification layer

        Args:
            layer_name: Name of the verification layer
            verified: Whether the layer verified the hypothesis
            confidence: Confidence score from the layer
            execution_time: Time taken to execute the layer
            is_true_positive: Whether it was a true positive (if known)
        """
        if layer_name not in self.verification_layer_metrics:
            self.verification_layer_metrics[layer_name] = VerificationLayerMetrics(
                layer_name=layer_name,
                total_verifications=0,
                true_positives=0,
                false_positives=0,
                false_negatives=0,
                avg_confidence=0.0,
                avg_execution_time=0.0,
                accuracy=0.0,
                last_updated=datetime.now().isoformat(),
            )

        metrics = self.verification_layer_metrics[layer_name]

        # Update counts
        metrics.total_verifications += 1

        if is_true_positive is not None:
            if verified and is_true_positive:
                metrics.true_positives += 1
            elif verified and not is_true_positive:
                metrics.false_positives += 1
            elif not verified and is_true_positive:
                metrics.false_negatives += 1

        # Update averages
        n = metrics.total_verifications
        metrics.avg_confidence = (metrics.avg_confidence * (n - 1) + confidence) / n
        metrics.avg_execution_time = (
            metrics.avg_execution_time * (n - 1) + execution_time
        ) / n

        # Calculate accuracy
        if metrics.true_positives + metrics.false_positives > 0:
            metrics.accuracy = metrics.true_positives / (
                metrics.true_positives + metrics.false_positives
            )

        metrics.last_updated = datetime.now().isoformat()

        self.save_database()

    def get_optimal_layer_weights(self) -> Dict[str, float]:
        """
        Calculate optimal weights for verification layers based on historical accuracy

        Returns:
            Dictionary mapping layer names to weights (sum to 1.0)
        """
        if not self.verification_layer_metrics:
            # Return default weights if no history
            return {
                "static_analysis": 0.15,
                "symbolic_execution": 0.25,
                "dynamic_testing": 0.25,
                "behavioral_analysis": 0.15,
                "poc_execution": 0.20,
            }

        # Calculate weights based on accuracy
        weights = {}
        total_accuracy = 0.0

        for layer_name, metrics in self.verification_layer_metrics.items():
            if metrics.total_verifications >= 5:  # Need minimum data
                # Use accuracy as weight basis
                accuracy = metrics.accuracy if metrics.accuracy > 0 else 0.5
                weights[layer_name] = accuracy
                total_accuracy += accuracy

        # Normalize to sum to 1.0
        if total_accuracy > 0:
            weights = {k: v / total_accuracy for k, v in weights.items()}
        else:
            # Fall back to equal weights
            weights = {
                k: 1.0 / len(self.verification_layer_metrics)
                for k in self.verification_layer_metrics.keys()
            }

        return weights

    def get_verification_layer_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all verification layers"""
        return {
            name: {
                "total_verifications": metrics.total_verifications,
                "accuracy": metrics.accuracy,
                "avg_confidence": metrics.avg_confidence,
                "avg_execution_time": metrics.avg_execution_time,
                "true_positives": metrics.true_positives,
                "false_positives": metrics.false_positives,
                "last_updated": metrics.last_updated,
            }
            for name, metrics in self.verification_layer_metrics.items()
        }

    def suggest_improvements(self) -> List[str]:
        """Suggest improvements based on learning data"""
        suggestions = []

        # Analyze pattern effectiveness
        low_confidence_patterns = [
            name
            for name, stats in self.pattern_effectiveness.items()
            if stats.confidence_score < 0.5 and stats.times_detected > 5
        ]

        if low_confidence_patterns:
            suggestions.append(
                f"Consider tuning these patterns with high false positive rates: {', '.join(low_confidence_patterns[:3])}"
            )

        # Check accuracy trend
        if len(self.accuracy_history) >= 20:
            recent = sum(self.accuracy_history[-10:]) / 10
            older = sum(self.accuracy_history[-20:-10]) / 10

            if recent < older:
                suggestions.append(
                    "Detection accuracy has decreased recently. Consider reviewing recent pattern changes."
                )
            elif recent > older:
                suggestions.append(
                    f"Detection accuracy improving! Recent: {recent:.2%}, Previous: {older:.2%}"
                )

        # Check coverage
        if len(self.vulnerability_corpus) < 10:
            suggestions.append(
                f"Limited vulnerability corpus ({len(self.vulnerability_corpus)} types). Run more diverse analyses."
            )

        return suggestions

    def update_adaptive_learning_data(self, adaptive_state: Dict[str, Any]):
        """
        Update adaptive learning fields from AdaptiveLearningSystem
        NEW: Support for adaptive learning integration
        """
        if "prompt_performance" in adaptive_state:
            self.prompt_performance = adaptive_state["prompt_performance"]

        if "verification_weights" in adaptive_state:
            self.verification_weights = adaptive_state["verification_weights"]

        if "user_feedback_log" in adaptive_state:
            self.user_feedback_log = adaptive_state["user_feedback_log"]

        # Initialize hypothesis quality trends if not exists
        if (
            not hasattr(self, "hypothesis_quality_trends")
            or not self.hypothesis_quality_trends
        ):
            self.hypothesis_quality_trends = {
                "avg_confidence_over_time": [],
                "false_positive_rate_over_time": [],
            }

        # Calculate current metrics
        if self.hypothesis_metrics:
            total_hypotheses = sum(
                m.total_generated for m in self.hypothesis_metrics.values()
            )
            total_verified = sum(
                m.verified_count for m in self.hypothesis_metrics.values()
            )

            if total_hypotheses > 0:
                avg_confidence = (
                    sum(
                        m.avg_final_confidence * m.total_generated
                        for m in self.hypothesis_metrics.values()
                    )
                    / total_hypotheses
                )

                fp_rate = 1 - (total_verified / total_hypotheses)

                self.hypothesis_quality_trends["avg_confidence_over_time"].append(
                    avg_confidence
                )
                self.hypothesis_quality_trends["false_positive_rate_over_time"].append(
                    fp_rate
                )

        # Save to disk
        self.save_database()

    def get_adaptive_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive adaptive learning metrics
        NEW: Returns all adaptive learning data
        """
        return {
            "prompt_performance": self.prompt_performance,
            "verification_weights": self.verification_weights,
            "hypothesis_quality_trends": getattr(self, "hypothesis_quality_trends", {}),
            "user_feedback": {
                "total_feedback": len(self.user_feedback_log),
                "recent_feedback": self.user_feedback_log[-10:]
                if self.user_feedback_log
                else [],
            },
        }


# Global learning database instance
_global_learning_db = None


def get_learning_db() -> PersistentLearningDB:
    """Get or create the global learning database"""
    global _global_learning_db
    if _global_learning_db is None:
        _global_learning_db = PersistentLearningDB()
    return _global_learning_db


if __name__ == "__main__":
    # Demo the learning system
    print("=" * 70)
    print("PERSISTENT LEARNING SYSTEM - Demo")
    print("=" * 70)

    db = PersistentLearningDB("demo_learning.json")

    # Simulate some analyses
    for i in range(3):
        contract = f"contract Test{i} {{ function vulnerable() {{ }} }}"

        vulns = [
            {"name": "reentrancy", "severity": "high"},
            {"name": "overflow", "severity": "medium"},
        ]

        record = db.record_analysis(
            contract_code=contract,
            vulnerabilities_found=vulns,
            llm_insights=[f"Analysis {i} insight"],
            processing_time=1.5,
            user_feedback={"confirmed": 2, "false_positives": []} if i > 0 else None,
        )

        print(f"\n✓ Recorded analysis: {record.id}")

    # Show improvement
    metrics = db.get_improvement_metrics()
    print("\n📊 Improvement Metrics:")
    print(f"   Total scans: {metrics['total_scans']}")
    print(f"   Patterns learned: {metrics['total_patterns_learned']}")
    print(f"   Top pattern: {metrics['top_patterns'][0]['name']}")

    # Show enhanced prompt
    print("\n📝 Enhanced LLM Prompt (first 500 chars):")
    print(db.get_enhanced_llm_prompt()[:500])

    print("\n" + "=" * 70)
    print("✅ Learning system demonstrated!")
