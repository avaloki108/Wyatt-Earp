"""
AI-Powered Hypothesis Generation & Verification System
Integrates all components for end-to-end vulnerability discovery
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json

from .hypothesis_engine import (
    HypothesisEngine,
    HypothesisGenerationConfig,
)
from .prompt_orchestrator import PromptOrchestrator
from .verification_pipeline import VerificationPipeline
from .poc_generator import PoCGenerator, PoCFramework
from .persistent_learning import PersistentLearningDB, get_learning_db


@dataclass
class AnalysisReport:
    """Complete analysis report with hypothesis and verification"""

    contract_name: str
    contract_hash: str
    timestamp: str

    # Hypothesis generation
    hypotheses_generated: int
    creative_hypotheses: int
    refined_hypotheses: int
    cross_contract_hypotheses: int

    # Verification results
    verified_vulnerabilities: List[Dict[str, Any]]
    rejected_hypotheses: List[Dict[str, Any]]
    uncertain_findings: List[Dict[str, Any]]

    # PoC generation
    pocs_generated: int
    pocs_executed: int

    # Confidence metrics
    avg_initial_confidence: float
    avg_final_confidence: float
    confidence_improvement: float

    # Performance
    total_processing_time: float

    # Recommendations
    recommendations: List[str]

    # Learning insights
    patterns_learned: List[str]
    prompt_optimizations: List[str]


class AIHypothesisSystem:
    """
    Complete AI-powered hypothesis generation and verification system
    Orchestrates the entire pipeline from creative exploration to PoC generation
    """

    def __init__(
        self,
        llm_client=None,
        symbolic_executor=None,
        enable_poc_generation: bool = True,
        enable_learning: bool = True,
    ):
        """
        Initialize the AI hypothesis system

        Args:
            llm_client: LLM client for hypothesis generation (optional)
            symbolic_executor: Symbolic execution engine (optional)
            enable_poc_generation: Whether to generate PoCs
            enable_learning: Whether to use persistent learning
        """
        # Core components
        self.hypothesis_engine = HypothesisEngine(
            llm_client=llm_client, config=HypothesisGenerationConfig()
        )

        self.prompt_orchestrator = PromptOrchestrator(llm_client=llm_client)

        self.verification_pipeline = VerificationPipeline(
            symbolic_executor=symbolic_executor
        )

        self.poc_generator: Optional[PoCGenerator] = None
        if enable_poc_generation:
            self.poc_generator = PoCGenerator(framework=PoCFramework.FOUNDRY)

        self.learning_db: Optional[PersistentLearningDB] = None
        if enable_learning:
            self.learning_db = get_learning_db()

        # Configuration
        self.llm_client = llm_client
        self.analysis_history: List[AnalysisReport] = []

    def analyze_contract(
        self,
        contract_code: str,
        contract_name: str = "Contract",
        contract_type: str = "unknown",
        static_analysis_results: Optional[Dict[str, Any]] = None,
        generate_pocs: bool = False,
    ) -> AnalysisReport:
        """
        Complete end-to-end analysis of a contract

        Returns:
            AnalysisReport with all findings and metrics
        """
        start_time = datetime.now()

        print("=" * 70)
        print(f"AI HYPOTHESIS SYSTEM - Analyzing {contract_name}")
        print("=" * 70)

        # Stage 1: Hypothesis Generation
        print("\n[Stage 1] Generating vulnerability hypotheses...")
        hypotheses = self.hypothesis_engine.generate_hypotheses(
            contract_code=contract_code,
            contract_type=contract_type,
            static_analysis_results=static_analysis_results,
        )

        print(f"✓ Generated {len(hypotheses)} hypotheses")

        # Stage 2: Hypothesis Verification
        print("\n[Stage 2] Verifying hypotheses through multi-layer pipeline...")
        verification_results = []
        for i, hypothesis in enumerate(hypotheses, 1):
            print(
                f"  Verifying hypothesis {i}/{len(hypotheses)}: {hypothesis.description[:60]}..."
            )
            result = self.verification_pipeline.verify_hypothesis(
                hypothesis=hypothesis, contract_code=contract_code, run_all_layers=True
            )
            verification_results.append(result)

            # Update hypothesis with verification results
            hypothesis.verification_status = result.verification_status
            hypothesis.final_confidence = result.final_confidence

        # Categorize results
        verified = [
            (h, r)
            for h, r in zip(hypotheses, verification_results)
            if r.verification_status == "verified"
        ]
        rejected = [
            (h, r)
            for h, r in zip(hypotheses, verification_results)
            if r.verification_status == "rejected"
        ]
        uncertain = [
            (h, r)
            for h, r in zip(hypotheses, verification_results)
            if r.verification_status == "uncertain"
        ]

        print(
            f"✓ Verification complete: {len(verified)} verified, {len(rejected)} rejected, {len(uncertain)} uncertain"
        )

        # Stage 3: PoC Generation (for verified vulnerabilities)
        pocs_generated = 0
        pocs_executed = 0

        if generate_pocs and self.poc_generator and verified:
            print("\n[Stage 3] Generating proof-of-concept exploits...")
            for hypothesis, _ in verified:
                poc_result = self.poc_generator.generate_and_execute(
                    hypothesis=hypothesis,
                    contract_code=contract_code,
                    contract_name=contract_name,
                    execute=False,  # Don't execute by default for safety
                )

                if poc_result.get("poc_code"):
                    pocs_generated += 1
                    hypothesis.poc_generated = True

                    if poc_result.get("success"):
                        pocs_executed += 1

            print(f"✓ Generated {pocs_generated} PoCs")

        # Stage 4: Learning and Optimization
        if self.learning_db:
            print("\n[Stage 4] Recording learnings...")

            # Track hypothesis quality
            for hypothesis, result in zip(hypotheses, verification_results):
                self.learning_db.track_hypothesis_quality(
                    hypothesis_type=hypothesis.type.value,
                    initial_confidence=hypothesis.confidence,
                    final_confidence=result.final_confidence,
                    verified=(result.verification_status == "verified"),
                )

            # Record analysis
            vulnerabilities_found = [
                {
                    "name": h.type.value,
                    "description": h.description,
                    "severity": r.severity_adjusted,
                    "confidence": r.final_confidence,
                    "type": h.type.value,
                    "detection_strategy": "ai_hypothesis",
                }
                for h, r in verified
            ]

            self.learning_db.record_analysis(
                contract_code=contract_code,
                vulnerabilities_found=vulnerabilities_found,
                llm_insights=[h.description for h, _ in verified[:5]],
                processing_time=(datetime.now() - start_time).total_seconds(),
            )

            print("✓ Learnings recorded")

        # Calculate metrics
        initial_confidences = [h.confidence for h in hypotheses]
        final_confidences = [r.final_confidence for r in verification_results]

        avg_initial = (
            sum(initial_confidences) / len(initial_confidences)
            if initial_confidences
            else 0
        )
        avg_final = (
            sum(final_confidences) / len(final_confidences) if final_confidences else 0
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(verified, uncertain, rejected)

        # Create report
        report = AnalysisReport(
            contract_name=contract_name,
            contract_hash=self._hash_contract(contract_code),
            timestamp=datetime.now().isoformat(),
            hypotheses_generated=len(hypotheses),
            creative_hypotheses=len(
                [h for h in hypotheses if h.generated_by.startswith("creative")]
            ),
            refined_hypotheses=len(
                [h for h in hypotheses if h.generated_by.startswith("refinement")]
            ),
            cross_contract_hypotheses=len(
                [h for h in hypotheses if h.generated_by.startswith("cross_contract")]
            ),
            verified_vulnerabilities=self._format_verified(verified),
            rejected_hypotheses=self._format_rejected(rejected),
            uncertain_findings=self._format_uncertain(uncertain),
            pocs_generated=pocs_generated,
            pocs_executed=pocs_executed,
            avg_initial_confidence=avg_initial,
            avg_final_confidence=avg_final,
            confidence_improvement=avg_final - avg_initial,
            total_processing_time=(datetime.now() - start_time).total_seconds(),
            recommendations=recommendations,
            patterns_learned=self._extract_patterns_learned(verified),
            prompt_optimizations=self._get_prompt_optimizations(),
        )

        self.analysis_history.append(report)

        # Print summary
        self._print_summary(report)

        return report

    def _format_verified(self, verified: List[tuple]) -> List[Dict[str, Any]]:
        """Format verified vulnerabilities for report"""
        return [
            {
                "id": h.id,
                "type": h.type.value,
                "description": h.description,
                "severity": r.severity_adjusted,
                "confidence": r.final_confidence,
                "attack_scenario": h.attack_scenario,
                "affected_functions": h.affected_functions,
                "verification_layers": {
                    layer.value: {
                        "verified": result.verified,
                        "confidence": result.confidence,
                        "evidence": result.evidence[:3],  # Limit evidence
                    }
                    for layer, result in r.layer_results.items()
                },
                "poc_generated": h.poc_generated,
                "recommendation": r.recommendation,
            }
            for h, r in verified
        ]

    def _format_rejected(self, rejected: List[tuple]) -> List[Dict[str, Any]]:
        """Format rejected hypotheses for report"""
        return [
            {
                "id": h.id,
                "type": h.type.value,
                "description": h.description,
                "initial_confidence": h.confidence,
                "final_confidence": r.final_confidence,
                "reason": r.recommendation,
            }
            for h, r in rejected
        ]

    def _format_uncertain(self, uncertain: List[tuple]) -> List[Dict[str, Any]]:
        """Format uncertain findings for report"""
        return [
            {
                "id": h.id,
                "type": h.type.value,
                "description": h.description,
                "confidence": r.final_confidence,
                "recommendation": r.recommendation,
            }
            for h, r in uncertain
        ]

    def _generate_recommendations(
        self, verified: List[tuple], uncertain: List[tuple], rejected: List[tuple]
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        if verified:
            recommendations.append(
                f"CRITICAL: {len(verified)} verified vulnerabilities require immediate attention"
            )

            # Group by severity
            critical = [h for h, r in verified if r.severity_adjusted == "critical"]
            high = [h for h, r in verified if r.severity_adjusted == "high"]

            if critical:
                recommendations.append(
                    f"• {len(critical)} CRITICAL severity issues - prioritize remediation"
                )
            if high:
                recommendations.append(
                    f"• {len(high)} HIGH severity issues - address soon"
                )

        if uncertain:
            recommendations.append(
                f"REVIEW REQUIRED: {len(uncertain)} findings need manual verification"
            )

        if not verified and not uncertain:
            recommendations.append(
                "✓ No high-confidence vulnerabilities detected. Contract appears secure."
            )

        # Learning-based recommendations
        if self.learning_db:
            learning_suggestions = self.learning_db.suggest_improvements()
            recommendations.extend(learning_suggestions[:3])

        return recommendations

    def _extract_patterns_learned(self, verified: List[tuple]) -> List[str]:
        """Extract patterns learned from this analysis"""
        patterns = []

        for hypothesis, _ in verified:
            pattern = f"{hypothesis.type.value}: {hypothesis.description[:80]}"
            patterns.append(pattern)

        return patterns[:5]  # Top 5 patterns

    def _get_prompt_optimizations(self) -> List[str]:
        """Get prompt optimization suggestions"""
        if not self.learning_db:
            return []

        recommendations = self.learning_db.get_prompt_recommendations()

        return [
            f"{rec['type']}: {rec['recommendation']}"
            for rec in recommendations.get("recommendations", [])[:3]
        ]

    def _hash_contract(self, contract_code: str) -> str:
        """Generate hash for contract"""
        import hashlib

        return hashlib.sha256(contract_code.encode()).hexdigest()[:16]

    def _print_summary(self, report: AnalysisReport):
        """Print analysis summary"""
        print("\n" + "=" * 70)
        print("ANALYSIS SUMMARY")
        print("=" * 70)

        print(f"\nContract: {report.contract_name}")
        print(f"Timestamp: {report.timestamp}")
        print(f"Processing Time: {report.total_processing_time:.2f}s")

        print("\nHypothesis Generation:")
        print(f"  Total: {report.hypotheses_generated}")
        print(f"  Creative: {report.creative_hypotheses}")
        print(f"  Refined: {report.refined_hypotheses}")
        print(f"  Cross-Contract: {report.cross_contract_hypotheses}")

        print("\nVerification Results:")
        print(f"  ✓ Verified: {len(report.verified_vulnerabilities)}")
        print(f"  ? Uncertain: {len(report.uncertain_findings)}")
        print(f"  ✗ Rejected: {len(report.rejected_hypotheses)}")

        if report.pocs_generated > 0:
            print("\nPoC Generation:")
            print(f"  Generated: {report.pocs_generated}")
            print(f"  Executed: {report.pocs_executed}")

        print("\nConfidence Metrics:")
        print(f"  Initial Avg: {report.avg_initial_confidence:.2f}")
        print(f"  Final Avg: {report.avg_final_confidence:.2f}")
        print(f"  Improvement: {report.confidence_improvement:+.2f}")

        if report.verified_vulnerabilities:
            print("\nVerified Vulnerabilities:")
            for i, vuln in enumerate(report.verified_vulnerabilities[:5], 1):
                print(f"  {i}. [{vuln['severity'].upper()}] {vuln['type']}")
                print(f"     {vuln['description'][:70]}...")
                print(f"     Confidence: {vuln['confidence']:.2f}")

        if report.recommendations:
            print("\nRecommendations:")
            for rec in report.recommendations[:5]:
                print(f"  • {rec}")

        print("\n" + "=" * 70)

    def export_report(
        self, report: AnalysisReport, filepath: str, format: str = "json"
    ):
        """Export analysis report to file"""
        if format == "json":
            with open(filepath, "w") as f:
                json.dump(asdict(report), f, indent=2)
        elif format == "markdown":
            self._export_markdown(report, filepath)

        print(f"✓ Report exported to {filepath}")

    def _export_markdown(self, report: AnalysisReport, filepath: str):
        """Export report as markdown"""
        md = f"""# Vulnerability Analysis Report

**Contract:** {report.contract_name}
**Date:** {report.timestamp}
**Processing Time:** {report.total_processing_time:.2f}s

## Executive Summary

- **Hypotheses Generated:** {report.hypotheses_generated}
- **Verified Vulnerabilities:** {len(report.verified_vulnerabilities)}
- **Uncertain Findings:** {len(report.uncertain_findings)}
- **PoCs Generated:** {report.pocs_generated}

## Verified Vulnerabilities

"""
        for i, vuln in enumerate(report.verified_vulnerabilities, 1):
            md += f"""### {i}. {vuln["type"]} - {vuln["severity"].upper()}

**Description:** {vuln["description"]}

**Attack Scenario:** {vuln["attack_scenario"]}

**Confidence:** {vuln["confidence"]:.2f}

**Affected Functions:** {", ".join(vuln["affected_functions"])}

**Recommendation:** {vuln["recommendation"]}

---

"""

        md += """## Recommendations

"""
        for rec in report.recommendations:
            md += f"- {rec}\n"

        md += f"""
## Metrics

- **Average Initial Confidence:** {report.avg_initial_confidence:.2f}
- **Average Final Confidence:** {report.avg_final_confidence:.2f}
- **Confidence Improvement:** {report.confidence_improvement:+.2f}

"""

        with open(filepath, "w") as f:
            f.write(md)

    def get_system_statistics(self) -> Dict[str, Any]:
        """Get overall system statistics"""
        stats = {
            "total_analyses": len(self.analysis_history),
            "hypothesis_engine": self.hypothesis_engine.get_hypothesis_stats(),
            "prompt_orchestrator": self.prompt_orchestrator.get_prompt_statistics(),
            "verification_pipeline": self.verification_pipeline.get_verification_stats(),
        }

        if self.poc_generator:
            stats["poc_generator"] = self.poc_generator.get_poc_stats()

        if self.learning_db:
            stats["learning_system"] = {
                "improvement_metrics": self.learning_db.get_improvement_metrics(),
                "hypothesis_quality": self.learning_db.get_hypothesis_quality_report(),
            }

        return stats

    def optimize_system(self):
        """Optimize system based on historical performance"""
        if not self.learning_db:
            print("Learning database not enabled - cannot optimize")
            return

        print("\n" + "=" * 70)
        print("SYSTEM OPTIMIZATION")
        print("=" * 70)

        # Get recommendations
        prompt_recs = self.learning_db.get_prompt_recommendations()

        print("\nPrompt Optimization Recommendations:")
        for rec in prompt_recs.get("recommendations", []):
            print(f"  • {rec['type']}: {rec['recommendation']}")

        # Update weights if needed
        hypothesis_quality = self.learning_db.get_hypothesis_quality_report()

        if hypothesis_quality.get("total_hypotheses_generated", 0) > 20:
            success_rate = hypothesis_quality.get("overall_success_rate", 0)

            if success_rate < 0.3:
                print("\n⚠ Low hypothesis success rate - adjusting generation config")
                self.hypothesis_engine.config.creative_temperature = max(
                    0.3, self.hypothesis_engine.config.creative_temperature - 0.1
                )
            elif success_rate > 0.7:
                print("\n✓ High hypothesis success rate - can increase creativity")
                self.hypothesis_engine.config.creative_temperature = min(
                    0.95, self.hypothesis_engine.config.creative_temperature + 0.05
                )

        print("\n✓ System optimization complete")
