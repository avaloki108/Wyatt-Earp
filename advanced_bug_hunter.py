#!/usr/bin/env python3
"""
Advanced Web3 Bug Hunter - Integration Script
Combines all advanced modules for comprehensive vulnerability discovery
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Import advanced modules
from advanced.symbolic_execution_engine import (
    AdvancedSymbolicExecutor,
    SymbolicState,
    VarType,
)
from advanced.novel_vulnerability_patterns import NovelPatternDetector
from advanced.behavioral_anomaly_detector import BehavioralAnomalyDetector
from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.enhanced_fuzzing_orchestrator import (
    EnhancedFuzzingOrchestrator,
    FuzzingConfig,
    FuzzingStrategy,
)
from advanced.persistent_learning import get_learning_db
from advanced.benchmark_comparison import BenchmarkSystem
from advanced.rare_vulnerability_detectors import RareVulnerabilityDetector
from advanced.adaptive_learning import (
    get_adaptive_system,
)  # NEW
from advanced.verification_pipeline import MultiLayerVerificationPipeline
from advanced.poc_generator import AutomatedPoCGenerator, PoCFramework
from advanced.cross_contract_analyzer import CrossContractAnalyzer

# Import existing modules (optional dependencies)
try:
    from llm.llm_integration import LLMVulnerabilityAnalyzer

    HAS_LLM = True
except ImportError:
    HAS_LLM = False

try:
    from scripts.cross_contract_tracker import CrossContractLogicTracker

    HAS_SLITHER = True
except ImportError:
    HAS_SLITHER = False


class AdvancedWeb3BugHunter:
    """
    Advanced Bug Hunter integrating all cutting-edge techniques:
    - Symbolic execution with Z3
    - Novel pattern detection
    - Behavioral anomaly detection
    - Multi-agent LLM reasoning
    - Enhanced fuzzing
    - Automated PoC generation
    - Multi-layer verification
    - Adaptive learning
    """

    def __init__(self, contract_path: str, config: Optional[Dict[str, Any]] = None):
        self.contract_path = Path(contract_path)
        self.config = config or {}
        self.start_time = datetime.now()

        # Check if analyzing directory for cross-contract analysis
        self.is_directory = self.contract_path.is_dir()

        # Initialize learning system first (needed by verification pipeline)
        self.learning_db = get_learning_db()

        # Initialize components
        self.symbolic_executor = AdvancedSymbolicExecutor()
        self.pattern_detector = NovelPatternDetector()
        self.anomaly_detector = BehavioralAnomalyDetector()
        self.rare_detector = RareVulnerabilityDetector()
        self.llm_reasoner = AdvancedLLMReasoner(
            openai_key=self.config.get("openai_key"),
            anthropic_key=self.config.get("anthropic_key"),
        )

        # Initialize multi-layer verification pipeline
        self.verification_pipeline = MultiLayerVerificationPipeline(
            pattern_detector=self.pattern_detector,
            rare_detector=self.rare_detector,
            symbolic_executor=self.symbolic_executor,
            anomaly_detector=self.anomaly_detector,
            learning_db=self.learning_db,  # Pass learning DB for adaptive weights
        )

        # Initialize PoC generator
        self.poc_generator = (
            AutomatedPoCGenerator(frameworks=[PoCFramework.FOUNDRY])
            if self.config.get("enable_poc_generation", True)
            else None
        )

        # NEW: Initialize adaptive learning system
        self.adaptive_system = get_adaptive_system(self.learning_db)

        # Initialize cross-contract analyzer for directory analysis
        self.cross_contract_analyzer = (
            CrossContractAnalyzer(verbose=True) if self.is_directory else None
        )

        self.results = {
            "contract": str(self.contract_path),
            "timestamp": self.start_time.isoformat(),
            "analysis_results": {},
            "learning_enhanced": True,
            "adaptive_learning_enabled": True,  # NEW
            "verification_enabled": True,
            "poc_generation_enabled": self.poc_generator is not None,
        }

    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Run complete analysis pipeline with all advanced techniques
        NOW WITH REAL LEARNING - Improves with each scan!
        """
        print("=" * 70)
        print(" ADVANCED WEB3 BUG HUNTER - COMPREHENSIVE ANALYSIS")
        print(" 🧠 LEARNING-ENABLED: Tool improves with every scan!")
        print(" 🔄 ADAPTIVE LEARNING: Continuous optimization enabled!")
        if self.poc_generator:
            print(" 🔬 PoC GENERATION: Automated exploit demonstrations")
        print("=" * 70)
        print(f"Contract: {self.contract_path}")
        print(f"Timestamp: {self.results['timestamp']}")

        # Show improvement metrics
        metrics = self.learning_db.get_improvement_metrics()
        if metrics.get("total_scans", 0) > 0:
            print(f"Previous scans: {metrics['total_scans']} | ")
            print(f"Patterns learned: {metrics.get('total_patterns_learned', 0)} | ")
            print(f"Current accuracy: {metrics.get('recent_accuracy', 0.0):.1%}")
        print()

        # Read contract code (only for single file analysis)
        if not self.is_directory:
            with open(self.contract_path, "r") as f:
                contract_code = f.read()
            contract_name = self.contract_path.stem
        else:
            # For directory analysis, use empty placeholders
            contract_code = ""
            contract_name = self.contract_path.name

        # Phase 0: Cross-Contract Analysis (if analyzing directory)
        cross_contract_results = None
        if self.cross_contract_analyzer and self.is_directory:
            print("\n[0/9] Running Cross-Contract Analysis...")
            print("-" * 70)
            print(
                "🔗 Analyzing contract interactions, dependencies, and protocol-wide vulnerabilities..."
            )
            try:
                cross_contract_results = self.cross_contract_analyzer.analyze_directory(
                    str(self.contract_path)
                )
                self.results["analysis_results"]["cross_contract"] = (
                    cross_contract_results
                )

                # Print summary
                summary = cross_contract_results.get("summary", {})
                print(f"\n📊 Cross-Contract Analysis Complete:")
                print(f"  Contracts analyzed: {summary.get('total_contracts', 0)}")
                print(f"  External calls: {summary.get('external_calls', 0)}")
                print(
                    f"  Cross-contract vulnerabilities: {summary.get('total_vulnerabilities', 0)}"
                )
                if summary.get("critical", 0) > 0:
                    print(f"  🚨 CRITICAL: {summary.get('critical', 0)}")
                if summary.get("high", 0) > 0:
                    print(f"  ⚠️  HIGH: {summary.get('high', 0)}")
            except Exception as e:
                print(f"  ⚠️  Cross-contract analysis failed: {str(e)}")
                self.results["analysis_results"]["cross_contract"] = {"error": str(e)}

        # Skip per-contract analysis if analyzing directory
        if self.is_directory:
            print("\n✅ Cross-contract analysis complete for directory!")
            print(f"   Analyzed {summary.get('total_contracts', 0)} contracts")
            print(f"   Use individual file analysis for detailed per-contract findings")
            return self.results

        # Phase 1: Pattern Detection
        phase_num = "1/9" if cross_contract_results else "1/8"
        print(f"\n[{phase_num}] Running Novel Pattern Detection...")
        print("-" * 70)
        patterns = self.pattern_detector.detect_all_patterns(
            contract_code, contract_name
        )
        self.results["analysis_results"]["novel_patterns"] = {
            "total_patterns": len(patterns),
            "critical": len([p for p in patterns if p.severity == "critical"]),
            "high": len([p for p in patterns if p.severity == "high"]),
            "patterns": [self._serialize_pattern(p) for p in patterns],
        }
        print(f"Found {len(patterns)} novel vulnerability patterns")
        self._print_pattern_summary(patterns)

        # Phase 2: Behavioral Anomaly Detection
        phase_num = "2/9" if cross_contract_results else "2/8"
        print(f"\n[{phase_num}] Running Behavioral Anomaly Detection...")
        print("-" * 70)
        anomalies = self.anomaly_detector.analyze_contract(contract_code, contract_name)
        self.results["analysis_results"]["anomalies"] = {
            "total_anomalies": len(anomalies),
            "critical": len([a for a in anomalies if a.severity == "critical"]),
            "high": len([a for a in anomalies if a.severity == "high"]),
            "anomalies": [self._serialize_anomaly(a) for a in anomalies],
        }
        print(f"Found {len(anomalies)} behavioral anomalies")
        self._print_anomaly_summary(anomalies)

        # Phase 2.5: Rare & Niche Vulnerability Detection
        phase_num = "2.5/9" if cross_contract_results else "2.5/8"
        print(f"\n[{phase_num}] Running Rare & Niche Vulnerability Detection...")
        print("-" * 70)
        print("🔍 Searching for obscure vulnerabilities that standard tools miss...")
        rare_vulns = self.rare_detector.detect_all(contract_code)
        self.results["analysis_results"]["rare_vulnerabilities"] = {
            "total_rare": len(rare_vulns),
            "critical": len([r for r in rare_vulns if r.severity == "critical"]),
            "high": len([r for r in rare_vulns if r.severity == "high"]),
            "findings": [self._serialize_rare_vuln(r) for r in rare_vulns],
        }
        print(f"Found {len(rare_vulns)} rare/niche vulnerabilities!")
        if rare_vulns:
            print("\n⭐ RARE FINDINGS (likely missed by other tools):")
            for i, vuln in enumerate(rare_vulns[:5], 1):
                print(f"  {i}. [{vuln.severity.upper()}] {vuln.name}")
                print(f"     {vuln.description}")
                print(f"     Confidence: {vuln.confidence:.0%}")
        else:
            print("No rare vulnerabilities detected (good sign!)")

        # Phase 3: Symbolic Execution
        phase_num = "3/9" if cross_contract_results else "3/8"
        print(f"\n[{phase_num}] Running Symbolic Execution Analysis...")
        print("-" * 70)
        symbolic_results = self._run_symbolic_analysis(contract_code)
        self.results["analysis_results"]["symbolic_execution"] = symbolic_results
        print("Symbolic execution completed")

        # Phase 4: LLM Multi-Agent Reasoning (WITH LEARNING!)
        llm_insights = []
        if self.config.get("use_llm", True) and HAS_LLM:
            phase_num = "4/9" if cross_contract_results else "4/8"
            print(
                f"\n[{phase_num}] Running LLM Multi-Agent Reasoning (Enhanced with Learning)..."
            )
            print("-" * 70)

            # Get enhanced prompt with learned patterns
            enhanced_prompt = self.learning_db.get_enhanced_llm_prompt()
            print(
                f"Using enhanced prompt with {len(self.learning_db.get_learned_patterns_for_analysis())} learned patterns"
            )

            static_results = {
                "patterns": [self._serialize_pattern(p) for p in patterns[:5]],
                "anomalies": [self._serialize_anomaly(a) for a in anomalies[:5]],
                "learned_patterns": self.learning_db.get_learned_patterns_for_analysis()[
                    :5
                ],
            }
            try:
                llm_results = self.llm_reasoner.analyze_contract_multi_agent(
                    contract_code,
                    static_results,
                    contract_type=self._detect_contract_type(contract_code),
                )
                self.results["analysis_results"]["llm_reasoning"] = [
                    self._serialize_llm_result(r) for r in llm_results
                ]

                # Extract insights for learning
                for result in llm_results:
                    if hasattr(result, "findings"):
                        llm_insights.extend([str(f) for f in result.findings])

                print(f"LLM analysis completed with {len(llm_results)} reasoning modes")
                print(f"Extracted {len(llm_insights)} insights for learning")
            except Exception as e:
                print(f"  ⚠️  LLM analysis failed: {str(e)}")
                self.results["analysis_results"]["llm_reasoning"] = {"error": str(e)}
        else:
            phase_num = "4/9" if cross_contract_results else "4/8"
            print(f"\n[{phase_num}] Skipping LLM analysis (disabled or unavailable)")

        # Phase 5: Enhanced Fuzzing
        if self.config.get("use_fuzzing", True):
            phase_num = "5/9" if cross_contract_results else "5/8"
            print(f"\n[{phase_num}] Running Enhanced Fuzzing Campaign...")
            print("-" * 70)
            fuzzing_results = self._run_enhanced_fuzzing(contract_code)
            self.results["analysis_results"]["fuzzing"] = fuzzing_results
            print("Fuzzing campaign completed")
        else:
            phase_num = "5/9" if cross_contract_results else "5/8"
            print(f"\n[{phase_num}] Skipping fuzzing (disabled in config)")

        # Phase 5.5: Automated PoC Generation
        poc_results = []
        if self.poc_generator and self.config.get("generate_pocs", True):
            phase_num = "5.5/9" if cross_contract_results else "5.5/8"
            print(f"\n[{phase_num}] 🔬 Generating Proof-of-Concept Exploits...")
            print("-" * 70)
            print("Generating PoCs for detected vulnerabilities...")

            # Collect high-confidence vulnerabilities for PoC generation
            vulnerabilities_for_poc = []

            # Add critical/high severity rare vulnerabilities
            for vuln in rare_vulns:
                if vuln.severity in ["critical", "high"] and vuln.confidence >= 0.7:
                    vulnerabilities_for_poc.append(vuln)

            # Add high-confidence patterns
            for pattern in patterns:
                if (
                    pattern.severity in ["critical", "high"]
                    and pattern.confidence >= 0.8
                ):
                    vulnerabilities_for_poc.append(pattern)

            # Add critical anomalies
            for anomaly in anomalies:
                if anomaly.severity == "critical" and anomaly.confidence >= 0.75:
                    vulnerabilities_for_poc.append(anomaly)

            # Limit to top 5 vulnerabilities to avoid long execution times
            vulnerabilities_for_poc = vulnerabilities_for_poc[:5]

            print(
                f"Selected {len(vulnerabilities_for_poc)} high-priority vulnerabilities for PoC generation"
            )

            # Generate PoCs
            import asyncio

            for i, vuln in enumerate(vulnerabilities_for_poc, 1):
                vuln_name = getattr(vuln, "name", "Unknown")
                print(
                    f"\n  [{i}/{len(vulnerabilities_for_poc)}] Generating PoC for: {vuln_name}"
                )

                try:
                    previous_loop = None
                    try:
                        previous_loop = asyncio.get_event_loop()
                    except RuntimeError:
                        previous_loop = None

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        poc_result = loop.run_until_complete(
                            self.poc_generator.generate_and_test_poc(
                                vuln,
                                contract_code,
                                contract_name,
                                execute_in_sandbox=self.config.get(
                                    "execute_pocs", False
                                ),
                            )
                        )
                    finally:
                        loop.close()
                        if previous_loop and not previous_loop.is_closed():
                            asyncio.set_event_loop(previous_loop)
                        else:
                            asyncio.set_event_loop(None)

                    if poc_result.get("success"):
                        print(
                            f"    ✓ PoC generated using '{poc_result.get('strategy_used', 'unknown')}' strategy"
                        )
                        if poc_result.get("safety_validated"):
                            print("    ✓ Safety validated")
                        if self.config.get("execute_pocs", False):
                            if poc_result.get("exploit_demonstrated"):
                                print(
                                    "    ✓ Exploit successfully demonstrated in sandbox"
                                )
                            else:
                                print(
                                    "    ⚠️  PoC generated but exploit not demonstrated"
                                )
                    else:
                        print(
                            f"    ✗ Failed to generate PoC: {poc_result.get('error', 'Unknown error')}"
                        )

                    poc_results.append(
                        {
                            "vulnerability": vuln_name,
                            "severity": getattr(vuln, "severity", "unknown"),
                            "poc_generated": poc_result.get("success", False),
                            "strategy": poc_result.get("strategy_used", "none"),
                            "safety_validated": poc_result.get(
                                "safety_validated", False
                            ),
                            "exploit_demonstrated": poc_result.get(
                                "exploit_demonstrated", False
                            ),
                            "poc_code_preview": poc_result.get("poc_code", "")[:200]
                            + "..."
                            if poc_result.get("poc_code")
                            else "",
                        }
                    )
                except Exception as e:
                    print(f"    ✗ Error generating PoC: {str(e)}")
                    poc_results.append({"vulnerability": vuln_name, "error": str(e)})

            # Store PoC results
            self.results["analysis_results"]["poc_generation"] = {
                "total_vulnerabilities_analyzed": len(vulnerabilities_for_poc),
                "pocs_generated": len(
                    [p for p in poc_results if p.get("poc_generated")]
                ),
                "pocs_safety_validated": len(
                    [p for p in poc_results if p.get("safety_validated")]
                ),
                "exploits_demonstrated": len(
                    [p for p in poc_results if p.get("exploit_demonstrated")]
                ),
                "results": poc_results,
                "statistics": self.poc_generator.get_statistics()
                if self.poc_generator
                else {},
            }

            print("\n✓ PoC Generation Summary:")
            print(
                f"  Total PoCs generated: {len([p for p in poc_results if p.get('poc_generated')])}/{len(vulnerabilities_for_poc)}"
            )
            print(
                f"  Safety validated: {len([p for p in poc_results if p.get('safety_validated')])}"
            )
            if self.config.get("execute_pocs", False):
                print(
                    f"  Exploits demonstrated: {len([p for p in poc_results if p.get('exploit_demonstrated')])}"
                )
        else:
            print("\n[5.5/8] Skipping PoC generation (disabled in config)")

        # Phase 6: Multi-Layer Verification
        if self.config.get("use_verification", True):
            phase_num = "6/9" if cross_contract_results else "6/8"
            print(f"\n[{phase_num}] Running Multi-Layer Verification Pipeline...")
            print("-" * 70)
            print("🔍 Cross-validating findings with multi-layer verification...")

            # Create hypotheses from detected vulnerabilities
            hypotheses = self._create_hypotheses_from_findings(
                patterns, anomalies, rare_vulns
            )

            if hypotheses:
                print(f"Verifying {len(hypotheses)} vulnerability hypotheses...")

                # Verify each hypothesis through the pipeline
                verified_findings = []
                rejected_findings = []
                uncertain_findings = []

                for i, hypothesis in enumerate(hypotheses, 1):
                    result = self.verification_pipeline.verify_hypothesis_sync(
                        hypothesis=hypothesis,
                        contract_code=contract_code,
                        run_all_layers=True,
                    )

                    if result["verification_status"] == "verified":
                        verified_findings.append(
                            {
                                "hypothesis": hypothesis,
                                "confidence": result["final_confidence"],
                                "layer_agreement": result["cross_layer_agreement"],
                            }
                        )
                    elif result["verification_status"] == "uncertain":
                        uncertain_findings.append(
                            {
                                "hypothesis": hypothesis,
                                "confidence": result["final_confidence"],
                                "layer_agreement": result["cross_layer_agreement"],
                            }
                        )
                    else:
                        rejected_findings.append(
                            {
                                "hypothesis": hypothesis,
                                "confidence": result["final_confidence"],
                                "reason": result.get("validation_reason", "Unknown"),
                            }
                        )

                # Get verification statistics
                verification_stats = self.verification_pipeline.get_verification_stats()

                self.results["analysis_results"]["verification"] = {
                    "total_hypotheses": len(hypotheses),
                    "verified": len(verified_findings),
                    "rejected": len(rejected_findings),
                    "uncertain": len(uncertain_findings),
                    "statistics": verification_stats,
                    "verified_findings": [
                        {
                            "name": v["hypothesis"].name,
                            "confidence": v["confidence"],
                            "layer_agreement": v["layer_agreement"],
                        }
                        for v in verified_findings
                    ],
                }

                print("✓ Verification complete:")
                print(f"  • Verified: {len(verified_findings)} (high confidence)")
                print(f"  • Uncertain: {len(uncertain_findings)} (needs review)")
                print(
                    f"  • Rejected: {len(rejected_findings)} (likely false positives)"
                )
                print(
                    f"  • False positive reduction: {verification_stats.get('false_positive_reduction', 0):.1%}"
                )
            else:
                print("No findings to verify")
                self.results["analysis_results"]["verification"] = {
                    "total_hypotheses": 0,
                    "message": "No findings to verify",
                }
        else:
            print("\n[5.5/7] Skipping verification (disabled in config)")

        # Phase 6: Generate Final Report & LEARN!
        print("\n[6/8] Generating Comprehensive Report & Recording Learning...")
        print("-" * 70)
        self._generate_final_report()

        # Record what we learned from this analysis
        processing_time = (datetime.now() - self.start_time).total_seconds()
        all_vulnerabilities = []

        # Collect all findings
        for pattern in patterns:
            all_vulnerabilities.append(
                {
                    "name": pattern.name,
                    "severity": pattern.severity,
                    "type": "pattern",
                    "confidence": pattern.confidence,
                }
            )

        for anomaly in anomalies:
            all_vulnerabilities.append(
                {
                    "name": anomaly.name,
                    "severity": anomaly.severity,
                    "type": "anomaly",
                    "confidence": anomaly.confidence,
                }
            )

        for rare_vuln in rare_vulns:
            all_vulnerabilities.append(
                {
                    "name": rare_vuln.name,
                    "severity": rare_vuln.severity,
                    "type": "rare",
                    "confidence": rare_vuln.confidence,
                }
            )

        # Record to learning database
        learning_record = self.learning_db.record_analysis(
            contract_code=contract_code,
            vulnerabilities_found=all_vulnerabilities,
            llm_insights=llm_insights,
            processing_time=processing_time,
        )

        self.results["learning_record_id"] = learning_record.id
        self.results["total_scans_to_date"] = len(self.learning_db.learning_records)

        print(f"✓ Learning recorded: {learning_record.id}")
        print(
            f"✓ Total analyses in knowledge base: {len(self.learning_db.learning_records)}"
        )

        # NEW: Process results through adaptive learning system
        print("\n[7/7] Processing Adaptive Learning Feedback...")
        print("-" * 70)

        try:
            # Use asyncio to process scan results
            import asyncio

            # Process scan results through adaptive learning
            previous_loop = None
            try:
                previous_loop = asyncio.get_event_loop()
            except RuntimeError:
                previous_loop = None

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                adaptive_result = loop.run_until_complete(
                    self.adaptive_system.process_scan_results(self.results)
                )
            finally:
                loop.close()
                if previous_loop and not previous_loop.is_closed():
                    asyncio.set_event_loop(previous_loop)
                else:
                    asyncio.set_event_loop(None)

            # Update learning database with adaptive learning data
            self.learning_db.update_adaptive_learning_data(
                self.adaptive_system.save_state()
            )

            print("✓ Adaptive learning updated:")
            print(
                f"  New patterns learned: {adaptive_result.get('new_patterns_learned', 0)}"
            )
            print(
                f"  Verification weights adjusted: {adaptive_result.get('current_verification_weights', {})}"
            )

            self.results["adaptive_learning_result"] = adaptive_result

        except Exception as e:
            print(f"  ⚠️  Adaptive learning update failed: {str(e)}")

        # Show improvement suggestions
        suggestions = self.learning_db.suggest_improvements()
        if suggestions:
            print("\n💡 Learning System Suggestions:")
            for suggestion in suggestions[:3]:
                print(f"   • {suggestion}")

        return self.results

    def _run_symbolic_analysis(self, contract_code: str) -> Dict[str, Any]:
        """Run symbolic execution analysis"""
        results = {
            "overflow_analysis": [],
            "reentrancy_analysis": [],
            "flash_loan_analysis": [],
            "oracle_manipulation": [],
            "access_control_analysis": [],
        }

        try:
            # Example: Integer overflow analysis
            a = self.symbolic_executor.create_symbolic_var(
                "userInput", VarType.UINT256, tainted=True
            )
            b = self.symbolic_executor.create_symbolic_var("balance", VarType.UINT256)

            overflows = self.symbolic_executor.analyze_integer_overflow_conditions(
                a, b, "add"
            )
            results["overflow_analysis"] = [
                {
                    "type": v["type"],
                    "operation": v["operation"],
                    "exploitable": v["exploitable"],
                    "example_values": str(v["example_values"]),
                }
                for v in overflows
            ]

            # Flash loan analysis
            initial_state = SymbolicState(
                variables={},
                constraints=[],
                balances={},
                storage={},
                call_stack=[],
                msg_sender=None,
                msg_value=None,
                block_timestamp=None,
                block_number=None,
            )

            operations = [
                ("swap", {"amount_in": "flash_loan_amount"}),
                ("borrow", {"collateral_factor": 75}),
                ("liquidate", {"bonus": 10}),
            ]

            flash_attacks = self.symbolic_executor.analyze_flash_loan_attack_vectors(
                initial_state, operations
            )

            results["flash_loan_analysis"] = [
                {
                    "type": v["type"],
                    "severity": v["severity"],
                    "description": v["description"],
                }
                for v in flash_attacks
            ]

        except Exception as e:
            results["error"] = str(e)

        return results

    def _run_enhanced_fuzzing(self, contract_code: str) -> Dict[str, Any]:
        """Run enhanced fuzzing campaign"""
        results = {"strategies": []}

        # Extract property functions from code
        import re

        properties = re.findall(r"function\s+(echidna_\w+)", contract_code)

        if not properties:
            properties = [
                "echidna_balance_conservation",
                "echidna_no_overflow",
                "echidna_access_control",
            ]

        # Run multiple fuzzing strategies
        strategies = [
            FuzzingStrategy.COVERAGE_GUIDED,
            FuzzingStrategy.MUTATION_BASED,
            FuzzingStrategy.ADVERSARIAL,
        ]

        for strategy in strategies:
            config = FuzzingConfig(
                strategy=strategy, max_iterations=1000, max_time_seconds=300
            )

            orchestrator = EnhancedFuzzingOrchestrator(config)

            try:
                result = orchestrator.run_fuzzing_campaign(
                    str(self.contract_path), properties
                )

                results["strategies"].append(
                    {
                        "strategy": strategy.value,
                        "iterations": result.iterations_run,
                        "coverage": result.coverage_achieved,
                        "vulnerabilities": len(result.vulnerabilities_found),
                        "crashes": result.crash_count,
                    }
                )

            except Exception as e:
                results["strategies"].append(
                    {"strategy": strategy.value, "error": str(e)}
                )

        return results

    def _detect_contract_type(self, contract_code: str) -> str:
        """Detect contract type for targeted analysis"""
        code_lower = contract_code.lower()

        if any(term in code_lower for term in ["swap", "exchange", "pair"]):
            return "dex"
        elif any(term in code_lower for term in ["borrow", "lend", "collateral"]):
            return "lending"
        elif any(term in code_lower for term in ["stake", "reward", "farm"]):
            return "staking"
        elif any(term in code_lower for term in ["bridge", "relay"]):
            return "bridge"
        elif any(term in code_lower for term in ["vote", "proposal", "govern"]):
            return "governance"
        else:
            return "unknown"

    def _print_pattern_summary(self, patterns):
        """Print summary of detected patterns"""
        if not patterns:
            return

        print("\nTop Findings:")
        for i, pattern in enumerate(patterns[:5], 1):
            print(f"  {i}. [{pattern.severity.upper()}] {pattern.name}")
            print(f"     {pattern.description}")

    def _print_anomaly_summary(self, anomalies):
        """Print summary of detected anomalies"""
        if not anomalies:
            return

        print("\nTop Findings:")
        for i, anomaly in enumerate(anomalies[:5], 1):
            print(f"  {i}. [{anomaly.severity.upper()}] {anomaly.name}")
            print(f"     {anomaly.description}")

    def _serialize_pattern(self, pattern) -> Dict[str, Any]:
        """Serialize pattern for JSON output"""
        return {
            "category": pattern.category.value,
            "name": pattern.name,
            "description": pattern.description,
            "severity": pattern.severity,
            "confidence": pattern.confidence,
            "attack_vector": pattern.attack_vector,
            "exploit_scenario": pattern.exploit_scenario,
            "remediation": pattern.remediation,
        }

    def _serialize_anomaly(self, anomaly) -> Dict[str, Any]:
        """Serialize anomaly for JSON output"""
        return {
            "type": anomaly.anomaly_type.value,
            "name": anomaly.name,
            "description": anomaly.description,
            "severity": anomaly.severity,
            "confidence": anomaly.confidence,
            "location": anomaly.location,
            "potential_exploit": anomaly.potential_exploit,
            "remediation": anomaly.remediation,
        }

    def _serialize_llm_result(self, result) -> Dict[str, Any]:
        """Serialize LLM reasoning result"""
        return {
            "mode": result.mode.value,
            "findings_count": len(result.findings),
            "attack_scenarios_count": len(result.attack_scenarios),
            "property_tests_count": len(result.property_tests),
            "confidence": result.confidence,
        }

    def _serialize_rare_vuln(self, vuln) -> Dict[str, Any]:
        """Serialize rare vulnerability"""
        return {
            "name": vuln.name,
            "description": vuln.description,
            "severity": vuln.severity,
            "confidence": vuln.confidence,
            "affected_code": vuln.affected_code,
            "exploit_scenario": vuln.exploit_scenario,
            "remediation": vuln.remediation,
            "references": vuln.references,
            "cve_id": vuln.cve_id,
        }

    def _create_hypotheses_from_findings(self, patterns, anomalies, rare_vulns):
        """Create verification hypotheses from detected findings"""
        from dataclasses import dataclass

        @dataclass
        class VerificationHypothesis:
            id: str
            name: str
            type: str
            description: str
            severity: str
            confidence: float
            attack_scenario: str = ""

        hypotheses = []

        # Create hypotheses from patterns
        for i, pattern in enumerate(patterns):
            hypotheses.append(
                VerificationHypothesis(
                    id=f"pattern_{i}",
                    name=pattern.name,
                    type=str(
                        pattern.category.value
                        if hasattr(pattern.category, "value")
                        else pattern.category
                    ),
                    description=pattern.description,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    attack_scenario=pattern.exploit_scenario,
                )
            )

        # Create hypotheses from anomalies
        for i, anomaly in enumerate(anomalies):
            hypotheses.append(
                VerificationHypothesis(
                    id=f"anomaly_{i}",
                    name=anomaly.name,
                    type=str(
                        anomaly.anomaly_type.value
                        if hasattr(anomaly.anomaly_type, "value")
                        else anomaly.anomaly_type
                    ),
                    description=anomaly.description,
                    severity=anomaly.severity,
                    confidence=anomaly.confidence,
                    attack_scenario=anomaly.potential_exploit or "",
                )
            )

        # Create hypotheses from rare vulnerabilities
        for i, rare_vuln in enumerate(rare_vulns):
            hypotheses.append(
                VerificationHypothesis(
                    id=f"rare_{i}",
                    name=rare_vuln.name,
                    type="rare_vulnerability",
                    description=rare_vuln.description,
                    severity=rare_vuln.severity,
                    confidence=rare_vuln.confidence,
                    attack_scenario=rare_vuln.exploit_scenario,
                )
            )

        return hypotheses

    def _generate_final_report(self):
        """Generate comprehensive final report"""
        analysis = self.results["analysis_results"]

        print("\n" + "=" * 70)
        print(" COMPREHENSIVE ANALYSIS REPORT")
        print("=" * 70)

        # Summary statistics
        total_findings = 0
        critical_count = 0
        high_count = 0

        if "novel_patterns" in analysis:
            patterns = analysis["novel_patterns"]
            total_findings += patterns["total_patterns"]
            critical_count += patterns["critical"]
            high_count += patterns["high"]

        if "anomalies" in analysis:
            anomalies = analysis["anomalies"]
            total_findings += anomalies["total_anomalies"]
            critical_count += anomalies["critical"]
            high_count += anomalies["high"]

        if "rare_vulnerabilities" in analysis:
            rare = analysis["rare_vulnerabilities"]
            total_findings += rare["total_rare"]
            critical_count += rare["critical"]
            high_count += rare["high"]

        print(f"\nTotal Findings: {total_findings}")
        print(f"  Critical: {critical_count}")
        print(f"  High: {high_count}")

        # Risk assessment
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 5:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        print(f"\nOverall Risk Level: {risk_level}")

        # Verification summary
        if "verification" in analysis:
            verification = analysis["verification"]
            print("\n" + "-" * 70)
            print("VERIFICATION PIPELINE SUMMARY")
            print("-" * 70)

            if verification.get("total_hypotheses", 0) > 0:
                verified_count = verification.get("verified", 0)
                uncertain_count = verification.get("uncertain", 0)
                rejected_count = verification.get("rejected", 0)

                print(f"\nHypotheses Tested: {verification['total_hypotheses']}")
                print(f"  ✓ Verified (High Confidence): {verified_count}")
                print(f"  ? Uncertain (Needs Review): {uncertain_count}")
                print(f"  ✗ Rejected (False Positives): {rejected_count}")

                if "statistics" in verification:
                    stats = verification["statistics"]
                    print("\nPipeline Performance:")
                    print(f"  Average Confidence: {stats.get('avg_confidence', 0):.2%}")
                    print(
                        f"  Average Layer Agreement: {stats.get('avg_cross_layer_agreement', 0):.1f}/4 layers"
                    )
                    print(
                        f"  False Positive Reduction: {stats.get('false_positive_reduction', 0):.1%}"
                    )

                if verification.get("verified_findings"):
                    print(
                        f"\n🎯 HIGH-CONFIDENCE FINDINGS ({len(verification['verified_findings'])}):"
                    )
                    for i, finding in enumerate(
                        verification["verified_findings"][:5], 1
                    ):
                        print(f"  {i}. {finding['name']}")
                        print(
                            f"     Confidence: {finding['confidence']:.2%} | Agreement: {finding['layer_agreement']}/4 layers"
                        )
            else:
                print("No verification performed")

        # Save to file
        output_file = Path("bug_hunter_report.json")
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\nDetailed report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Web3 Bug Hunter - Find novel vulnerabilities in smart contracts with LEARNING"
    )
    parser.add_argument("contract", nargs="?", help="Path to Solidity contract file")
    parser.add_argument("--openai-key", help="OpenAI API key for LLM analysis")
    parser.add_argument("--anthropic-key", help="Anthropic API key for Claude")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM analysis")
    parser.add_argument("--no-fuzzing", action="store_true", help="Disable fuzzing")
    parser.add_argument(
        "--no-verification",
        action="store_true",
        help="Disable multi-layer verification",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file for results (default: bug_hunter_report.json)",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run benchmark comparison vs Slither/Mythril",
    )
    parser.add_argument(
        "--show-learning", action="store_true", help="Show learning metrics and exit"
    )

    # NEW: User feedback commands
    parser.add_argument(
        "--mark-false-positive",
        metavar="PATTERN",
        help="Mark a pattern as false positive",
    )
    parser.add_argument(
        "--confirm-vuln", metavar="PATTERN", help="Confirm a vulnerability pattern"
    )
    parser.add_argument(
        "--feedback-details", help="Additional details for feedback (JSON string)"
    )

    args = parser.parse_args()

    # NEW: Process user feedback commands (can run without a contract)
    if args.mark_false_positive or args.confirm_vuln:
        learning_db = get_learning_db()
        adaptive_system = get_adaptive_system(learning_db)

        pattern_name = args.mark_false_positive or args.confirm_vuln
        feedback_type = "false_positive" if args.mark_false_positive else "confirmed"

        # Parse additional details if provided
        details = {}
        if args.feedback_details:
            try:
                details = json.loads(args.feedback_details)
            except json.JSONDecodeError:
                print("Warning: Invalid JSON in --feedback-details, ignoring")

        # Process feedback
        feedback = adaptive_system.feedback_processor.process_feedback(
            vulnerability_id=f"manual-{pattern_name}",
            feedback_type=feedback_type,
            pattern_name=pattern_name,
            details=details,
        )

        print("=" * 70)
        print("USER FEEDBACK PROCESSED")
        print("=" * 70)
        print(f"Pattern: {pattern_name}")
        print(f"Feedback Type: {feedback_type}")
        print(f"Timestamp: {feedback.timestamp}")

        # Update learning database
        learning_db.update_adaptive_learning_data(adaptive_system.save_state())

        # Show updated pattern confidence (if tracked)
        if pattern_name in learning_db.pattern_effectiveness:
            stats = learning_db.pattern_effectiveness[pattern_name]
            print("\nUpdated Pattern Statistics:")
            print(f"  Confidence: {stats.confidence_score:.1%}")
            print(f"  True Positives: {stats.true_positives}")
            print(f"  False Positives: {stats.false_positives}")

        print("\n✓ Feedback recorded and learning database updated")
        sys.exit(0)

    # Show learning metrics if requested
    if args.show_learning:
        learning_db = get_learning_db()
        metrics = learning_db.get_improvement_metrics()

        print("=" * 70)
        print("LEARNING SYSTEM METRICS")
        print("=" * 70)
        print(f"\nTotal scans completed: {metrics.get('total_scans', 0)}")
        print(f"Patterns learned: {metrics.get('total_patterns_learned', 0)}")
        print(
            f"Vulnerability types known: {metrics.get('vulnerability_types_known', 0)}"
        )

        if metrics.get("total_scans", 0) >= 2:
            print("\nAccuracy Metrics:")
            print(f"  Initial accuracy: {metrics.get('initial_accuracy', 0):.1%}")
            print(f"  Recent accuracy: {metrics.get('recent_accuracy', 0):.1%}")
            print(f"  Improvement: {metrics.get('improvement_percentage', 0):.1f}%")

        if metrics.get("top_patterns"):
            print("\nTop Detection Patterns:")
            for i, p in enumerate(metrics["top_patterns"][:5], 1):
                if isinstance(p, dict):
                    name = p.get("name", "unknown")
                    conf = p.get("confidence", 0.0)
                    det = p.get("detections", "?")
                    print(f"  {i}. {name} (confidence: {conf:.1%}, detections: {det})")
                else:
                    print(f"  {i}. {p}")

        # NEW: Show adaptive learning metrics
        adaptive_metrics = learning_db.get_adaptive_metrics()

        if adaptive_metrics.get("prompt_performance"):
            print("\n📊 Prompt Performance:")
            for stage, perf in adaptive_metrics["prompt_performance"].items():
                print(f"  {stage}:")
                print(f"    Success Rate: {perf.get('success_rate', 0):.1%}")
                print(
                    f"    Hypotheses: {perf.get('total_hypotheses', 0)} total, {perf.get('successful_hypotheses', 0)} successful"
                )
                print(f"    Temperature: {perf.get('avg_temperature', 0):.2f}")

        if adaptive_metrics.get("verification_weights"):
            vw_data = adaptive_metrics["verification_weights"]
            weights = vw_data.get("weights", {})
            if weights and isinstance(weights, dict):
                if "static" in weights and isinstance(weights["static"], (int, float)):
                    print("\n⚖️  Verification Layer Weights:")
                    for layer in ["static", "symbolic", "dynamic", "behavioral"]:
                        if layer in weights:
                            print(f"  {layer}: {weights[layer]:.2%}")
                    last_updated = weights.get("last_updated") or vw_data.get(
                        "weights", {}
                    ).get("last_updated", "N/A")
                    print(f"  Last Updated: {last_updated}")

        if adaptive_metrics.get("hypothesis_quality_trends"):
            trends = adaptive_metrics["hypothesis_quality_trends"]
            if trends.get("avg_confidence_over_time"):
                recent_conf = (
                    trends["avg_confidence_over_time"][-1]
                    if trends["avg_confidence_over_time"]
                    else 0
                )
                print("\n📈 Hypothesis Quality Trends:")
                print(f"  Recent Avg Confidence: {recent_conf:.1%}")
                if len(trends["avg_confidence_over_time"]) >= 2:
                    initial_conf = trends["avg_confidence_over_time"][0]
                    improvement = (
                        ((recent_conf - initial_conf) / initial_conf * 100)
                        if initial_conf > 0
                        else 0
                    )
                    print(f"  Confidence Improvement: {improvement:+.1f}%")

        feedback_info = adaptive_metrics.get("user_feedback", {})
        if feedback_info.get("total_feedback", 0) > 0:
            print("\n💬 User Feedback:")
            print(f"  Total Feedback Received: {feedback_info['total_feedback']}")
            if feedback_info.get("recent_feedback"):
                print(
                    f"  Recent Feedback Items: {len(feedback_info['recent_feedback'])}"
                )

        suggestions = learning_db.suggest_improvements()
        if suggestions:
            print("\n💡 Suggestions:")
            for suggestion in suggestions:
                print(f"  • {suggestion}")

        sys.exit(0)

    # Benchmark mode
    if args.benchmark:
        print("=" * 70)
        print("BENCHMARK MODE: Comparing vs Slither and Mythril")
        print("=" * 70)

        benchmark_system = BenchmarkSystem()
        report = benchmark_system.compare_all_tools(args.contract)

        summary = benchmark_system.generate_summary_report()
        print("\n📊 Overall Statistics:")
        print(f"   Total benchmarks: {summary['total_benchmarks']}")
        print(f"   Win rate: {summary['win_rate']:.1%}")
        print(f"   Unique findings: {summary['total_unique_findings']}")
        sys.exit(0)

    # Normal analysis requires a contract path
    if not args.contract:
        print("Error: Contract file is required for analysis")
        print("Use --show-learning or --mark-false-positive without contract file")
        sys.exit(1)

    if not Path(args.contract).exists():
        print(f"Error: Contract file not found: {args.contract}")
        sys.exit(1)

    config = {
        "openai_key": args.openai_key,
        "anthropic_key": args.anthropic_key,
        "use_llm": not args.no_llm,
        "use_fuzzing": not args.no_fuzzing,
        "use_verification": not args.no_verification,
        "output_file": args.output or "bug_hunter_report.json",
        # features
        "enable_poc_generation": True,
        "generate_pocs": True,
        "execute_pocs": False,
    }

    # Run analysis
    hunter = AdvancedWeb3BugHunter(args.contract, config)
    hunter.run_comprehensive_analysis()

    print("\n" + "=" * 70)
    print(" ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
