#!/usr/bin/env python3
"""
Web3 Bug Hunting Integration Script
Combines Slither, Echidna, LLM analysis, cross-chain simulation, and formal verification for comprehensive vulnerability detection
"""

import os
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Import our custom modules
from llm.llm_integration import LLMVulnerabilityAnalyzer
from llm.advanced_prompts import AdvancedAuditPrompts
from llm.economic_invariant_generator import EconomicInvariantGenerator
from scripts.cross_contract_tracker import CrossContractLogicTracker
from scripts.cross_chain_simulator import BridgeSimulator, ChainType
from scripts.formal_verification_helpers import FormalVerificationHelper


class Web3BugHunter:
    def __init__(self, contract_path: str, openai_key: Optional[str] = None):
        self.contract_path = Path(contract_path)
        self.openai_key = openai_key or os.getenv("OPENAI_API_KEY")
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)
        self.compilation_unit = None  # Will be set after Slither run
        self.generated_properties_file: Optional[Any] = None

    def run_full_analysis(self) -> Dict[str, Any]:
        """
        Run complete analysis pipeline
        """
        print("🚀 Starting Web3 Bug Hunting Analysis...")
        timestamp = datetime.utcnow().isoformat() + "Z"
        results = {
            "timestamp": timestamp,
            "contract_analyzed": str(self.contract_path),
            "slither_analysis": {},
            "custom_detectors": {},
            "cross_contract_analysis": {},
            "llm_analysis": {},
            "generated_invariants": {},
            "echidna_fuzzing": {},
            "cross_chain_simulation": {},
            "formal_verification": {},
            "final_report": {},
        }

        # Step 1: Slither Analysis with custom detectors
        print("📊 Running Slither analysis with custom detectors...")
        results["slither_analysis"] = self.run_slither_analysis()

        # Step 2: Cross-Contract Logic Tracking (requires Slither compilation unit)
        print("🔗 Analyzing cross-contract interactions...")
        results["cross_contract_analysis"] = self.run_cross_contract_analysis()

        # Step 3: Custom Detectors (integrated via Slither above, but explicit run if needed)
        print("🔍 Running explicit custom detectors...")
        results["custom_detectors"] = self.run_custom_detectors()

        # Step 4: LLM Analysis with advanced prompts
        if self.openai_key:
            print("🧠 Running LLM-powered analysis with advanced prompts...")
            results["llm_analysis"] = self.run_llm_analysis(results)
        else:
            print("⚠️  Skipping LLM analysis - no OpenAI key provided")
            results["llm_analysis"] = {"error": "No OpenAI key provided"}

        # Step 5: Generate Economic Invariants
        print("📈 Generating economic invariants...")
        results["generated_invariants"] = self.generate_economic_invariants()

        # Step 6: Echidna Fuzzing with generated properties
        print("🐍 Running Echidna fuzzing with advanced and generated properties...")
        results["echidna_fuzzing"] = self.run_echidna_fuzzing()

        # Step 7: Cross-Chain Simulation
        print("🌉 Running cross-chain bridge simulation...")
        results["cross_chain_simulation"] = self.run_cross_chain_simulation()

        # Step 8: Formal Verification Helpers
        print("🔬 Generating formal verification specifications...")
        results["formal_verification"] = self.run_formal_verification()

        # Step 9: Generate Final Report
        print("📋 Generating final report...")
        results["final_report"] = self.generate_final_report(results)

        # Cleanup generated files
        self.cleanup_generated_files()

        return results

    def run_slither_analysis(self) -> Dict[str, Any]:
        """
        Run Slither analysis with custom detectors
        """
        try:
            # Custom detectors arguments
            custom_detectors = [
                "--detect",
                "custom-logic-flaw",
                "--detect",
                "bridge-vulnerabilities",
                "--detect",
                "governance-vulnerabilities",
            ]
            cmd = ["slither", str(self.contract_path), "--json", "-"] + custom_detectors
            result = subprocess.run(
                cmd, capture_output=True, text=True, cwd=self.contract_path.parent
            )

            if result.returncode == 0:
                slither_results = json.loads(result.stdout)
                # Store compilation unit for other tools if possible (simplified)
                self.compilation_unit = slither_results.get("compilation_unit", None)
                return slither_results
            else:
                print(f"Slither error: {result.stderr}")
                return {"error": result.stderr}
        except Exception as e:
            print(f"Slither analysis failed: {e}")
            return {"error": str(e)}

    def run_custom_detectors(self) -> Dict[str, Any]:
        """
        Run custom vulnerability detectors explicitly
        """
        try:
            findings = {
                "custom_logic_flaw": [],
                "bridge_vulnerabilities": [],
                "governance_vulnerabilities": [],
            }

            # Since detectors are Slither-based, results are in slither_analysis
            # Here we can run standalone if needed, but for now return status
            return {
                "status": "integrated_in_slither",
                "detectors_used": [
                    "CustomLogicFlawDetector",
                    "BridgeVulnerabilityDetector",
                    "GovernanceVulnerabilityDetector",
                ],
                "findings": findings,
            }
        except Exception as e:
            return {"error": str(e)}

    def run_cross_contract_analysis(self) -> Dict[str, Any]:
        """
        Analyze cross-contract logic using tracker
        """
        try:
            if self.compilation_unit:
                tracker = CrossContractLogicTracker(self.compilation_unit)
                graph = tracker.build_contract_graph()
                vulnerabilities = tracker.detect_potential_vulnerabilities()
                report = tracker.generate_report()
                return {
                    "contract_graph": graph,
                    "vulnerabilities": vulnerabilities,
                    "report": report,
                    "status": "completed",
                }
            else:
                return {"error": "Compilation unit not available", "status": "skipped"}
        except Exception as e:
            return {"error": str(e)}

    def run_llm_analysis(self, previous_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run LLM-powered vulnerability analysis with advanced prompts
        """
        try:
            analyzer = LLMVulnerabilityAnalyzer(self.openai_key)

            # Read contract code
            with open(self.contract_path, "r") as f:
                contract_code = f.read()

            # Use advanced prompts for specialized analysis
            prompts = [
                AdvancedAuditPrompts.bridge_vulnerability_analysis(contract_code),
                AdvancedAuditPrompts.business_logic_flaws(
                    contract_code, "DeFi protocol"
                ),
                AdvancedAuditPrompts.cross_contract_logic(contract_code),
                AdvancedAuditPrompts.attack_scenario_simulation(
                    contract_code, "flash_loan"
                ),
            ]

            analyses = []
            for prompt in prompts:
                analysis = analyzer.analyze_contract_logic_with_prompt(
                    contract_code, previous_results["slither_analysis"], prompt
                )
                analyses.append(analysis)

            return {
                "analyses": analyses,
                "prompt_types": [
                    "bridge",
                    "business_logic",
                    "cross_contract",
                    "flash_loan",
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def generate_economic_invariants(self) -> Dict[str, Any]:
        """
        Generate economic invariants using the generator
        """
        try:
            with open(self.contract_path, "r") as f:
                contract_code = f.read()

            gen = EconomicInvariantGenerator()
            invariants = gen.generate_invariants(contract_code, "auto")

            # Write generated properties to temp file for Echidna
            self.generated_properties_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".sol", delete=False
            )
            content = gen.create_invariant_test_suite(
                invariants, self.contract_path.stem
            )
            self.generated_properties_file.write(content)
            self.generated_properties_file.close()

            return {
                "invariants": [inv.__dict__ for inv in invariants],
                "generated_file": self.generated_properties_file.name,
                "count": len(invariants),
            }
        except Exception as e:
            return {"error": str(e)}

    def run_echidna_fuzzing(self) -> Dict[str, Any]:
        """
        Run Echidna fuzzing with custom, advanced, and generated properties
        """
        try:
            # Check if Echidna is available
            result = subprocess.run(
                ["echidna", "--version"], capture_output=True, text=True
            )
            if result.returncode != 0:
                return {"error": "Echidna not installed"}

            config_path = Path("fuzzing/echidna_config.yaml")
            contract_name = self.contract_path.stem + ".sol"

            # Create a combined properties file
            combined_props = Path("fuzzing/combined_properties.sol")
            combined_content = ""

            # Add custom properties
            with open("fuzzing/custom_properties.sol", "r") as f:
                combined_content += f.read() + "\n\n"

            # Add advanced properties
            with open("fuzzing/advanced_properties.sol", "r") as f:
                combined_content += f.read() + "\n\n"

            # Add generated properties if available
            if self.generated_properties_file:
                with open(self.generated_properties_file.name, "r") as f:
                    combined_content += f.read()

            with open(combined_props, "w") as f:
                f.write(combined_content)

            cmd = [
                "echidna",
                contract_name,
                "--contract",
                self.contract_path.stem,
                "--test-mode",
                "Property",
                "--config",
                str(config_path),
                "--test-limit",
                "10000",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.contract_path.parent,
                timeout=600,
            )

            # Cleanup combined file
            combined_props.unlink(missing_ok=True)

            return {
                "output": result.stdout,
                "errors": result.stderr,
                "return_code": result.returncode,
                "properties_tested": ["custom", "advanced", "generated"],
            }
        except subprocess.TimeoutExpired:
            return {"error": "Echidna fuzzing timed out"}
        except Exception as e:
            return {"error": str(e)}

    def run_cross_chain_simulation(self) -> Dict[str, Any]:
        """
        Run cross-chain bridge simulation
        """
        try:
            simulator = BridgeSimulator()

            # Setup demo chains and contracts
            simulator.add_chain(1, ChainType.ETHEREUM)
            simulator.add_chain(2, ChainType.BSC)
            simulator.deploy_contract(1, "0xbridge1", "BridgeContract")
            simulator.deploy_contract(2, "0xbridge2", "BridgeContract")

            # Run attack simulations
            attacks = [
                simulator.simulate_attack(
                    "nomad_confirmat_zero", chain_id=1, contract_address="0xbridge1"
                ),
                simulator.simulate_attack(
                    "qubit_legacy_function", chain_id=1, contract_address="0xbridge1"
                ),
                simulator.simulate_attack("message_replay"),
                simulator.simulate_attack(
                    "invalid_signature", chain_id=1, contract_address="0xbridge1"
                ),
            ]

            report = simulator.get_simulation_report()
            report["attacks"] = attacks

            return report
        except Exception as e:
            return {"error": str(e)}

    def run_formal_verification(self) -> Dict[str, Any]:
        """
        Generate formal verification specifications
        """
        try:
            with open(self.contract_path, "r") as f:
                contract_code = f.read()

            helper = FormalVerificationHelper()
            props = helper.generate_invariants_from_contract(
                contract_code, self.contract_path.stem
            )
            certora_spec = helper.generate_certora_spec(self.contract_path.stem, props)
            scribble_code = helper.generate_scribble_annotations(contract_code, props)
            validation = helper.validate_properties(props)

            # Write specs to files
            spec_path = self.results_dir / f"{self.contract_path.stem}_certora.spec"
            with open(spec_path, "w") as f:
                f.write(certora_spec)

            scribble_path = self.results_dir / f"{self.contract_path.stem}_scribble.sol"
            with open(scribble_path, "w") as f:
                f.write(scribble_code)

            return {
                "properties": [p.__dict__ for p in props],
                "certora_spec_file": str(spec_path),
                "scribble_annotated_file": str(scribble_path),
                "validation": validation,
            }
        except Exception as e:
            return {"error": str(e)}

    def generate_final_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive final report
        """
        report = {
            "summary": {
                "contract_analyzed": str(self.contract_path),
                "analysis_timestamp": results["timestamp"],
                "tools_used": [
                    "slither",
                    "custom_detectors",
                    "llm_analysis",
                    "echidna",
                    "cross_contract_tracker",
                    "cross_chain_simulator",
                    "formal_verification",
                ],
                "total_findings": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0,
            },
            "recommendations": [
                "Review high-severity findings immediately",
                "Test failed Echidna properties with manual PoCs",
                "Verify LLM suggestions manually",
                "Run formal specs in Certora for proof",
                "Simulate attacks on mainnet fork",
            ],
            "bounty_tips": [
                "Focus on economic exploits for higher payouts",
                "Document with clear PoC code",
                "Target bridges and governance for criticals",
            ],
        }

        # Aggregate findings (simplified counting)
        all_findings = []
        slither_results = results.get("slither_analysis", {})
        if "results" in slither_results and "detectors" in slither_results["results"]:
            for detector_name, findings in slither_results["results"][
                "detectors"
            ].items():
                all_findings.extend(findings)
                for finding in findings:
                    impact = finding.get("impact", "informational").lower()
                    if "high" in impact or "critical" in impact:
                        report["summary"]["high_severity"] += 1
                    elif "medium" in impact:
                        report["summary"]["medium_severity"] += 1
                    else:
                        report["summary"]["low_severity"] += 1

        # Add other findings
        report["summary"]["total_findings"] = len(all_findings) + len(
            results.get("cross_contract_analysis", {}).get("vulnerabilities", [])
        )

        # Echidna failed properties as findings
        echidna = results.get("echidna_fuzzing", {})
        if "output" in echidna:
            failed_props = echidna["output"].count("Property FAILED!")
            report["summary"]["high_severity"] += failed_props

        # LLM findings (parse from analyses)
        llm = results.get("llm_analysis", {})
        if "analyses" in llm:
            for analysis in llm["analyses"]:
                # Simplified - count mentions of critical terms
                text = analysis.get("raw_response", "")
                if "critical" in text.lower() or "high severity" in text.lower():
                    report["summary"]["high_severity"] += 1

        # Cross-chain attack successes
        sim = results.get("cross_chain_simulation", {})
        if "attacks" in sim:
            successful_attacks = sum(
                1 for a in sim["attacks"] if a.get("success", False)
            )
            report["summary"]["high_severity"] += successful_attacks

        return report

    def cleanup_generated_files(self):
        """
        Cleanup temporary generated files
        """
        if self.generated_properties_file and os.path.exists(
            self.generated_properties_file.name
        ):
            os.unlink(self.generated_properties_file.name)

    def save_results(self, results: Dict[str, Any], output_file: Optional[str] = None):
        """
        Save analysis results to file
        """
        if not output_file:
            output_file = f"analysis_results_{self.contract_path.stem}.json"
        output_path = self.results_dir / output_file
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"📁 Results saved to {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python main_integration.py <contract_path> [openai_key]")
        sys.exit(1)

    contract_path = sys.argv[1]
    openai_key = sys.argv[2] if len(sys.argv) > 2 else None

    hunter = Web3BugHunter(contract_path, openai_key)
    results = hunter.run_full_analysis()
    hunter.save_results(results)

    print("✅ Analysis complete! Check results/ for detailed output.")


if __name__ == "__main__":
    main()
