#!/usr/bin/env python3
"""
Elite Detector Integration - Integrates all 4 elite detectors into multi-agent workflow
Runs storage collision, flash loan, state desync, and oracle manipulation detectors

Author: Elite Web3 Bug Hunter
Version: 1.0.0
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# Add parent directories to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import elite detectors
from detectors.storage_collision_detector import StorageCollisionDetector
from detectors.flash_loan_simulator import FlashLoanSimulator
from detectors.state_desync_analyzer import StateDesyncAnalyzer
from detectors.oracle_manipulation_detector import OracleManipulationDetector


@dataclass
class EliteDetectorResults:
    """Aggregated results from all elite detectors"""

    storage_collision_findings: List[Dict[str, Any]]
    flash_loan_findings: List[Dict[str, Any]]
    state_desync_findings: List[Dict[str, Any]]
    oracle_manipulation_findings: List[Dict[str, Any]]

    @property
    def total_findings(self) -> int:
        return (
            len(self.storage_collision_findings)
            + len(self.flash_loan_findings)
            + len(self.state_desync_findings)
            + len(self.oracle_manipulation_findings)
        )

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for findings in [
                self.storage_collision_findings,
                self.flash_loan_findings,
                self.state_desync_findings,
                self.oracle_manipulation_findings,
            ]
            for finding in findings
            if finding.get("severity") == "critical"
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for findings in [
                self.storage_collision_findings,
                self.flash_loan_findings,
                self.state_desync_findings,
                self.oracle_manipulation_findings,
            ]
            for finding in findings
            if finding.get("severity") == "high"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "storage_collision": {
                "count": len(self.storage_collision_findings),
                "findings": self.storage_collision_findings,
            },
            "flash_loan": {
                "count": len(self.flash_loan_findings),
                "findings": self.flash_loan_findings,
            },
            "state_desync": {
                "count": len(self.state_desync_findings),
                "findings": self.state_desync_findings,
            },
            "oracle_manipulation": {
                "count": len(self.oracle_manipulation_findings),
                "findings": self.oracle_manipulation_findings,
            },
            "summary": {
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
            },
        }


class EliteDetectorOrchestrator:
    """
    Elite Detector Orchestrator - Runs all 4 elite detectors

    Detectors:
    1. Storage Collision Detector - Proxy/inheritance storage issues
    2. Flash Loan Simulator - Economic attack viability
    3. State Desync Analyzer - Multi-tx state synchronization
    4. Oracle Manipulation Detector - Price feed vulnerabilities
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: Optional[EliteDetectorResults] = None

    def run_all_detectors(self, target_path: str) -> EliteDetectorResults:
        """Run all 4 elite detectors on target path"""

        if self.verbose:
            print("=" * 80)
            print("🎯 ELITE DETECTOR SUITE")
            print("=" * 80)
            print(f"Target: {target_path}")
            print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 80)

        # Run Detector #1: Storage Collision
        if self.verbose:
            print("\n🔍 [1/4] Running Storage Collision Detector...")
        storage_findings = self._run_storage_collision_detector(target_path)

        # Run Detector #2: Flash Loan Simulator
        if self.verbose:
            print(f"    ✓ Found {len(storage_findings)} storage issues")
            print("\n💰 [2/4] Running Flash Loan Economic Simulator...")
        flash_loan_findings = self._run_flash_loan_simulator(target_path)

        # Run Detector #3: State Desync Analyzer
        if self.verbose:
            print(f"    ✓ Found {len(flash_loan_findings)} flash loan attacks")
            print("\n🔄 [3/4] Running State Desync Analyzer...")
        state_desync_findings = self._run_state_desync_analyzer(target_path)

        # Run Detector #4: Oracle Manipulation Detector
        if self.verbose:
            print(f"    ✓ Found {len(state_desync_findings)} state desync issues")
            print("\n🔮 [4/4] Running Oracle Manipulation Detector...")
        oracle_findings = self._run_oracle_manipulation_detector(target_path)

        if self.verbose:
            print(f"    ✓ Found {len(oracle_findings)} oracle vulnerabilities")

        # Aggregate results
        self.results = EliteDetectorResults(
            storage_collision_findings=storage_findings,
            flash_loan_findings=flash_loan_findings,
            state_desync_findings=state_desync_findings,
            oracle_manipulation_findings=oracle_findings,
        )

        if self.verbose:
            self._print_summary()

        return self.results

    def _run_storage_collision_detector(self, target_path: str) -> List[Dict[str, Any]]:
        """Run storage collision detector"""
        try:
            detector = StorageCollisionDetector(verbose=False)
            findings = detector.analyze_directory(target_path)
            return [f.to_dict() for f in findings]
        except Exception as e:
            if self.verbose:
                print(f"    ⚠️  Error in storage collision detector: {e}")
            return []

    def _run_flash_loan_simulator(self, target_path: str) -> List[Dict[str, Any]]:
        """Run flash loan simulator"""
        try:
            simulator = FlashLoanSimulator(verbose=False)
            findings = simulator.analyze_directory(target_path)
            return [f.to_dict() for f in findings]
        except Exception as e:
            if self.verbose:
                print(f"    ⚠️  Error in flash loan simulator: {e}")
            return []

    def _run_state_desync_analyzer(self, target_path: str) -> List[Dict[str, Any]]:
        """Run state desync analyzer"""
        try:
            analyzer = StateDesyncAnalyzer(verbose=False)
            findings = analyzer.analyze_directory(target_path)
            return [f.to_dict() for f in findings]
        except Exception as e:
            if self.verbose:
                print(f"    ⚠️  Error in state desync analyzer: {e}")
            return []

    def _run_oracle_manipulation_detector(
        self, target_path: str
    ) -> List[Dict[str, Any]]:
        """Run oracle manipulation detector"""
        try:
            detector = OracleManipulationDetector(verbose=False)
            findings = detector.analyze_directory(target_path)
            return [f.to_dict() for f in findings]
        except Exception as e:
            if self.verbose:
                print(f"    ⚠️  Error in oracle manipulation detector: {e}")
            return []

    def _print_summary(self):
        """Print summary of all findings"""
        if not self.results:
            return

        print("\n" + "=" * 80)
        print("📊 ELITE DETECTOR SUMMARY")
        print("=" * 80)

        print(f"\n🔍 Storage Collision Detector:")
        print(f"   Total: {len(self.results.storage_collision_findings)}")
        storage_critical = sum(
            1
            for f in self.results.storage_collision_findings
            if f.get("severity") == "critical"
        )
        storage_high = sum(
            1
            for f in self.results.storage_collision_findings
            if f.get("severity") == "high"
        )
        print(f"   Critical: {storage_critical} | High: {storage_high}")

        print(f"\n💰 Flash Loan Simulator:")
        print(f"   Total: {len(self.results.flash_loan_findings)}")
        flash_critical = sum(
            1
            for f in self.results.flash_loan_findings
            if f.get("severity") == "critical"
        )
        flash_high = sum(
            1 for f in self.results.flash_loan_findings if f.get("severity") == "high"
        )
        print(f"   Critical: {flash_critical} | High: {flash_high}")
        profitable = sum(
            1
            for f in self.results.flash_loan_findings
            if f.get("attack_scenario", {}).get("is_profitable", False)
        )
        print(f"   Profitable Attacks: {profitable}")

        print(f"\n🔄 State Desync Analyzer:")
        print(f"   Total: {len(self.results.state_desync_findings)}")
        desync_critical = sum(
            1
            for f in self.results.state_desync_findings
            if f.get("severity") == "critical"
        )
        desync_high = sum(
            1 for f in self.results.state_desync_findings if f.get("severity") == "high"
        )
        print(f"   Critical: {desync_critical} | High: {desync_high}")

        print(f"\n🔮 Oracle Manipulation Detector:")
        print(f"   Total: {len(self.results.oracle_manipulation_findings)}")
        oracle_critical = sum(
            1
            for f in self.results.oracle_manipulation_findings
            if f.get("severity") == "critical"
        )
        oracle_high = sum(
            1
            for f in self.results.oracle_manipulation_findings
            if f.get("severity") == "high"
        )
        print(f"   Critical: {oracle_critical} | High: {oracle_high}")
        flash_loan_attacks = sum(
            1
            for f in self.results.oracle_manipulation_findings
            if f.get("flash_loan_required", False)
        )
        print(f"   Flash Loan Attacks: {flash_loan_attacks}")

        print(f"\n{'=' * 80}")
        print(f"🎯 TOTAL FINDINGS: {self.results.total_findings}")
        print(f"🔴 CRITICAL: {self.results.critical_count}")
        print(f"🟠 HIGH: {self.results.high_count}")
        print(f"{'=' * 80}")

        if self.results.critical_count > 0:
            print("\n⚠️  CRITICAL VULNERABILITIES DETECTED - IMMEDIATE ACTION REQUIRED")
        elif self.results.high_count > 0:
            print(
                "\n⚠️  HIGH SEVERITY VULNERABILITIES DETECTED - PROMPT ACTION REQUIRED"
            )
        else:
            print("\n✓ No critical or high severity vulnerabilities detected")

    def save_report(self, output_path: str):
        """Save comprehensive report to file"""
        if not self.results:
            print("No results to save. Run detectors first.")
            return

        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0",
                "detector_suite": "Elite Web3 Bug Hunter",
            },
            "results": self.results.to_dict(),
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        if self.verbose:
            print(f"\n📄 Full report saved to: {output_path}")

    def generate_bug_bounty_report(self, output_path: str):
        """Generate bug bounty submission-ready report"""
        if not self.results:
            print("No results to report. Run detectors first.")
            return

        # Filter to only high-confidence, high-severity findings
        critical_findings = []
        high_findings = []

        for findings_list in [
            self.results.storage_collision_findings,
            self.results.flash_loan_findings,
            self.results.state_desync_findings,
            self.results.oracle_manipulation_findings,
        ]:
            for finding in findings_list:
                if (
                    finding.get("severity") == "critical"
                    and finding.get("confidence", 0) >= 0.85
                ):
                    critical_findings.append(finding)
                elif (
                    finding.get("severity") == "high"
                    and finding.get("confidence", 0) >= 0.80
                ):
                    high_findings.append(finding)

        report = {
            "title": f"Elite Web3 Security Audit - {len(critical_findings)} Critical Issues",
            "severity": "Critical"
            if critical_findings
            else "High"
            if high_findings
            else "Medium",
            "summary": self._generate_executive_summary(
                critical_findings, high_findings
            ),
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "impact": self._calculate_impact(critical_findings, high_findings),
            "recommendations": self._generate_recommendations(
                critical_findings, high_findings
            ),
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(critical_findings) + len(high_findings),
                "critical_count": len(critical_findings),
                "high_count": len(high_findings),
            },
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        if self.verbose:
            print(f"\n📋 Bug bounty report saved to: {output_path}")

    def _generate_executive_summary(self, critical: List, high: List) -> str:
        """Generate executive summary for bug bounty report"""
        summary = f"This audit identified {len(critical)} critical and {len(high)} high severity vulnerabilities "
        summary += "using elite-tier detection methods that focus on:\n\n"
        summary += "1. Storage Collision Attacks (Proxy/Inheritance Issues)\n"
        summary += "2. Flash Loan Economic Exploits (Profitability Analysis)\n"
        summary += "3. Multi-Transaction State Desynchronization\n"
        summary += "4. Oracle Manipulation Vectors\n\n"

        if critical:
            summary += "CRITICAL VULNERABILITIES:\n"
            for i, finding in enumerate(critical[:3], 1):
                summary += f"{i}. {finding.get('category', 'Unknown')}: {finding.get('description', '')[:100]}...\n"

        return summary

    def _calculate_impact(self, critical: List, high: List) -> Dict[str, Any]:
        """Calculate economic impact"""
        # Estimate TVL at risk
        total_tvl = 0
        for finding in critical + high:
            if "tvl_at_risk" in finding:
                try:
                    tvl = float(finding["tvl_at_risk"])
                    total_tvl += tvl
                except:
                    pass

        # Calculate potential profit for attacker
        total_profit = 0
        for finding in critical + high:
            if "potential_profit" in finding:
                try:
                    profit = float(finding["potential_profit"])
                    total_profit += profit
                except:
                    pass

        return {
            "tvl_at_risk": f"${total_tvl:,.0f}",
            "potential_attacker_profit": f"${total_profit:,.0f}",
            "exploitability": "High"
            if any(f.get("exploitability") == "high" for f in critical)
            else "Medium",
            "requires_flash_loan": any(
                f.get("flash_loan_required", False) for f in critical + high
            ),
        }

    def _generate_recommendations(self, critical: List, high: List) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []

        # Storage collision fixes
        if any("storage" in f.get("category", "") for f in critical + high):
            recommendations.append(
                "1. STORAGE COLLISION: Audit all proxy patterns. Align storage layouts. Use storage gaps."
            )

        # Flash loan fixes
        if any("flash_loan" in f.get("category", "") for f in critical + high):
            recommendations.append(
                "2. FLASH LOAN PROTECTION: Implement flash loan detection. Use TWAP oracles. Add price impact limits."
            )

        # State desync fixes
        if any("desync" in f.get("category", "") for f in critical + high):
            recommendations.append(
                "3. STATE VALIDATION: Add staleness checks. Use atomic operations. Implement mutex locks."
            )

        # Oracle fixes
        if any("oracle" in f.get("category", "") for f in critical + high):
            recommendations.append(
                "4. ORACLE SECURITY: Replace spot prices with TWAP. Add Chainlink validation. Implement circuit breakers."
            )

        return recommendations


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Elite Web3 Vulnerability Detector Suite"
    )
    parser.add_argument("target", help="Target directory to analyze")
    parser.add_argument(
        "--output",
        "-o",
        default="elite_detector_report.json",
        help="Output file path for full report",
    )
    parser.add_argument(
        "--bounty-report",
        "-b",
        default="bug_bounty_submission.json",
        help="Output file path for bug bounty report",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Run orchestrator
    orchestrator = EliteDetectorOrchestrator(verbose=args.verbose)
    results = orchestrator.run_all_detectors(args.target)

    # Save reports
    orchestrator.save_report(args.output)
    orchestrator.generate_bug_bounty_report(args.bounty_report)

    # Exit with error code if critical issues found
    if results.critical_count > 0:
        sys.exit(1)
    elif results.high_count > 0:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
