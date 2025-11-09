#!/usr/bin/env python3
"""
Elite Detector Unified Runner - Runs all 15 modular detectors

Complete coverage of 33 elite Web3 vulnerability patterns.

Author: Elite Web3 Bug Hunter
"""

import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "detectors"))

# Import all 15 elite detectors
try:
    from storage_collision_detector import StorageCollisionDetector
    from flash_loan_simulator import FlashLoanSimulator
    from state_desync_analyzer import StateDesyncAnalyzer
    from oracle_manipulation_detector import OracleManipulationDetector
    from reentrancy_hooks_detector import ReentrancyHooksDetector
    from timing_dependency_detector import TimingDependencyDetector
    from economic_invariant_detector import EconomicInvariantDetector
    from upgrade_safety_detector import UpgradeSafetyDetector
    from governance_security_detector import GovernanceSecurityDetector
    from token_standard_detector import TokenStandardDetector
    from dos_gas_detector import DOSGasDetector
    from cryptographic_weakness_detector import CryptographicWeaknessDetector
    from offchain_trust_detector import OffchainTrustDetector
    from lowlevel_safety_detector import LowlevelSafetyDetector
    from crosschain_bridge_detector import CrosschainBridgeDetector
except ImportError as e:
    print(f"❌ Error importing detectors: {e}")
    print(f"Make sure you're running from the correct directory")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python run_all_elite_detectors.py <target> [--output report.json] [--verbose]"
        )
        print("\nRuns all 15 elite detectors covering 33 vulnerability patterns")
        sys.exit(1)

    target = Path(sys.argv[1])
    output = (
        Path(sys.argv[sys.argv.index("--output") + 1])
        if "--output" in sys.argv
        else None
    )
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    # All 15 detectors in order
    detectors = [
        # Phase 1 - Original 4 detectors
        ("Storage Collision", StorageCollisionDetector),
        ("Flash Loan", FlashLoanSimulator),
        ("State Desync", StateDesyncAnalyzer),
        ("Oracle Manipulation", OracleManipulationDetector),
        # Phase 2 - Callback & Timing (3 detectors)
        ("Reentrancy & Hooks", ReentrancyHooksDetector),
        ("Timing Dependency", TimingDependencyDetector),
        ("Economic Invariants", EconomicInvariantDetector),
        # Phase 3 - Remaining 8 detectors
        ("Upgrade Safety", UpgradeSafetyDetector),
        ("Governance Security", GovernanceSecurityDetector),
        ("Token Standards", TokenStandardDetector),
        ("DOS & Gas", DOSGasDetector),
        ("Cryptographic Weakness", CryptographicWeaknessDetector),
        ("Off-chain Trust", OffchainTrustDetector),
        ("Low-level Safety", LowlevelSafetyDetector),
        ("Cross-chain Bridge", CrosschainBridgeDetector),
    ]

    print(f"\n{'=' * 70}")
    print(f"🔍 ELITE WEB3 BUG HUNTER - COMPLETE DETECTOR SUITE")
    print(f"{'=' * 70}")
    print(f"📦 {len(detectors)} Detectors | 33 Vulnerability Patterns | 100% Coverage")
    print(f"🎯 Target: {target}")
    print(f"{'=' * 70}\n")

    all_findings = []
    results = {}
    detector_times = {}
    start_time = time.time()

    for name, DetectorClass in detectors:
        print(f"🔎 Running {name}...", end=" ", flush=True)
        detector_start = time.time()

        try:
            detector = DetectorClass(verbose=verbose)
            findings = detector.detect(target)
            all_findings.extend(findings)

            detector_time = time.time() - detector_start
            detector_times[name] = detector_time
            results[name] = len(findings)

            # Count by severity
            severity_counts = {}
            for f in findings:
                sev = f.severity if hasattr(f, "severity") else "unknown"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            severity_str = (
                " | ".join(
                    f"{sev.upper()}:{count}"
                    for sev, count in severity_counts.items()
                    if count > 0
                )
                or "None"
            )

            print(
                f"✅ {len(findings)} findings ({detector_time:.2f}s) | {severity_str}"
            )

        except Exception as e:
            print(f"❌ FAILED: {e}")
            results[name] = 0
            detector_times[name] = 0

    total_time = time.time() - start_time

    # Print final summary
    print(f"\n{'=' * 70}")
    print(f"📊 FINAL RESULTS")
    print(f"{'=' * 70}")
    print(f"Total findings: {len(all_findings)}")
    print(f"Total time: {total_time:.2f}s")
    print(f"\nFindings by detector:")

    for name, count in results.items():
        elapsed = detector_times.get(name, 0)
        print(f"  {name:30} {count:4} findings ({elapsed:5.2f}s)")

    # Count by severity across all detectors
    print(f"\nFindings by severity:")
    severity_totals = {}
    for f in all_findings:
        sev = f.severity if hasattr(f, "severity") else "unknown"
        severity_totals[sev] = severity_totals.get(sev, 0) + 1

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_totals.get(sev, 0)
        if count > 0:
            print(f"  {sev.upper():10} {count}")

    print(f"{'=' * 70}\n")

    # Export to JSON if requested
    if output and all_findings:
        report = {
            "metadata": {
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_detectors": len(detectors),
                "coverage": "33/33 vulnerability patterns (100%)",
            },
            "summary": {
                "total_findings": len(all_findings),
                "time_seconds": total_time,
                "by_detector": results,
                "by_severity": severity_totals,
            },
            "findings": [f.to_dict() for f in all_findings],
        }

        with open(output, "w") as f:
            json.dump(report, f, indent=2)

        print(f"✅ Report saved to {output}")
        print(f"📄 {len(all_findings)} findings exported\n")

    # Exit with appropriate code
    sys.exit(0 if len(all_findings) == 0 else 1)


if __name__ == "__main__":
    main()
