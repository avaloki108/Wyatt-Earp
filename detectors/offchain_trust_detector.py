#!/usr/bin/env python3
"""Off-chain Trust Detector - Vulns #16, #31"""
import re
from pathlib import Path
from base_elite_detector import EliteDetector, VulnerabilityFinding, Severity, Confidence

class OffchainTrustDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "offchain_trust"
    
    def get_vulnerability_ids(self) -> list:
        return ["EVENT_TRUST_001", "VIEW_SHADOW_001"]
    
    def detect(self, target_path: Path) -> list:
        self.findings = []
        if target_path.is_file():
            self._analyze_file(target_path)
        else:
            for sol_file in self.scan_directory(target_path):
                self._analyze_file(sol_file)
        return self.findings
    
    def _analyze_file(self, file_path: Path) -> None:
        source = self.load_contract(file_path)
        if not source:
            return
        contracts = self.parse_contracts(source, str(file_path))
        for contract in contracts:
            if contract.is_interface:
                continue
            # Detect reliance on events for critical logic
            for func in contract.functions:
                func_body = func.get("body", "")
                # Check if function emits event and relies on it
                has_emit = "emit " in func_body
                has_comment_trust = "indexer" in func_body.lower() or "offchain" in func_body.lower()
                if has_emit and has_comment_trust:
                    self._add_finding(
                        vulnerability_id="EVENT_TRUST_001",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.MEDIUM.value,
                        title=f"Off-chain event trust in {contract.name}.{func['name']}",
                        description="Function trusts off-chain indexer to process events correctly",
                        category="event_trust",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        attack_vector="Indexer manipulation or missing events",
                        proof_of_concept="// Event not emitted in revert case",
                        remediation="Don't rely on events for authoritative state",
                        economic_impact="medium",
                        exploitability="low",
                        novelty="high",
                        rarity="uncommon",
                        human_only=True,
                    )

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    detector = OffchainTrustDetector(verbose="--verbose" in sys.argv)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
