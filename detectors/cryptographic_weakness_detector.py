#!/usr/bin/env python3
"""Cryptographic Weakness Detector - Vuln #26"""
import re
from pathlib import Path
from base_elite_detector import EliteDetector, VulnerabilityFinding, Severity, Confidence

class CryptographicWeaknessDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "cryptographic_weakness"
    
    def get_vulnerability_ids(self) -> list:
        return ["BAD_RNG_001"]
    
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
            for func in contract.functions:
                func_body = func.get("body", "")
                # Check for predictable RNG
                has_random = re.search(r"(random|rand)", func_body, re.IGNORECASE)
                uses_timestamp = "block.timestamp" in func_body or "now" in func_body
                uses_blockhash = "blockhash" in func_body
                if has_random and (uses_timestamp or uses_blockhash):
                    self._add_finding(
                        vulnerability_id="BAD_RNG_001",
                        severity=Severity.CRITICAL.value,
                        confidence=Confidence.HIGH.value,
                        title=f"Predictable RNG in {contract.name}.{func['name']}",
                        description="Function uses block.timestamp or blockhash for randomness - predictable!",
                        category="bad_rng",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        attack_vector="Attacker predicts random value, always wins lottery/gambling",
                        proof_of_concept="// Calculate blockhash/timestamp, submit winning tx",
                        remediation="Use Chainlink VRF or commit-reveal scheme",
                        economic_impact="critical",
                        exploitability="easy",
                        novelty="low",
                        rarity="uncommon",
                        human_only=False,
                    )

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    detector = CryptographicWeaknessDetector(verbose="--verbose" in sys.argv)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
