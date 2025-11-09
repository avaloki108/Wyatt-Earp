#!/usr/bin/env python3
"""Low-level Safety Detector - Vulns #11, #17, #21"""
import re
from pathlib import Path
from base_elite_detector import EliteDetector, VulnerabilityFinding, Severity, Confidence

class LowlevelSafetyDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "lowlevel_safety"
    
    def get_vulnerability_ids(self) -> list:
        return ["FORCED_ETHER_001", "CALLDATA_PACK_001", "ASSEMBLY_MEMORY_001"]
    
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
            # Detect forced ether assumption (Vuln #11)
            for func in contract.functions:
                func_body = func.get("body", "")
                checks_exact_balance = re.search(r"(require|if)\s*\([^)]*address\(this\)\.balance\s*==", func_body)
                if checks_exact_balance:
                    self._add_finding(
                        vulnerability_id="FORCED_ETHER_001",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.HIGH.value,
                        title=f"Forced ether invariant in {contract.name}.{func['name']}",
                        description="Function checks exact balance, broken by selfdestruct forced ether",
                        category="forced_ether",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        attack_vector="Attacker selfdestructs into contract, breaking balance invariant",
                        proof_of_concept="// selfdestruct(targetContract) adds ether",
                        remediation="Don't rely on exact balance checks",
                        economic_impact="medium",
                        exploitability="easy",
                        novelty="medium",
                        rarity="uncommon",
                        human_only=True,
                    )
            # Detect unsafe assembly (Vuln #21)
            if "assembly" in source:
                for func in contract.functions:
                    func_body = func.get("body", "")
                    if "assembly" in func_body:
                        # Check for mload without bounds check
                        has_mload = "mload" in func_body
                        has_bounds_check = "length" in func_body or "size" in func_body
                        if has_mload and not has_bounds_check:
                            self._add_finding(
                                vulnerability_id="ASSEMBLY_MEMORY_001",
                                severity=Severity.HIGH.value,
                                confidence=Confidence.MEDIUM.value,
                                title=f"Unsafe assembly in {contract.name}.{func['name']}",
                                description="Assembly mload without bounds checking",
                                category="assembly_safety",
                                file_path=contract.file_path,
                                line_numbers=[func["line"]],
                                affected_contracts=[contract.name],
                                affected_functions=[func["name"]],
                                attack_vector="Out-of-bounds memory read, data corruption",
                                proof_of_concept="// mload past array end",
                                remediation="Add explicit length checks before mload",
                                economic_impact="high",
                                exploitability="medium",
                                novelty="high",
                                rarity="rare",
                                human_only=True,
                            )

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    detector = LowlevelSafetyDetector(verbose="--verbose" in sys.argv)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
