#!/usr/bin/env python3
"""DOS & Gas Detector - Vulns #13, #25"""
import re
from pathlib import Path
from base_elite_detector import EliteDetector, VulnerabilityFinding, Severity, Confidence

class DOSGasDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "dos_gas"
    
    def get_vulnerability_ids(self) -> list:
        return ["GAS_GRIEF_001", "RESOURCE_EXHAUST_001"]
    
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
            # Detect unbounded loops (Vuln #13, #25)
            for func in contract.functions:
                func_body = func.get("body", "")
                # Check for loops over user-controlled arrays
                has_loop = re.search(r"for\s*\(", func_body)
                if has_loop:
                    # Check if loop iterates over .length of state array
                    loops_array = re.search(r"\.length", func_body)
                    if loops_array:
                        self._add_finding(
                            vulnerability_id="GAS_GRIEF_001",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.HIGH.value,
                            title=f"Unbounded loop in {contract.name}.{func['name']}",
                            description="Function loops over unbounded array, enabling DOS via gas exhaustion",
                            category="gas_griefing",
                            file_path=contract.file_path,
                            line_numbers=[func["line"]],
                            affected_contracts=[contract.name],
                            affected_functions=[func["name"]],
                            attack_vector="Attacker bloats array, making function uncallable",
                            proof_of_concept="// Push 10000 items to array, function runs out of gas",
                            remediation="Use pagination or bounded iterations",
                            economic_impact="high",
                            exploitability="easy",
                            novelty="low",
                            rarity="common",
                            human_only=False,
                        )

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    detector = DOSGasDetector(verbose="--verbose" in sys.argv)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
