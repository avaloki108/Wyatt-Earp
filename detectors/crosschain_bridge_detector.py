#!/usr/bin/env python3
"""Cross-chain Bridge Detector - Vuln #23"""
import re
from pathlib import Path
from base_elite_detector import EliteDetector, VulnerabilityFinding, Severity, Confidence

class CrosschainBridgeDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "crosschain_bridge"
    
    def get_vulnerability_ids(self) -> list:
        return ["BRIDGE_FINALITY_001"]
    
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
            # Check for bridge/relayer patterns
            is_bridge = any(kw in source.lower() for kw in ["bridge", "relay", "crosschain", "portal"])
            if not is_bridge:
                continue
            # Detect message processing without finality checks
            for func in contract.functions:
                func_body = func.get("body", "")
                processes_message = "message" in func_body.lower() or "proof" in func_body.lower()
                has_finality_check = "finality" in func_body.lower() or "confirmation" in func_body.lower()
                if processes_message and not has_finality_check:
                    self._add_finding(
                        vulnerability_id="BRIDGE_FINALITY_001",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        title=f"Bridge finality assumption in {contract.name}.{func['name']}",
                        description="Bridge processes messages without finality checks, vulnerable to reorgs",
                        category="bridge_finality",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        attack_vector="Chain reorg causes double-spending or message replay",
                        proof_of_concept="// Process message on fork, then replay on canonical chain",
                        remediation="Add finality delay or confirmation threshold",
                        economic_impact="critical",
                        exploitability="hard",
                        novelty="very_high",
                        rarity="rare",
                        human_only=True,
                    )

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    detector = CrosschainBridgeDetector(verbose="--verbose" in sys.argv)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
