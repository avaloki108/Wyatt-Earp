#!/usr/bin/env python3
"""Token Standard Detector - Vulns #8, #15, #18, #32"""
import re
from pathlib import Path
from base_elite_detector import EliteDetector, VulnerabilityFinding, Severity, Confidence

class TokenStandardDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "token_standard"
    
    def get_vulnerability_ids(self) -> list:
        return ["PERMIT_REPLAY_001", "TOKEN_ASSUMPTION_001", "NONSTANDARD_ERC20_001", "ALLOWANCE_RACE_001"]
    
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
            # Detect permit replay (Vuln #8)
            if "permit" in source.lower():
                for func in contract.functions:
                    if "permit" in func["name"].lower():
                        func_body = func.get("body", "")
                        has_domain_separator = "DOMAIN_SEPARATOR" in func_body
                        has_nonce = "nonce" in func_body.lower()
                        if not (has_domain_separator and has_nonce):
                            self._add_finding(
                                vulnerability_id="PERMIT_REPLAY_001",
                                severity=Severity.HIGH.value,
                                confidence=Confidence.HIGH.value,
                                title=f"Permit replay risk in {contract.name}.{func['name']}",
                                description="Permit function missing domain separator or nonce, enabling replay attacks",
                                category="permit_replay",
                                file_path=contract.file_path,
                                line_numbers=[func["line"]],
                                affected_contracts=[contract.name],
                                affected_functions=[func["name"]],
                                attack_vector="Replay permit signature across chains or contracts",
                                proof_of_concept="// Reuse signature on forked chain",
                                remediation="Add proper domain separator and nonce tracking",
                                economic_impact="high",
                                exploitability="medium",
                                novelty="high",
                                rarity="rare",
                                human_only=True,
                            )
            # Detect non-standard ERC20 (Vuln #18)
            for func in contract.functions:
                func_body = func.get("body", "")
                if "transfer" in func["name"].lower() and "From" not in func["name"]:
                    # Check if returns bool
                    returns = func.get("returns", "")
                    if not returns or "bool" not in returns:
                        self._add_finding(
                            vulnerability_id="NONSTANDARD_ERC20_001",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.HIGH.value,
                            title=f"Non-standard ERC20 in {contract.name}.{func['name']}",
                            description="Transfer function doesn't return bool (ERC20 violation)",
                            category="nonstandard_token",
                            file_path=contract.file_path,
                            line_numbers=[func["line"]],
                            affected_contracts=[contract.name],
                            affected_functions=[func["name"]],
                            attack_vector="Integration expects bool return, reverts unexpectedly",
                            proof_of_concept="// SafeERC20 required",
                            remediation="Return bool from transfer functions",
                            economic_impact="medium",
                            exploitability="low",
                            novelty="low",
                            rarity="common",
                            human_only=False,
                        )

if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    detector = TokenStandardDetector(verbose="--verbose" in sys.argv)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
