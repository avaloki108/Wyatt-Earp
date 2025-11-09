#!/usr/bin/env python3
"""
Governance Security Detector - Elite-tier vulnerability detection

Detects:
- Vuln #9: Governance snapshot/gaming by composability
- Vuln #19: Implicit-authorization via tx.origin or msg.sender mistakes
- Vuln #27: Implicit trust in off-chain relayers/keepers

Author: Elite Web3 Bug Hunter
Category: Governance & Access Control
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from base_elite_detector import (
    EliteDetector,
    VulnerabilityFinding,
    Severity,
    Confidence,
    ContractInfo,
)


class GovernanceSecurityDetector(EliteDetector):
    def get_detector_name(self) -> str:
        return "governance_security"

    def get_vulnerability_ids(self) -> List[str]:
        return ["SNAPSHOT_GAMING_001", "TX_ORIGIN_001", "RELAYER_TRUST_001"]

    def detect(self, target_path: Path) -> List[VulnerabilityFinding]:
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
            self._detect_snapshot_gaming(contract)
            self._detect_tx_origin_misuse(contract)
            self._detect_relayer_trust(contract)

    def _detect_snapshot_gaming(self, contract: ContractInfo) -> None:
        """Detect governance snapshot gaming (Vuln #9)"""
        for func in contract.functions:
            func_body = func.get("body", "")
            # Check for voting/governance functions
            is_vote_func = any(
                kw in func["name"].lower() for kw in ["vote", "proposal", "ballot"]
            )
            if not is_vote_func:
                continue
            # Check if uses current balance instead of snapshot
            uses_current_balance = re.search(
                r"balanceOf\s*\(\s*[^)]+\)", func_body
            ) and not re.search(r"snapshot", func_body, re.IGNORECASE)
            if uses_current_balance:
                self._add_finding(
                    vulnerability_id="SNAPSHOT_GAMING_001",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    title=f"Snapshot gaming in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' uses current token balance for voting "
                        f"power instead of snapshots. Attackers can flash-borrow tokens, "
                        f"vote, and return tokens in one transaction to manipulate governance."
                    ),
                    category="snapshot_gaming",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    attack_vector=(
                        "1. Flash loan large token amount\n"
                        "2. Vote with inflated balance\n"
                        "3. Return tokens\n"
                        "4. Governance manipulated in single tx"
                    ),
                    proof_of_concept="// Flash loan tokens -> vote() -> return tokens",
                    remediation="Use snapshot-based voting (past block numbers)",
                    economic_impact="critical",
                    exploitability="medium",
                    requires_flash_loan=True,
                    novelty="high",
                    rarity="rare",
                    human_only=True,
                )

    def _detect_tx_origin_misuse(self, contract: ContractInfo) -> None:
        """Detect tx.origin misuse (Vuln #19)"""
        source = contract.source_code or ""
        if "tx.origin" in source:
            # Find all uses of tx.origin
            for func in contract.functions:
                func_body = func.get("body", "")
                if "tx.origin" in func_body:
                    # Check if used for auth
                    has_tx_origin_auth = re.search(
                        r"(require|if)\s*\([^)]*tx\.origin", func_body
                    )
                    if has_tx_origin_auth:
                        self._add_finding(
                            vulnerability_id="TX_ORIGIN_001",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.HIGH.value,
                            title=f"tx.origin authentication in {contract.name}.{func['name']}",
                            description=(
                                f"Function '{func['name']}' uses tx.origin for authentication. "
                                f"This is vulnerable to phishing attacks where user interacts "
                                f"with malicious contract that calls back to this contract."
                            ),
                            category="tx_origin_misuse",
                            file_path=contract.file_path,
                            line_numbers=[func["line"]],
                            affected_contracts=[contract.name],
                            affected_functions=[func["name"]],
                            attack_vector=(
                                "1. Attacker deploys malicious contract\n"
                                "2. User calls attacker contract\n"
                                "3. Attacker contract calls vulnerable function\n"
                                "4. tx.origin check passes (is user)\n"
                                "5. Unauthorized action executed"
                            ),
                            proof_of_concept="// Phishing contract calls victim with user's tx.origin",
                            remediation="Use msg.sender instead of tx.origin",
                            economic_impact="high",
                            exploitability="easy",
                            novelty="medium",
                            rarity="uncommon",
                            human_only=False,
                        )

    def _detect_relayer_trust(self, contract: ContractInfo) -> None:
        """Detect implicit trust in relayers/keepers (Vuln #27)"""
        for func in contract.functions:
            func_body = func.get("body", "")
            # Check for keeper/relayer patterns
            is_keeper_func = any(
                kw in func["name"].lower() for kw in ["keeper", "relayer", "perform", "execute"]
            )
            if not is_keeper_func:
                continue
            # Check if there's slashing or penalty mechanism
            has_penalty = any(
                kw in func_body.lower() for kw in ["slash", "penalty", "punish", "bond"]
            )
            if not has_penalty:
                self._add_finding(
                    vulnerability_id="RELAYER_TRUST_001",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.MEDIUM.value,
                    title=f"Unpenalized relayer in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' relies on off-chain relayer/keeper "
                        f"but has no slashing or penalty mechanism. Relayer can act "
                        f"maliciously or go offline without consequences."
                    ),
                    category="relayer_trust",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    attack_vector="Relayer censors transactions or acts maliciously",
                    proof_of_concept="// Relayer delays/censors critical operations",
                    remediation="Add bond/slash mechanism or fallback execution",
                    economic_impact="medium",
                    exploitability="medium",
                    novelty="high",
                    rarity="uncommon",
                    human_only=True,
                )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python governance_security_detector.py <target> [--output output.json]")
        sys.exit(1)
    target = Path(sys.argv[1])
    output = Path(sys.argv[sys.argv.index("--output") + 1]) if "--output" in sys.argv else None
    verbose = "--verbose" in sys.argv
    detector = GovernanceSecurityDetector(verbose=verbose)
    findings = detector.detect(target)
    detector.print_summary()
    if output:
        detector.export_findings(output)
    sys.exit(0 if len(findings) == 0 else 1)
