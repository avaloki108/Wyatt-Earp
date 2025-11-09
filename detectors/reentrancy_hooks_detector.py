#!/usr/bin/env python3
"""
Reentrancy & Hooks Detector - Elite-tier vulnerability detection

Detects:
- Vuln #6: Phantom reentrancy (logical reentrancy)
- Vuln #14: Payable fallback / ERC777 hooks triggering unexpected side effects
- Vuln #29: Privilege escalation through fallback/receive redirects

Author: Elite Web3 Bug Hunter
Category: Callback & Hook Security
"""

import re
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from base_elite_detector import (
    EliteDetector,
    VulnerabilityFinding,
    Severity,
    Confidence,
    SolidityParser,
    ContractInfo,
)


class ReentrancyHooksDetector(EliteDetector):
    """
    Detects subtle reentrancy and callback-related vulnerabilities

    Goes beyond simple reentrancy to detect:
    1. Logical reentrancy where callbacks affect other functions
    2. Token hooks (ERC777, ERC1363) causing state inconsistencies
    3. Privilege escalation through receive/fallback callbacks
    """

    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.state_changing_funcs: Dict[str, List[str]] = {}
        self.external_call_funcs: Dict[str, List[str]] = {}

    def get_detector_name(self) -> str:
        return "reentrancy_hooks"

    def get_vulnerability_ids(self) -> List[str]:
        return ["PHANTOM_REENTRY_001", "TOKEN_HOOK_001", "CALLBACK_PRIV_ESC_001"]

    def detect(self, target_path: Path) -> List[VulnerabilityFinding]:
        """Main detection logic"""
        self.findings = []

        if target_path.is_file():
            self._analyze_file(target_path)
        else:
            for sol_file in self.scan_directory(target_path):
                self._analyze_file(sol_file)

        return self.findings

    def _analyze_file(self, file_path: Path) -> None:
        """Analyze a single Solidity file"""
        source = self.load_contract(file_path)
        if not source:
            return

        contracts = self.parse_contracts(source, str(file_path))

        for contract in contracts:
            if contract.is_interface or contract.is_library:
                continue

            # Build state change and external call maps
            self._build_function_maps(contract)

            # Check for phantom reentrancy
            self._detect_phantom_reentrancy(contract)

            # Check for token hooks vulnerabilities
            self._detect_token_hook_issues(contract)

            # Check for callback privilege escalation
            self._detect_callback_privilege_escalation(contract)

    def _build_function_maps(self, contract: ContractInfo) -> None:
        """Build maps of state-changing and external-calling functions"""
        contract_key = f"{contract.file_path}:{contract.name}"

        self.state_changing_funcs[contract_key] = []
        self.external_call_funcs[contract_key] = []

        for func in contract.functions:
            func_body = func.get("body", "")

            # Check for state changes
            if self._has_state_changes(func_body, contract):
                self.state_changing_funcs[contract_key].append(func["name"])

            # Check for external calls
            if self._has_external_calls(func_body):
                self.external_call_funcs[contract_key].append(func["name"])

    def _has_state_changes(self, code: str, contract: ContractInfo) -> bool:
        """Check if code modifies contract state"""
        # Look for assignments to state variables
        for var in contract.state_variables:
            var_name = var["name"]
            # Pattern: varName = or varName += etc
            if re.search(rf"\b{var_name}\s*[+\-*/]?=", code):
                return True
            # Pattern: mapping[key] =
            if re.search(rf"\b{var_name}\[", code):
                return True

        # Look for storage keyword or delete
        if re.search(r"\bstorage\b", code) or "delete " in code:
            return True

        return False

    def _has_external_calls(self, code: str) -> bool:
        """Check if code makes external calls"""
        external_patterns = [
            r"\.call\{",
            r"\.call\(",
            r"\.delegatecall\(",
            r"\.staticcall\(",
            r"\.transfer\(",
            r"\.send\(",
            r"payable\([^)]+\)\.call",
        ]

        return any(re.search(pattern, code) for pattern in external_patterns)

    def _detect_phantom_reentrancy(self, contract: ContractInfo) -> None:
        """
        Detect phantom/logical reentrancy (Vuln #6)

        Pattern:
        1. Function makes external call
        2. Another function can be called during callback
        3. State assumptions are violated
        """
        contract_key = f"{contract.file_path}:{contract.name}"

        for func in contract.functions:
            if func["name"] not in self.external_call_funcs.get(contract_key, []):
                continue

            func_body = func.get("body", "")

            # Check for CEI pattern violation (Checks-Effects-Interactions)
            cei_violation = self._check_cei_violation(func_body, contract)

            if cei_violation:
                # Check if contract has reentrancy guard
                has_guard = self._has_reentrancy_guard(
                    func_body
                ) or self._contract_has_reentrancy_guard(contract)

                if not has_guard:
                    # High severity if no guard and state changes after external call
                    severity = Severity.HIGH.value
                    confidence = Confidence.HIGH.value

                    self._add_finding(
                        vulnerability_id="PHANTOM_REENTRY_001",
                        severity=severity,
                        confidence=confidence,
                        title=f"Phantom reentrancy in {contract.name}.{func['name']}",
                        description=(
                            f"Function '{func['name']}' makes external calls and modifies state "
                            f"after the call, allowing logical reentrancy. An attacker can use "
                            f"callbacks to invoke other contract functions and violate business "
                            f"logic invariants."
                        ),
                        category="logical_reentrancy",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        vulnerable_code=func_body[:300],
                        attack_vector=(
                            "1. Attacker contract receives callback during external call\n"
                            "2. Callback invokes other functions on vulnerable contract\n"
                            "3. State assumptions are violated, enabling double-spending or logic breaks"
                        ),
                        proof_of_concept=self._generate_phantom_reentry_poc(
                            contract.name, func["name"]
                        ),
                        remediation=(
                            "1. Follow CEI pattern: Checks-Effects-Interactions\n"
                            "2. Use ReentrancyGuard on all state-changing functions\n"
                            "3. Consider using mutex locks across related functions\n"
                            "4. Move state updates before external calls"
                        ),
                        economic_impact="high",
                        exploitability="medium",
                        attack_complexity="medium",
                        requires_flash_loan=False,
                        requires_multi_tx=False,
                        novelty="very_high",
                        rarity="rare",
                        human_only=True,
                    )

    def _check_cei_violation(self, func_body: str, contract: ContractInfo) -> bool:
        """
        Check for CEI (Checks-Effects-Interactions) pattern violation
        Returns True if state changes occur after external calls
        """
        # Split function into lines
        lines = func_body.split("\n")

        external_call_line = -1
        state_change_line = -1

        for i, line in enumerate(lines):
            # Check for external call
            if self._has_external_calls(line):
                if external_call_line == -1:
                    external_call_line = i

            # Check for state change after external call
            if external_call_line != -1 and i > external_call_line:
                if self._has_state_changes(line, contract):
                    state_change_line = i
                    return True

        return False

    def _has_reentrancy_guard(self, code: str) -> bool:
        """Check if function has reentrancy guard modifier"""
        guard_patterns = [
            "nonReentrant",
            "noReentrancy",
            "reentrancyGuard",
            "mutex",
            "_locked",
        ]
        return any(pattern in code for pattern in guard_patterns)

    def _contract_has_reentrancy_guard(self, contract: ContractInfo) -> bool:
        """Check if contract implements any reentrancy guard"""
        if not contract.source_code:
            return False

        return self._has_reentrancy_guard(contract.source_code)

    def _detect_token_hook_issues(self, contract: ContractInfo) -> None:
        """
        Detect ERC777/ERC1363 token hook vulnerabilities (Vuln #14)

        Pattern:
        1. Contract accepts token transfers
        2. Token standard has hooks (tokensReceived, onTransferReceived)
        3. Hooks can trigger state changes
        """
        # Check if contract implements token receiver hooks
        hook_functions = [
            "tokensReceived",
            "onTransferReceived",
            "onApprovalReceived",
            "onERC721Received",
        ]

        for func in contract.functions:
            func_name = func["name"]
            func_body = func.get("body", "")

            # Check if this is a token hook
            if func_name in hook_functions:
                # Check if hook modifies state
                if self._has_state_changes(func_body, contract):
                    self._add_finding(
                        vulnerability_id="TOKEN_HOOK_001",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.HIGH.value,
                        title=f"State-changing token hook in {contract.name}.{func_name}",
                        description=(
                            f"Token receiver hook '{func_name}' modifies contract state. "
                            f"Malicious tokens can exploit this to trigger unintended state "
                            f"changes during token transfers, enabling reentrancy-like attacks."
                        ),
                        category="token_hook_exploit",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func_name],
                        vulnerable_code=func_body[:300],
                        attack_vector=(
                            "1. Attacker creates malicious ERC777/ERC1363 token\n"
                            "2. Token transfer triggers receiver hook\n"
                            "3. Hook modifies contract state unexpectedly\n"
                            "4. Attacker exploits state inconsistencies"
                        ),
                        proof_of_concept=self._generate_token_hook_poc(
                            contract.name, func_name
                        ),
                        remediation=(
                            "1. Avoid state changes in token receiver hooks\n"
                            "2. Use separate claiming mechanism instead of automatic processing\n"
                            "3. Whitelist trusted tokens only\n"
                            "4. Add reentrancy guards to hooks"
                        ),
                        economic_impact="high",
                        exploitability="medium",
                        attack_complexity="medium",
                        requires_flash_loan=False,
                        requires_multi_tx=False,
                        novelty="high",
                        rarity="uncommon",
                        human_only=True,
                    )

            # Also check for functions that call external token transfers
            if "transferFrom" in func_body or "safeTransferFrom" in func_body:
                # Check if state changes occur after token transfer
                if self._check_cei_violation(func_body, contract):
                    self._add_finding(
                        vulnerability_id="TOKEN_HOOK_001",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.MEDIUM.value,
                        title=f"Token transfer before state update in {contract.name}.{func_name}",
                        description=(
                            f"Function '{func_name}' performs token transfers before updating "
                            f"state. If token has hooks (ERC777/ERC1363), callback can exploit "
                            f"stale state."
                        ),
                        category="token_callback_race",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func_name],
                        vulnerable_code=func_body[:300],
                        attack_vector=(
                            "1. Function calls token.transferFrom() or safeTransferFrom()\n"
                            "2. Token hook is triggered before state update\n"
                            "3. Hook reads stale state and exploits inconsistency"
                        ),
                        proof_of_concept="// Malicious token hook can reenter and read stale balances",
                        remediation=(
                            "1. Update state before token transfers\n"
                            "2. Use reentrancy guards\n"
                            "3. Validate final state after transfers"
                        ),
                        economic_impact="medium",
                        exploitability="medium",
                        attack_complexity="low",
                        requires_flash_loan=False,
                        requires_multi_tx=False,
                        novelty="high",
                        rarity="uncommon",
                        human_only=True,
                    )

    def _detect_callback_privilege_escalation(self, contract: ContractInfo) -> None:
        """
        Detect privilege escalation through fallback/receive (Vuln #29)

        Pattern:
        1. Contract sends ETH to external address
        2. External address has receive/fallback
        3. Callback can call privileged functions
        """
        privileged_functions = []
        payment_functions = []

        # Identify privileged functions (those with access control)
        for func in contract.functions:
            func_body = func.get("body", "")

            # Check for access control patterns
            if self._has_access_control(func_body):
                privileged_functions.append(func)

            # Check for payment functions
            if self._has_external_calls(func_body) and "value:" in func_body:
                payment_functions.append(func)

        # Check if payment functions can be exploited
        for payment_func in payment_functions:
            func_body = payment_func.get("body", "")

            # Check if privileged functions can be called during callback
            # (i.e., no reentrancy guard)
            if not self._has_reentrancy_guard(func_body):
                # Check if any privileged functions exist
                if privileged_functions:
                    self._add_finding(
                        vulnerability_id="CALLBACK_PRIV_ESC_001",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        title=f"Callback privilege escalation in {contract.name}.{payment_func['name']}",
                        description=(
                            f"Function '{payment_func['name']}' sends ETH to external addresses "
                            f"without reentrancy protection. During the receive/fallback callback, "
                            f"attacker can call privileged functions like "
                            f"{', '.join(f['name'] for f in privileged_functions[:3])} "
                            f"to escalate privileges or manipulate state."
                        ),
                        category="callback_privilege_escalation",
                        file_path=contract.file_path,
                        line_numbers=[payment_func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[payment_func["name"]]
                        + [f["name"] for f in privileged_functions],
                        vulnerable_code=func_body[:300],
                        attack_vector=(
                            "1. Attacker contract has receive() or fallback() function\n"
                            "2. Vulnerable contract sends ETH to attacker\n"
                            "3. Attacker's receive() calls back to privileged functions\n"
                            "4. Access control checks may pass due to msg.sender context\n"
                            "5. Attacker gains unauthorized access or manipulates state"
                        ),
                        proof_of_concept=self._generate_callback_priv_esc_poc(
                            contract.name,
                            payment_func["name"],
                            privileged_functions[0]["name"]
                            if privileged_functions
                            else "privilegedFunc",
                        ),
                        remediation=(
                            "1. Add nonReentrant modifier to payment and privileged functions\n"
                            "2. Use pull-over-push pattern for payments\n"
                            "3. Validate caller context in privileged functions\n"
                            "4. Consider using 2-step withdrawal pattern"
                        ),
                        economic_impact="critical",
                        exploitability="medium",
                        attack_complexity="low",
                        requires_flash_loan=False,
                        requires_multi_tx=False,
                        novelty="very_high",
                        rarity="rare",
                        human_only=True,
                    )

    def _has_access_control(self, code: str) -> bool:
        """Check if function has access control modifiers or checks"""
        access_patterns = [
            r"onlyOwner",
            r"onlyAdmin",
            r"require\s*\(\s*msg\.sender\s*==",
            r"require\s*\(\s*owner\s*==",
            r"require\s*\(\s*hasRole\(",
            r"_checkRole\(",
            r"_onlyOwner\(",
        ]
        return any(re.search(pattern, code) for pattern in access_patterns)

    # POC Generation Methods

    def _generate_phantom_reentry_poc(self, contract_name: str, func_name: str) -> str:
        """Generate POC for phantom reentrancy"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {func_name}() external payable;
    function otherFunction() external;
}}

contract PhantomReentryExploit {{
    IVulnerable public target;
    bool private attacking;

    constructor(address _target) {{
        target = IVulnerable(_target);
    }}

    function attack() external payable {{
        attacking = true;
        target.{func_name}{{value: msg.value}}();
    }}

    // Triggered during external call
    receive() external payable {{
        if (attacking) {{
            attacking = false;
            // Call other function while state is inconsistent
            target.otherFunction();
        }}
    }}
}}
"""

    def _generate_token_hook_poc(self, contract_name: str, hook_name: str) -> str:
        """Generate POC for token hook exploitation"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function deposit(address token, uint256 amount) external;
}}

contract MaliciousToken {{
    IVulnerable public target;
    bool private attacking;

    function setTarget(address _target) external {{
        target = IVulnerable(_target);
    }}

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {{
        // Trigger hook before transfer completes
        if (to == address(target) && !attacking) {{
            attacking = true;
            // Reenter or manipulate state
            target.deposit(address(this), amount);
        }}
        return true;
    }}
}}
"""

    def _generate_callback_priv_esc_poc(
        self, contract_name: str, payment_func: str, priv_func: str
    ) -> str:
        """Generate POC for callback privilege escalation"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {payment_func}() external payable;
    function {priv_func}(address newOwner) external;
}}

contract CallbackPrivEscExploit {{
    IVulnerable public target;
    address public attacker;

    constructor(address _target) {{
        target = IVulnerable(_target);
        attacker = msg.sender;
    }}

    function attack() external payable {{
        target.{payment_func}{{value: msg.value}}();
    }}

    // During receive callback, escalate privileges
    receive() external payable {{
        try target.{priv_func}(attacker) {{
            // Successfully escalated privileges
        }} catch {{
            // Access denied, but state may still be exploitable
        }}
    }}
}}
"""


# CLI entry point
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python reentrancy_hooks_detector.py <target_path> [--output output.json] [--verbose]"
        )
        sys.exit(1)

    target = Path(sys.argv[1])
    output = None
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if "--output" in sys.argv:
        output_idx = sys.argv.index("--output") + 1
        if output_idx < len(sys.argv):
            output = Path(sys.argv[output_idx])

    detector = ReentrancyHooksDetector(verbose=verbose)
    findings = detector.detect(target)

    detector.print_summary()

    if output:
        detector.export_findings(output)
        print(f"✅ Results exported to {output}")

    sys.exit(0 if len(findings) == 0 else 1)
