#!/usr/bin/env python3
"""
Timing Dependency Detector - Elite-tier vulnerability detection

Detects:
- Vuln #12: Time-dependency and miner/validator timestamp bias
- Vuln #20: Unchecked external call side-effects (state mutation in modifiers)
- Vuln #24: Batching and aggregation race conditions

Author: Elite Web3 Bug Hunter
Category: Timing & Ordering Vulnerabilities
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


class TimingDependencyDetector(EliteDetector):
    """
    Detects timing and ordering vulnerabilities

    Covers:
    1. Block timestamp manipulation by miners/validators
    2. State-mutating modifiers that break invariant checks
    3. Race conditions in batch operations
    """

    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.time_patterns = [
            r"block\.timestamp",
            r"block\.number",
            r"\bnow\b",
        ]

    def get_detector_name(self) -> str:
        return "timing_dependency"

    def get_vulnerability_ids(self) -> List[str]:
        return ["TIMESTAMP_MANIP_001", "MODIFIER_STATE_001", "BATCH_RACE_001"]

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

            # Detect timestamp manipulation vulnerabilities
            self._detect_timestamp_manipulation(contract)

            # Detect state-mutating modifiers
            self._detect_modifier_state_mutation(contract)

            # Detect batch operation race conditions
            self._detect_batch_race_conditions(contract)

    def _detect_timestamp_manipulation(self, contract: ContractInfo) -> None:
        """
        Detect timestamp manipulation vulnerabilities (Vuln #12)

        Pattern:
        1. Critical logic depends on block.timestamp or block.number
        2. No tolerance window or validation
        3. Used for access control, randomness, or financial decisions
        """
        for func in contract.functions:
            func_body = func.get("body", "")

            # Check if function uses timestamp
            uses_timestamp = any(
                re.search(pattern, func_body) for pattern in self.time_patterns
            )

            if not uses_timestamp:
                continue

            # Check if it's used in critical contexts
            critical_contexts = self._identify_critical_timestamp_usage(
                func_body, func["name"]
            )

            for context in critical_contexts:
                severity = context["severity"]
                confidence = context["confidence"]

                self._add_finding(
                    vulnerability_id="TIMESTAMP_MANIP_001",
                    severity=severity,
                    confidence=confidence,
                    title=f"Timestamp manipulation in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' uses {context['usage']} for {context['purpose']}. "
                        f"Miners/validators can manipulate timestamps within a ~15 second window "
                        f"(~900 seconds on some chains) to influence outcomes. "
                        f"This enables {context['attack_type']}."
                    ),
                    category="timestamp_manipulation",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    vulnerable_code=func_body[:300],
                    attack_vector=(
                        f"1. Critical logic depends on {context['usage']}\n"
                        f"2. Miner/validator manipulates timestamp within allowed drift\n"
                        f"3. {context['attack_scenario']}\n"
                        f"4. Attacker gains unfair advantage or bypasses controls"
                    ),
                    proof_of_concept=self._generate_timestamp_poc(
                        contract.name, func["name"], context["usage"]
                    ),
                    remediation=(
                        f"1. Use block numbers instead of timestamps when possible\n"
                        f"2. Add tolerance windows (e.g., ±15 seconds)\n"
                        f"3. Use Chainlink VRF for randomness, not timestamps\n"
                        f"4. For time-locks, use block numbers: (block.number - startBlock) > BLOCKS_PER_DAY\n"
                        f"5. {context['specific_fix']}"
                    ),
                    economic_impact=context["economic_impact"],
                    exploitability="easy",
                    attack_complexity="low",
                    requires_flash_loan=False,
                    requires_multi_tx=False,
                    time_window="immediate",
                    novelty="high",
                    rarity="uncommon",
                    human_only=True,
                )

    def _identify_critical_timestamp_usage(
        self, func_body: str, func_name: str
    ) -> List[Dict[str, Any]]:
        """Identify critical uses of timestamps"""
        contexts = []

        # Pattern 1: Randomness generation
        if re.search(r"(random|rand|seed)", func_body, re.IGNORECASE):
            if any(re.search(pattern, func_body) for pattern in self.time_patterns):
                contexts.append(
                    {
                        "usage": "block.timestamp",
                        "purpose": "randomness generation",
                        "attack_type": "predictable randomness exploitation",
                        "attack_scenario": "Attacker predicts timestamp to win lottery/gambling",
                        "specific_fix": "Use Chainlink VRF or commit-reveal scheme",
                        "severity": Severity.CRITICAL.value,
                        "confidence": Confidence.HIGH.value,
                        "economic_impact": "critical",
                    }
                )

        # Pattern 2: Access control (time-based locks)
        if re.search(
            r"(unlockTime|lockTime|releaseTime|claimTime)", func_body, re.IGNORECASE
        ):
            if any(re.search(pattern, func_body) for pattern in self.time_patterns):
                contexts.append(
                    {
                        "usage": "block.timestamp",
                        "purpose": "time-lock access control",
                        "attack_type": "premature unlock or delayed access",
                        "attack_scenario": "Miner adjusts timestamp to unlock funds early or lock longer",
                        "specific_fix": "Accept ±15s tolerance or use block numbers",
                        "severity": Severity.HIGH.value,
                        "confidence": Confidence.HIGH.value,
                        "economic_impact": "high",
                    }
                )

        # Pattern 3: Price/rate calculations
        if re.search(r"(price|rate|interest|reward)", func_body, re.IGNORECASE):
            if any(re.search(pattern, func_body) for pattern in self.time_patterns):
                contexts.append(
                    {
                        "usage": "block.timestamp",
                        "purpose": "financial calculations",
                        "attack_type": "favorable pricing or rate manipulation",
                        "attack_scenario": "Miner times block to maximize interest/rewards",
                        "specific_fix": "Use TWAP or block number-based accrual",
                        "severity": Severity.HIGH.value,
                        "confidence": Confidence.MEDIUM.value,
                        "economic_impact": "high",
                    }
                )

        # Pattern 4: Deadline checks (less critical but still exploitable)
        if re.search(r"(deadline|expir|timeout)", func_body, re.IGNORECASE):
            if any(re.search(pattern, func_body) for pattern in self.time_patterns):
                contexts.append(
                    {
                        "usage": "block.timestamp",
                        "purpose": "deadline enforcement",
                        "attack_type": "deadline bypass or DOS",
                        "attack_scenario": "Miner extends deadline or causes premature expiration",
                        "specific_fix": "Accept timing uncertainty or use block numbers",
                        "severity": Severity.MEDIUM.value,
                        "confidence": Confidence.MEDIUM.value,
                        "economic_impact": "medium",
                    }
                )

        # Pattern 5: Generic timestamp comparison (lowest severity)
        if not contexts and any(
            re.search(pattern, func_body) for pattern in self.time_patterns
        ):
            # Check if it's in a require/if statement
            if re.search(
                r"(require|if)\s*\([^)]*(" + "|".join(self.time_patterns) + r")",
                func_body,
            ):
                contexts.append(
                    {
                        "usage": "block.timestamp",
                        "purpose": "conditional logic",
                        "attack_type": "timing manipulation",
                        "attack_scenario": "Miner influences conditional branches",
                        "specific_fix": "Evaluate if timing precision is critical",
                        "severity": Severity.LOW.value,
                        "confidence": Confidence.MEDIUM.value,
                        "economic_impact": "low",
                    }
                )

        return contexts

    def _detect_modifier_state_mutation(self, contract: ContractInfo) -> None:
        """
        Detect state-mutating modifiers (Vuln #20)

        Pattern:
        1. Modifier changes state before function body
        2. Function body has checks that depend on that state
        3. Logic is broken because checks see modified state
        """
        for modifier in contract.modifiers:
            modifier_name = modifier["name"]

            # Find modifier body in source
            modifier_code = self._extract_modifier_body(
                contract.source_code, modifier_name
            )

            if not modifier_code:
                continue

            # Check if modifier mutates state
            mutates_state = self._modifier_mutates_state(modifier_code, contract)

            if not mutates_state:
                continue

            # Find functions that use this modifier
            affected_funcs = []
            for func in contract.functions:
                func_body = func.get("body", "")
                # Check if function uses this modifier
                if re.search(rf"\b{modifier_name}\b", func_body):
                    affected_funcs.append(func)

            if not affected_funcs:
                continue

            # Check if any affected function has state checks
            for func in affected_funcs:
                func_body = func.get("body", "")

                # Look for require/if statements that check state
                has_state_checks = self._has_state_checks(func_body, contract)

                if has_state_checks:
                    self._add_finding(
                        vulnerability_id="MODIFIER_STATE_001",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.HIGH.value,
                        title=f"State-mutating modifier breaks invariants in {contract.name}.{func['name']}",
                        description=(
                            f"Modifier '{modifier_name}' mutates contract state before function '{func['name']}' executes. "
                            f"The function has checks that depend on state variables, but these checks "
                            f"see the already-modified state, breaking intended invariants. "
                            f"This can enable bypassing checks or causing logic errors."
                        ),
                        category="modifier_state_mutation",
                        file_path=contract.file_path,
                        line_numbers=[modifier["line"], func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"], modifier_name],
                        vulnerable_code=f"modifier {modifier_name} {modifier_code[:200]}",
                        attack_vector=(
                            f"1. Modifier '{modifier_name}' changes state (e.g., updates timestamp, counter)\n"
                            f"2. Function '{func['name']}' checks that state variable\n"
                            f"3. Check sees modified state instead of original\n"
                            f"4. Invariant violated, check always fails or always passes"
                        ),
                        proof_of_concept=self._generate_modifier_state_poc(
                            contract.name, modifier_name, func["name"]
                        ),
                        remediation=(
                            f"1. Move state mutations to end of modifier (after _ placeholder)\n"
                            f"2. Or move state mutations into function body after checks\n"
                            f"3. Ensure checks see original state before mutations\n"
                            f"4. Consider using separate tracking variables"
                        ),
                        economic_impact="high",
                        exploitability="medium",
                        attack_complexity="low",
                        requires_flash_loan=False,
                        requires_multi_tx=False,
                        novelty="very_high",
                        rarity="rare",
                        human_only=True,
                    )

    def _extract_modifier_body(self, source: str, modifier_name: str) -> Optional[str]:
        """Extract modifier body from source code"""
        pattern = rf"modifier\s+{modifier_name}\s*\([^)]*\)\s*\{{"
        match = re.search(pattern, source)

        if not match:
            return None

        start_pos = match.end() - 1
        brace_count = 0
        end_pos = start_pos

        for i, char in enumerate(source[start_pos:], start=start_pos):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i
                    break

        return source[start_pos : end_pos + 1]

    def _modifier_mutates_state(
        self, modifier_code: str, contract: ContractInfo
    ) -> bool:
        """Check if modifier mutates state variables"""
        # Look for state variable assignments
        for var in contract.state_variables:
            var_name = var["name"]
            # Check for assignment: varName = or varName +=
            if re.search(rf"\b{var_name}\s*[+\-*/]?=", modifier_code):
                return True
            # Check for mapping assignment
            if re.search(rf"\b{var_name}\[", modifier_code):
                return True

        # Look for storage keyword
        if "storage" in modifier_code:
            return True

        return False

    def _has_state_checks(self, func_body: str, contract: ContractInfo) -> bool:
        """Check if function has state variable checks"""
        # Look for require/if with state variables
        for var in contract.state_variables:
            var_name = var["name"]
            if re.search(rf"(require|if)\s*\([^)]*\b{var_name}\b", func_body):
                return True

        return False

    def _detect_batch_race_conditions(self, contract: ContractInfo) -> None:
        """
        Detect batch operation race conditions (Vuln #24)

        Pattern:
        1. Function processes array/batch of items
        2. External calls or state changes per item
        3. No atomicity guarantees across iterations
        """
        for func in contract.functions:
            func_body = func.get("body", "")

            # Check for loop with array parameter
            has_batch_loop = self._is_batch_operation(func_body)

            if not has_batch_loop:
                continue

            # Check if loop has external calls
            has_external_calls = self._has_external_calls_in_loop(func_body)

            # Check if loop modifies state per iteration
            has_state_changes = self._has_state_changes_in_loop(func_body, contract)

            if has_external_calls or has_state_changes:
                # Determine severity based on what's in the loop
                severity = (
                    Severity.HIGH.value if has_external_calls else Severity.MEDIUM.value
                )
                confidence = (
                    Confidence.HIGH.value
                    if has_external_calls
                    else Confidence.MEDIUM.value
                )

                self._add_finding(
                    vulnerability_id="BATCH_RACE_001",
                    severity=severity,
                    confidence=confidence,
                    title=f"Batch operation race condition in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' processes batch operations with "
                        f"{'external calls' if has_external_calls else 'state changes'} "
                        f"in a loop. There are no atomicity guarantees across iterations. "
                        f"Attacker can front-run, reorder, or exploit partial execution to "
                        f"cause state inconsistencies or extract value."
                    ),
                    category="batch_race_condition",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    vulnerable_code=func_body[:400],
                    attack_vector=(
                        f"1. Function iterates over array with state changes/external calls\n"
                        f"2. Attacker front-runs transaction or manipulates array order\n"
                        f"3. Partial execution leaves inconsistent state\n"
                        f"4. Subsequent iterations or other txs exploit inconsistency\n"
                        f"5. Double-spending, incorrect accounting, or DOS"
                    ),
                    proof_of_concept=self._generate_batch_race_poc(
                        contract.name, func["name"]
                    ),
                    remediation=(
                        f"1. Use Checks-Effects-Interactions pattern for entire batch\n"
                        f"2. Accumulate all state changes, then apply atomically\n"
                        f"3. Add reentrancy guards to prevent mid-batch exploitation\n"
                        f"4. Validate array order and uniqueness\n"
                        f"5. Consider commit-reveal for ordering\n"
                        f"6. Add nonce/sequence validation"
                    ),
                    economic_impact="high" if has_external_calls else "medium",
                    exploitability="medium",
                    attack_complexity="medium",
                    requires_flash_loan=False,
                    requires_multi_tx=True,
                    novelty="high",
                    rarity="uncommon",
                    human_only=True,
                )

    def _is_batch_operation(self, func_body: str) -> bool:
        """Check if function has batch/loop operations"""
        # Look for for loops iterating over arrays
        batch_patterns = [
            r"for\s*\(\s*uint\w*\s+\w+\s*=\s*0\s*;",  # for (uint i = 0; ...)
            r"for\s*\(\s*uint\w*\s+\w+\s*;\s*\w+\s*<\s*\w+\.length",  # for loop with array.length
            r"\.length\s*;",  # any .length in loop condition
        ]

        return any(re.search(pattern, func_body) for pattern in batch_patterns)

    def _has_external_calls_in_loop(self, func_body: str) -> bool:
        """Check if loop contains external calls"""
        # Extract loop body (simplified)
        loop_match = re.search(r"for\s*\([^)]+\)\s*\{", func_body)
        if not loop_match:
            return False

        loop_start = loop_match.end()
        brace_count = 1
        loop_end = loop_start

        for i, char in enumerate(func_body[loop_start:], start=loop_start):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    loop_end = i
                    break

        loop_body = func_body[loop_start:loop_end]

        # Check for external calls in loop
        call_patterns = [
            r"\.call\{",
            r"\.call\(",
            r"\.transfer\(",
            r"\.send\(",
        ]

        return any(re.search(pattern, loop_body) for pattern in call_patterns)

    def _has_state_changes_in_loop(
        self, func_body: str, contract: ContractInfo
    ) -> bool:
        """Check if loop modifies state"""
        # Extract loop body
        loop_match = re.search(r"for\s*\([^)]+\)\s*\{", func_body)
        if not loop_match:
            return False

        loop_start = loop_match.end()
        brace_count = 1
        loop_end = loop_start

        for i, char in enumerate(func_body[loop_start:], start=loop_start):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    loop_end = i
                    break

        loop_body = func_body[loop_start:loop_end]

        # Check for state variable modifications
        for var in contract.state_variables:
            var_name = var["name"]
            if re.search(rf"\b{var_name}\s*[+\-*/]?=", loop_body):
                return True
            if re.search(rf"\b{var_name}\[", loop_body):
                return True

        return False

    # POC Generation Methods

    def _generate_timestamp_poc(
        self, contract_name: str, func_name: str, usage: str
    ) -> str:
        """Generate POC for timestamp manipulation"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {func_name}() external returns (uint256);
}}

contract TimestampManipExploit {{
    IVulnerable public target;

    constructor(address _target) {{
        target = IVulnerable(_target);
    }}

    function exploit() external {{
        // Miner/validator can manipulate {usage} by ±15 seconds
        // For L2s/sidechains, manipulation window can be much larger (up to 15 minutes)

        // Example: If target uses timestamp for randomness
        // Miner tries different timestamps until favorable outcome

        // Example: If target uses timestamp for time-lock
        // Miner can push timestamp forward to unlock early
        // or hold back to delay unlock

        uint256 result = target.{func_name}();
        // Attacker benefits from manipulated timestamp
    }}
}}

// Attack scenario:
// 1. Attacker monitors mempool for target transactions
// 2. Miner adjusts block timestamp within allowed drift
// 3. Critical logic (randomness, unlock, pricing) is affected
// 4. Attacker extracts value or bypasses controls
"""

    def _generate_modifier_state_poc(
        self, contract_name: str, modifier_name: str, func_name: str
    ) -> str:
        """Generate POC for modifier state mutation"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ModifierStateMutationExample {{
    uint256 public lastAccess;

    // VULNERABLE: Modifier updates state before function body
    modifier {modifier_name}() {{
        lastAccess = block.timestamp; // State changed here!
        _;
    }}

    // Function checks lastAccess but sees already-modified value
    function {func_name}() external {modifier_name} {{
        require(block.timestamp - lastAccess > 1 days, "too soon");
        // This check ALWAYS FAILS because modifier already updated lastAccess
        // to current timestamp, so difference is ~0

        // Critical logic that should be time-locked
        // is now bypassable
    }}
}}

// Fix: Move state update to after function execution
modifier {modifier_name}Fixed() {{
    _;
    lastAccess = block.timestamp; // State changed after function
}}
"""

    def _generate_batch_race_poc(self, contract_name: str, func_name: str) -> str:
        """Generate POC for batch race condition"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function {func_name}(address[] calldata recipients, uint256[] calldata amounts) external;
    function balanceOf(address) external view returns (uint256);
}}

contract BatchRaceExploit {{
    IVulnerable public target;
    address public attacker;

    constructor(address _target) {{
        target = IVulnerable(_target);
        attacker = msg.sender;
    }}

    function exploitBatch() external {{
        // Create batch with attacker address multiple times
        // or with carefully ordered addresses to exploit partial execution
        address[] memory recipients = new address[](3);
        uint256[] memory amounts = new uint256[](3);

        recipients[0] = attacker;
        recipients[1] = address(this); // This will trigger callback
        recipients[2] = attacker;

        amounts[0] = 100 ether;
        amounts[1] = 100 ether;
        amounts[2] = 100 ether;

        target.{func_name}(recipients, amounts);
    }}

    // If batch operation makes external calls, we can reenter
    receive() external payable {{
        // During iteration 2, state is partially updated
        // We can read inconsistent state or call other functions

        // Example: double-spend by front-running our own batch
        // or exploiting lack of uniqueness checks
    }}
}}

// Attack vectors:
// 1. Duplicate addresses in array (if no uniqueness check)
// 2. Front-run own transaction to exploit ordering
// 3. Reenter during batch to exploit partial state
// 4. DOS by reverting mid-batch, leaving inconsistent state
"""

    def _has_external_calls(self, code: str) -> bool:
        """Check if code makes external calls"""
        external_patterns = [
            r"\.call\{",
            r"\.call\(",
            r"\.delegatecall\(",
            r"\.staticcall\(",
            r"\.transfer\(",
            r"\.send\(",
        ]
        return any(re.search(pattern, code) for pattern in external_patterns)


# CLI entry point
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python timing_dependency_detector.py <target_path> [--output output.json] [--verbose]"
        )
        sys.exit(1)

    target = Path(sys.argv[1])
    output = None
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if "--output" in sys.argv:
        output_idx = sys.argv.index("--output") + 1
        if output_idx < len(sys.argv):
            output = Path(sys.argv[output_idx])

    detector = TimingDependencyDetector(verbose=verbose)
    findings = detector.detect(target)

    detector.print_summary()

    if output:
        detector.export_findings(output)
        print(f"✅ Results exported to {output}")

    sys.exit(0 if len(findings) == 0 else 1)
