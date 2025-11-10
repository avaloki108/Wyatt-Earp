#!/usr/bin/env python3
"""
Upgrade Safety Detector - Elite-tier vulnerability detection

Detects:
- Vuln #4: Delegatecall gadget chaining
- Vuln #5: Initialization and constructor-time assumptions (extcodesize == 0)
- Vuln #30: Conditional compile/optimizer artifacts (solc optimizer surprises)

Author: Elite Web3 Bug Hunter
Category: Upgrade & Proxy Safety
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


class UpgradeSafetyDetector(EliteDetector):
    """
    Detects upgrade and proxy-related vulnerabilities

    Covers:
    1. Delegatecall gadget chaining (multiple delegatecalls)
    2. Constructor-time assumptions (extcodesize, code.length checks)
    3. Compiler/optimizer version inconsistencies
    """

    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.delegatecall_chains: Dict[str, List[str]] = {}
        self.proxy_contracts: List[ContractInfo] = []

    def get_detector_name(self) -> str:
        return "upgrade_safety"

    def get_vulnerability_ids(self) -> List[str]:
        return [
            "DELEGATECALL_CHAIN_001",
            "CONSTRUCTOR_ASSUME_001",
            "OPTIMIZER_ARTIFACT_001",
        ]

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
            if contract.is_interface:
                continue

            # Classify as proxy if relevant
            if self._is_proxy_contract(contract):
                self.proxy_contracts.append(contract)

            # Detect delegatecall chaining
            self._detect_delegatecall_gadgets(contract)

            # Detect constructor-time assumptions
            self._detect_constructor_assumptions(contract, source)

            # Detect optimizer artifacts
            self._detect_optimizer_artifacts(contract, source)

    def _is_proxy_contract(self, contract: ContractInfo) -> bool:
        """Check if contract is a proxy"""
        proxy_keywords = ["proxy", "delegatecall", "implementation", "upgrade"]
        source = (contract.source_code or "").lower()
        return any(kw in source for kw in proxy_keywords)

    def _detect_delegatecall_gadgets(self, contract: ContractInfo) -> None:
        """
        Detect delegatecall gadget chaining (Vuln #4)

        Pattern:
        1. Contract has multiple delegatecall operations
        2. Chained delegatecalls allow pivot to arbitrary storage writes
        3. Attacker controls call chain to overwrite critical storage
        """
        for func in contract.functions:
            func_body = func.get("body", "")

            # Find all delegatecall operations
            delegatecalls = re.findall(
                r"(\w+)\.delegatecall\s*\{?[^}]*\}?\s*\([^)]*\)", func_body
            )

            if len(delegatecalls) < 1:
                continue

            # Check if delegatecall target is controllable
            has_controllable_target = self._has_controllable_delegatecall(func_body)

            # Check if contract has chained delegatecalls (one delegatecall leading to another)
            has_chain = len(delegatecalls) > 1 or self._has_delegatecall_chain(
                contract, func
            )

            if has_controllable_target:
                severity = Severity.CRITICAL.value if has_chain else Severity.HIGH.value
                confidence = Confidence.HIGH.value

                self._add_finding(
                    vulnerability_id="DELEGATECALL_CHAIN_001",
                    severity=severity,
                    confidence=confidence,
                    title=f"Delegatecall gadget in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' uses delegatecall with "
                        f"{'chained operations' if has_chain else 'controllable target'}. "
                        f"Attacker can chain delegatecalls through multiple contracts "
                        f"to pivot storage writes into arbitrary slots, enabling "
                        f"complete contract takeover through storage manipulation."
                    ),
                    category="delegatecall_chaining",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    vulnerable_code=func_body[:400],
                    attack_vector=(
                        "1. Attacker identifies delegatecall with controllable target\n"
                        "2. Deploys malicious implementation contract (gadget)\n"
                        "3. Chains delegatecalls: Proxy -> Gadget1 -> Gadget2\n"
                        "4. Each gadget writes to specific storage slots\n"
                        "5. Final gadget overwrites critical storage (owner, implementation)\n"
                        "6. Complete contract takeover achieved"
                    ),
                    proof_of_concept=self._generate_delegatecall_poc(
                        contract.name, func["name"], has_chain
                    ),
                    remediation=(
                        "1. Restrict delegatecall targets to trusted, immutable addresses\n"
                        "2. Use whitelist pattern for implementation contracts\n"
                        "3. Add access control on functions with delegatecall\n"
                        "4. Validate storage layout compatibility before upgrades\n"
                        "5. Use TransparentProxy or UUPS patterns correctly\n"
                        "6. Never allow user-controlled delegatecall targets"
                    ),
                    economic_impact="critical",
                    exploitability="medium",
                    attack_complexity="high",
                    requires_flash_loan=False,
                    requires_multi_tx=False,
                    novelty="very_high",
                    rarity="extreme",
                    human_only=True,
                )

            # Also check for unprotected delegatecall in non-proxy contracts
            if not self._is_proxy_contract(contract) and len(delegatecalls) > 0:
                if not self._has_access_control(func_body):
                    self._add_finding(
                        vulnerability_id="DELEGATECALL_CHAIN_001",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.MEDIUM.value,
                        title=f"Unprotected delegatecall in {contract.name}.{func['name']}",
                        description=(
                            f"Function '{func['name']}' uses delegatecall without proper "
                            f"access control. This is dangerous in non-proxy contracts as "
                            f"it can lead to unexpected storage writes and logic hijacking."
                        ),
                        category="unprotected_delegatecall",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        attack_vector="Attacker calls delegatecall with malicious implementation",
                        proof_of_concept="// See delegatecall chaining POC",
                        remediation="Add onlyOwner or similar access control",
                        economic_impact="high",
                        exploitability="medium",
                        novelty="high",
                        rarity="rare",
                        human_only=True,
                    )

    def _has_controllable_delegatecall(self, func_body: str) -> bool:
        """Check if delegatecall target can be controlled by user"""
        # Pattern: delegatecall to a parameter or state variable that can be set
        patterns = [
            r"delegatecall\([^)]*\b(implementation|target|destination|to)\b",
            r"\b(implementation|target)\b\s*\.delegatecall",
        ]
        return any(re.search(pattern, func_body, re.IGNORECASE) for pattern in patterns)

    def _has_delegatecall_chain(
        self, contract: ContractInfo, func: Dict[str, Any]
    ) -> bool:
        """Check if function is part of a delegatecall chain"""
        func_body = func.get("body", "")

        # Look for sequential delegatecalls
        if re.findall(r"delegatecall", func_body).__len__() > 1:
            return True

        # Look for delegatecall followed by another call
        if re.search(r"delegatecall.*\.(call|delegatecall)", func_body, re.DOTALL):
            return True

        return False

    def _has_access_control(self, code: str) -> bool:
        """Check if function has access control"""
        access_patterns = [
            r"onlyOwner",
            r"onlyAdmin",
            r"require\s*\(\s*msg\.sender\s*==",
            r"_checkRole\(",
        ]
        return any(re.search(pattern, code) for pattern in access_patterns)

    def _detect_constructor_assumptions(
        self, contract: ContractInfo, source: str
    ) -> None:
        """
        Detect constructor-time assumptions (Vuln #5)

        Pattern:
        1. Constructor or initializer uses extcodesize or code.length
        2. These checks fail during construction (code.length == 0)
        3. Contracts assume deployed state during construction
        """
        # Find constructor
        constructor_pattern = re.compile(
            r"constructor\s*\([^)]*\)\s*[^{]*\{([^}]+)\}", re.DOTALL
        )

        for match in constructor_pattern.finditer(source):
            constructor_body = match.group(1)
            line_num = source[: match.start()].count("\n") + 1

            # Check for extcodesize usage
            if re.search(r"(extcodesize|\.code\.length)", constructor_body):
                self._add_finding(
                    vulnerability_id="CONSTRUCTOR_ASSUME_001",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    title=f"Constructor code.length assumption in {contract.name}",
                    description=(
                        f"Constructor in {contract.name} uses extcodesize or code.length. "
                        f"During contract construction, code.length is 0 even for contracts. "
                        f"Checks like 'require(target.code.length > 0)' will fail unexpectedly "
                        f"if target is being constructed, breaking initialization logic."
                    ),
                    category="constructor_assumption",
                    file_path=contract.file_path,
                    line_numbers=[line_num],
                    affected_contracts=[contract.name],
                    affected_functions=["constructor"],
                    vulnerable_code=constructor_body[:300],
                    attack_vector=(
                        "1. Contract A's constructor calls contract B's constructor\n"
                        "2. Contract A checks if B is deployed: require(B.code.length > 0)\n"
                        "3. Check fails because B's code.length is 0 during construction\n"
                        "4. Initialization fails or behaves incorrectly\n"
                        "5. Contract deployed in invalid state"
                    ),
                    proof_of_concept=self._generate_constructor_poc(contract.name),
                    remediation=(
                        "1. Never use extcodesize/code.length in constructors\n"
                        "2. Use post-deployment initialization (two-step pattern)\n"
                        "3. For proxy initialization, use initializer functions not constructors\n"
                        "4. Check contract interfaces, not code presence\n"
                        "5. Document construction dependencies clearly"
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

        # Also check initializer functions (common in upgradeable contracts)
        for func in contract.functions:
            if "initializ" in func["name"].lower():
                func_body = func.get("body", "")

                if re.search(r"(extcodesize|\.code\.length)", func_body):
                    self._add_finding(
                        vulnerability_id="CONSTRUCTOR_ASSUME_001",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.HIGH.value,
                        title=f"Initializer code.length assumption in {contract.name}.{func['name']}",
                        description=(
                            f"Initializer function '{func['name']}' uses extcodesize or code.length. "
                            f"This can fail if called during proxy deployment or when checking "
                            f"contracts that are mid-construction."
                        ),
                        category="initializer_assumption",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        vulnerable_code=func_body[:300],
                        attack_vector="Initialization fails due to code.length check during deployment",
                        proof_of_concept=self._generate_constructor_poc(contract.name),
                        remediation="Use interface checks instead of code.length",
                        economic_impact="medium",
                        exploitability="low",
                        novelty="high",
                        rarity="uncommon",
                        human_only=True,
                    )

    def _detect_optimizer_artifacts(self, contract: ContractInfo, source: str) -> None:
        """
        Detect optimizer artifacts (Vuln #30)

        Pattern:
        1. Pragma specifies no optimizer or specific version
        2. Code has tight gas optimization or storage packing
        3. Inconsistent optimizer settings across upgrades break storage layout
        """
        # Extract pragma statements
        pragma_pattern = re.compile(r"pragma\s+solidity\s+([^;]+);")
        pragmas = pragma_pattern.findall(source)

        # Check for multiple storage variables that rely on packing
        packed_storage = self._detect_storage_packing(contract)

        if packed_storage and len(packed_storage) > 2:
            # Check if there's documentation about optimizer requirements
            has_optimizer_docs = re.search(
                r"(optimizer|--optimize|optimization)", source, re.IGNORECASE
            )

            if not has_optimizer_docs:
                self._add_finding(
                    vulnerability_id="OPTIMIZER_ARTIFACT_001",
                    severity=Severity.MEDIUM.value,
                    confidence=Confidence.MEDIUM.value,
                    title=f"Undocumented optimizer dependency in {contract.name}",
                    description=(
                        f"Contract {contract.name} uses tight storage packing (found "
                        f"{len(packed_storage)} packed variables) but doesn't document "
                        f"optimizer requirements. Different optimizer settings across "
                        f"deployment/upgrade can change storage layout, gas costs, and behavior. "
                        f"This is especially dangerous for proxy upgrades."
                    ),
                    category="optimizer_artifact",
                    file_path=contract.file_path,
                    line_numbers=[contract.start_line],
                    affected_contracts=[contract.name],
                    affected_functions=["all"],
                    vulnerable_code=f"Packed storage: {', '.join(packed_storage[:5])}",
                    attack_vector=(
                        "1. Original contract compiled with optimizer enabled\n"
                        "2. Storage layout optimized and tightly packed\n"
                        "3. Upgrade compiled with different optimizer settings\n"
                        "4. Storage layout changes (different slot assignments)\n"
                        "5. State corruption across upgrade\n"
                        "6. Critical variables overwritten or misaligned"
                    ),
                    proof_of_concept=self._generate_optimizer_poc(contract.name),
                    remediation=(
                        "1. Document optimizer settings in contract comments\n"
                        "2. Use consistent compiler flags across all deployments\n"
                        "3. Test upgrades with exact compiler configuration\n"
                        "4. Add optimizer version to deployment scripts\n"
                        "5. Use storage gaps for upgradeable contracts\n"
                        "6. Run storage layout verification tools pre-upgrade"
                    ),
                    economic_impact="high",
                    exploitability="low",
                    attack_complexity="high",
                    requires_flash_loan=False,
                    requires_multi_tx=False,
                    novelty="very_high",
                    rarity="rare",
                    human_only=True,
                )

        # Also check for assembly blocks that may behave differently with optimizer
        for func in contract.functions:
            func_body = func.get("body", "")

            if "assembly" in func_body:
                # Check if assembly does complex operations that optimizer might affect
                if re.search(
                    r"assembly\s*\{[^}]*(mload|mstore|sload|sstore)", func_body
                ):
                    self._add_finding(
                        vulnerability_id="OPTIMIZER_ARTIFACT_001",
                        severity=Severity.LOW.value,
                        confidence=Confidence.MEDIUM.value,
                        title=f"Assembly block sensitive to optimizer in {contract.name}.{func['name']}",
                        description=(
                            f"Function '{func['name']}' contains assembly with memory/storage "
                            f"operations. Optimizer can reorder or optimize these operations "
                            f"differently, causing unexpected behavior changes between "
                            f"compiler versions or optimizer settings."
                        ),
                        category="optimizer_assembly",
                        file_path=contract.file_path,
                        line_numbers=[func["line"]],
                        affected_contracts=[contract.name],
                        affected_functions=[func["name"]],
                        vulnerable_code=func_body[:300],
                        attack_vector="Optimizer changes assembly behavior, breaking assumptions",
                        proof_of_concept="// See optimizer artifact POC",
                        remediation="Document optimizer requirements and test with different settings",
                        economic_impact="medium",
                        exploitability="low",
                        novelty="high",
                        rarity="uncommon",
                        human_only=True,
                    )

    def _detect_storage_packing(self, contract: ContractInfo) -> List[str]:
        """Detect tightly packed storage variables (uint8, bool, etc.)"""
        packed_vars = []

        for var in contract.state_variables:
            var_type = var.get("type", "")

            # Small types that get packed
            if any(
                t in var_type
                for t in ["uint8", "uint16", "uint32", "uint64", "uint128", "bool"]
            ):
                packed_vars.append(var["name"])

        return packed_vars

    # POC Generation Methods

    def _generate_delegatecall_poc(
        self, contract_name: str, func_name: str, has_chain: bool
    ) -> str:
        """Generate POC for delegatecall gadget chaining"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Delegatecall Gadget Chain Exploit

contract Proxy {{
    address public implementation;
    address public owner;

    function {func_name}(address target, bytes calldata data) external {{
        // VULNERABLE: Controllable delegatecall
        target.delegatecall(data);
    }}
}}

contract Gadget1 {{
    address public dummy1;
    address public dummy2;

    function exploit(address nextGadget, bytes calldata data) external {{
        // Gadget 1: Setup state for next delegatecall
        nextGadget.delegatecall(data);
    }}
}}

contract Gadget2 {{
    address public dummy1;  // Matches Proxy.implementation slot
    address public owner;   // Matches Proxy.owner slot

    function takeOwnership() external {{
        // Gadget 2: Overwrite Proxy's storage slots
        owner = msg.sender;  // Writes to Proxy's owner slot via delegatecall
    }}
}}

contract DelegatecallChainExploit {{
    function attack(address proxy) external {{
        Proxy p = Proxy(proxy);

        // Step 1: Deploy gadgets
        Gadget1 g1 = new Gadget1();
        Gadget2 g2 = new Gadget2();

        // Step 2: Chain delegatecalls through gadgets
        // Proxy.delegatecall -> Gadget1.delegatecall -> Gadget2.takeOwnership

        bytes memory data2 = abi.encodeWithSelector(
            Gadget2.takeOwnership.selector
        );

        bytes memory data1 = abi.encodeWithSelector(
            Gadget1.exploit.selector,
            address(g2),
            data2
        );

        // Step 3: Execute attack
        p.{func_name}(address(g1), data1);

        // Result: Attacker is now owner of Proxy via storage overwrite
        assert(p.owner() == msg.sender);
    }}
}}

// Impact: Complete contract takeover through delegatecall chaining
// All storage slots can be overwritten, including owner, implementation, etc.
"""

    def _generate_constructor_poc(self, contract_name: str) -> str:
        """Generate POC for constructor assumptions"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Constructor Code.Length Assumption Vulnerability

contract ContractB {{
    uint256 public value;

    constructor(uint256 _value) {{
        value = _value;
    }}

    function getValue() external view returns (uint256) {{
        return value;
    }}
}}

contract ContractA {{
    ContractB public contractB;

    constructor() {{
        // VULNERABLE: Creating ContractB in constructor
        contractB = new ContractB(42);

        // This check FAILS because ContractB.code.length is 0 during construction
        require(address(contractB).code.length > 0, "ContractB not deployed");

        // This line is never reached!
    }}
}}

// The require() always fails because during construction:
// - ContractB exists (has address)
// - But ContractB.code.length == 0 (code not yet deployed)
// - Ethereum only sets code.length after constructor completes

// Impact: Deployment fails unexpectedly
// Contracts deployed in invalid state or initialization fails

// Fix: Remove code.length check from constructor
contract ContractA_Fixed {{
    ContractB public contractB;

    constructor() {{
        contractB = new ContractB(42);
        // Don't check code.length in constructor
    }}

    // Or use two-step initialization
    function initialize() external {{
        contractB = new ContractB(42);
        require(address(contractB).code.length > 0, "ContractB not deployed");
    }}
}}
"""

    def _generate_optimizer_poc(self, contract_name: str) -> str:
        """Generate POC for optimizer artifacts"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Optimizer Artifact Vulnerability

// Storage layout depends on optimizer settings
contract StoragePacking {{
    uint8 public a;    // Slot 0 (packed)
    uint8 public b;    // Slot 0 (packed)
    uint256 public c;  // Slot 1

    // With optimizer: a and b packed into slot 0
    // Without optimizer: might use separate slots
}}

// Scenario: Upgradeable contract
contract Implementation_V1 {{
    uint8 public a;
    uint8 public b;
    uint256 public c;

    function setValue(uint256 _c) external {{
        c = _c;
    }}
}}

// Compiled with --optimize
// Storage: [a,b in slot0] [c in slot1]

contract Implementation_V2 {{
    uint8 public a;
    uint8 public b;
    uint256 public c;
    uint256 public d;  // New variable

    function setValueV2(uint256 _c, uint256 _d) external {{
        c = _c;
        d = _d;
    }}
}}

// If compiled WITHOUT --optimize, storage layout changes:
// Storage: [a in slot0] [b in slot1] [c in slot2] [d in slot3]
// Now c is in slot2, not slot1!

// Impact of upgrade with different optimizer:
contract OptimizerExploit {{
    function demonstrateCorruption(address proxy) external {{
        // V1 deployed with optimizer: c is at slot 1
        Implementation_V1(proxy).setValue(100);

        // Upgrade to V2 WITHOUT optimizer: c is now at slot 2
        // But proxy thinks c is at slot 1
        // Setting c actually overwrites b!

        // State corruption: wrong variables get wrong values
    }}
}}

// Mitigation:
// 1. Always use same compiler version and optimizer settings
// 2. Document required build flags in code
// 3. Use storage gaps in upgradeable contracts
// 4. Test upgrades with exact compiler configuration
"""


# CLI entry point
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python upgrade_safety_detector.py <target_path> [--output output.json] [--verbose]"
        )
        sys.exit(1)

    target = Path(sys.argv[1])
    output = None
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if "--output" in sys.argv:
        output_idx = sys.argv.index("--output") + 1
        if output_idx < len(sys.argv):
            output = Path(sys.argv[output_idx])

    detector = UpgradeSafetyDetector(verbose=verbose)
    findings = detector.detect(target)

    detector.print_summary()

    if output:
        detector.export_findings(output)
        print(f"✅ Results exported to {output}")

    sys.exit(0 if len(findings) == 0 else 1)
