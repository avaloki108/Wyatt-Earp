"""
Formal verification helpers for Web3 contracts
Enhanced for comprehensive Certora/Scribble specs generation based on contract analysis.
Supports advanced property generation for DeFi, bridges, governance; integrates economic invariants;
improved parsing, validation, and tool-specific outputs (Certora rules, Scribble annotations, SMT queries).
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import json


class PropertyType(Enum):
    INVARIANT = "invariant"
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    RULE = "rule"
    ASSERTION = "assertion"


class VerificationTool(Enum):
    CERTORA = "certora"
    SCRIBBLE = "scribble"
    SMT = "smt"
    ALL = "all"


@dataclass
class FormalProperty:
    """Enhanced formal property with priority and dependencies"""

    name: str
    property_type: PropertyType
    description: str
    formal_spec: str
    solidity_annotation: str
    verification_tool: VerificationTool
    severity: str = "medium"  # critical, high, medium, low
    dependencies: Optional[List[str]] = None  # Other properties this depends on
    contract_specific: bool = False  # Tailored to parsed contract elements

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class FormalVerificationHelper:
    """Enhanced helper for creating comprehensive formal specifications"""

    def __init__(self, verbose: bool = False):
        self.properties: List[FormalProperty] = []
        self.parsed_contract: Optional[Dict[str, Any]] = None
        self.state_variables = []
        self.functions = []
        self.contract_name = ""
        self.verbose = verbose

    def parse_contract(self, contract_code: str) -> Dict[str, Any]:
        """Enhanced parsing of contract code for state vars, functions, patterns"""
        self.contract_name = self._extract_contract_name(contract_code)
        self.state_variables = self._extract_state_variables(contract_code)
        self.functions = self._extract_functions(contract_code)
        self.parsed_contract = {
            "name": self.contract_name,
            "state_vars": self.state_variables,
            "functions": self.functions,
            "patterns": self._detect_patterns(contract_code),
        }
        if self.verbose:
            print(
                f"Parsed {self.contract_name}: {len(self.state_variables)} state vars, {len(self.functions)} functions"
            )
        return self.parsed_contract

    def _extract_contract_name(self, code: str) -> str:
        match = re.search(r"contract\s+(\w+)", code)
        return match.group(1) if match else "UnknownContract"

    def _extract_state_variables(self, code: str) -> List[str]:
        """Extract state variable names with types"""
        var_pattern = (
            r"(uint|address|bool|string|bytes|mapping)\s*\(?(\d+)?\)?\s+(\w+)\s*(?==|;)"
        )
        matches = re.findall(var_pattern, code, re.IGNORECASE)
        vars = [
            f"{typ}{size} {name}" if size else f"{typ} {name}"
            for typ, size, name in matches
        ]
        return vars

    def _extract_functions(self, code: str) -> List[Dict]:
        """Extract function names, visibility, modifiers"""
        func_pattern = r"function\s+(\w+)\s*\((.*?)\)\s*(external|public|internal|private)?\s*(view|pure)?\s*(returns\s*\((.*?)\))?\s*{"
        matches = re.findall(func_pattern, code, re.DOTALL)
        functions = []
        for name, params, visibility, state_mut, returns, _ in matches:
            functions.append(
                {
                    "name": name,
                    "visibility": visibility or "public",
                    "state_mut": state_mut is None,  # Not view/pure
                    "params": params.strip(),
                    "returns": returns or "void",
                }
            )
        return functions

    def _detect_patterns(self, code: str) -> Dict[str, int]:
        """Detect common patterns for property generation"""
        patterns = {
            "reentrancy": len(re.findall(r"\.call\{value:", code)),
            "access_control": len(re.findall(r"onlyOwner|require\(msg\.sender", code)),
            "oracle": len(re.findall(r"oracle|price", code)),
            "mapping": len(re.findall(r"mapping\s*\(", code)),
            "governance": len(re.findall(r"vote|proposal|quorum", code)),
            "bridge": len(re.findall(r"bridge|crosschain|relay", code)),
        }
        return patterns

    def generate_invariants_from_contract(
        self, contract_code: str, contract_name: Optional[str] = None
    ) -> List[FormalProperty]:
        """Enhanced generation using parsed contract and economic invariants integration"""
        self.parse_contract(contract_code)
        if contract_name:
            self.contract_name = contract_name

        properties = []

        # Base invariants from parsing
        properties.extend(self._generate_balance_invariants())
        properties.extend(self._generate_access_control_invariants())
        properties.extend(self._generate_state_invariants())
        properties.extend(self._generate_math_invariants())

        # Pattern-specific properties
        patterns = self.parsed_contract["patterns"]
        if patterns["oracle"] > 0:
            properties.extend(self._generate_oracle_invariants())
        if patterns["mapping"] > 0:
            properties.extend(self._generate_mapping_invariants())
        if patterns["governance"] > 0:
            properties.extend(self._generate_governance_invariants())
        if patterns["bridge"] > 0:
            properties.extend(self._generate_bridge_invariants())

        # Integrate economic invariants (mock call to generator)
        try:
            from ..llm.economic_invariant_generator import EconomicInvariantGenerator

            gen = EconomicInvariantGenerator()
            econ_invs = gen.generate_invariants(contract_code, "auto")
            for inv in econ_invs:
                prop = FormalProperty(
                    name=inv.name,
                    property_type=PropertyType.INVARIANT,
                    description=inv.description,
                    formal_spec=inv.invariant_code.split("returns")[1]
                    .strip()
                    .split(";")[0]
                    if "returns" in inv.invariant_code
                    else inv.invariant_code,
                    solidity_annotation=f"/// @invariant {inv.description}",
                    verification_tool=VerificationTool.CERTORA,
                    severity=inv.risk_level,
                )
                properties.append(prop)
        except ImportError:
            if self.verbose:
                print("Economic generator not available; skipping integration")

        # Prioritize by severity
        properties.sort(
            key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3}[p.severity]
        )

        self.properties = properties
        return properties

    def _generate_balance_invariants(self) -> List[FormalProperty]:
        """Enhanced balance invariants with contract-specific vars"""
        vars_with_balance = [
            v
            for v in self.state_variables
            if "balance" in v.lower() or "supply" in v.lower()
        ]
        properties = []
        if vars_with_balance:
            properties.append(
                FormalProperty(
                    name="balance_conservation_specific",
                    property_type=PropertyType.INVARIANT,
                    description=f"Total {self.contract_name} balance conserved: totalSupply == sum(balances)",
                    formal_spec=f"totalSupply == sum({', '.join([v.split()[-1] for v in vars_with_balance[:3]])})",  # Limit for spec
                    solidity_annotation="/// @invariant totalSupply == sum(balances)",
                    verification_tool=VerificationTool.CERTORA,
                    severity="critical",
                    contract_specific=True,
                )
            )
        properties.append(
            FormalProperty(
                name="no_negative_balance",
                property_type=PropertyType.INVARIANT,
                description="No negative balances in any user account",
                formal_spec="forall address u. balances[u] >= 0",
                solidity_annotation="/// @invariant forall address u. balances[u] >= 0",
                verification_tool=VerificationTool.SCRIBBLE,
                severity="high",
            )
        )
        properties.append(
            FormalProperty(
                name="withdrawal_precond",
                property_type=PropertyType.PRECONDITION,
                description="Withdrawal amount <= user balance",
                formal_spec="amount <= balances[msg.sender]",
                solidity_annotation="/// @pre amount <= balances[msg.sender]",
                verification_tool=VerificationTool.ALL,
                severity="medium",
            )
        )
        return properties

    def _generate_access_control_invariants(self) -> List[FormalProperty]:
        """Enhanced access control with function-specific rules"""
        owner_functions = [
            f
            for f in self.functions
            if "onlyOwner"
            in self.parsed_contract.get("patterns", {}).get("access_control", 0)
            > 0
        ]
        properties = []
        properties.append(
            FormalProperty(
                name="owner_preservation",
                property_type=PropertyType.INVARIANT,
                description="Owner preserved unless transferred by current owner",
                formal_spec="owner == old(owner) || msg.sender == old(owner)",
                solidity_annotation="/// @invariant owner == old(owner) || msg.sender == old(owner)",
                verification_tool=VerificationTool.CERTORA,
                severity="high",
            )
        )
        if owner_functions:
            properties.append(
                FormalProperty(
                    name="owner_function_rule",
                    property_type=PropertyType.RULE,
                    description=f"Only owner can call {owner_functions[0]['name']} if onlyOwner",
                    formal_spec=f"rule onlyOwnerRule() {{ env.msg.sender == owner => {owner_functions[0]['name']}() }}",
                    solidity_annotation=f"/// @rule Only owner can call {owner_functions[0]['name']}",
                    verification_tool=VerificationTool.CERTORA,
                    severity="critical",
                    contract_specific=True,
                )
            )
        properties.append(
            FormalProperty(
                name="unique_owner",
                property_type=PropertyType.INVARIANT,
                description="Exactly one owner exists",
                formal_spec="exists1 address o. o == owner",
                solidity_annotation="/// @invariant exists1 address o. o == owner",
                verification_tool=VerificationTool.SMT,
                severity="medium",
            )
        )
        return properties

    def _generate_state_invariants(self) -> List[FormalProperty]:
        """State machine invariants based on parsed state vars"""
        properties = []
        state_vars = [
            v.split()[-1]
            for v in self.state_variables
            if "state" in v.lower() or "status" in v.lower()
        ]
        if state_vars:
            properties.append(
                FormalProperty(
                    name="valid_state_enum",
                    property_type=PropertyType.INVARIANT,
                    description=f"State variable {state_vars[0]} in valid enum values",
                    formal_spec=f"{state_vars[0]} in {self.contract_name}State.PENDING | {self.contract_name}State.ACTIVE | ...",  # Mock enum
                    solidity_annotation=f"/// @invariant {state_vars[0]} in valid states",
                    verification_tool=VerificationTool.CERTORA,
                    severity="medium",
                    contract_specific=True,
                )
            )
        # General state consistency
        properties.append(
            FormalProperty(
                name="state_transition_valid",
                property_type=PropertyType.POSTCONDITION,
                description="State transitions maintain consistency",
                formal_spec="old(state) != state => transition_valid(old(state), state)",
                solidity_annotation="/// @post old(state) != state => transition_valid(old(state), state)",
                verification_tool=VerificationTool.SCRIBBLE,
                severity="high",
            )
        )
        return properties

    def _generate_math_invariants(self) -> List[FormalProperty]:
        """Mathematical invariants with overflow checks"""
        properties = [
            FormalProperty(
                name="no_arithmetic_overflow",
                property_type=PropertyType.INVARIANT,
                description="All arithmetic operations within uint256 bounds",
                formal_spec="forall uint x y. safeMath(x + y) && safeMath(x * y)",
                solidity_annotation="/// @invariant forall uint x y. safeMath(x + y) && safeMath(x * y)",
                verification_tool=VerificationTool.CERTORA,
                severity="critical",
            ),
            FormalProperty(
                name="division_no_zero",
                property_type=PropertyType.PRECONDITION,
                description="No division by zero in calculations",
                formal_spec="denominator > 0",
                solidity_annotation="/// @pre denominator > 0",
                verification_tool=VerificationTool.ALL,
                severity="high",
            ),
            FormalProperty(
                name="rounding_consistent",
                property_type=PropertyType.INVARIANT,
                description="Rounding in fees/interest consistent (no loss/gain exploit)",
                formal_spec="rounded_value == floor(value / precision) * precision",
                solidity_annotation="/// @invariant rounded_value == floor(value / precision) * precision",
                verification_tool=VerificationTool.SMT,
                severity="medium",
            ),
        ]
        return properties

    def _generate_oracle_invariants(self) -> List[FormalProperty]:
        """Oracle-specific properties"""
        properties = [
            FormalProperty(
                name="oracle_price_bounds",
                property_type=PropertyType.INVARIANT,
                description="Oracle prices within reasonable bounds to prevent manipulation",
                formal_spec="MIN_PRICE <= oraclePrice <= MAX_PRICE",
                solidity_annotation="/// @invariant MIN_PRICE <= oraclePrice <= MAX_PRICE",
                verification_tool=VerificationTool.CERTORA,
                severity="high",
                contract_specific=True,
            ),
            FormalProperty(
                name="no_stale_oracle",
                property_type=PropertyType.PRECONDITION,
                description="Oracle data not stale (timestamp check)",
                formal_spec="block.timestamp - oracleTimestamp <= STALE_THRESHOLD",
                solidity_annotation="/// @pre block.timestamp - oracleTimestamp <= STALE_THRESHOLD",
                verification_tool=VerificationTool.SCRIBBLE,
                severity="critical",
            ),
            FormalProperty(
                name="oracle_adjust_safety",
                property_type=PropertyType.RULE,
                description="Oracle adjustment doesn't create free collateral",
                formal_spec="rule oracleRule() { balanceAfterAdjust <= balanceBefore + legitimateGain }",
                solidity_annotation="/// @rule balanceAfterAdjust <= balanceBefore + legitimateGain",
                verification_tool=VerificationTool.CERTORA,
                severity="high",
            ),
        ]
        return properties

    def _generate_mapping_invariants(self) -> List[FormalProperty]:
        """Mapping safety for bridges/default exploits"""
        properties = [
            FormalProperty(
                name="mapping_initialized",
                property_type=PropertyType.INVARIANT,
                description="Critical mappings initialized, no default value exploits",
                formal_spec="forall key. initializedMapping[key] || defaultSafe(key)",
                solidity_annotation="/// @invariant forall key. initializedMapping[key] || defaultSafe(key)",
                verification_tool=VerificationTool.CERTORA,
                severity="critical",
                contract_specific=True,
            ),
            FormalProperty(
                name="no_default_key_exploit",
                property_type=PropertyType.INVARIANT,
                description="Key 0 or default keys don't allow unauthorized access",
                formal_spec="confirmAt[0] == false",  # Nomad-like
                solidity_annotation="/// @invariant confirmAt[0] == false",
                verification_tool=VerificationTool.SCRIBBLE,
                severity="high",
            ),
        ]
        return properties

    def _generate_governance_invariants(self) -> List[FormalProperty]:
        """Governance-specific properties"""
        properties = [
            FormalProperty(
                name="vote_conservation",
                property_type=PropertyType.INVARIANT,
                description="Total votes conserved, no flash loan inflation",
                formal_spec="totalVotesAfter == totalVotesBefore",
                solidity_annotation="/// @invariant totalVotesAfter == totalVotesBefore",
                verification_tool=VerificationTool.CERTORA,
                severity="high",
            ),
            FormalProperty(
                name="quorum_met",
                property_type=PropertyType.PRECONDITION,
                description="Proposals require quorum for execution",
                formal_spec="participatingVotes >= quorumThreshold",
                solidity_annotation="/// @pre participatingVotes >= quorumThreshold",
                verification_tool=VerificationTool.ALL,
                severity="critical",
            ),
            FormalProperty(
                name="timelock_delay",
                property_type=PropertyType.INVARIANT,
                description="Governance changes respect timelock",
                formal_spec="executionTime >= proposalTime + delay",
                solidity_annotation="/// @invariant executionTime >= proposalTime + delay",
                verification_tool=VerificationTool.SMT,
                severity="medium",
            ),
        ]
        return properties

    def _generate_bridge_invariants(self) -> List[FormalProperty]:
        """Bridge-specific properties"""
        properties = [
            FormalProperty(
                name="bridge_conservation",
                property_type=PropertyType.INVARIANT,
                description="Locked on source == minted on target",
                formal_spec="lockedAmountSource == mintedAmountTarget",
                solidity_annotation="/// @invariant lockedAmountSource == mintedAmountTarget",
                verification_tool=VerificationTool.CERTORA,
                severity="critical",
                contract_specific=True,
            ),
            FormalProperty(
                name="message_nonce_order",
                property_type=PropertyType.INVARIANT,
                description="Messages processed in nonce order",
                formal_spec="currentNonce == old(currentNonce) + 1",
                solidity_annotation="/// @invariant currentNonce == old(currentNonce) + 1",
                verification_tool=VerificationTool.SCRIBBLE,
                severity="high",
            ),
            FormalProperty(
                name="no_replay",
                property_type=PropertyType.INVARIANT,
                description="No message replay (nonce unique)",
                formal_spec="processedNonces[nonce] == true => nonce not reused",
                solidity_annotation="/// @invariant processedNonces[nonce] == true => nonce not reused",
                verification_tool=VerificationTool.SMT,
                severity="critical",
            ),
        ]
        return properties

    def generate_certora_spec(
        self, contract_name: str, properties: List[FormalProperty]
    ) -> str:
        """Enhanced Certora spec with rules, invariants, and ghost vars"""
        if contract_name is None:
            contract_name = self.contract_name
        spec = f"""/*
 * Comprehensive Certora Specification for {contract_name}
 * Generated by Web3 Bug Hunter Formal Verification Helper
 * Includes invariants, rules for reentrancy, access, oracle, bridge, governance
 */

using {contract_name} as Protocol;

methods {{{{
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function complexTransfer(address to, uint256 amount, uint256 fee) external;
    function adjustBalanceBasedOnPrice(address user, uint256 multiplier) external;
    function updateAuthorization(address user, bool status) external;
    function emergencyWithdraw() external;
    function totalSupply() external view returns (uint256);
    function balances(address) external view returns (uint256);
    function owner() external view returns (address);
    function isAuthorized(address) external view returns (bool);
}}}}

ghost uint256 totalProcessedMessages;  // Ghost for message counting in bridge sim
ghost mapping(uint256 => bool) processedNonces;  // For replay protection

// Hook for message processing
hook Sstore currentNonce uint256 newNonce {{{{
    totalProcessedMessages = totalProcessedMessages + 1;
    processedNonces[newNonce] = true;
}}}}

"""

        # Invariants section
        certora_props = [
            p
            for p in properties
            if p.verification_tool in [VerificationTool.CERTORA, VerificationTool.ALL]
        ]
        if certora_props:
            spec += "\n// === INVARIANTS ===\n"
            for prop in certora_props:
                if prop.property_type == PropertyType.INVARIANT:
                    spec += f"invariant {prop.name}() {{\n"
                    spec += f"    {prop.formal_spec};\n"
                    spec += f"    // {prop.description} (severity: {prop.severity})\n"
                    spec += "}\n\n"

        # Rules section
        rules = [p for p in properties if p.property_type == PropertyType.RULE]
        if rules:
            spec += "// === RULES ===\n"
            for rule in rules:
                spec += f"rule {rule.name}() {{\n"
                spec += "    env e; calldataarg args;\n"
                spec += f"    // {rule.description}\n"
                spec += f"    {rule.formal_spec};\n"
                spec += f"    // Applies to {self.contract_name} (severity: {rule.severity})\n"
                spec += "}}\n\n"

        # Property-specific rules (e.g., reentrancy)
        spec += self._generate_certora_reentrancy_rule()
        spec += self._generate_certora_bridge_rule()

        return spec

    def _generate_certora_reentrancy_rule(self) -> str:
        """Generate reentrancy-specific rule"""
        return """
// Reentrancy Rule for withdraw-like functions
rule noReentrancyExploit() {
    env e;
    calldataarg args;
    uint256 initialBalance = balances[e.msg.sender];

    // Call withdraw
    withdraw@withrevert(e, args);
    bool reverted = lastReverted;

    // Check no multiple withdraw if not reverted
    assert !reverted => balances[e.msg.sender] == initialBalance - expectedAmount;
    // State updated before external call in safe impl
}
"""

    def _generate_certora_bridge_rule(self) -> str:
        """Generate bridge-specific rule"""
        return """
// Bridge Conservation Rule
rule bridgeConservation() {
    env e;
    uint256 initialLocked = lockedAmount;
    uint256 initialMinted = mintedAmount;

    // Process message
    processMessage@withrevert(e);
    bool reverted = lastReverted;

    assert !reverted => lockedAmount == initialLocked + delta && mintedAmount == initialMinted + delta;
    // Conservation holds
}
"""

    def generate_scribble_annotations(
        self, contract_code: str, properties: List[FormalProperty]
    ) -> str:
        """Enhanced Scribble annotations inserted at appropriate locations"""
        annotated_code = contract_code
        scribble_props = [
            p
            for p in properties
            if p.verification_tool in [VerificationTool.SCRIBBLE, VerificationTool.ALL]
        ]

        # Insert contract-level invariants
        invariants = [
            p for p in scribble_props if p.property_type == PropertyType.INVARIANT
        ]
        if invariants:
            contract_start = re.search(r"contract\s+\w+\s*{", annotated_code).end()
            invariant_block = "\n    // Scribble Invariants\n"
            for inv in invariants:
                invariant_block += f"    {inv.solidity_annotation}\n"
            annotated_code = (
                annotated_code[:contract_start]
                + invariant_block
                + annotated_code[contract_start:]
            )

        # Insert pre/post for functions
        pre_posts = [
            p
            for p in scribble_props
            if p.property_type
            in [PropertyType.PRECONDITION, PropertyType.POSTCONDITION]
        ]
        for prop in pre_posts:
            # Find matching function
            func_match = re.search(
                rf"function\s+{prop.name.split('_')[0]}\s*\(", annotated_code
            )  # Approximate match
            if func_match:
                insert_pos = func_match.start()
                annotation = f"\n    {prop.solidity_annotation}\n    "
                annotated_code = (
                    annotated_code[:insert_pos]
                    + annotation
                    + annotated_code[insert_pos:]
                )

        # Add assertions for critical paths
        assertions = [
            p for p in scribble_props if p.property_type == PropertyType.ASSERTION
        ]
        for ass in assertions:
            # Insert assert in code (simplified, after require)
            require_pos = annotated_code.find("require(")
            if require_pos != -1:
                insert_pos = annotated_code.find(";", require_pos)
                annotation = f"\n    assert {ass.formal_spec}; // {ass.description}\n"
                annotated_code = (
                    annotated_code[:insert_pos]
                    + annotation
                    + annotated_code[insert_pos:]
                )

        return annotated_code

    def create_smt_queries(self, properties: List[FormalProperty]) -> List[str]:
        """Enhanced SMT queries with more variables and constraints"""
        queries = []
        smt_props = [
            p
            for p in properties
            if p.verification_tool in [VerificationTool.SMT, VerificationTool.ALL]
        ]

        for prop in smt_props:
            query = f""";
 * SMT Query for {prop.name}
 * {prop.description}
 * Severity: {prop.severity}

(declare-datatypes () ((Address (mk-Address (val Int)))))
(declare-datatypes () ((Uint256 (mk-Uint256 (val Int)))))

; Variables from contract
(declare-const owner Address)
(declare-const msg_sender Address)
(declare-const balance_sender Uint256)
(declare-const total_supply Uint256)
(declare-const oracle_price Uint256)
(declare-const nonce Uint256)

; Define max uint256
(define-fun max_uint256 () Int 115792089237316195423570985008687907853269984665640564039457584007913129639935)

; Property definition
(define-fun {prop.name} () Bool
    {self._convert_to_smt_enhanced(prop.formal_spec)}
)

; Assert negation and check sat
(assert (not ({prop.name})))
(check-sat)
(get-model)
"""
            queries.append(query)

        return queries

    def _convert_to_smt_enhanced(self, formal_spec: str) -> str:
        """Enhanced SMT conversion with more operators"""
        smt_spec = formal_spec

        # Replace Solidity to SMT
        replacements = {
            "forall address u.": "(forall ((u Address)) ",
            "exists address o.": "(exists ((o Address)) ",
            "msg.sender": "msg_sender.val",
            "balances[u]": "(ite (= u.val (mk-Address u.val)) balance_sender.val 0)",  # Simplified
            "totalSupply": "total_supply.val",
            "oraclePrice": "oracle_price.val",
            "==": "=",
            ">=": ">=",
            "<=": "<=",
            " > ": " > ",
            " + ": " + ",
            " * ": " * ",
            " / ": " / ",
            " && ": " and ",
            " || ": " or ",
            " !": " not ",
            "block.timestamp": "current_timestamp",  # Assume declared
        }
        for sol, smt in replacements.items():
            smt_spec = smt_spec.replace(sol, smt)

        # Close forall/exists
        smt_spec = smt_spec.replace("forall", "(forall").replace("exists", "(exists")
        if smt_spec.count("(") > smt_spec.count(")"):
            smt_spec += ")"

        # Bounds check
        smt_spec += " && (<= total_supply.val max_uint256)"

        return smt_spec

    def validate_properties(self, properties: List[FormalProperty]) -> Dict[str, Any]:
        """Enhanced validation with dependency checks and severity scoring"""
        results = {
            "valid": 0,
            "invalid": 0,
            "warnings": [],
            "critical_count": 0,
            "high_count": 0,
            "dependency_issues": [],
        }

        for prop in properties:
            if not prop.name or not prop.formal_spec:
                results["invalid"] += 1
                continue

            # Severity count
            if prop.severity == "critical":
                results["critical_count"] += 1
            elif prop.severity == "high":
                results["high_count"] += 1

            # Dependency check
            for dep in prop.dependencies:
                if not any(d.name == dep for d in properties):
                    results["dependency_issues"].append(
                        f"{prop.name} depends on missing {dep}"
                    )

            # Tool compatibility
            if (
                "forall" in prop.formal_spec
                and prop.verification_tool == VerificationTool.SCRIBBLE
            ):
                results["warnings"].append(
                    f"{prop.name}: Forall not fully supported in Scribble"
                )

            if len(prop.formal_spec) > 300:
                results["warnings"].append(
                    f"{prop.name}: Complex spec may timeout in verification"
                )

            results["valid"] += 1

        results["total"] = len(properties)
        results["coverage_score"] = (
            results["valid"] / results["total"] if results["total"] > 0 else 0
        )

        return results

    def generate_comprehensive_report(
        self, properties: List[FormalProperty]
    ) -> Dict[str, Any]:
        """Generate report with prioritization and bounty impact"""
        validation = self.validate_properties(properties)
        specs = {
            "certora": self.generate_certora_spec(None, properties),
            "scribble": self.generate_scribble_annotations("", properties),  # Need code
            "smt_queries": self.create_smt_queries(properties),
        }

        bounty_impact = []
        criticals = [p for p in properties if p.severity == "critical"]
        if criticals:
            bounty_impact.append(
                "Critical properties suggest high-severity vulns; potential $50k+ bounty"
            )

        report = {
            "properties": [asdict(p) for p in properties],
            "validation": validation,
            "specs": {
                k: v[:500] + "..." if isinstance(v, str) and len(v) > 500 else v
                for k, v in specs.items()
            },
            "bounty_recommendations": bounty_impact,
            "next_steps": [
                "Run Certora Prover on generated spec",
                "Annotate contract with Scribble and compile",
                "Use Z3 for SMT queries to find counterexamples",
                "Focus on critical properties for manual PoC",
            ],
        }

        return report


# Enhanced example usage
def demonstrate_enhanced_formal_verification():
    """Demonstrate enhanced formal verification with vulnerable contract"""
    helper = FormalVerificationHelper(verbose=True)

    # Load vulnerable contract
    with open("../../examples/vulnerable_contract.sol", "r") as f:
        code = f.read()

    # Generate comprehensive properties
    properties = helper.generate_invariants_from_contract(
        code, "VulnerableDeFiProtocol"
    )

    # Generate specs
    certora_spec = helper.generate_certora_spec("VulnerableDeFiProtocol", properties)
    scribble_code = helper.generate_scribble_annotations(code, properties)
    smt_queries = helper.create_smt_queries(properties)

    # Report
    report = helper.generate_comprehensive_report(properties)

    # Save outputs
    with open("enhanced_certora.spec", "w") as f:
        f.write(certora_spec)
    with open("enhanced_scribble.sol", "w") as f:
        f.write(scribble_code)
    with open("smt_queries.smt", "w") as f:
        f.write("\n\n".join(smt_queries))

    print(
        f"Generated {len(properties)} properties: {report['validation']['critical_count']} critical"
    )
    print("Files saved: enhanced_certora.spec, enhanced_scribble.sol, smt_queries.smt")
    return report


if __name__ == "__main__":
    report = demonstrate_enhanced_formal_verification()
    print(json.dumps(report, indent=2, default=str))
