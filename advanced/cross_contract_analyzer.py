"""
Cross-Contract Analysis Module
Analyzes interactions, dependencies, and vulnerabilities across multiple contracts
"""

import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from collections import defaultdict, deque
from enum import Enum
import hashlib


class CrossContractVulnType(Enum):
    """Types of cross-contract vulnerabilities"""

    CIRCULAR_DEPENDENCY = "circular_dependency"
    REENTRANCY_CHAIN = "cross_contract_reentrancy"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    STATE_INCONSISTENCY = "state_inconsistency"
    UNSAFE_DELEGATION = "unsafe_delegation"
    ORACLE_MANIPULATION = "oracle_manipulation_chain"
    FLASH_LOAN_ATTACK = "flash_loan_attack_vector"
    SANDWICH_ATTACK = "sandwich_attack_opportunity"
    BUSINESS_LOGIC_FLAW = "business_logic_violation"
    ACCESS_CONTROL_BYPASS = "access_control_bypass"
    SHARED_STATE_RACE = "shared_state_race_condition"
    PROXY_COLLISION = "proxy_storage_collision"


@dataclass
class ContractInfo:
    """Information about a single contract"""

    name: str
    path: str
    code: str
    functions: Dict[str, "FunctionInfo"] = field(default_factory=dict)
    state_variables: Dict[str, str] = field(default_factory=dict)
    external_calls: List["ExternalCall"] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    inherits: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    is_library: bool = False
    is_interface: bool = False
    is_abstract: bool = False


@dataclass
class FunctionInfo:
    """Information about a contract function"""

    name: str
    contract: str
    visibility: str
    mutability: str
    modifiers: List[str]
    parameters: List[str]
    returns: List[str]
    calls_external: List[str]
    reads_state: List[str]
    writes_state: List[str]
    has_require: bool
    has_assert: bool
    payable: bool
    code: str


@dataclass
class ExternalCall:
    """Information about an external contract call"""

    from_contract: str
    from_function: str
    to_contract: str
    to_function: str
    call_type: str  # call, delegatecall, staticcall
    line_number: int
    context: str


@dataclass
class CrossContractVulnerability:
    """A vulnerability spanning multiple contracts"""

    vuln_type: CrossContractVulnType
    severity: str  # critical, high, medium, low
    confidence: float
    name: str
    description: str
    contracts_involved: List[str]
    attack_scenario: str
    exploit_path: List[str]
    affected_functions: List[str]
    business_logic_violation: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    code_evidence: Dict[str, str] = field(default_factory=dict)


@dataclass
class CallGraph:
    """Cross-contract call graph"""

    nodes: Set[str] = field(default_factory=set)  # contract.function
    edges: List[Tuple[str, str]] = field(default_factory=list)  # (from, to)
    external_edges: List[Tuple[str, str, str]] = field(
        default_factory=list
    )  # (from, to, call_type)


@dataclass
class ProtocolInvariant:
    """Business logic invariant that should hold across the protocol"""

    name: str
    description: str
    contracts_involved: List[str]
    validation_rule: str
    violated: bool = False
    violation_evidence: str = ""


class CrossContractAnalyzer:
    """
    Analyzes multiple contracts together to find vulnerabilities
    that only appear when considering contract interactions
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.contracts: Dict[str, ContractInfo] = {}
        self.call_graph = CallGraph()
        self.vulnerabilities: List[CrossContractVulnerability] = []
        self.invariants: List[ProtocolInvariant] = []
        self.contract_relationships: Dict[str, List[str]] = defaultdict(list)

    def analyze_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Analyze all contracts in a directory

        Args:
            directory_path: Path to directory containing Solidity files

        Returns:
            Comprehensive analysis results
        """
        self._log(f"🔍 Cross-Contract Analysis: {directory_path}")
        self._log("=" * 70)

        # Step 1: Load all contracts
        self._log("\n[1/7] Loading contracts...")
        self._load_contracts(directory_path)
        self._log(f"  Loaded {len(self.contracts)} contracts")

        # Step 2: Parse contract structures
        self._log("\n[2/7] Parsing contract structures...")
        for contract in self.contracts.values():
            self._parse_contract_structure(contract)
        self._log(
            f"  Parsed {sum(len(c.functions) for c in self.contracts.values())} functions"
        )

        # Step 3: Build call graph
        self._log("\n[3/7] Building cross-contract call graph...")
        self._build_call_graph()
        self._log(f"  Found {len(self.call_graph.external_edges)} external calls")

        # Step 4: Analyze dependencies
        self._log("\n[4/7] Analyzing contract dependencies...")
        self._analyze_dependencies()

        # Step 5: Detect cross-contract vulnerabilities
        self._log("\n[5/7] Detecting cross-contract vulnerabilities...")
        self._detect_vulnerabilities()
        self._log(f"  Found {len(self.vulnerabilities)} cross-contract issues")

        # Step 6: Validate business logic
        self._log("\n[6/7] Validating protocol-wide business logic...")
        self._validate_business_logic()

        # Step 7: Generate report
        self._log("\n[7/7] Generating analysis report...")
        report = self._generate_report()

        self._log("\n✅ Cross-contract analysis complete!")
        return report

    def _load_contracts(self, directory_path: str):
        """Load all Solidity contracts from directory"""
        path = Path(directory_path)

        if path.is_file() and path.suffix == ".sol":
            # Single file
            self._load_contract_file(path)
        elif path.is_dir():
            # Directory - find all .sol files
            for sol_file in path.rglob("*.sol"):
                # Skip common library directories
                if any(
                    skip in str(sol_file) for skip in ["node_modules", "lib", "test"]
                ):
                    continue
                self._load_contract_file(sol_file)
        else:
            raise ValueError(f"Invalid path: {directory_path}")

    def _load_contract_file(self, file_path: Path):
        """Load a single Solidity file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            # Extract contract names from file
            contract_pattern = (
                r"(?:contract|interface|library|abstract\s+contract)\s+(\w+)"
            )
            contracts_in_file = re.findall(contract_pattern, code)

            for contract_name in contracts_in_file:
                # Extract just this contract's code
                contract_code = self._extract_contract_code(code, contract_name)

                self.contracts[contract_name] = ContractInfo(
                    name=contract_name,
                    path=str(file_path),
                    code=contract_code,
                    is_library="library" in code,
                    is_interface="interface" in code,
                    is_abstract="abstract contract" in code,
                )
        except Exception as e:
            self._log(f"  Warning: Failed to load {file_path}: {e}")

    def _extract_contract_code(self, full_code: str, contract_name: str) -> str:
        """Extract code for a specific contract from file"""
        pattern = rf"((?:contract|interface|library|abstract\s+contract)\s+{contract_name}[^{{]*\{{)"
        match = re.search(pattern, full_code)

        if not match:
            return full_code

        start = match.start()
        brace_count = 0
        in_contract = False
        end = start

        for i in range(start, len(full_code)):
            if full_code[i] == "{":
                brace_count += 1
                in_contract = True
            elif full_code[i] == "}":
                brace_count -= 1
                if in_contract and brace_count == 0:
                    end = i + 1
                    break

        return full_code[start:end] if end > start else full_code

    def _parse_contract_structure(self, contract: ContractInfo):
        """Parse contract structure: functions, state variables, etc."""
        code = contract.code

        # Extract inheritance
        inherit_pattern = (
            rf"(?:contract|abstract\s+contract)\s+{contract.name}\s+is\s+([^{{]+)\s*{{"
        )
        inherit_match = re.search(inherit_pattern, code)
        if inherit_match:
            inherited = inherit_match.group(1)
            contract.inherits = [i.strip() for i in inherited.split(",")]

        # Extract state variables
        state_var_pattern = r"^\s*((?:public|private|internal)\s+)?(\w+(?:\[\])?)\s+(?:public|private|internal)?\s*(\w+)\s*(?:=|;)"
        for match in re.finditer(state_var_pattern, code, re.MULTILINE):
            var_type = match.group(2)
            var_name = match.group(3)
            contract.state_variables[var_name] = var_type

        # Extract functions
        func_pattern = r"function\s+(\w+)\s*\(([^)]*)\)\s*(public|private|internal|external)?\s*(pure|view|payable)?\s*((?:returns\s*\([^)]*\))?)?\s*(?:(\w+(?:\([^)]*\))?(?:\s+\w+(?:\([^)]*\))?)*))?\s*\{"

        for match in re.finditer(func_pattern, code):
            func_name = match.group(1)
            params = match.group(2) or ""
            visibility = match.group(3) or "public"
            mutability = match.group(4) or ""
            returns = match.group(5) or ""
            modifiers_str = match.group(6) or ""

            # Extract function body
            start_pos = match.end()
            func_body = self._extract_function_body(code[start_pos:])

            # Parse function details
            func_info = FunctionInfo(
                name=func_name,
                contract=contract.name,
                visibility=visibility,
                mutability=mutability,
                modifiers=self._parse_modifiers(modifiers_str),
                parameters=self._parse_parameters(params),
                returns=self._parse_returns(returns),
                calls_external=[],
                reads_state=[],
                writes_state=[],
                has_require="require(" in func_body,
                has_assert="assert(" in func_body,
                payable="payable" in mutability,
                code=func_body,
            )

            # Find external calls in function
            func_info.calls_external = self._find_external_calls(
                func_body, contract.name, func_name
            )

            # Find state variable access
            func_info.reads_state, func_info.writes_state = self._find_state_access(
                func_body, contract.state_variables
            )

            contract.functions[func_name] = func_info

        # Extract interfaces used
        interface_pattern = r"(\w+)\s*\([^)]*\)\s*\.(?:call|delegatecall|staticcall)"
        contract.interfaces = list(set(re.findall(interface_pattern, code)))

    def _extract_function_body(self, code: str) -> str:
        """Extract function body between braces"""
        brace_count = 1
        i = 0

        while i < len(code) and brace_count > 0:
            if code[i] == "{":
                brace_count += 1
            elif code[i] == "}":
                brace_count -= 1
            i += 1

        return code[: i - 1] if i > 0 else code[:200]

    def _parse_modifiers(self, modifiers_str: str) -> List[str]:
        """Parse function modifiers"""
        if not modifiers_str:
            return []

        # Extract modifier names
        mods = []
        for word in modifiers_str.split():
            if word and word[0].islower() and "(" not in word:
                mods.append(word)
        return mods

    def _parse_parameters(self, params_str: str) -> List[str]:
        """Parse function parameters"""
        if not params_str.strip():
            return []

        params = []
        for param in params_str.split(","):
            param = param.strip()
            if param:
                # Extract type and name
                parts = param.split()
                if len(parts) >= 2:
                    params.append(f"{parts[0]} {parts[-1]}")
        return params

    def _parse_returns(self, returns_str: str) -> List[str]:
        """Parse return types"""
        if not returns_str:
            return []

        # Extract types from returns(type1, type2)
        match = re.search(r"returns\s*\(([^)]+)\)", returns_str)
        if match:
            return [t.strip() for t in match.group(1).split(",")]
        return []

    def _find_external_calls(
        self, func_body: str, contract_name: str, func_name: str
    ) -> List[str]:
        """Find external contract calls in function body"""
        external_calls = []

        # Pattern for interface calls: ContractName(addr).function()
        interface_call_pattern = r"(\w+)\s*\([^)]*\)\s*\.(\w+)\s*\("
        for match in re.finditer(interface_call_pattern, func_body):
            external_calls.append(f"{match.group(1)}.{match.group(2)}")

        # Pattern for direct calls: contract.function()
        direct_call_pattern = r"(\w+)\.(\w+)\s*\("
        for match in re.finditer(direct_call_pattern, func_body):
            if match.group(1) not in ["this", "super", "msg", "block", "tx"]:
                external_calls.append(f"{match.group(1)}.{match.group(2)}")

        return list(set(external_calls))

    def _find_state_access(
        self, func_body: str, state_vars: Dict[str, str]
    ) -> Tuple[List[str], List[str]]:
        """Find which state variables are read/written"""
        reads = []
        writes = []

        for var_name in state_vars.keys():
            # Check for reads
            read_pattern = rf"\b{var_name}\b(?!\s*=)"
            if re.search(read_pattern, func_body):
                reads.append(var_name)

            # Check for writes
            write_pattern = rf"\b{var_name}\s*(?:=|\+=|-=|\*=|/=)"
            if re.search(write_pattern, func_body):
                writes.append(var_name)

        return reads, writes

    def _build_call_graph(self):
        """Build cross-contract call graph"""
        # Add all functions as nodes
        for contract in self.contracts.values():
            for func_name in contract.functions.keys():
                node = f"{contract.name}.{func_name}"
                self.call_graph.nodes.add(node)

        # Add edges for external calls
        for contract in self.contracts.values():
            for func_name, func_info in contract.functions.items():
                from_node = f"{contract.name}.{func_name}"

                # Check each external call
                for ext_call in func_info.calls_external:
                    # Parse external call
                    if "." in ext_call:
                        target_contract, target_func = ext_call.split(".", 1)

                        # Check if target contract exists in our analyzed contracts
                        if target_contract in self.contracts:
                            to_node = f"{target_contract}.{target_func}"

                            # Determine call type from code
                            call_type = "call"
                            if "delegatecall" in func_info.code:
                                call_type = "delegatecall"
                            elif "staticcall" in func_info.code:
                                call_type = "staticcall"

                            self.call_graph.edges.append((from_node, to_node))
                            self.call_graph.external_edges.append(
                                (from_node, to_node, call_type)
                            )

    def _analyze_dependencies(self):
        """Analyze contract dependencies and relationships"""
        # Build dependency graph
        for contract in self.contracts.values():
            # Track inheritance relationships
            for parent in contract.inherits:
                if parent in self.contracts:
                    self.contract_relationships[contract.name].append(parent)

            # Track external call relationships
            for func in contract.functions.values():
                for ext_call in func.calls_external:
                    if "." in ext_call:
                        target_contract = ext_call.split(".")[0]
                        if target_contract in self.contracts:
                            if (
                                target_contract
                                not in self.contract_relationships[contract.name]
                            ):
                                self.contract_relationships[contract.name].append(
                                    target_contract
                                )

    def _detect_vulnerabilities(self):
        """Detect cross-contract vulnerabilities"""
        self._detect_circular_dependencies()
        self._detect_cross_contract_reentrancy()
        self._detect_privilege_escalation()
        self._detect_state_inconsistencies()
        self._detect_unsafe_delegatecalls()
        self._detect_flash_loan_vectors()
        self._detect_sandwich_opportunities()
        self._detect_access_control_bypasses()
        self._detect_shared_state_races()
        self._detect_proxy_collisions()

    def _detect_circular_dependencies(self):
        """Detect circular dependencies between contracts"""
        # Use DFS to detect cycles
        visited = set()
        rec_stack = set()

        def has_cycle(node, path):
            visited.add(node)
            rec_stack.add(node)

            for neighbor in self.contract_relationships.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor, path + [neighbor]):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle = path[path.index(neighbor) :] + [neighbor]
                    self.vulnerabilities.append(
                        CrossContractVulnerability(
                            vuln_type=CrossContractVulnType.CIRCULAR_DEPENDENCY,
                            severity="medium",
                            confidence=0.95,
                            name="Circular Contract Dependency",
                            description=f"Circular dependency detected: {' -> '.join(cycle)}",
                            contracts_involved=cycle,
                            attack_scenario="Circular dependencies can lead to deployment issues and unexpected behavior",
                            exploit_path=cycle,
                            affected_functions=[],
                            remediation="Refactor contracts to remove circular dependencies. Consider using interfaces or events.",
                        )
                    )
                    return True

            rec_stack.remove(node)
            return False

        for contract in self.contracts.keys():
            if contract not in visited:
                has_cycle(contract, [contract])

    def _detect_cross_contract_reentrancy(self):
        """Detect reentrancy vulnerabilities across multiple contracts"""
        # Find paths where:
        # 1. Contract A calls Contract B
        # 2. Contract B can call back to Contract A
        # 3. Contract A's state is modified after the call

        for from_node, to_node, call_type in self.call_graph.external_edges:
            from_contract, from_func = from_node.split(".")
            to_contract, to_func = to_node.split(".")

            if from_contract == to_contract:
                continue

            # Check if there's a path back
            callback_paths = self._find_callback_paths(to_node, from_contract)

            if callback_paths:
                # Check if state is modified after external call
                func_info = self.contracts[from_contract].functions.get(from_func)
                if func_info and func_info.writes_state:
                    # Check if writes happen after external call
                    ext_call_pos = func_info.code.find(to_func)

                    if ext_call_pos > 0:
                        code_after_call = func_info.code[ext_call_pos:]

                        # Check if any state variable is written after the call
                        for state_var in func_info.writes_state:
                            if state_var in code_after_call:
                                self.vulnerabilities.append(
                                    CrossContractVulnerability(
                                        vuln_type=CrossContractVulnType.REENTRANCY_CHAIN,
                                        severity="critical",
                                        confidence=0.85,
                                        name="Cross-Contract Reentrancy Chain",
                                        description=f"{from_contract}.{from_func} is vulnerable to reentrancy via {to_contract}",
                                        contracts_involved=[from_contract, to_contract],
                                        attack_scenario=f"Attacker can exploit callback path: {from_node} -> {to_node} -> {callback_paths[0]}",
                                        exploit_path=[from_node, to_node]
                                        + callback_paths[0].split(" -> "),
                                        affected_functions=[from_func, to_func],
                                        remediation="Use checks-effects-interactions pattern or nonReentrant modifier",
                                        references=[
                                            "Lendf.me hack ($25M)",
                                            "DAO hack ($60M)",
                                        ],
                                    )
                                )
                                break

    def _find_callback_paths(
        self, start_node: str, target_contract: str, max_depth: int = 3
    ) -> List[str]:
        """Find paths from start_node back to target_contract"""
        paths = []
        visited = set()

        def dfs(node, path, depth):
            if depth > max_depth:
                return

            if node in visited:
                return

            visited.add(node)
            contract_name = node.split(".")[0]

            if contract_name == target_contract and len(path) > 1:
                paths.append(" -> ".join(path))
                return

            # Find outgoing edges
            for from_n, to_n, _ in self.call_graph.external_edges:
                if from_n == node:
                    dfs(to_n, path + [to_n], depth + 1)

            visited.remove(node)

        dfs(start_node, [start_node], 0)
        return paths

    def _detect_privilege_escalation(self):
        """Detect privilege escalation opportunities"""
        # Find contracts with access control
        for contract in self.contracts.values():
            # Find functions with modifiers (likely access controlled)
            protected_funcs = {
                name: func
                for name, func in contract.functions.items()
                if func.modifiers
                and any(
                    m in ["onlyOwner", "onlyAdmin", "authorized"]
                    for m in func.modifiers
                )
            }

            if not protected_funcs:
                continue

            # Check if protected functions call external contracts
            for func_name, func_info in protected_funcs.items():
                for ext_call in func_info.calls_external:
                    if "." in ext_call:
                        target_contract, target_func = ext_call.split(".", 1)

                        if target_contract in self.contracts:
                            target_func_info = self.contracts[
                                target_contract
                            ].functions.get(target_func)

                            # Check if target function has less protection
                            if target_func_info and not target_func_info.modifiers:
                                # Check if target function can modify important state
                                if target_func_info.writes_state:
                                    self.vulnerabilities.append(
                                        CrossContractVulnerability(
                                            vuln_type=CrossContractVulnType.PRIVILEGE_ESCALATION,
                                            severity="high",
                                            confidence=0.75,
                                            name="Privilege Escalation via External Call",
                                            description=f"Protected function {contract.name}.{func_name} calls unprotected {target_contract}.{target_func}",
                                            contracts_involved=[
                                                contract.name,
                                                target_contract,
                                            ],
                                            attack_scenario=f"Attacker could potentially bypass access control by calling {target_contract}.{target_func} directly",
                                            exploit_path=[
                                                f"{contract.name}.{func_name}",
                                                f"{target_contract}.{target_func}",
                                            ],
                                            affected_functions=[func_name, target_func],
                                            remediation=f"Add access control to {target_contract}.{target_func} or validate caller in the function",
                                        )
                                    )

    def _detect_state_inconsistencies(self):
        """Detect potential state inconsistencies across contracts"""
        # Find contracts that share similar state variables (likely related)
        shared_state = defaultdict(list)

        for contract in self.contracts.values():
            for var_name, var_type in contract.state_variables.items():
                # Common shared state patterns
                if any(
                    keyword in var_name.lower()
                    for keyword in ["balance", "total", "supply", "rate", "price"]
                ):
                    shared_state[var_name].append(contract.name)

        # Check if these contracts update shared state without synchronization
        for var_name, contracts_list in shared_state.items():
            if len(contracts_list) > 1:
                # Check if both contracts write to this variable
                writers = []
                for contract_name in contracts_list:
                    contract = self.contracts[contract_name]
                    for func_name, func_info in contract.functions.items():
                        if var_name in func_info.writes_state:
                            writers.append((contract_name, func_name))

                if len(writers) > 1:
                    self.vulnerabilities.append(
                        CrossContractVulnerability(
                            vuln_type=CrossContractVulnType.STATE_INCONSISTENCY,
                            severity="high",
                            confidence=0.65,
                            name="Potential State Inconsistency",
                            description=f"Multiple contracts modify similar state variable '{var_name}'",
                            contracts_involved=contracts_list,
                            attack_scenario="State could become inconsistent if updates are not properly synchronized",
                            exploit_path=[f"{c}.{f}" for c, f in writers],
                            affected_functions=[f for _, f in writers],
                            remediation="Ensure state updates are atomic or properly synchronized across contracts",
                        )
                    )

    def _detect_unsafe_delegatecalls(self):
        """Detect unsafe delegatecall patterns"""
        for from_node, to_node, call_type in self.call_graph.external_edges:
            if call_type == "delegatecall":
                from_contract, from_func = from_node.split(".")
                to_contract, to_func = to_node.split(".")

                func_info = self.contracts[from_contract].functions[from_func]

                # Check if target is user-controlled
                if any(param for param in func_info.parameters if "address" in param):
                    self.vulnerabilities.append(
                        CrossContractVulnerability(
                            vuln_type=CrossContractVulnType.UNSAFE_DELEGATION,
                            severity="critical",
                            confidence=0.90,
                            name="Unsafe Delegatecall to User-Controlled Address",
                            description=f"{from_contract}.{from_func} uses delegatecall with potentially user-controlled target",
                            contracts_involved=[from_contract, to_contract],
                            attack_scenario="Attacker can execute arbitrary code in the context of the calling contract",
                            exploit_path=[from_node, to_node],
                            affected_functions=[from_func],
                            remediation="Never use delegatecall with user-controlled addresses. Use whitelist if necessary.",
                            references=["Parity Wallet hack ($150M)"],
                        )
                    )

    def _detect_flash_loan_vectors(self):
        """Detect potential flash loan attack vectors"""
        # Look for patterns indicating flash loan vulnerability:
        # 1. Functions that check balances
        # 2. Functions that calculate based on reserves
        # 3. Functions without reentrancy protection

        for contract in self.contracts.values():
            for func_name, func_info in contract.functions.items():
                # Check if function reads balance/reserve state
                balance_reads = [
                    v
                    for v in func_info.reads_state
                    if any(
                        kw in v.lower()
                        for kw in ["balance", "reserve", "total", "supply"]
                    )
                ]

                if balance_reads and func_info.visibility == "external":
                    # Check if this function can be called in same tx as external calls
                    has_external_calls = len(func_info.calls_external) > 0
                    no_reentrancy_guard = "nonReentrant" not in func_info.modifiers

                    if has_external_calls and no_reentrancy_guard:
                        self.vulnerabilities.append(
                            CrossContractVulnerability(
                                vuln_type=CrossContractVulnType.FLASH_LOAN_ATTACK,
                                severity="high",
                                confidence=0.70,
                                name="Potential Flash Loan Attack Vector",
                                description=f"{contract.name}.{func_name} reads balance/reserves without reentrancy protection",
                                contracts_involved=[contract.name],
                                attack_scenario="Attacker could manipulate balances via flash loan and exploit this function",
                                exploit_path=[f"{contract.name}.{func_name}"],
                                affected_functions=[func_name],
                                remediation="Add reentrancy guard or use snapshot-based accounting",
                                references=[
                                    "Harvest Finance hack ($34M)",
                                    "Cream Finance hack ($130M)",
                                ],
                            )
                        )

    def _detect_sandwich_opportunities(self):
        """Detect MEV/sandwich attack opportunities"""
        # Look for functions that:
        # 1. Modify price/exchange rate
        # 2. Are public/external
        # 3. Don't have slippage protection

        for contract in self.contracts.values():
            for func_name, func_info in contract.functions.items():
                if func_info.visibility not in ["external", "public"]:
                    continue

                # Check if function affects price-sensitive state
                price_vars = [
                    v
                    for v in func_info.writes_state
                    if any(
                        kw in v.lower() for kw in ["price", "rate", "ratio", "reserve"]
                    )
                ]

                if price_vars:
                    # Check for slippage protection
                    has_slippage = any(
                        kw in func_info.code.lower()
                        for kw in ["slippage", "minreturn", "minamount", "deadline"]
                    )

                    if not has_slippage:
                        self.vulnerabilities.append(
                            CrossContractVulnerability(
                                vuln_type=CrossContractVulnType.SANDWICH_ATTACK,
                                severity="high",
                                confidence=0.75,
                                name="Sandwich Attack Opportunity",
                                description=f"{contract.name}.{func_name} modifies price without slippage protection",
                                contracts_involved=[contract.name],
                                attack_scenario="Attacker can front-run transaction, manipulate price, and back-run for profit",
                                exploit_path=[f"{contract.name}.{func_name}"],
                                affected_functions=[func_name],
                                remediation="Add slippage protection parameters (minReturn, maxPrice, deadline)",
                                references=["MEV attacks cost users $1B+ in 2021-2023"],
                            )
                        )

    def _detect_access_control_bypasses(self):
        """Detect access control bypass opportunities across contracts"""
        # Find protected functions and check if they can be bypassed via other contracts

        for contract in self.contracts.values():
            protected_funcs = {
                name: func
                for name, func in contract.functions.items()
                if func.modifiers
            }

            for func_name, func_info in protected_funcs.items():
                # Check if this function's state changes can be achieved via other contracts
                for state_var in func_info.writes_state:
                    # Find other functions that write to same state
                    alternative_writers = []

                    for other_contract in self.contracts.values():
                        if other_contract.name == contract.name:
                            continue

                        for (
                            other_func_name,
                            other_func,
                        ) in other_contract.functions.items():
                            if state_var in other_func.writes_state:
                                # Check if this path has less protection
                                if len(other_func.modifiers) < len(func_info.modifiers):
                                    alternative_writers.append(
                                        (other_contract.name, other_func_name)
                                    )

                    if alternative_writers:
                        self.vulnerabilities.append(
                            CrossContractVulnerability(
                                vuln_type=CrossContractVulnType.ACCESS_CONTROL_BYPASS,
                                severity="critical",
                                confidence=0.80,
                                name="Access Control Bypass via External Contract",
                                description=f"Protected {contract.name}.{func_name} can be bypassed via {alternative_writers[0][0]}.{alternative_writers[0][1]}",
                                contracts_involved=[
                                    contract.name,
                                    alternative_writers[0][0],
                                ],
                                attack_scenario=f"Attacker bypasses {func_info.modifiers} by calling alternative path",
                                exploit_path=[
                                    f"{c}.{f}" for c, f in alternative_writers
                                ],
                                affected_functions=[func_name]
                                + [f for _, f in alternative_writers],
                                remediation="Ensure consistent access control across all functions that modify critical state",
                            )
                        )

    def _detect_shared_state_races(self):
        """Detect race conditions in shared state across contracts"""
        # Find functions that read state from one contract and write to another

        for contract in self.contracts.values():
            for func_name, func_info in contract.functions.items():
                if not func_info.calls_external:
                    continue

                # Check if function reads external state then writes local state
                for ext_call in func_info.calls_external:
                    if "." not in ext_call:
                        continue

                    target_contract, target_func = ext_call.split(".", 1)

                    if target_contract not in self.contracts:
                        continue

                    target_func_info = self.contracts[target_contract].functions.get(
                        target_func
                    )

                    if (
                        target_func_info
                        and target_func_info.reads_state
                        and func_info.writes_state
                    ):
                        # Potential TOCTOU (Time-of-check Time-of-use)
                        self.vulnerabilities.append(
                            CrossContractVulnerability(
                                vuln_type=CrossContractVulnType.SHARED_STATE_RACE,
                                severity="medium",
                                confidence=0.60,
                                name="Shared State Race Condition",
                                description=f"{contract.name}.{func_name} reads from {target_contract} then writes local state",
                                contracts_involved=[contract.name, target_contract],
                                attack_scenario="State could change between read and write, causing inconsistency",
                                exploit_path=[
                                    f"{contract.name}.{func_name}",
                                    f"{target_contract}.{target_func}",
                                ],
                                affected_functions=[func_name, target_func],
                                remediation="Use atomic operations or implement proper locking mechanism",
                            )
                        )

    def _detect_proxy_collisions(self):
        """Detect storage collision risks in proxy patterns"""
        # Look for contracts that might be used as proxies

        for contract in self.contracts.values():
            # Check if contract uses delegatecall (proxy pattern indicator)
            uses_delegatecall = any(
                "delegatecall" in func.code for func in contract.functions.values()
            )

            if not uses_delegatecall:
                continue

            # Check inheritance - proxies often inherit from upgradeable bases
            for inherited in contract.inherits:
                if inherited in self.contracts:
                    parent = self.contracts[inherited]

                    # Check for storage variable conflicts
                    child_vars = set(contract.state_variables.keys())
                    parent_vars = set(parent.state_variables.keys())

                    conflicts = child_vars & parent_vars

                    if conflicts:
                        self.vulnerabilities.append(
                            CrossContractVulnerability(
                                vuln_type=CrossContractVulnType.PROXY_COLLISION,
                                severity="critical",
                                confidence=0.85,
                                name="Proxy Storage Collision",
                                description=f"Storage collision between {contract.name} and {inherited}: {conflicts}",
                                contracts_involved=[contract.name, inherited],
                                attack_scenario="Storage collision can cause state corruption in proxy patterns",
                                exploit_path=[contract.name, inherited],
                                affected_functions=list(contract.functions.keys()),
                                remediation="Use unique storage slots or follow EIP-1967 standard for proxy storage",
                                references=["Audius hack ($6M) - storage collision"],
                            )
                        )

    def _validate_business_logic(self):
        """Validate protocol-wide business logic and invariants"""
        # Define common DeFi invariants
        self._check_supply_invariants()
        self._check_balance_invariants()
        self._check_access_control_consistency()
        self._check_upgrade_safety()

    def _check_supply_invariants(self):
        """Check that token supply invariants hold"""
        # Find contracts with totalSupply
        supply_contracts = []

        for contract in self.contracts.values():
            if "totalSupply" in contract.state_variables:
                supply_contracts.append(contract.name)

                # Check if mint/burn functions properly update totalSupply
                for func_name, func_info in contract.functions.items():
                    if "mint" in func_name.lower() or "burn" in func_name.lower():
                        if "totalSupply" not in func_info.writes_state:
                            invariant = ProtocolInvariant(
                                name="Total Supply Invariant",
                                description=f"{func_name} should update totalSupply",
                                contracts_involved=[contract.name],
                                validation_rule="mint/burn must update totalSupply",
                                violated=True,
                                violation_evidence=f"{contract.name}.{func_name} modifies balances but not totalSupply",
                            )
                            self.invariants.append(invariant)

                            self.vulnerabilities.append(
                                CrossContractVulnerability(
                                    vuln_type=CrossContractVulnType.BUSINESS_LOGIC_FLAW,
                                    severity="high",
                                    confidence=0.90,
                                    name="Supply Invariant Violation",
                                    description=f"{contract.name}.{func_name} doesn't update totalSupply",
                                    contracts_involved=[contract.name],
                                    attack_scenario="Token supply accounting becomes incorrect",
                                    exploit_path=[f"{contract.name}.{func_name}"],
                                    affected_functions=[func_name],
                                    business_logic_violation="Total supply should equal sum of all balances",
                                    remediation=f"Update totalSupply in {func_name}",
                                )
                            )

    def _check_balance_invariants(self):
        """Check balance accounting invariants"""
        # Check for contracts managing user balances

        for contract in self.contracts.values():
            balance_vars = [
                v for v in contract.state_variables.keys() if "balance" in v.lower()
            ]

            if not balance_vars:
                continue

            # Check withdraw/deposit functions
            for func_name, func_info in contract.functions.items():
                if "withdraw" in func_name.lower():
                    # Should have balance check
                    if not func_info.has_require:
                        self.vulnerabilities.append(
                            CrossContractVulnerability(
                                vuln_type=CrossContractVulnType.BUSINESS_LOGIC_FLAW,
                                severity="high",
                                confidence=0.75,
                                name="Missing Balance Validation",
                                description=f"{contract.name}.{func_name} withdraws without balance check",
                                contracts_involved=[contract.name],
                                attack_scenario="User could withdraw more than their balance",
                                exploit_path=[f"{contract.name}.{func_name}"],
                                affected_functions=[func_name],
                                business_logic_violation="Withdrawals should not exceed user balance",
                                remediation="Add require(balance >= amount) check",
                            )
                        )

    def _check_access_control_consistency(self):
        """Check for consistent access control across related functions"""
        # Group functions by what state they modify
        state_modifiers = defaultdict(list)

        for contract in self.contracts.values():
            for func_name, func_info in contract.functions.items():
                for state_var in func_info.writes_state:
                    state_modifiers[state_var].append(
                        (contract.name, func_name, func_info.modifiers)
                    )

        # Check if all functions modifying same state have consistent protection
        for state_var, funcs in state_modifiers.items():
            if len(funcs) > 1:
                # Check if some are protected and some aren't
                protected = [f for f in funcs if f[2]]
                unprotected = [f for f in funcs if not f[2]]

                if protected and unprotected:
                    self.vulnerabilities.append(
                        CrossContractVulnerability(
                            vuln_type=CrossContractVulnType.BUSINESS_LOGIC_FLAW,
                            severity="high",
                            confidence=0.80,
                            name="Inconsistent Access Control",
                            description=f"State variable '{state_var}' has inconsistent protection",
                            contracts_involved=list(set(c for c, _, _ in funcs)),
                            attack_scenario=f"Attacker can modify {state_var} via unprotected function",
                            exploit_path=[f"{c}.{f}" for c, f, _ in unprotected],
                            affected_functions=[f for _, f, _ in funcs],
                            business_logic_violation="All functions modifying critical state should have consistent access control",
                            remediation="Add access control modifiers to unprotected functions",
                        )
                    )

    def _check_upgrade_safety(self):
        """Check for upgrade safety issues"""
        # Find initializer functions
        for contract in self.contracts.values():
            init_funcs = [
                f
                for f in contract.functions.keys()
                if "init" in f.lower() or f == "initialize"
            ]

            for init_func in init_funcs:
                func_info = contract.functions[init_func]

                # Check if initializer can be called multiple times
                prevents_reinit = any(
                    modifier in func_info.modifiers
                    for modifier in ["initializer", "onlyOnce"]
                )

                if not prevents_reinit:
                    self.vulnerabilities.append(
                        CrossContractVulnerability(
                            vuln_type=CrossContractVulnType.BUSINESS_LOGIC_FLAW,
                            severity="critical",
                            confidence=0.85,
                            name="Re-initialization Vulnerability",
                            description=f"{contract.name}.{init_func} can be called multiple times",
                            contracts_involved=[contract.name],
                            attack_scenario="Attacker can re-initialize contract and take control",
                            exploit_path=[f"{contract.name}.{init_func}"],
                            affected_functions=[init_func],
                            business_logic_violation="Initializers should only be callable once",
                            remediation="Add initializer modifier or initialized flag check",
                            references=["Wormhole hack ($325M) - re-initialization"],
                        )
                    )

    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        # Sort vulnerabilities by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: (severity_order.get(v.severity, 4), -v.confidence),
        )

        # Count by severity
        severity_counts = defaultdict(int)
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1

        # Count by type
        type_counts = defaultdict(int)
        for vuln in self.vulnerabilities:
            type_counts[vuln.vuln_type.value] += 1

        report = {
            "summary": {
                "total_contracts": len(self.contracts),
                "total_functions": sum(
                    len(c.functions) for c in self.contracts.values()
                ),
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "external_calls": len(self.call_graph.external_edges),
                "contract_dependencies": len(self.contract_relationships),
            },
            "contracts": {
                name: {
                    "path": info.path,
                    "functions": len(info.functions),
                    "state_variables": len(info.state_variables),
                    "external_calls": len(info.external_calls),
                    "is_library": info.is_library,
                    "is_interface": info.is_interface,
                    "inherits": info.inherits,
                }
                for name, info in self.contracts.items()
            },
            "call_graph": {
                "nodes": list(self.call_graph.nodes),
                "external_calls": [
                    {"from": f, "to": t, "type": call_type}
                    for f, t, call_type in self.call_graph.external_edges
                ],
            },
            "vulnerabilities": [
                {
                    "type": vuln.vuln_type.value,
                    "severity": vuln.severity,
                    "confidence": vuln.confidence,
                    "name": vuln.name,
                    "description": vuln.description,
                    "contracts_involved": vuln.contracts_involved,
                    "attack_scenario": vuln.attack_scenario,
                    "exploit_path": vuln.exploit_path,
                    "affected_functions": vuln.affected_functions,
                    "business_logic_violation": vuln.business_logic_violation,
                    "remediation": vuln.remediation,
                    "references": vuln.references,
                }
                for vuln in sorted_vulns
            ],
            "business_logic": {
                "invariants_checked": len(self.invariants),
                "violations": [
                    {
                        "name": inv.name,
                        "description": inv.description,
                        "contracts": inv.contracts_involved,
                        "violated": inv.violated,
                        "evidence": inv.violation_evidence,
                    }
                    for inv in self.invariants
                    if inv.violated
                ],
            },
            "vulnerability_types": dict(type_counts),
            "recommendations": self._generate_recommendations(),
        }

        return report

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []

        critical_count = sum(
            1 for v in self.vulnerabilities if v.severity == "critical"
        )
        if critical_count > 0:
            recommendations.append(
                f"🚨 {critical_count} CRITICAL issues found - address immediately before deployment"
            )

        # Specific recommendations based on vulnerability types
        vuln_types = set(v.vuln_type for v in self.vulnerabilities)

        if CrossContractVulnType.REENTRANCY_CHAIN in vuln_types:
            recommendations.append(
                "Implement checks-effects-interactions pattern across all contracts"
            )

        if CrossContractVulnType.ACCESS_CONTROL_BYPASS in vuln_types:
            recommendations.append(
                "Review and standardize access control across all contracts"
            )

        if CrossContractVulnType.FLASH_LOAN_ATTACK in vuln_types:
            recommendations.append(
                "Add flash loan protection: reentrancy guards and snapshot-based accounting"
            )

        if CrossContractVulnType.STATE_INCONSISTENCY in vuln_types:
            recommendations.append(
                "Implement atomic state updates across contracts or use proper synchronization"
            )

        if CrossContractVulnType.PROXY_COLLISION in vuln_types:
            recommendations.append(
                "Follow EIP-1967 for proxy storage and use storage gaps"
            )

        # General recommendations
        if len(self.contracts) > 5:
            recommendations.append(
                "Consider comprehensive integration testing for multi-contract interactions"
            )

        if len(self.call_graph.external_edges) > 10:
            recommendations.append(
                "High contract interdependency - consider simplifying architecture"
            )

        return recommendations

    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(message)

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get quick summary statistics"""
        return {
            "contracts": len(self.contracts),
            "vulnerabilities": len(self.vulnerabilities),
            "critical": sum(
                1 for v in self.vulnerabilities if v.severity == "critical"
            ),
            "high": sum(1 for v in self.vulnerabilities if v.severity == "high"),
            "external_calls": len(self.call_graph.external_edges),
        }
