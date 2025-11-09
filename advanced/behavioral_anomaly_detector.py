"""
Behavioral Anomaly Detection for Smart Contracts
Uses statistical analysis and ML-inspired heuristics to detect unusual patterns
Identifies logic flaws that don't match standard vulnerability signatures
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import re
from enum import Enum


class AnomalyType(Enum):
    STATISTICAL_OUTLIER = "statistical_outlier"
    UNUSUAL_PATTERN = "unusual_pattern"
    INCONSISTENT_BEHAVIOR = "inconsistent_behavior"
    SUSPICIOUS_COMPLEXITY = "suspicious_complexity"
    ANTI_PATTERN = "anti_pattern"


@dataclass
class Anomaly:
    """Detected behavioral anomaly"""
    anomaly_type: AnomalyType
    name: str
    description: str
    severity: str
    confidence: float
    location: str
    evidence: Dict[str, Any]
    potential_exploit: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class FunctionMetrics:
    """Metrics for a single function"""
    name: str
    num_external_calls: int = 0
    num_state_writes: int = 0
    num_conditionals: int = 0
    cyclomatic_complexity: int = 0
    num_loops: int = 0
    num_requires: int = 0
    num_asserts: int = 0
    num_parameters: int = 0
    uses_assembly: bool = False
    uses_delegatecall: bool = False
    uses_selfdestruct: bool = False
    has_reentrancy_guard: bool = False
    modifies_balance: bool = False
    reads_timestamp: bool = False
    reads_blockhash: bool = False


class BehavioralAnomalyDetector:
    """
    Detects anomalies in contract behavior using statistical analysis
    Finds unusual patterns that may indicate logic flaws or hidden backdoors
    """

    def __init__(self):
        self.anomalies: List[Anomaly] = []
        self.function_metrics: Dict[str, FunctionMetrics] = {}
        self.contract_stats: Dict[str, Any] = {}

    def analyze_contract(self, contract_code: str, contract_name: str) -> List[Anomaly]:
        """Run complete behavioral analysis"""
        self.anomalies = []

        # Extract metrics
        self._extract_function_metrics(contract_code)
        self._calculate_contract_statistics()

        # Run anomaly detectors
        self.anomalies.extend(self._detect_complexity_anomalies())
        self.anomalies.extend(self._detect_access_control_inconsistencies(contract_code))
        self.anomalies.extend(self._detect_unusual_external_call_patterns(contract_code))
        self.anomalies.extend(self._detect_suspicious_assembly_usage(contract_code))
        self.anomalies.extend(self._detect_hidden_backdoors(contract_code))
        self.anomalies.extend(self._detect_gas_griefing_patterns(contract_code))
        self.anomalies.extend(self._detect_unusual_inheritance_patterns(contract_code))
        self.anomalies.extend(self._detect_timestamp_manipulation_patterns(contract_code))
        self.anomalies.extend(self._detect_selfdestruct_risks(contract_code))
        self.anomalies.extend(self._detect_delegatecall_risks(contract_code))
        self.anomalies.extend(self._detect_unchecked_return_values(contract_code))
        self.anomalies.extend(self._detect_denial_of_service_patterns(contract_code))
        
        # NEW POWERFUL ANOMALY DETECTORS (from PR #2)
        self.anomalies.extend(self._detect_centralization_risks(contract_code))
        self.anomalies.extend(self._detect_oracle_dependency_risks(contract_code))
        self.anomalies.extend(self._detect_flash_loan_vulnerable_patterns(contract_code))

        return self.anomalies

    def _extract_function_metrics(self, contract_code: str):
        """Extract detailed metrics for each function"""
        # Find all functions
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(.*?)\{'
        functions = list(re.finditer(func_pattern, contract_code, re.DOTALL))

        for i, match in enumerate(functions):
            func_name = match.group(1)
            params = match.group(2)
            modifiers = match.group(3)

            # Extract function body
            start = match.end()
            end = self._find_function_end(contract_code, start)
            func_body = contract_code[start:end]

            # Calculate metrics
            metrics = FunctionMetrics(name=func_name)

            # Count parameters
            metrics.num_parameters = len([p for p in params.split(',') if p.strip()])

            # External calls
            metrics.num_external_calls = len(re.findall(r'\.call|\.delegatecall|\.transfer|\.send', func_body))

            # State writes
            metrics.num_state_writes = len(re.findall(r'\w+\s*=\s*(?!.*==)', func_body))

            # Conditionals
            metrics.num_conditionals = len(re.findall(r'\bif\s*\(|\belse\b', func_body))

            # Loops
            metrics.num_loops = len(re.findall(r'\bfor\s*\(|\bwhile\s*\(', func_body))

            # Requires and asserts
            metrics.num_requires = len(re.findall(r'\brequire\s*\(', func_body))
            metrics.num_asserts = len(re.findall(r'\bassert\s*\(', func_body))

            # Special patterns
            metrics.uses_assembly = 'assembly' in func_body
            metrics.uses_delegatecall = 'delegatecall' in func_body
            metrics.uses_selfdestruct = 'selfdestruct' in func_body
            metrics.has_reentrancy_guard = 'nonReentrant' in modifiers or 'ReentrancyGuard' in modifiers
            metrics.modifies_balance = 'balance' in func_body and '=' in func_body
            metrics.reads_timestamp = 'block.timestamp' in func_body or 'now' in func_body
            metrics.reads_blockhash = 'blockhash' in func_body

            # Cyclomatic complexity (simplified)
            metrics.cyclomatic_complexity = (
                1 + metrics.num_conditionals + metrics.num_loops + metrics.num_requires
            )

            self.function_metrics[func_name] = metrics

    def _find_function_end(self, code: str, start: int) -> int:
        """Find the end of a function body by matching braces"""
        depth = 1
        i = start

        while i < len(code) and depth > 0:
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
            i += 1

        return i

    def _calculate_contract_statistics(self):
        """Calculate statistical measures across all functions"""
        if not self.function_metrics:
            return

        complexities = [m.cyclomatic_complexity for m in self.function_metrics.values()]
        external_calls = [m.num_external_calls for m in self.function_metrics.values()]
        state_writes = [m.num_state_writes for m in self.function_metrics.values()]

        self.contract_stats = {
            "avg_complexity": sum(complexities) / len(complexities),
            "max_complexity": max(complexities),
            "avg_external_calls": sum(external_calls) / len(external_calls),
            "avg_state_writes": sum(state_writes) / len(state_writes),
            "total_functions": len(self.function_metrics),
            "functions_with_assembly": sum(1 for m in self.function_metrics.values() if m.uses_assembly),
            "functions_with_delegatecall": sum(1 for m in self.function_metrics.values() if m.uses_delegatecall)
        }

    def _detect_complexity_anomalies(self) -> List[Anomaly]:
        """Detect functions with unusually high complexity"""
        anomalies = []

        avg_complexity = self.contract_stats.get("avg_complexity", 0)

        for func_name, metrics in self.function_metrics.items():
            # Flag functions significantly more complex than average
            if metrics.cyclomatic_complexity > avg_complexity * 3 and metrics.cyclomatic_complexity > 15:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.SUSPICIOUS_COMPLEXITY,
                    name="excessive_complexity",
                    description=f"Function '{func_name}' has unusually high complexity (CC={metrics.cyclomatic_complexity})",
                    severity="medium",
                    confidence=0.75,
                    location=func_name,
                    evidence={
                        "cyclomatic_complexity": metrics.cyclomatic_complexity,
                        "avg_complexity": avg_complexity,
                        "num_conditionals": metrics.num_conditionals,
                        "num_loops": metrics.num_loops
                    },
                    potential_exploit="Complex functions are harder to audit and may hide vulnerabilities",
                    remediation="Refactor into smaller, more testable functions"
                ))

        return anomalies

    def _detect_access_control_inconsistencies(self, contract_code: str) -> List[Anomaly]:
        """Detect inconsistent access control patterns"""
        anomalies = []

        # Find all functions with similar names
        function_groups = defaultdict(list)

        for func_name in self.function_metrics.keys():
            # Group by common prefixes
            prefix = func_name.split('_')[0] if '_' in func_name else func_name[:3]
            function_groups[prefix].append(func_name)

        # Check if similar functions have different access controls
        for prefix, funcs in function_groups.items():
            if len(funcs) < 2:
                continue

            # Extract access control modifiers
            access_controls = {}
            for func_name in funcs:
                pattern = rf'function\s+{func_name}\s*\([^)]*\)\s+([^{{]*)'
                match = re.search(pattern, contract_code)
                if match:
                    modifiers = match.group(1)
                    has_access_control = bool(re.search(r'onlyOwner|onlyAdmin|require.*msg\.sender', modifiers))
                    access_controls[func_name] = has_access_control

            # Check for inconsistencies
            if access_controls and len(set(access_controls.values())) > 1:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.INCONSISTENT_BEHAVIOR,
                    name="inconsistent_access_control",
                    description=f"Similar functions have different access control: {list(access_controls.keys())}",
                    severity="high",
                    confidence=0.70,
                    location=", ".join(funcs),
                    evidence={"access_controls": access_controls},
                    potential_exploit="Missing access control on some functions may allow unauthorized access",
                    remediation="Ensure consistent access control across related functions"
                ))

        return anomalies

    def _detect_unusual_external_call_patterns(self, contract_code: str) -> List[Anomaly]:
        """Detect unusual patterns in external calls"""
        anomalies = []

        for func_name, metrics in self.function_metrics.items():
            # Multiple external calls without reentrancy guard
            if metrics.num_external_calls > 1 and not metrics.has_reentrancy_guard:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.UNUSUAL_PATTERN,
                    name="multiple_external_calls_no_guard",
                    description=f"Function '{func_name}' makes {metrics.num_external_calls} external calls without reentrancy guard",
                    severity="high",
                    confidence=0.85,
                    location=func_name,
                    evidence={
                        "num_external_calls": metrics.num_external_calls,
                        "has_reentrancy_guard": metrics.has_reentrancy_guard
                    },
                    potential_exploit="Vulnerable to complex reentrancy attacks",
                    remediation="Add nonReentrant modifier or implement checks-effects-interactions pattern"
                ))

            # External call before state update (checks-effects-interactions violation)
            func_pattern = rf'function\s+{func_name}\s*\([^)]*\).*?\{{(.*?)\}}'
            match = re.search(func_pattern, contract_code, re.DOTALL)
            if match:
                func_body = match.group(1)
                # Find positions of external calls and state writes
                call_positions = [m.start() for m in re.finditer(r'\.call|\.transfer', func_body)]
                write_positions = [m.start() for m in re.finditer(r'\w+\s*=', func_body)]

                if call_positions and write_positions:
                    # Check if any write comes after a call
                    if any(call_pos < write_pos for call_pos in call_positions for write_pos in write_positions):
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.ANTI_PATTERN,
                            name="state_update_after_external_call",
                            description=f"Function '{func_name}' updates state after external call",
                            severity="high",
                            confidence=0.80,
                            location=func_name,
                            evidence={"pattern": "checks-effects-interactions violation"},
                            potential_exploit="Classic reentrancy vulnerability",
                            remediation="Move state updates before external calls"
                        ))

        return anomalies

    def _detect_suspicious_assembly_usage(self, contract_code: str) -> List[Anomaly]:
        """Detect potentially dangerous assembly usage"""
        anomalies = []

        for func_name, metrics in self.function_metrics.items():
            if metrics.uses_assembly:
                # Extract assembly block
                func_pattern = rf'function\s+{func_name}\s*\([^)]*\).*?\{{(.*?)\}}'
                match = re.search(func_pattern, contract_code, re.DOTALL)
                if match:
                    func_body = match.group(1)

                    # Check for dangerous operations in assembly
                    dangerous_ops = []
                    if 'selfdestruct' in func_body:
                        dangerous_ops.append('selfdestruct')
                    if 'delegatecall' in func_body:
                        dangerous_ops.append('delegatecall')
                    if 'callcode' in func_body:
                        dangerous_ops.append('callcode')
                    if 'sstore' in func_body:
                        dangerous_ops.append('sstore (direct storage manipulation)')

                    if dangerous_ops:
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.SUSPICIOUS_COMPLEXITY,
                            name="dangerous_assembly_operations",
                            description=f"Function '{func_name}' uses assembly with dangerous operations: {dangerous_ops}",
                            severity="high",
                            confidence=0.90,
                            location=func_name,
                            evidence={"dangerous_operations": dangerous_ops},
                            potential_exploit="Assembly bypasses Solidity safety checks",
                            remediation="Minimize assembly usage and add extensive tests"
                        ))

        return anomalies

    def _detect_hidden_backdoors(self, contract_code: str) -> List[Anomaly]:
        """Detect potential hidden backdoor patterns"""
        anomalies = []

        # Check for functions with suspicious names or patterns
        suspicious_patterns = [
            (r'function\s+_[a-z]+\s*\([^)]*\)\s+external', "External function with private-looking name"),
            (r'function\s+\w*back\w*\s*\([^)]*\)', "Function name contains 'back'"),
            (r'function\s+\w*secret\w*\s*\([^)]*\)', "Function name contains 'secret'"),
            (r'function\s+\w*emergency\w*\s*\([^)]*\)(?!.*onlyOwner)', "Emergency function without access control"),
            (r'if\s*\(\s*msg\.sender\s*==\s*0x[a-fA-F0-9]{40}\s*\)', "Hardcoded address check"),
        ]

        for pattern, description in suspicious_patterns:
            matches = re.finditer(pattern, contract_code)
            for match in matches:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.UNUSUAL_PATTERN,
                    name="potential_backdoor",
                    description=description,
                    severity="critical",
                    confidence=0.60,  # May be false positive
                    location=match.group(0)[:50],
                    evidence={"matched_pattern": pattern},
                    potential_exploit="Could be hidden backdoor for unauthorized access",
                    remediation="Review code carefully and ensure proper access control"
                ))

        return anomalies

    def _detect_gas_griefing_patterns(self, contract_code: str) -> List[Anomaly]:
        """Detect patterns that could lead to gas griefing"""
        anomalies = []

        # Unbounded loops
        for func_name, metrics in self.function_metrics.items():
            if metrics.num_loops > 0:
                func_pattern = rf'function\s+{func_name}\s*\([^)]*\).*?\{{(.*?)\}}'
                match = re.search(func_pattern, contract_code, re.DOTALL)
                if match:
                    func_body = match.group(1)

                    # Check for array iteration without bounds
                    if re.search(r'for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length', func_body):
                        # Check if array is user-controlled
                        if re.search(r'mapping.*=>.*\[|push\(', func_body):
                            anomalies.append(Anomaly(
                                anomaly_type=AnomalyType.ANTI_PATTERN,
                                name="unbounded_loop_gas_griefing",
                                description=f"Function '{func_name}' has unbounded loop over user-controlled array",
                                severity="medium",
                                confidence=0.75,
                                location=func_name,
                                evidence={"num_loops": metrics.num_loops},
                                potential_exploit="Attacker can cause out-of-gas by growing array",
                                remediation="Add maximum iteration limit or use pagination"
                            ))

        return anomalies

    def _detect_unusual_inheritance_patterns(self, contract_code: str) -> List[Anomaly]:
        """Detect unusual inheritance patterns"""
        anomalies = []

        # Extract inheritance
        contract_pattern = r'contract\s+\w+\s+is\s+([^{]+)\{'
        match = re.search(contract_pattern, contract_code)

        if match:
            inherited = match.group(1).split(',')
            inherited = [i.strip() for i in inherited]

            # Check for unusual number of inherited contracts
            if len(inherited) > 5:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.SUSPICIOUS_COMPLEXITY,
                    name="excessive_inheritance",
                    description=f"Contract inherits from {len(inherited)} contracts: {inherited}",
                    severity="low",
                    confidence=0.60,
                    location="contract_declaration",
                    evidence={"inherited_contracts": inherited},
                    potential_exploit="Complex inheritance can hide storage collisions",
                    remediation="Simplify inheritance hierarchy"
                ))

        return anomalies

    def _detect_timestamp_manipulation_patterns(self, contract_code: str) -> List[Anomaly]:
        """Detect risky timestamp dependencies"""
        anomalies = []

        for func_name, metrics in self.function_metrics.items():
            if metrics.reads_timestamp:
                func_pattern = rf'function\s+{func_name}\s*\([^)]*\).*?\{{(.*?)\}}'
                match = re.search(func_pattern, contract_code, re.DOTALL)
                if match:
                    func_body = match.group(1)

                    # Check if timestamp used in critical logic
                    if re.search(r'block\.timestamp.*[<>]=.*\d+\s*minutes', func_body):
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.UNUSUAL_PATTERN,
                            name="short_timestamp_dependency",
                            description=f"Function '{func_name}' relies on timestamp with minute-level precision",
                            severity="medium",
                            confidence=0.70,
                            location=func_name,
                            evidence={"reads_timestamp": True},
                            potential_exploit="Miners can manipulate timestamp by ~15 seconds",
                            remediation="Use block numbers for time-sensitive operations or longer time windows"
                        ))

        return anomalies

    def _detect_selfdestruct_risks(self, contract_code: str) -> List[Anomaly]:
        """Detect selfdestruct usage risks"""
        anomalies = []

        if 'selfdestruct' in contract_code:
            # Check access control
            if not re.search(r'selfdestruct.*onlyOwner|require.*owner', contract_code):
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.ANTI_PATTERN,
                    name="unprotected_selfdestruct",
                    description="Selfdestruct without proper access control",
                    severity="critical",
                    confidence=0.95,
                    location="selfdestruct_call",
                    evidence={"has_access_control": False},
                    potential_exploit="Anyone can destroy contract",
                    remediation="Add onlyOwner or similar access control"
                ))

        return anomalies

    def _detect_delegatecall_risks(self, contract_code: str) -> List[Anomaly]:
        """Detect delegatecall risks"""
        anomalies = []

        for func_name, metrics in self.function_metrics.items():
            if metrics.uses_delegatecall:
                func_pattern = rf'function\s+{func_name}\s*\([^)]*\).*?\{{(.*?)\}}'
                match = re.search(func_pattern, contract_code, re.DOTALL)
                if match:
                    func_body = match.group(1)

                    # Check if target address is user-controlled
                    if re.search(r'delegatecall\([^)]*msg\.sender|delegatecall\([^)]*_\w+', func_body):
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.ANTI_PATTERN,
                            name="user_controlled_delegatecall",
                            description=f"Function '{func_name}' delegatecalls to user-controlled address",
                            severity="critical",
                            confidence=0.90,
                            location=func_name,
                            evidence={"uses_delegatecall": True},
                            potential_exploit="Attacker can execute arbitrary code in contract context",
                            remediation="Only delegatecall to trusted, immutable addresses"
                        ))

        return anomalies

    def _detect_unchecked_return_values(self, contract_code: str) -> List[Anomaly]:
        """Detect unchecked low-level call return values"""
        anomalies = []

        # Find low-level calls
        call_pattern = r'(\w+)\.call\{|(\w+)\.call\('
        matches = list(re.finditer(call_pattern, contract_code))

        for match in matches:
            # Check if return value is checked
            context = contract_code[match.start():match.start() + 200]

            if not re.search(r'\(bool\s+\w+,|require\(.*\.call', context):
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.ANTI_PATTERN,
                    name="unchecked_call_return_value",
                    description="Low-level call without checking return value",
                    severity="high",
                    confidence=0.85,
                    location=context[:50],
                    evidence={"pattern": "unchecked_call"},
                    potential_exploit="Silent failure could lead to incorrect state",
                    remediation="Always check return value: (bool success,) = addr.call(...); require(success)"
                ))

        return anomalies

    def _detect_denial_of_service_patterns(self, contract_code: str) -> List[Anomaly]:
        """Detect DoS vulnerability patterns"""
        anomalies = []

        # Check for external calls in loops
        for func_name, metrics in self.function_metrics.items():
            if metrics.num_loops > 0 and metrics.num_external_calls > 0:
                func_pattern = rf'function\s+{func_name}\s*\([^)]*\).*?\{{(.*?)\}}'
                match = re.search(func_pattern, contract_code, re.DOTALL)
                if match:
                    func_body = match.group(1)

                    # Check if external call inside loop
                    if re.search(r'for.*\{[^}]*\.call[^}]*\}', func_body, re.DOTALL):
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.ANTI_PATTERN,
                            name="external_call_in_loop",
                            description=f"Function '{func_name}' makes external calls inside loop",
                            severity="high",
                            confidence=0.85,
                            location=func_name,
                            evidence={
                                "num_loops": metrics.num_loops,
                                "num_external_calls": metrics.num_external_calls
                            },
                            potential_exploit="Single failed call can block entire function (DoS)",
                            remediation="Use pull payment pattern or handle failures gracefully"
                        ))

        return anomalies

    def _detect_centralization_risks(self, contract_code: str) -> List[Anomaly]:
        """
        NEW: Detect excessive centralization that creates rug pull risk
        """
        anomalies = []
        
        # Count owner-only functions
        owner_funcs = len(re.findall(r'onlyOwner|require.*owner.*msg\.sender', contract_code))
        total_funcs = len(re.findall(r'function\s+\w+', contract_code))
        
        if total_funcs > 0:
            centralization_ratio = owner_funcs / total_funcs
            
            if centralization_ratio > 0.3:  # More than 30% owner-only
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.SUSPICIOUS_COMPLEXITY,
                    name="excessive_centralization",
                    description=f"{owner_funcs}/{total_funcs} functions require owner privileges ({centralization_ratio*100:.1f}%)",
                    severity="medium",
                    confidence=0.90,
                    location="access_control",
                    evidence={"owner_functions": owner_funcs, "total_functions": total_funcs},
                    potential_exploit="Owner has excessive control - rug pull risk",
                    remediation="Implement timelock, multisig, or decentralized governance"
                ))
        
        return anomalies

    def _detect_oracle_dependency_risks(self, contract_code: str) -> List[Anomaly]:
        """
        NEW: Detect risky oracle usage patterns
        """
        anomalies = []
        
        # Check for oracle usage
        oracle_patterns = [r'getPrice', r'latestAnswer', r'consult', r'oracle', r'Chainlink']
        has_oracle = any(re.search(pattern, contract_code, re.IGNORECASE) for pattern in oracle_patterns)
        
        if has_oracle:
            # Check for freshness validation
            has_freshness_check = bool(re.search(r'updatedAt|timestamp.*require|stale', contract_code, re.IGNORECASE))
            
            if not has_freshness_check:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.ANTI_PATTERN,
                    name="no_oracle_freshness_check",
                    description="Oracle price used without freshness validation",
                    severity="high",
                    confidence=0.85,
                    location="oracle_integration",
                    evidence={"has_freshness_check": False},
                    potential_exploit="Stale prices can be exploited for arbitrage",
                    remediation="Validate: require(block.timestamp - updatedAt < MAX_DELAY)"
                ))
        
        return anomalies

    def _detect_flash_loan_vulnerable_patterns(self, contract_code: str) -> List[Anomaly]:
        """
        NEW: Detect patterns vulnerable to flash loan attacks
        """
        anomalies = []
        
        # Check for balance-based logic without reentrancy guard
        balance_logic = r'balanceOf.*if|if.*balanceOf'
        has_balance_logic = bool(re.search(balance_logic, contract_code))
        has_reentrancy_guard = bool(re.search(r'nonReentrant|ReentrancyGuard|locked', contract_code))
        
        if has_balance_logic and not has_reentrancy_guard:
            anomalies.append(Anomaly(
                anomaly_type=AnomalyType.ANTI_PATTERN,
                name="balance_based_logic_without_guard",
                description="Balance-based conditionals without reentrancy protection",
                severity="high",
                confidence=0.75,
                location="balance_checks",
                evidence={"has_balance_logic": True, "has_guard": False},
                potential_exploit="Flash loan can manipulate balance checks",
                remediation="Add reentrancy guard or use internal accounting"
            ))
        
        # Check for price calculations using reserves without TWAP
        reserve_price_calc = r'reserve.*\/.*reserve|getReserves'
        has_reserve_pricing = bool(re.search(reserve_price_calc, contract_code, re.IGNORECASE))
        
        if has_reserve_pricing:
            has_twap = bool(re.search(r'TWAP|timeWeighted|observe', contract_code, re.IGNORECASE))
            
            if not has_twap:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.ANTI_PATTERN,
                    name="spot_price_without_twap",
                    description="Uses spot price from reserves without TWAP",
                    severity="critical",
                    confidence=0.90,
                    location="price_calculations",
                    evidence={"uses_reserves": True, "has_twap": False},
                    potential_exploit="Flash loan can manipulate spot price for profit",
                    remediation="Use TWAP oracle or Chainlink price feed"
                ))
        
        return anomalies


def demonstrate_behavioral_analysis():
    """Demonstrate behavioral anomaly detection"""

    detector = BehavioralAnomalyDetector()

    # Example contract with various anomalies
    suspicious_contract = """
    contract SuspiciousContract {
        address[] public users;

        function complexFunction(uint256 a, uint256 b, uint256 c) public {
            if (a > 10) {
                if (b < 20) {
                    for (uint i = 0; i < 100; i++) {
                        if (c == i) {
                            doSomething();
                        }
                    }
                } else if (b > 50) {
                    doSomethingElse();
                } else {
                    yetAnotherThing();
                }
            }
        }

        function withdraw() public {
            msg.sender.call{value: amount}("");  // Unchecked!
            balance[msg.sender] = 0;  // State update after call!
        }

        function _backdoor() external {  // Suspicious!
            if (msg.sender == 0x1234567890123456789012345678901234567890) {
                selfdestruct(payable(msg.sender));
            }
        }

        function batchTransfer() public {
            for (uint i = 0; i < users.length; i++) {  // Unbounded!
                users[i].call{value: 1 ether}("");  // External call in loop!
            }
        }

        function timelock() public {
            require(block.timestamp > unlockTime + 5 minutes);  // Short window!
        }

        function execute(address target, bytes memory data) public {
            target.delegatecall(data);  // User-controlled delegatecall!
        }
    }
    """

    anomalies = detector.analyze_contract(suspicious_contract, "SuspiciousContract")

    print(f"Found {len(anomalies)} behavioral anomalies:\n")

    # Group by severity
    by_severity = defaultdict(list)
    for anomaly in anomalies:
        by_severity[anomaly.severity].append(anomaly)

    for severity in ["critical", "high", "medium", "low"]:
        if severity in by_severity:
            print(f"\n{'='*60}")
            print(f"{severity.upper()} SEVERITY ({len(by_severity[severity])} findings)")
            print(f"{'='*60}")

            for anomaly in by_severity[severity]:
                print(f"\n[{anomaly.anomaly_type.value}] {anomaly.name}")
                print(f"Description: {anomaly.description}")
                print(f"Confidence: {anomaly.confidence:.2f}")
                print(f"Location: {anomaly.location}")
                if anomaly.potential_exploit:
                    print(f"Potential Exploit: {anomaly.potential_exploit}")
                if anomaly.remediation:
                    print(f"Remediation: {anomaly.remediation}")

    return anomalies


if __name__ == "__main__":
    results = demonstrate_behavioral_analysis()
    print(f"\n\nTotal anomalies detected: {len(results)}")
    print(f"Critical: {sum(1 for a in results if a.severity == 'critical')}")
    print(f"High: {sum(1 for a in results if a.severity == 'high')}")
    print(f"Medium: {sum(1 for a in results if a.severity == 'medium')}")
    print(f"Low: {sum(1 for a in results if a.severity == 'low')}")
