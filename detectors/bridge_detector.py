from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import FunctionContract
from slither.core.variables.state_variable import StateVariable
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


class BridgeVulnerabilityDetector(AbstractDetector):
    """
    Custom detector for bridge-specific vulnerabilities
    Based on real bridge hacks like Nomad and Qubit
    """

    ARGUMENT = "bridge-vulnerabilities"
    HELP = "Detects bridge-specific vulnerabilities like message validation flaws and initialization issues"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts:
            # Check for bridge-related patterns
            if self._is_bridge_contract(contract):
                vulnerabilities = []

                # Check for Nomad-style confirmAt[0] vulnerability
                nomad_issues = self._check_nomad_pattern(contract)
                vulnerabilities.extend(nomad_issues)

                # Check for Qubit-style legacy function issues
                qubit_issues = self._check_qubit_pattern(contract)
                vulnerabilities.extend(qubit_issues)

                # Check for message validation weaknesses
                validation_issues = self._check_message_validation(contract)
                vulnerabilities.extend(validation_issues)

                # Check for initialization vulnerabilities
                init_issues = self._check_initialization_vulns(contract)
                vulnerabilities.extend(init_issues)

                for vuln in vulnerabilities:
                    results.append(
                        self.generate_result_from_vulnerability(contract, vuln)
                    )

        return results

    def _is_bridge_contract(self, contract) -> bool:
        """Determine if contract appears to be a bridge"""
        bridge_keywords = [
            "bridge",
            "message",
            "crosschain",
            "relay",
            "deposit",
            "withdraw",
        ]
        contract_name = contract.name.lower()
        return any(keyword in contract_name for keyword in bridge_keywords)

    def _check_nomad_pattern(self, contract) -> list:
        """Check for Nomad-style confirmAt[0] default value exploitation"""
        issues = []

        for var in contract.state_variables:
            if isinstance(var.type, MappingType) and var.name.lower() in [
                "confirm",
                "confirmed",
                "verify",
            ]:
                # Check if mapping is used in validation without proper initialization
                for function in contract.functions:
                    if self._uses_mapping_in_validation(function, var):
                        # Check if there's any initialization of this mapping
                        if not self._mapping_properly_initialized(contract, var):
                            issues.append(
                                {
                                    "type": "nomad_confirmat_zero",
                                    "variable": var.name,
                                    "function": function.name,
                                    "description": f"Mapping {var.name} used in validation but may rely on default values",
                                }
                            )
        return issues

    def _check_qubit_pattern(self, contract) -> list:
        """Check for Qubit-style legacy function vulnerabilities"""
        issues = []

        # Look for deprecated-looking functions
        for function in contract.functions:
            if self._is_legacy_function(function):
                # Check if function can still be called and affects critical state
                if self._function_affects_critical_state(function):
                    issues.append(
                        {
                            "type": "legacy_function_exposed",
                            "function": function.name,
                            "description": f"Legacy function {function.name} still callable and affects critical state",
                        }
                    )
        return issues

    def _check_message_validation(self, contract) -> list:
        """Check for weak message validation"""
        issues = []

        for function in contract.functions:
            if "process" in function.name.lower() or "execute" in function.name.lower():
                # Check for insufficient validation
                validation_score = self._assess_validation_strength(function)
                if validation_score < 3:  # Arbitrary threshold
                    issues.append(
                        {
                            "type": "weak_message_validation",
                            "function": function.name,
                            "score": validation_score,
                            "description": f"Function {function.name} has weak message validation (score: {validation_score}/5)",
                        }
                    )
        return issues

    def _check_initialization_vulns(self, contract) -> list:
        """Check for initialization-related vulnerabilities"""
        issues = []

        # Check constructor for proper initialization
        if contract.constructor:
            initialized_vars = set()
            for node in contract.constructor.nodes:
                for ir in node.irs:
                    if hasattr(ir, "lvalue") and isinstance(ir.lvalue, StateVariable):
                        initialized_vars.add(ir.lvalue.name)

            # Check critical variables that should be initialized
            critical_vars = ["owner", "guardian", "threshold", "root", "domain"]
            for var in contract.state_variables:
                if any(critical in var.name.lower() for critical in critical_vars):
                    if var.name not in initialized_vars:
                        issues.append(
                            {
                                "type": "uninitialized_critical_var",
                                "variable": var.name,
                                "description": f"Critical variable {var.name} not initialized in constructor",
                            }
                        )
        return issues

    def _uses_mapping_in_validation(
        self, function: FunctionContract, mapping_var: StateVariable
    ) -> bool:
        """Check if function uses mapping in validation logic"""
        for node in function.nodes:
            for ir in node.irs:
                if hasattr(ir, "lvalue") or hasattr(ir, "rvalue"):
                    # Simplified check - in practice would need more sophisticated analysis
                    if hasattr(ir, "variable") and ir.variable == mapping_var:
                        return True
        return False

    def _mapping_properly_initialized(
        self, contract, mapping_var: StateVariable
    ) -> bool:
        """Check if mapping is properly initialized"""
        # Check if mapping is set anywhere in the contract
        for function in contract.functions:
            for node in function.nodes:
                for ir in node.irs:
                    if hasattr(ir, "lvalue") and ir.lvalue == mapping_var:
                        return True
        return False

    def _is_legacy_function(self, function: FunctionContract) -> bool:
        """Determine if function appears to be legacy/deprecated"""
        legacy_indicators = ["old", "legacy", "deprecated", "v1", "previous"]
        func_name = function.name.lower()

        # Check function name
        if any(indicator in func_name for indicator in legacy_indicators):
            return True

        # Check comments (if available)
        if hasattr(function, "source_mapping") and function.source_mapping:
            content = function.source_mapping.content.lower()
            if any(indicator in content for indicator in legacy_indicators):
                return True

        return False

    def _function_affects_critical_state(self, function: FunctionContract) -> bool:
        """Check if function affects critical state variables"""
        critical_keywords = [
            "balance",
            "supply",
            "mint",
            "burn",
            "transfer",
            "withdraw",
        ]

        for node in function.nodes:
            for ir in node.irs:
                if hasattr(ir, "lvalue") and isinstance(ir.lvalue, StateVariable):
                    var_name = ir.lvalue.name.lower()
                    if any(keyword in var_name for keyword in critical_keywords):
                        return True
        return False

    def _assess_validation_strength(self, function: FunctionContract) -> int:
        """Assess the strength of validation in a function (0-5 scale)"""
        score = 0

        # Check for signature verification
        if self._has_signature_verification(function):
            score += 2

        # Check for merkle proof verification
        if self._has_merkle_verification(function):
            score += 2

        # Check for basic input validation
        if self._has_input_validation(function):
            score += 1

        return min(score, 5)

    def _has_signature_verification(self, function: FunctionContract) -> bool:
        """Check if function verifies signatures"""
        sig_keywords = ["ecrecover", "signature", "sign", "verify"]
        for node in function.nodes:
            for ir in node.irs:
                if hasattr(ir, "function") and ir.function:
                    func_name = ir.function.name.lower()
                    if any(keyword in func_name for keyword in sig_keywords):
                        return True
        return False

    def _has_merkle_verification(self, function: FunctionContract) -> bool:
        """Check if function verifies merkle proofs"""
        merkle_keywords = ["merkle", "proof", "root", "leaf"]
        for node in function.nodes:
            for ir in node.irs:
                if hasattr(ir, "function") and ir.function:
                    func_name = ir.function.name.lower()
                    if any(keyword in func_name for keyword in merkle_keywords):
                        return True
        return False

    def _has_input_validation(self, function: FunctionContract) -> bool:
        """Check for basic input validation"""
        for node in function.nodes:
            for ir in node.irs:
                if hasattr(ir, "function") and ir.function:
                    if "require" in str(ir) or "assert" in str(ir):
                        return True
        return False

    def generate_result_from_vulnerability(self, contract, vulnerability):
        info = f"Bridge Vulnerability in {contract.name}: {vulnerability['type']}\n"
        info += f"Description: {vulnerability['description']}\n"
        if "function" in vulnerability:
            info += f"Function: {vulnerability['function']}\n"
        if "variable" in vulnerability:
            info += f"Variable: {vulnerability['variable']}\n"

        json_result = self.generate_result(info)
        return Output(info, json_result)
