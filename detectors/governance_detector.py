from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import FunctionContract
from slither.core.expressions import CallExpression
from slither.utils.output import Output


class GovernanceVulnerabilityDetector(AbstractDetector):
    """
    Custom detector for governance protocol vulnerabilities
    Focuses on flash loan attacks, vote manipulation, and proposal execution flaws
    """

    ARGUMENT = "governance-vulnerabilities"
    HELP = "Detects governance-specific vulnerabilities like flash loan vote manipulation and proposal execution flaws"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts:
            # Check for governance-related patterns
            if self._is_governance_contract(contract):
                vulnerabilities = []

                # Check for flash loan vote manipulation
                flash_loan_issues = self._check_flash_loan_voting(contract)
                vulnerabilities.extend(flash_loan_issues)

                # Check for proposal execution vulnerabilities
                proposal_issues = self._check_proposal_execution(contract)
                vulnerabilities.extend(proposal_issues)

                # Check for quorum manipulation
                quorum_issues = self._check_quorum_manipulation(contract)
                vulnerabilities.extend(quorum_issues)

                # Check for timelock bypass
                timelock_issues = self._check_timelock_bypass(contract)
                vulnerabilities.extend(timelock_issues)

                for vuln in vulnerabilities:
                    results.append(
                        self.generate_result_from_vulnerability(contract, vuln)
                    )

        return results

    def _is_governance_contract(self, contract) -> bool:
        """Determine if contract appears to be a governance system"""
        governance_keywords = [
            "govern",
            "vote",
            "proposal",
            "quorum",
            "timelock",
            "delegate",
        ]
        contract_name = contract.name.lower()
        return any(keyword in contract_name for keyword in governance_keywords)

    def _check_flash_loan_voting(self, contract) -> list:
        """Check for flash loan vote manipulation vulnerabilities"""
        issues = []

        for function in contract.functions:
            if self._is_voting_function(function):
                # Check if voting power can be manipulated atomically
                if self._has_atomic_voting_power_change(function):
                    issues.append(
                        {
                            "type": "flash_loan_voting",
                            "function": function.name,
                            "description": f"Voting function {function.name} vulnerable to flash loan manipulation - atomic voting power changes detected",
                        }
                    )

                # Check for insufficient delegation checks
                if not self._has_delegation_validation(function):
                    issues.append(
                        {
                            "type": "weak_delegation",
                            "function": function.name,
                            "description": f"Voting function {function.name} lacks proper delegation validation",
                        }
                    )

        return issues

    def _check_proposal_execution(self, contract) -> list:
        """Check for proposal execution vulnerabilities"""
        issues = []

        for function in contract.functions:
            if "execute" in function.name.lower() or "queue" in function.name.lower():
                # Check for missing vote threshold validation
                if not self._has_vote_threshold_check(function):
                    issues.append(
                        {
                            "type": "missing_vote_threshold",
                            "function": function.name,
                            "description": f"Execution function {function.name} lacks vote threshold validation",
                        }
                    )

                # Check for timelock bypass
                if self._allows_immediate_execution(function):
                    issues.append(
                        {
                            "type": "immediate_execution",
                            "function": function.name,
                            "description": f"Execution function {function.name} allows immediate execution without timelock",
                        }
                    )

        return issues

    def _check_quorum_manipulation(self, contract) -> list:
        """Check for quorum manipulation vulnerabilities"""
        issues = []

        # Look for quorum calculation logic
        for function in contract.functions:
            if (
                "quorum" in function.name.lower()
                or "participation" in function.name.lower()
            ):
                # Check if quorum can be manipulated through delegation
                if self._quorum_manipulable_via_delegation(function):
                    issues.append(
                        {
                            "type": "quorum_manipulation",
                            "function": function.name,
                            "description": f"Quorum calculation in {function.name} vulnerable to delegation manipulation",
                        }
                    )

        return issues

    def _check_timelock_bypass(self, contract) -> list:
        """Check for timelock bypass vulnerabilities"""
        issues = []

        for function in contract.functions:
            if "timelock" in function.name.lower() or "delay" in function.name.lower():
                # Check for emergency bypass mechanisms
                if self._has_emergency_bypass(function):
                    issues.append(
                        {
                            "type": "emergency_bypass_risk",
                            "function": function.name,
                            "description": f"Timelock function {function.name} has emergency bypass that could be abused",
                        }
                    )

                # Check for insufficient delay validation
                if not self._has_delay_validation(function):
                    issues.append(
                        {
                            "type": "weak_delay_validation",
                            "function": function.name,
                            "description": f"Timelock function {function.name} lacks proper delay validation",
                        }
                    )

        return issues

    def _is_voting_function(self, function: FunctionContract) -> bool:
        """Determine if function is a voting function"""
        voting_keywords = ["vote", "cast", "delegate", "participate"]
        func_name = function.name.lower()
        return any(keyword in func_name for keyword in voting_keywords)

    def _has_atomic_voting_power_change(self, function: FunctionContract) -> bool:
        """Check if voting power can change atomically (flash loan vulnerability)"""
        # Look for delegatecall or external calls that could change voting power
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, CallExpression):
                    if hasattr(ir, "function") and ir.function:
                        func_name = ir.function.name.lower()
                        if "delegate" in func_name or "transfer" in func_name:
                            return True
        return False

    def _has_delegation_validation(self, function: FunctionContract) -> bool:
        """Check for delegation validation"""
        # Look for checks on delegation authority
        validation_keywords = ["require", "assert", "onlydelegate"]
        for node in function.nodes:
            for ir in node.irs:
                if any(keyword in str(ir).lower() for keyword in validation_keywords):
                    if "delegate" in str(ir).lower():
                        return True
        return False

    def _has_vote_threshold_check(self, function: FunctionContract) -> bool:
        """Check for vote threshold validation"""
        threshold_keywords = ["threshold", "quorum", "majority"]
        for node in function.nodes:
            for ir in node.irs:
                if any(keyword in str(ir).lower() for keyword in threshold_keywords):
                    return True
        return False

    def _allows_immediate_execution(self, function: FunctionContract) -> bool:
        """Check if function allows immediate execution"""
        # Look for lack of timelock/delay checks
        delay_keywords = ["timelock", "delay", "eta", "queue"]
        has_delay_check = False
        for node in function.nodes:
            for ir in node.irs:
                if any(keyword in str(ir).lower() for keyword in delay_keywords):
                    has_delay_check = True
                    break
            if has_delay_check:
                break

        return not has_delay_check

    def _quorum_manipulable_via_delegation(self, function: FunctionContract) -> bool:
        """Check if quorum can be manipulated through delegation"""
        # Simplified check - look for quorum calculation without delegation validation
        quorum_calc = False
        delegation_use = False

        for node in function.nodes:
            for ir in node.irs:
                if "quorum" in str(ir).lower():
                    quorum_calc = True
                if "delegate" in str(ir).lower():
                    delegation_use = True

        return quorum_calc and delegation_use

    def _has_emergency_bypass(self, function: FunctionContract) -> bool:
        """Check for emergency bypass mechanisms"""
        emergency_keywords = ["emergency", "bypass", "override", "force"]
        for node in function.nodes:
            for ir in node.irs:
                if any(keyword in str(ir).lower() for keyword in emergency_keywords):
                    return True
        return False

    def _has_delay_validation(self, function: FunctionContract) -> bool:
        """Check for delay validation"""
        validation_keywords = ["require", "assert", "if", "block.timestamp"]
        delay_check = False

        for node in function.nodes:
            for ir in node.irs:
                if any(keyword in str(ir).lower() for keyword in validation_keywords):
                    if "delay" in str(ir).lower() or "timelock" in str(ir).lower():
                        delay_check = True
                        break
            if delay_check:
                break

        return delay_check

    def generate_result_from_vulnerability(self, contract, vulnerability):
        info = f"Governance Vulnerability in {contract.name}: {vulnerability['type']}\n"
        info += f"Description: {vulnerability['description']}\n"
        if "function" in vulnerability:
            info += f"Function: {vulnerability['function']}\n"

        json_result = self.generate_result(info)
        return Output(info, json_result)
