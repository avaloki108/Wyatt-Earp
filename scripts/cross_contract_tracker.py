from typing import Dict, List, Any
from slither.core.declarations import Contract
from slither.core.declarations import FunctionContract
from slither.core.expressions import CallExpression


class CrossContractLogicTracker:
    def __init__(self, compilation_unit):
        self.compilation_unit = compilation_unit
        self.contract_graph = {}
        self.state_dependencies = {}
        self.function_calls = {}

    def build_contract_graph(self) -> Dict[str, List[str]]:
        """
        Build a graph of contract interactions
        """
        for contract in self.compilation_unit.contracts:
            self.contract_graph[contract.name] = []
            self.state_dependencies[contract.name] = set()
            self.function_calls[contract.name] = []

            for function in contract.functions:
                self._analyze_function_calls(contract, function)

        return self.contract_graph

    def _analyze_function_calls(self, contract: Contract, function: FunctionContract):
        """
        Analyze function calls within a contract
        """
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, CallExpression):
                    called_contract = self._get_called_contract(ir)
                    if called_contract and called_contract != contract.name:
                        if called_contract not in self.contract_graph[contract.name]:
                            self.contract_graph[contract.name].append(called_contract)

                        # Track function calls
                        call_info = {
                            'caller_function': function.name,
                            'called_contract': called_contract,
                            'called_function': getattr(ir, 'function', {}).get('name', 'unknown'),
                            'node_id': node.node_id
                        }
                        self.function_calls[contract.name].append(call_info)

                        # Track state dependencies
                        self._track_state_dependencies(contract, function, called_contract)

    def _get_called_contract(self, call_expression) -> str:
        """
        Extract the called contract name from a call expression
        """
        if hasattr(call_expression, 'function') and call_expression.function:
            if hasattr(call_expression.function, 'contract'):
                return call_expression.function.contract.name
        return None

    def _track_state_dependencies(self, contract: Contract, function: FunctionContract, called_contract: str):
        """
        Track state variables that might be affected by cross-contract calls
        """
        # This is a simplified implementation
        # In practice, you'd need more sophisticated data flow analysis
        for state_var in contract.state_variables:
            if state_var.name in function.source_mapping.content:
                self.state_dependencies[contract.name].add(state_var.name)

    def detect_potential_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Detect potential cross-contract vulnerabilities
        """
        vulnerabilities = []

        # Check for circular dependencies
        cycles = self._find_cycles()
        if cycles:
            vulnerabilities.append({
                'type': 'circular_dependency',
                'contracts': cycles,
                'severity': 'medium'
            })

        # Check for shared state without proper synchronization
        shared_state_issues = self._check_shared_state()
        vulnerabilities.extend(shared_state_issues)

        # Check for reentrancy patterns
        reentrancy_issues = self._check_reentrancy_patterns()
        vulnerabilities.extend(reentrancy_issues)

        return vulnerabilities

    def _find_cycles(self) -> List[List[str]]:
        """
        Find cycles in the contract dependency graph
        """
        def dfs(node, visited, path):
            visited.add(node)
            path.append(node)

            cycles = []
            for neighbor in self.contract_graph.get(node, []):
                if neighbor not in visited:
                    cycles.extend(dfs(neighbor, visited, path))
                elif neighbor in path:
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])

            path.pop()
            return cycles

        visited = set()
        all_cycles = []
        for contract in self.contract_graph:
            if contract not in visited:
                all_cycles.extend(dfs(contract, visited, []))

        return all_cycles

    def _check_shared_state(self) -> List[Dict[str, Any]]:
        """
        Check for shared state issues
        """
        issues = []
        # Simplified check - in practice, this would be more complex
        for contract, deps in self.state_dependencies.items():
            if len(deps) > 3:  # Arbitrary threshold
                issues.append({
                    'type': 'complex_state_management',
                    'contract': contract,
                    'state_variables': list(deps),
                    'severity': 'low'
                })
        return issues

    def _check_reentrancy_patterns(self) -> List[Dict[str, Any]]:
        """
        Check for reentrancy patterns in cross-contract calls
        """
        issues = []
        for contract, calls in self.function_calls.items():
            external_calls = [call for call in calls if call['called_contract'] != contract]
            if len(external_calls) > 1:
                issues.append({
                    'type': 'multiple_external_calls',
                    'contract': contract,
                    'calls': external_calls,
                    'severity': 'high'
                })
        return issues

    def generate_report(self) -> str:
        """
        Generate a human-readable report
        """
        report = "Cross-Contract Logic Analysis Report\n"
        report += "=" * 40 + "\n\n"

        report += "Contract Dependencies:\n"
        for contract, deps in self.contract_graph.items():
            report += f"  {contract} -> {', '.join(deps) if deps else 'None'}\n"

        report += "\nState Dependencies:\n"
        for contract, states in self.state_dependencies.items():
            report += f"  {contract}: {', '.join(states) if states else 'None'}\n"

        vulnerabilities = self.detect_potential_vulnerabilities()
        report += f"\nPotential Vulnerabilities ({len(vulnerabilities)}):\n"
        for vuln in vulnerabilities:
            report += f"  - {vuln['type']} in {vuln.get('contract', 'multiple contracts')}: {vuln['severity']}\n"

        return report