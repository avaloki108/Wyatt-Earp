from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.variables.state_variable import StateVariable
from slither.core.expressions import CallExpression
from slither.utils.output import Output


class CustomLogicFlawDetector(AbstractDetector):
    """
    Custom detector for novel logic flaws in Web3 contracts.
    This detector looks for potential reentrancy-like patterns in state updates.
    """

    ARGUMENT = "custom-logic-flaw"
    HELP = "Detects potential logic flaws where state is updated after external calls"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                if function.visibility in ["public", "external"]:
                    # Check for state updates after external calls
                    external_calls = []
                    state_updates = []

                    for node in function.nodes:
                        for ir in node.irs:
                            if isinstance(ir, CallExpression):
                                # Check if it's an external call (low-level call or interface call)
                                if hasattr(ir, "function") and ir.function:
                                    if ir.function.name in [
                                        "call",
                                        "delegatecall",
                                        "staticcall",
                                    ] or (
                                        hasattr(ir.function, "contract")
                                        and ir.function.contract != contract
                                    ):
                                        external_calls.append(node)

                            # Check for state variable assignments
                            if hasattr(ir, "lvalue") and isinstance(
                                ir.lvalue, StateVariable
                            ):
                                state_updates.append(node)

                    # Flag if state updates happen after external calls
                    if external_calls and state_updates:
                        last_call = max(external_calls, key=lambda x: x.node_id)
                        first_update = min(state_updates, key=lambda x: x.node_id)
                        if first_update.node_id > last_call.node_id:
                            results.append(
                                self.generate_result_from_contract(contract, function)
                            )

        return results

    def generate_result_from_contract(self, contract, function):
        info = f"Potential logic flaw in {contract.name}.{function.name}: State updated after external call\n"
        info += f"Function: {function.name}\n"
        info += f"Contract: {contract.name}\n"

        json_result = self.generate_result(info)
        return Output(info, json_result)
