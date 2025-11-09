"""
Economic invariant generation for DeFi protocols
Creates invariants that capture economic properties and prevent exploitation
"""

from typing import List
from dataclasses import dataclass
import re


@dataclass
class EconomicInvariant:
    """Represents an economic invariant for a DeFi protocol"""
    name: str
    category: str  # "conservation", "bounds", "fairness", "safety"
    description: str
    invariant_code: str
    risk_level: str  # "critical", "high", "medium", "low"
    protocol_type: str  # "lending", "dex", "yield", "bridge", etc.


class EconomicInvariantGenerator:
    """Generates economic invariants for various DeFi protocols"""

    def __init__(self):
        self.protocol_patterns = {
            'lending': self._generate_lending_invariants,
            'dex': self._generate_dex_invariants,
            'yield': self._generate_yield_invariants,
            'bridge': self._generate_bridge_invariants,
            'staking': self._generate_staking_invariants,
            'governance': self._generate_governance_invariants
        }

    def generate_invariants(self, contract_code: str, protocol_type: str) -> List[EconomicInvariant]:
        """
        Generate economic invariants based on protocol type and contract analysis
        """
        # Auto-detect protocol type if not specified
        if protocol_type == 'auto':
            protocol_type = self._detect_protocol_type(contract_code)

        generator = self.protocol_patterns.get(protocol_type, self._generate_generic_invariants)
        return generator(contract_code)

    def _detect_protocol_type(self, contract_code: str) -> str:
        """Auto-detect protocol type from contract code"""
        code_lower = contract_code.lower()

        if any(term in code_lower for term in ['borrow', 'lend', 'collateral', 'liquidat']):
            return 'lending'
        elif any(term in code_lower for term in ['swap', 'exchange', 'pair', 'router']):
            return 'dex'
        elif any(term in code_lower for term in ['stake', 'reward', 'farm', 'yield']):
            return 'yield'
        elif any(term in code_lower for term in ['bridge', 'crosschain', 'relay']):
            return 'bridge'
        elif any(term in code_lower for term in ['govern', 'proposal', 'vote']):
            return 'governance'
        else:
            return 'generic'

    def _generate_lending_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate invariants for lending protocols"""
        return [
            EconomicInvariant(
                name="collateral_safety",
                category="safety",
                description="Total collateral value should exceed total debt",
                invariant_code="echidna_collateral_safety() public view returns (bool) { return totalCollateralValue >= totalDebtValue; }",
                risk_level="critical",
                protocol_type="lending"
            ),
            EconomicInvariant(
                name="liquidation_bounds",
                category="bounds",
                description="Liquidation should not leave bad debt",
                invariant_code="echidna_liquidation_safety() public view returns (bool) { return liquidatedAmount <= availableCollateral; }",
                risk_level="high",
                protocol_type="lending"
            ),
            EconomicInvariant(
                name="interest_accrual",
                category="conservation",
                description="Interest should accrue correctly without creating free money",
                invariant_code="echidna_interest_conservation() public view returns (bool) { return totalInterestPaid <= totalInterestEarned; }",
                risk_level="medium",
                protocol_type="lending"
            ),
            EconomicInvariant(
                name="health_factor_bounds",
                category="bounds",
                description="Health factor should prevent under-collateralized positions",
                invariant_code="echidna_health_factor() public view returns (bool) { return healthFactor >= MIN_HEALTH_FACTOR; }",
                risk_level="critical",
                protocol_type="lending"
            ),
            EconomicInvariant(
                name="flash_loan_impossible",
                category="safety",
                description="Flash loans should not create risk-free profit",
                invariant_code="echidna_no_risk_free_profit() public view returns (bool) { return flashLoanProfit <= acceptableSlippage; }",
                risk_level="high",
                protocol_type="lending"
            )
        ]

    def _generate_dex_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate invariants for DEX protocols"""
        return [
            EconomicInvariant(
                name="constant_product",
                category="conservation",
                description="AMM constant product should be maintained",
                invariant_code="echidna_constant_product() public view returns (bool) { return reserveA * reserveB == k; }",
                risk_level="critical",
                protocol_type="dex"
            ),
            EconomicInvariant(
                name="price_manipulation_resistance",
                category="fairness",
                description="Large trades should not manipulate price excessively",
                invariant_code="echidna_price_stability() public view returns (bool) { return priceImpact <= MAX_PRICE_IMPACT; }",
                risk_level="high",
                protocol_type="dex"
            ),
            EconomicInvariant(
                name="arbitrage_bounds",
                category="fairness",
                description="Arbitrage opportunities should be bounded",
                invariant_code="echidna_arbitrage_bounds() public view returns (bool) { return arbitrageProfit <= expectedSlippage; }",
                risk_level="medium",
                protocol_type="dex"
            ),
            EconomicInvariant(
                name="sandwich_attack_prevention",
                category="safety",
                description="Sandwich attacks should not cause excessive slippage",
                invariant_code="echidna_no_sandwich_exploit() public view returns (bool) { return victimLoss <= MAX_SLIPPAGE; }",
                risk_level="high",
                protocol_type="dex"
            )
        ]

    def _generate_yield_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate invariants for yield farming protocols"""
        return [
            EconomicInvariant(
                name="reward_distribution_fairness",
                category="fairness",
                description="Rewards should be distributed proportionally to stake",
                invariant_code="echidna_reward_fairness() public view returns (bool) { return userReward <= (userStake * totalRewards) / totalStaked; }",
                risk_level="high",
                protocol_type="yield"
            ),
            EconomicInvariant(
                name="total_reward_conservation",
                category="conservation",
                description="Total rewards distributed should not exceed allocated amount",
                invariant_code="echidna_reward_conservation() public view returns (bool) { return totalDistributed <= totalAllocated; }",
                risk_level="critical",
                protocol_type="yield"
            ),
            EconomicInvariant(
                name="inflation_control",
                category="bounds",
                description="Token inflation should stay within bounds",
                invariant_code="echidna_inflation_bounds() public view returns (bool) { return annualInflation <= MAX_INFLATION_RATE; }",
                risk_level="medium",
                protocol_type="yield"
            ),
            EconomicInvariant(
                name="compounding_safety",
                category="safety",
                description="Reward compounding should not create infinite loops",
                invariant_code="echidna_compounding_safety() public view returns (bool) { return compoundingIterations <= MAX_ITERATIONS; }",
                risk_level="medium",
                protocol_type="yield"
            )
        ]

    def _generate_bridge_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate invariants for bridge protocols"""
        return [
            EconomicInvariant(
                name="bridge_balance_conservation",
                category="conservation",
                description="Tokens locked should equal tokens minted on destination",
                invariant_code="echidna_bridge_conservation() public view returns (bool) { return lockedAmount == mintedAmount; }",
                risk_level="critical",
                protocol_type="bridge"
            ),
            EconomicInvariant(
                name="message_uniqueness",
                category="safety",
                description="Each message should be processed only once",
                invariant_code="echidna_message_uniqueness() public view returns (bool) { return processedMessages[messageId] == false; }",
                risk_level="critical",
                protocol_type="bridge"
            ),
            EconomicInvariant(
                name="validator_threshold",
                category="safety",
                description="Validator consensus should meet threshold",
                invariant_code="echidna_validator_consensus() public view returns (bool) { return validatorSignatures >= REQUIRED_SIGNATURES; }",
                risk_level="high",
                protocol_type="bridge"
            ),
            EconomicInvariant(
                name="timeout_safety",
                category="bounds",
                description="Bridge operations should timeout appropriately",
                invariant_code="echidna_timeout_safety() public view returns (bool) { return block.timestamp - startTime <= MAX_TIMEOUT; }",
                risk_level="medium",
                protocol_type="bridge"
            )
        ]

    def _generate_staking_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate invariants for staking protocols"""
        return [
            EconomicInvariant(
                name="stake_withdrawal_safety",
                category="safety",
                description="Users should be able to withdraw their stake",
                invariant_code="echidna_withdrawal_safety() public view returns (bool) { return userStake >= requestedWithdrawal; }",
                risk_level="critical",
                protocol_type="staking"
            ),
            EconomicInvariant(
                name="slashing_bounds",
                category="bounds",
                description="Slashing should not exceed stake amount",
                invariant_code="echidna_slashing_bounds() public view returns (bool) { return slashedAmount <= userStake; }",
                risk_level="high",
                protocol_type="staking"
            ),
            EconomicInvariant(
                name="delegation_safety",
                category="safety",
                description="Delegation should not compromise stake security",
                invariant_code="echidna_delegation_safety() public view returns (bool) { return delegatedStake <= validatorCapacity; }",
                risk_level="medium",
                protocol_type="staking"
            )
        ]

    def _generate_governance_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate invariants for governance protocols"""
        return [
            EconomicInvariant(
                name="vote_manipulation_prevention",
                category="fairness",
                description="Votes should not be manipulated",
                invariant_code="echidna_vote_integrity() public view returns (bool) { return actualVotes == legitimateVotes; }",
                risk_level="critical",
                protocol_type="governance"
            ),
            EconomicInvariant(
                name="proposal_execution_safety",
                category="safety",
                description="Only passed proposals should execute",
                invariant_code="echidna_proposal_safety() public view returns (bool) { return executedProposals.forall(p => p.votes >= threshold); }",
                risk_level="high",
                protocol_type="governance"
            ),
            EconomicInvariant(
                name="quorum_requirements",
                category="fairness",
                description="Quorum requirements should be met",
                invariant_code="echidna_quorum_satisfaction() public view returns (bool) { return participatingVotes >= requiredQuorum; }",
                risk_level="high",
                protocol_type="governance"
            )
        ]

    def _generate_generic_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Generate generic invariants applicable to most protocols"""
        return [
            EconomicInvariant(
                name="balance_conservation",
                category="conservation",
                description="Total balance should be conserved",
                invariant_code="echidna_balance_conservation() public view returns (bool) { return totalSupply == sum(userBalances); }",
                risk_level="high",
                protocol_type="generic"
            ),
            EconomicInvariant(
                name="no_negative_values",
                category="bounds",
                description="No negative values in critical state variables",
                invariant_code="echidna_no_negative_values() public view returns (bool) { return forall(addr => balances[addr] >= 0); }",
                risk_level="medium",
                protocol_type="generic"
            ),
            EconomicInvariant(
                name="access_control_integrity",
                category="safety",
                description="Access controls should remain intact",
                invariant_code="echidna_access_control() public view returns (bool) { return owner == INITIAL_OWNER || transferAuthorized; }",
                risk_level="high",
                protocol_type="generic"
            )
        ]

    def generate_attack_specific_invariants(self, attack_type: str) -> List[EconomicInvariant]:
        """Generate invariants specifically targeting common attack vectors"""
        attack_invariants = {
            'flash_loan': [
                EconomicInvariant(
                    name="flash_loan_atomicity",
                    category="safety",
                    description="Flash loan operations must be atomic",
                    invariant_code="echidna_flash_loan_atomicity() public view returns (bool) { return loanAmount == repaidAmount; }",
                    risk_level="critical",
                    protocol_type="generic"
                )
            ],
            'oracle_manipulation': [
                EconomicInvariant(
                    name="oracle_bounds",
                    category="bounds",
                    description="Oracle prices should stay within reasonable bounds",
                    invariant_code="echidna_oracle_bounds() public view returns (bool) { return price >= MIN_PRICE && price <= MAX_PRICE; }",
                    risk_level="high",
                    protocol_type="generic"
                )
            ],
            'reentrancy': [
                EconomicInvariant(
                    name="reentrancy_guard",
                    category="safety",
                    description="Reentrancy should be prevented",
                    invariant_code="echidna_reentrancy_protection() public view returns (bool) { return !currentlyExecuting; }",
                    risk_level="critical",
                    protocol_type="generic"
                )
            ]
        }

        return attack_invariants.get(attack_type, [])

    def create_invariant_test_suite(self, invariants: List[EconomicInvariant], contract_name: str) -> str:
        """Create a complete Solidity test suite with all invariants"""
        test_suite = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * Economic Invariant Test Suite for {contract_name}
 * Generated by Web3 Bug Hunter
 */
contract EconomicInvariantTests {{

    {contract_name} protocol;

    constructor() {{
        protocol = new {contract_name}();
    }}

"""

        for invariant in invariants:
            test_suite += f"""
    /** {invariant.description} */
    function {invariant.name}() public {{
        // Test implementation would go here
        // This is a template - customize based on actual contract
        assert(true); // Placeholder
    }}

"""

        test_suite += "}\n"
        return test_suite

    def analyze_contract_for_custom_invariants(self, contract_code: str) -> List[EconomicInvariant]:
        """Analyze contract code to suggest custom invariants"""
        custom_invariants = []

        # Look for mathematical operations that might need invariants
        if re.search(r'\b(?:\w+)\s*\*\s*(?:\w+)', contract_code):
            custom_invariants.append(EconomicInvariant(
                name="multiplication_safety",
                category="safety",
                description="Multiplication operations should not overflow",
                invariant_code="echidna_multiplication_safety() public view returns (bool) { return a * b <= type(uint256).max; }",
                risk_level="high",
                protocol_type="generic"
            ))

        # Look for division operations
        if re.search(r'\b(?:\w+)\s*/\s*(?:\w+)', contract_code):
            custom_invariants.append(EconomicInvariant(
                name="division_safety",
                category="safety",
                description="Division operations should not divide by zero",
                invariant_code="echidna_division_safety() public view returns (bool) { return denominator != 0; }",
                risk_level="critical",
                protocol_type="generic"
            ))

        # Look for time-dependent operations
        if 'block.timestamp' in contract_code:
            custom_invariants.append(EconomicInvariant(
                name="timestamp_dependencies",
                category="bounds",
                description="Time-dependent operations should be reasonable",
                invariant_code="echidna_timestamp_reasonable() public view returns (bool) { return deadline >= block.timestamp; }",
                risk_level="medium",
                protocol_type="generic"
            ))

        return custom_invariants


# Example usage
def demonstrate_economic_invariants():
    """Demonstrate economic invariant generation"""

    generator = EconomicInvariantGenerator()

    # Generate invariants for different protocol types
    lending_invariants = generator.generate_invariants("", "lending")
    dex_invariants = generator.generate_invariants("", "dex")
    bridge_invariants = generator.generate_invariants("", "bridge")

    # Generate attack-specific invariants
    flash_loan_invariants = generator.generate_attack_specific_invariants("flash_loan")

    return {
        "lending_invariants": len(lending_invariants),
        "dex_invariants": len(dex_invariants),
        "bridge_invariants": len(bridge_invariants),
        "flash_loan_invariants": len(flash_loan_invariants),
        "sample_invariant": lending_invariants[0].invariant_code if lending_invariants else None
    }


if __name__ == "__main__":
    result = demonstrate_economic_invariants()
    print(f"Generated economic invariants: {result}")