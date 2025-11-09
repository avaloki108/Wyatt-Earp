"""
Advanced LLM prompts for novel vulnerability detection in Web3 contracts
"""

from typing import Optional


class AdvancedAuditPrompts:
    """Collection of specialized prompts for different vulnerability types"""

    @staticmethod
    def bridge_vulnerability_analysis(
        contract_code: str, bridge_context: str = ""
    ) -> str:
        """Prompt for analyzing bridge-specific vulnerabilities"""
        return f"""
        Analyze this bridge contract for cross-chain vulnerabilities. Focus on:

        BRIDGE CONTRACT CODE:
        {contract_code}

        {f"BRIDGE CONTEXT: {bridge_context}" if bridge_context else ""}

        Look for these specific bridge attack patterns:

        1. **Message Validation Flaws**:
           - Insufficient signature verification
           - Weak Merkle proof validation
           - Default value exploitation (like Nomad's confirmAt[0] issue)
           - Message replay protection failures

        2. **Initialization & Setup Issues**:
           - Uninitialized critical variables
           - Improper guardian setup
           - Default value assumptions in mappings

        3. **Legacy Code Exploitation**:
           - Deprecated functions still callable
           - Old deposit methods that bypass new logic
           - Backwards compatibility issues

        4. **Cross-Chain Timing Attacks**:
           - Message ordering dependencies
           - Race conditions between chains
           - Time-based validation weaknesses

        5. **Economic/Logic Flaws**:
           - Minting without proper backing
           - Fee bypass mechanisms
           - Token standard assumption violations

        For each potential vulnerability:
        - Explain the attack scenario
        - Show the specific code that enables it
        - Suggest how to fix it
        - Rate severity (Critical/High/Medium/Low)

        Focus on novel attack vectors that automated tools might miss.
        """

    @staticmethod
    def business_logic_flaws(contract_code: str, protocol_description: str = "") -> str:
        """Prompt for detecting complex business logic vulnerabilities"""
        return f"""
        Analyze this DeFi protocol contract for business logic flaws that could lead to economic exploits:

        CONTRACT CODE:
        {contract_code}

        {f"PROTOCOL DESCRIPTION: {protocol_description}" if protocol_description else ""}

        Focus on these business logic attack vectors:

        1. **State Transition Vulnerabilities**:
           - Invalid state transitions
           - Missing state validation
           - State-dependent function misuse

        2. **Economic Invariant Violations**:
           - Balance conservation failures
           - Fee calculation errors
           - Reward distribution flaws

        3. **Multi-Step Attack Sequences**:
           - Function call ordering exploits
           - Sandwich attack opportunities
           - Flash loan enabled attacks

        4. **Oracle Manipulation Vectors**:
           - Price manipulation through external calls
           - Stale price usage
           - Oracle dependency assumptions

        5. **Access Control Logic**:
           - Role transition vulnerabilities
           - Permission escalation paths
           - Emergency function abuse

        6. **Mathematical/Precision Issues**:
           - Rounding error exploitation
           - Overflow/underflow in calculations
           - Division by zero edge cases

        For each identified flaw:
        - Describe the economic impact
        - Provide a concrete attack scenario
        - Show the code vulnerability
        - Suggest mitigation strategies

        Think like an economic attacker - what would maximize profit?
        """

    @staticmethod
    def cross_contract_logic(
        contract_code: str, related_contracts: Optional[list] = None
    ) -> str:
        """Prompt for analyzing cross-contract interaction vulnerabilities"""
        related_info = ""
        if related_contracts:
            related_info = "\nRELATED CONTRACTS:\n" + "\n".join(related_contracts)

        return f"""
        Analyze this contract for vulnerabilities that arise from cross-contract interactions:

        PRIMARY CONTRACT:
        {contract_code}

        {related_info}

        Focus on cross-contract attack patterns:

        1. **Trust Assumptions**:
           - External contract behavior assumptions
           - Callback safety violations
           - Interface compliance issues

        2. **Shared State Vulnerabilities**:
           - State synchronization failures
           - Concurrent modification issues
           - Cross-contract reentrancy

        3. **Token Standard Exploitation**:
           - Non-standard ERC20/ERC721 behavior
           - Fee-on-transfer token issues
           - Rebasing token complications

        4. **Proxy/Upgrade Patterns**:
           - Delegatecall safety issues
           - Storage collision vulnerabilities
           - Upgrade authorization flaws

        5. **Event-Driven Logic**:
           - Event ordering dependencies
           - Missing event validation
           - Off-chain event manipulation

        For each cross-contract vulnerability:
        - Identify the trusted external component
        - Explain how it could be malicious
        - Show the attack setup
        - Propose secure interaction patterns
        """

    @staticmethod
    def invariant_generation(contract_code: str, protocol_type: str = "DeFi") -> str:
        """Generate comprehensive invariants for property-based testing"""
        return f"""
        Generate comprehensive invariants for property-based testing of this {protocol_type} contract:

        CONTRACT CODE:
        {contract_code}

        Create invariants for these categories:

        1. **Balance Invariants**:
           - Total supply conservation
           - User balance limits
           - Contract balance consistency

        2. **Access Control Invariants**:
           - Permission preservation
           - Role consistency
           - Authorization state

        3. **Economic Invariants**:
           - Value conservation
           - Fee collection correctness
           - Reward distribution fairness

        4. **State Consistency Invariants**:
           - Configuration immutability
           - State transition validity
           - Critical variable bounds

        5. **Cross-Contract Invariants**:
           - External balance tracking
           - Callback safety
           - Interface compliance

        For each invariant:
        - Write it as an Echidna property function
        - Explain what it prevents
        - Note any assumptions or limitations
        - Suggest test scenarios that might violate it

        Focus on invariants that would catch novel logic flaws, not just basic safety properties.
        """

    @staticmethod
    def attack_scenario_simulation(
        contract_code: str, attack_type: str = "general"
    ) -> str:
        """Simulate specific attack scenarios"""
        attack_contexts = {
            "flash_loan": "Simulate a flash loan attack scenario",
            "oracle_manipulation": "Simulate oracle price manipulation",
            "governance_attack": "Simulate governance manipulation",
            "reentrancy": "Simulate complex reentrancy patterns",
            "arbitrage": "Simulate arbitrage opportunities",
        }

        context = attack_contexts.get(
            attack_type, "Simulate a sophisticated attack scenario"
        )

        return f"""
        {context} against this contract:

        CONTRACT CODE:
        {contract_code}

        Think step-by-step like an attacker:

        1. **Reconnaissance**:
           - What are the contract's main functions?
           - What state variables control value/assets?
           - What external dependencies exist?

        2. **Attack Vector Identification**:
           - What functions can be called in sequence?
           - What external conditions can be manipulated?
           - What assumptions does the contract make?

        3. **Exploit Construction**:
           - Design a step-by-step attack
           - Calculate potential profit
           - Identify required preconditions

        4. **Mitigation Analysis**:
           - Why does this attack work?
           - What code changes would prevent it?
           - Are there alternative attack paths?

        Provide:
        - Detailed attack scenario
        - Code example of the exploit
        - Economic impact assessment
        - Prevention recommendations

        Focus on creative, multi-step attacks that combine protocol features.
        """

    @staticmethod
    def formal_specification_helper(contract_code: str) -> str:
        """Help create formal specifications for verification"""
        return f"""
        Help create formal specifications for verifying this contract:

        CONTRACT CODE:
        {contract_code}

        Generate formal properties in a format suitable for tools like Certora or Scribble:

        1. **Functional Properties**:
           - Pre/post conditions for key functions
           - State transition specifications
           - Invariant preservation rules

        2. **Security Properties**:
           - Access control specifications
           - Safety assertions
           - Liveness properties

        3. **Economic Properties**:
           - Value conservation rules
           - Balance invariants
           - Fee correctness specifications

        For each property:
        - Write in formal notation
        - Explain the security guarantee
        - Note verification challenges
        - Suggest testing approaches

        Focus on properties that capture the contract's intended behavior and prevent exploitation.
        """
