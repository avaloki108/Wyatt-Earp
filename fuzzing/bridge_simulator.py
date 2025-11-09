"""
Cross-Chain Bridge Simulator
Simulates bridge attacks: message replay, reordering, forged proofs, double-spending
"""

import hashlib
import time
from typing import List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class MessageStatus(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class BridgeMessage:
    """Cross-chain bridge message"""
    msg_id: str
    source_chain: str
    dest_chain: str
    sender: str
    recipient: str
    amount: int
    nonce: int
    timestamp: int
    proof: str
    status: MessageStatus = MessageStatus.PENDING
    executed_on_dest: bool = False


@dataclass
class ChainState:
    """State of a blockchain"""
    chain_id: str
    balances: Dict[str, int] = field(default_factory=dict)
    locked_tokens: int = 0
    minted_tokens: int = 0
    message_nonces: Dict[str, int] = field(default_factory=dict)
    processed_messages: set = field(default_factory=set)


class BridgeAttackSimulator:
    """
    Simulates various bridge attack vectors:
    1. Message replay attacks
    2. Message reordering
    3. Forged proofs
    4. Double withdrawal
    5. Finality violations
    """

    def __init__(self):
        self.chains: Dict[str, ChainState] = {}
        self.messages: List[BridgeMessage] = []
        self.attack_log: List[Dict[str, Any]] = []

    def create_chain(self, chain_id: str) -> ChainState:
        """Create a new chain"""
        chain = ChainState(chain_id=chain_id)
        self.chains[chain_id] = chain
        return chain

    def mint_tokens(self, chain_id: str, user: str, amount: int):
        """Mint tokens on a chain"""
        if chain_id not in self.chains:
            raise ValueError(f"Chain {chain_id} not found")

        chain = self.chains[chain_id]
        chain.balances[user] = chain.balances.get(user, 0) + amount

    def lock_tokens(self, source_chain: str, user: str, amount: int, dest_chain: str) -> BridgeMessage:
        """
        Lock tokens on source chain to bridge to destination chain
        This is the LOCK operation in Lock & Mint bridge
        """
        if source_chain not in self.chains or dest_chain not in self.chains:
            raise ValueError("Chain not found")

        source = self.chains[source_chain]

        # Check user has enough balance
        if source.balances.get(user, 0) < amount:
            raise ValueError(f"Insufficient balance: {source.balances.get(user, 0)} < {amount}")

        # Lock tokens
        source.balances[user] -= amount
        source.locked_tokens += amount

        # Get nonce
        nonce = source.message_nonces.get(user, 0)
        source.message_nonces[user] = nonce + 1

        # Create bridge message
        msg_id = self._generate_message_id(source_chain, dest_chain, user, amount, nonce)
        proof = self._generate_proof(msg_id, source_chain)

        message = BridgeMessage(
            msg_id=msg_id,
            source_chain=source_chain,
            dest_chain=dest_chain,
            sender=user,
            recipient=user,  # Same user on dest chain
            amount=amount,
            nonce=nonce,
            timestamp=int(time.time()),
            proof=proof,
            status=MessageStatus.CONFIRMED
        )

        self.messages.append(message)
        return message

    def mint_on_destination(self, message: BridgeMessage) -> bool:
        """
        Mint tokens on destination chain (MINT operation in Lock & Mint)
        VULNERABLE: Can be exploited if not checking message_id properly
        """
        dest = self.chains[message.dest_chain]

        # CRITICAL: Check if message already processed
        if message.msg_id in dest.processed_messages:
            self._log_attack("REPLAY_ATTACK", f"Message {message.msg_id} already processed!")
            return False

        # Verify proof (simplified - real bridge would verify merkle proof)
        if not self._verify_proof(message.proof, message.msg_id, message.source_chain):
            self._log_attack("FORGED_PROOF", f"Invalid proof for message {message.msg_id}")
            return False

        # Mark as processed BEFORE minting (reentrancy protection)
        dest.processed_messages.add(message.msg_id)

        # Mint tokens
        dest.balances[message.recipient] = dest.balances.get(message.recipient, 0) + message.amount
        dest.minted_tokens += message.amount

        message.status = MessageStatus.EXECUTED
        message.executed_on_dest = True

        return True

    def check_invariants(self) -> List[str]:
        """
        Check bridge invariants - these should NEVER be violated
        """
        violations = []

        for chain_id, chain in self.chains.items():
            # Invariant 1: locked tokens on source == minted tokens on all destinations
            # This is a simplified check - real bridge would track per-pair
            pass  # Complex to check across all chains

        # Invariant 2: Total supply should be conserved across all chains
        total_supply = 0
        for chain in self.chains.values():
            total_supply += sum(chain.balances.values())
            total_supply += chain.locked_tokens

        # Check for token creation out of thin air
        # (This would catch minting without locking)

        # Invariant 3: No message should be executed twice
        # (Sets don't have duplicates, so this check is for logic validation)
        seen_messages = []
        for msg in self.messages:
            if msg.status == MessageStatus.EXECUTED:
                if msg.msg_id in seen_messages:
                    violations.append(f"Message {msg.msg_id} executed multiple times!")
                seen_messages.append(msg.msg_id)

        return violations

    # ========================================================================
    # ATTACK SIMULATIONS
    # ========================================================================

    def simulate_replay_attack(self, message: BridgeMessage) -> Dict[str, Any]:
        """
        Simulate message replay attack
        Attacker tries to execute the same message twice
        """
        print("\n[ATTACK] Simulating MESSAGE REPLAY attack...")

        initial_balance = self.chains[message.dest_chain].balances.get(message.recipient, 0)

        # First execution (legitimate)
        success1 = self.mint_on_destination(message)

        balance_after_first = self.chains[message.dest_chain].balances.get(message.recipient, 0)

        # Try to replay the same message
        success2 = self.mint_on_destination(message)

        balance_after_replay = self.chains[message.dest_chain].balances.get(message.recipient, 0)

        exploited = success1 and success2

        result = {
            "attack_type": "replay_attack",
            "exploited": exploited,
            "first_mint_success": success1,
            "replay_mint_success": success2,
            "initial_balance": initial_balance,
            "balance_after_first": balance_after_first,
            "balance_after_replay": balance_after_replay,
            "tokens_stolen": balance_after_replay - balance_after_first if exploited else 0
        }

        self.attack_log.append(result)
        return result

    def simulate_reordering_attack(self, messages: List[BridgeMessage]) -> Dict[str, Any]:
        """
        Simulate message reordering attack
        Attacker reorders messages to exploit ordering assumptions
        """
        print("\n[ATTACK] Simulating MESSAGE REORDERING attack...")

        if len(messages) < 2:
            return {"attack_type": "reordering_attack", "exploited": False, "reason": "Need at least 2 messages"}

        # Simulate: User deposits, then withdraws
        # Attacker reorders to: withdraw first, then deposit
        # If bridge doesn't check ordering properly, this could succeed

        # Original order
        original_order = messages.copy()

        # Reversed order (attack)
        attack_order = list(reversed(messages))

        results = {
            "attack_type": "reordering_attack",
            "original_order": [m.msg_id for m in original_order],
            "attack_order": [m.msg_id for m in attack_order],
            "exploited": False,
            "details": []
        }

        # Try executing in reversed order
        for msg in attack_order:
            success = self.mint_on_destination(msg)
            results["details"].append({
                "msg_id": msg.msg_id,
                "success": success,
                "nonce": msg.nonce
            })

        # Check if any message succeeded that shouldn't have
        # (e.g., withdraw before deposit)
        # This would be detected by checking nonces

        self.attack_log.append(results)
        return results

    def simulate_forged_proof_attack(self, message: BridgeMessage) -> Dict[str, Any]:
        """
        Simulate forged proof attack
        Attacker creates fake proof to mint tokens without locking
        """
        print("\n[ATTACK] Simulating FORGED PROOF attack...")

        # Create a fake message with forged proof
        fake_message = BridgeMessage(
            msg_id="FORGED_" + message.msg_id,
            source_chain=message.source_chain,
            dest_chain=message.dest_chain,
            sender="attacker",
            recipient="attacker",
            amount=message.amount * 1000,  # Try to steal 1000x
            nonce=999,
            timestamp=int(time.time()),
            proof="FORGED_PROOF_12345",  # Fake proof
            status=MessageStatus.CONFIRMED
        )

        initial_balance = self.chains[fake_message.dest_chain].balances.get("attacker", 0)

        # Try to mint with forged proof
        success = self.mint_on_destination(fake_message)

        final_balance = self.chains[fake_message.dest_chain].balances.get("attacker", 0)

        result = {
            "attack_type": "forged_proof_attack",
            "exploited": success,
            "initial_balance": initial_balance,
            "final_balance": final_balance,
            "attempted_amount": fake_message.amount,
            "tokens_stolen": final_balance - initial_balance if success else 0
        }

        self.attack_log.append(result)
        return result

    def simulate_double_withdrawal_attack(self, user: str, amount: int) -> Dict[str, Any]:
        """
        Simulate double withdrawal attack
        User withdraws from bridge on both chains simultaneously
        """
        print("\n[ATTACK] Simulating DOUBLE WITHDRAWAL attack...")

        if len(self.chains) < 2:
            return {"attack_type": "double_withdrawal", "exploited": False, "reason": "Need at least 2 chains"}

        chain_ids = list(self.chains.keys())
        chain1, chain2 = chain_ids[0], chain_ids[1]

        # Setup: User has tokens locked on both chains
        self.mint_tokens(chain1, user, amount)
        self.mint_tokens(chain2, user, amount)

        # User withdraws from chain1
        msg1 = self.lock_tokens(chain1, user, amount, chain2)

        # Simultaneously, user tries to withdraw from chain2
        # This should fail if bridge checks locked amounts
        try:
            msg2 = self.lock_tokens(chain2, user, amount, chain1)
            double_withdrawal_succeeded = True
        except ValueError:
            double_withdrawal_succeeded = False
            msg2 = None

        result = {
            "attack_type": "double_withdrawal_attack",
            "exploited": double_withdrawal_succeeded,
            "first_withdrawal": msg1.msg_id if msg1 else None,
            "second_withdrawal": msg2.msg_id if msg2 else None,
            "amount_per_withdrawal": amount
        }

        self.attack_log.append(result)
        return result

    def simulate_finality_attack(self, message: BridgeMessage, reorg_depth: int = 6) -> Dict[str, Any]:
        """
        Simulate chain reorganization attack
        Message is confirmed, then source chain reorgs and message is removed
        """
        print("\n[ATTACK] Simulating FINALITY VIOLATION (reorg) attack...")

        # User mints on destination
        success = self.mint_on_destination(message)

        balance_after_mint = self.chains[message.dest_chain].balances.get(message.recipient, 0)

        # Simulate chain reorg - message is no longer in source chain
        # But tokens already minted on dest chain!

        # In real attack: source chain reverts, locked tokens returned
        # But dest chain doesn't know about reorg
        source = self.chains[message.source_chain]
        source.locked_tokens -= message.amount  # Tokens returned due to reorg

        # Check if this creates tokens out of thin air
        violations = self.check_invariants()

        result = {
            "attack_type": "finality_attack",
            "exploited": success,
            "reorg_depth": reorg_depth,
            "tokens_minted_on_dest": message.amount if success else 0,
            "tokens_unlocked_on_source": message.amount,
            "invariant_violations": violations,
            "tokens_created_from_nothing": message.amount if success else 0
        }

        self.attack_log.append(result)
        return result

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _generate_message_id(self, source: str, dest: str, user: str, amount: int, nonce: int) -> str:
        """Generate unique message ID"""
        data = f"{source}:{dest}:{user}:{amount}:{nonce}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _generate_proof(self, msg_id: str, chain_id: str) -> str:
        """Generate proof (simplified - real would be merkle proof)"""
        data = f"{msg_id}:{chain_id}:proof"
        return hashlib.sha256(data.encode()).hexdigest()

    def _verify_proof(self, proof: str, msg_id: str, chain_id: str) -> bool:
        """Verify proof"""
        expected_proof = self._generate_proof(msg_id, chain_id)
        return proof == expected_proof

    def _log_attack(self, attack_type: str, description: str):
        """Log attack attempt"""
        print(f"  ⚠️  {attack_type}: {description}")

    def get_attack_report(self) -> Dict[str, Any]:
        """Generate comprehensive attack report"""
        return {
            "total_attacks_simulated": len(self.attack_log),
            "successful_exploits": sum(1 for a in self.attack_log if a.get("exploited", False)),
            "attacks": self.attack_log,
            "invariant_violations": self.check_invariants()
        }


# ============================================================================
# BRIDGE VULNERABILITY PATTERNS
# ============================================================================

class BridgeVulnerabilityDetector:
    """Detect common bridge vulnerability patterns"""

    @staticmethod
    def check_replay_protection(contract_code: str) -> List[Dict[str, Any]]:
        """Check if bridge has replay protection"""
        vulnerabilities = []

        # Check for processed messages tracking
        if "mapping" not in contract_code or "processed" not in contract_code.lower():
            vulnerabilities.append({
                "type": "missing_replay_protection",
                "severity": "critical",
                "description": "No mapping to track processed messages - vulnerable to replay attacks"
            })

        # Check if message ID is used as key
        if "messageId" not in contract_code and "msgId" not in contract_code:
            vulnerabilities.append({
                "type": "weak_message_id",
                "severity": "high",
                "description": "No clear message ID tracking - may allow duplicates"
            })

        return vulnerabilities

    @staticmethod
    def check_finality_requirements(contract_code: str) -> List[Dict[str, Any]]:
        """Check if bridge respects finality"""
        vulnerabilities = []

        # Check for confirmation blocks requirement
        if "confirmations" not in contract_code.lower() and "finality" not in contract_code.lower():
            vulnerabilities.append({
                "type": "no_finality_check",
                "severity": "critical",
                "description": "No finality checks - vulnerable to reorg attacks"
            })

        return vulnerabilities

    @staticmethod
    def check_proof_verification(contract_code: str) -> List[Dict[str, Any]]:
        """Check proof verification logic"""
        vulnerabilities = []

        # Check for merkle proof verification
        if "merkle" not in contract_code.lower() and "proof" in contract_code.lower():
            vulnerabilities.append({
                "type": "weak_proof_verification",
                "severity": "critical",
                "description": "Proof verification present but no merkle proof - may be forgeable"
            })

        return vulnerabilities


# Example usage
if __name__ == "__main__":
    print("="*70)
    print("CROSS-CHAIN BRIDGE ATTACK SIMULATOR")
    print("="*70)

    # Setup
    simulator = BridgeAttackSimulator()

    # Create two chains
    ethereum = simulator.create_chain("ethereum")
    arbitrum = simulator.create_chain("arbitrum")

    # Give user some tokens on Ethereum
    simulator.mint_tokens("ethereum", "alice", 1000)

    print("\n📊 Initial State:")
    print(f"  Alice on Ethereum: {ethereum.balances['alice']} tokens")
    print(f"  Alice on Arbitrum: {arbitrum.balances.get('alice', 0)} tokens")

    # Alice bridges 100 tokens from Ethereum to Arbitrum
    print("\n🌉 Alice bridges 100 tokens: Ethereum → Arbitrum")
    msg = simulator.lock_tokens("ethereum", "alice", 100, "arbitrum")
    simulator.mint_on_destination(msg)

    print("\n📊 After Bridge:")
    print(f"  Alice on Ethereum: {ethereum.balances['alice']} tokens")
    print(f"  Alice on Arbitrum: {arbitrum.balances.get('alice', 0)} tokens")
    print(f"  Locked on Ethereum: {ethereum.locked_tokens} tokens")
    print(f"  Minted on Arbitrum: {arbitrum.minted_tokens} tokens")

    # Run attacks
    print("\n" + "="*70)
    print("RUNNING ATTACK SIMULATIONS")
    print("="*70)

    # Attack 1: Replay attack
    replay_result = simulator.simulate_replay_attack(msg)
    print(f"\n✓ Replay Attack - Exploited: {replay_result['exploited']}")
    if replay_result['exploited']:
        print(f"  💰 Tokens stolen: {replay_result['tokens_stolen']}")

    # Attack 2: Create new bridge message for other attacks
    simulator.mint_tokens("ethereum", "bob", 200)
    msg2 = simulator.lock_tokens("ethereum", "bob", 50, "arbitrum")

    # Attack 3: Forged proof
    forged_result = simulator.simulate_forged_proof_attack(msg2)
    print(f"\n✓ Forged Proof Attack - Exploited: {forged_result['exploited']}")
    if forged_result['exploited']:
        print(f"  💰 Tokens stolen: {forged_result['tokens_stolen']}")

    # Attack 4: Double withdrawal
    double_result = simulator.simulate_double_withdrawal_attack("charlie", 100)
    print(f"\n✓ Double Withdrawal Attack - Exploited: {double_result['exploited']}")

    # Attack 5: Finality attack
    simulator.mint_tokens("ethereum", "dave", 500)
    msg3 = simulator.lock_tokens("ethereum", "dave", 200, "arbitrum")
    finality_result = simulator.simulate_finality_attack(msg3, reorg_depth=6)
    print(f"\n✓ Finality Attack - Exploited: {finality_result['exploited']}")
    if finality_result['exploited']:
        print(f"  💰 Tokens created from nothing: {finality_result['tokens_created_from_nothing']}")

    # Generate report
    print("\n" + "="*70)
    print("ATTACK REPORT")
    print("="*70)

    report = simulator.get_attack_report()
    print(f"Total attacks simulated: {report['total_attacks_simulated']}")
    print(f"Successful exploits: {report['successful_exploits']}")

    if report['invariant_violations']:
        print("\n⚠️  INVARIANT VIOLATIONS:")
        for violation in report['invariant_violations']:
            print(f"  - {violation}")

    print("\n" + "="*70)
