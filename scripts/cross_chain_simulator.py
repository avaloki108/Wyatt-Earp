"""
Cross-chain simulation framework for testing bridge vulnerabilities
Enhanced for better multi-chain simulation and real attack replay (Nomad, Qubit, etc.)
Supports detailed PoC generation, historical attack replay, and integration with vulnerable contracts.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from copy import deepcopy
import random
from datetime import datetime

# Setup logging for detailed attack traces
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ChainType(Enum):
    ETHEREUM = "ethereum"
    BSC = "bsc"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    NOMAD_TESTNET = "nomad_testnet"  # For specific attack sim
    QUBIT_TESTNET = "qubit_testnet"


@dataclass
class ChainState:
    """Represents the state of a blockchain with enhanced tracking"""

    chain_id: int
    chain_type: ChainType
    contracts: Dict[
        str, Dict[str, Any]
    ]  # address -> {'code': str, 'state': dict, 'balance': int, 'deployed': bool, 'last_nonce': int}
    messages: List[Dict[str, Any]]  # pending cross-chain messages with timestamps
    block_number: int
    timestamp: int
    validators: List[str]  # Validator addresses for consensus sim
    total_value_locked: int = 0  # TVL for economic sim


@dataclass
class CrossChainMessage:
    """Enhanced cross-chain message with signatures and proofs"""

    source_chain: int
    target_chain: int
    sender: str
    target_contract: str
    payload: Dict[str, Any]  # {'amount': int, 'token': str, 'root': int, etc.}
    nonce: int
    signature: Optional[str] = None
    merkle_proof: Optional[Dict[str, Any]] = None  # {'root': str, 'proof': list}
    timestamp: int = 0
    relay_fee: int = 0
    status: str = "pending"  # pending, processed, failed, replayed


class AttackType(Enum):
    NOMAD_CONFIRMAT_ZERO = "nomad_confirmat_zero"
    QUBIT_LEGACY_FUNCTION = "qubit_legacy_function"
    MESSAGE_REPLAY = "message_replay"
    INVALID_SIGNATURE = "invalid_signature"
    OUT_OF_ORDER_PROCESSING = "out_of_order_processing"
    VALIDATOR_COMPROMISE = "validator_compromise"
    DEFAULT_MAPPING_EXPLOIT = "default_mapping_exploit"


class BridgeSimulator:
    """Enhanced simulator for multi-chain bridges with real attack replay"""

    def __init__(self, verbose: bool = True):
        self.chains: Dict[int, ChainState] = {}
        self.messages: List[CrossChainMessage] = []
        self.message_queue: List[CrossChainMessage] = []
        self.processed_messages: Dict[int, bool] = {}  # nonce -> processed
        self.nonce_counter = 0
        self.attack_history: List[Dict[str, Any]] = []
        self.verbose = verbose
        self.historical_attacks = self._load_historical_attacks()

    def _load_historical_attacks(self) -> Dict[str, Dict]:
        """Load parameters for real historical attacks"""
        # Simulated historical data for Nomad and Qubit
        return {
            AttackType.NOMAD_CONFIRMAT_ZERO.value: {
                "description": "Nomad Bridge exploit via confirmAt[0] default true",
                "amount_exploited": 190_000_000,  # USD equivalent
                "date": "2022-08-01",
                "root_zero": True,
                "poc": "Use root=0 to bypass validation",
            },
            AttackType.QUBIT_LEGACY_FUNCTION.value: {
                "description": "Qubit legacy deposit function bypass",
                "amount_exploited": 80_000_000,
                "date": "2022-01-01",
                "legacy_token": "0x0000000000000000000000000000000000000000",
                "poc": "Call old deposit with address(0) to mint without lock",
            },
        }

    def add_chain(
        self,
        chain_id: int,
        chain_type: ChainType,
        validators: Optional[List[str]] = None,
    ) -> None:
        """Add a new chain with validators for consensus sim"""
        self.chains[chain_id] = ChainState(
            chain_id=chain_id,
            chain_type=chain_type,
            contracts={},
            messages=[],
            block_number=0,
            timestamp=int(datetime.now().timestamp()),
            validators=validators
            or [f"0xval{i:02x}" for i in range(1, 6)],  # Default 5 validators
        )
        if self.verbose:
            logger.info(
                f"Added chain {chain_id} ({chain_type.value}) with {len(self.chains[chain_id].validators)} validators"
            )

    def deploy_contract(
        self,
        chain_id: int,
        contract_address: str,
        contract_code: str,
        initial_state: Optional[Dict] = None,
    ) -> None:
        """Deploy a contract with initial state"""
        if chain_id not in self.chains:
            raise ValueError(f"Chain {chain_id} not found")
        initial_state = initial_state or {
            "last_nonce": 0,
            "confirmAt": {},
            "guardian": "0xguardian",
        }
        self.chains[chain_id].contracts[contract_address] = {
            "code": contract_code,
            "state": initial_state,
            "balance": 0,
            "deployed": True,
            "last_nonce": 0,
        }
        self.chains[chain_id].total_value_locked += 1000  # Simulated TVL
        if self.verbose:
            logger.info(f"Deployed contract {contract_address} on chain {chain_id}")

    def send_message(self, message: CrossChainMessage) -> str:
        """Send a cross-chain message with validation"""
        message.nonce = self.nonce_counter
        self.nonce_counter += 1
        message.timestamp = self.chains[message.source_chain].timestamp
        # Simulate signature (simplified)
        message.signature = f"sig_{message.nonce}_{random.randint(1, 1000)}"
        self.message_queue.append(message)
        if self.verbose:
            logger.info(
                f"Sent message nonce {message.nonce} from chain {message.source_chain} to {message.target_chain}"
            )
        return message.signature

    def process_messages(self, batch_size: int = 10) -> Dict[str, Any]:
        """Process pending messages with consensus simulation"""
        processed = []
        failed = []
        self.chains[
            self.message_queue[0].target_chain
        ].block_number += 1  # Advance block

        for i, message in enumerate(self.message_queue[:batch_size]):
            try:
                # Simulate consensus: require majority validators
                if self._simulate_consensus(message):
                    result = self._process_single_message(message)
                    processed.append(result)
                    self.processed_messages[message.nonce] = True
                    # Update TVL
                    self.chains[
                        message.target_chain
                    ].total_value_locked += message.payload.get("amount", 0)
                else:
                    failed.append({"message": message, "error": "Consensus failed"})
            except Exception as e:
                failed.append({"message": message, "error": str(e)})
                logger.warning(f"Message {message.nonce} failed: {e}")

        # Remove processed
        self.message_queue = [
            m for m in self.message_queue if m.nonce not in self.processed_messages
        ]

        return {
            "processed": processed,
            "failed": failed,
            "consensus_success_rate": len(processed) / (len(processed) + len(failed))
            if processed or failed
            else 0,
        }

    def _simulate_consensus(self, message: CrossChainMessage) -> bool:
        """Simulate validator consensus for message processing"""
        target_chain = self.chains[message.target_chain]
        required_signatures = len(target_chain.validators) // 2 + 1  # Majority
        simulated_signatures = random.randint(1, len(target_chain.validators))
        return simulated_signatures >= required_signatures

    def _process_single_message(self, message: CrossChainMessage) -> Dict[str, Any]:
        """Enhanced processing with state updates and validation"""
        target_chain = self.chains.get(message.target_chain)
        if not target_chain:
            raise ValueError(f"Target chain {message.target_chain} not found")

        target_contract = target_chain.contracts.get(message.target_contract)
        if not target_contract:
            raise ValueError(f"Target contract {message.target_contract} not found")

        # Validate signature and proof (simplified)
        if not self._validate_message(message):
            raise ValueError("Invalid message signature or proof")

        # Check nonce order
        if message.nonce != target_contract["state"].get("last_nonce", -1) + 1:
            raise ValueError("Out of order nonce")

        # Update state
        target_contract["state"]["last_nonce"] = message.nonce
        target_contract["balance"] += message.payload.get("amount", 0)
        target_contract["state"]["processed_messages"] = (
            target_contract["state"].get("processed_messages", 0) + 1
        )

        # Simulate payload execution (e.g., mint tokens)
        amount = message.payload.get("amount", 0)
        logger.info(
            f"Processed message {message.nonce}: Minted {amount} on chain {message.target_chain}"
        )

        message.status = "processed"
        self.messages.append(asdict(message))

        return {
            "message": asdict(message),
            "target_chain": message.target_chain,
            "target_contract": message.target_contract,
            "processed": True,
            "state_changes": {"balance_increase": amount, "nonce": message.nonce},
        }

    def _validate_message(self, message: CrossChainMessage) -> bool:
        """Validate message integrity"""
        # Check signature (mock)
        if message.signature is None:
            return False
        # Check merkle proof (simplified)
        if message.merkle_proof and message.merkle_proof.get("root") == "0":
            return False  # Nomad-like invalid root
        return True

    def simulate_attack(self, attack_type: AttackType, **kwargs) -> Dict[str, Any]:
        """Enhanced attack simulation with PoC and historical replay"""
        attack_info = self.historical_attacks.get(attack_type.value, {})
        attack_results = {
            "attack_type": attack_type.value,
            "description": attack_info.get("description", "Custom attack"),
            "historical_date": attack_info.get("date", "N/A"),
            "success": False,
            "details": {},
            "exploited_amount": 0,
            "poc_code": self._generate_poc(attack_type, **kwargs),
            "mitigation": self._suggest_mitigation(attack_type),
        }

        if attack_type == AttackType.NOMAD_CONFIRMAT_ZERO:
            attack_results = self._enhanced_nomad_attack(**kwargs)
        elif attack_type == AttackType.QUBIT_LEGACY_FUNCTION:
            attack_results = self._enhanced_qubit_attack(**kwargs)
        elif attack_type == AttackType.MESSAGE_REPLAY:
            attack_results = self._enhanced_replay_attack(**kwargs)
        elif attack_type == AttackType.INVALID_SIGNATURE:
            attack_results = self._enhanced_signature_attack(**kwargs)
        elif attack_type == AttackType.OUT_OF_ORDER_PROCESSING:
            attack_results = self._out_of_order_attack(**kwargs)
        elif attack_type == AttackType.VALIDATOR_COMPROMISE:
            attack_results = self._validator_compromise_attack(**kwargs)
        elif attack_type == AttackType.DEFAULT_MAPPING_EXPLOIT:
            attack_results = self._default_mapping_attack(**kwargs)

        self.attack_history.append(attack_results)
        if attack_results["success"]:
            logger.warning(
                f"Attack {attack_type.value} succeeded! Potential vulnerability."
            )
        else:
            logger.info(f"Attack {attack_type.value} prevented.")

        return attack_results

    def _enhanced_nomad_attack(self, **kwargs) -> Dict[str, Any]:
        """Enhanced Nomad attack with root=0 and default confirmAt true"""
        chain_id = kwargs.get("chain_id", 1)
        contract_address = kwargs.get("contract_address", "0xbridge1")
        amount = kwargs.get("amount", 1000000)

        contract = self.chains[chain_id].contracts.get(contract_address)
        if contract:
            # Set vulnerability: confirmAt[0] defaults to true
            contract["state"]["confirmAt"] = {0: True}  # Default mapping exploit

            # Create fake message with root=0
            fake_message = CrossChainMessage(
                source_chain=chain_id + 1,
                target_chain=chain_id,
                sender="0xattacker",
                target_contract=contract_address,
                payload={"amount": amount, "root": 0, "token": "0xusdt"},
                nonce=0,  # Replay zero nonce
            )

            try:
                # Bypass validation due to default
                result = self._process_single_message(fake_message)
                return {
                    **self._base_attack_result(
                        AttackType.NOMAD_CONFIRMAT_ZERO.value, amount
                    ),
                    "success": True,
                    "details": "Bypassed validation using root=0 and default confirmAt[0]=true",
                    "poc_steps": [
                        "Set root=0 in message",
                        "Default mapping allows processing without confirmation",
                    ],
                }
            except Exception as e:
                return {
                    **self._base_attack_result(
                        AttackType.NOMAD_CONFIRMAT_ZERO.value, 0
                    ),
                    "success": False,
                    "details": f"Attack blocked: {str(e)}",
                }
        return self._base_attack_result(
            AttackType.NOMAD_CONFIRMAT_ZERO.value,
            0,
            success=False,
            details="Contract not found",
        )

    def _enhanced_qubit_attack(self, **kwargs) -> Dict[str, Any]:
        """Enhanced Qubit attack using legacy function with address(0)"""
        chain_id = kwargs.get("chain_id", 1)
        contract_address = kwargs.get("contract_address", "0xbridge1")
        amount = kwargs.get("amount", 1000000)

        contract = self.chains[chain_id].contracts.get(contract_address)
        if contract:
            # Simulate legacy deposit call with invalid token
            legacy_payload = {
                "token": "0x0000000000000000000000000000000000000000",  # Address zero
                "amount": amount,
                "legacy_mode": True,
            }

            # Vulnerability: Legacy function mints without lock check
            contract["state"]["total_minted"] = (
                contract["state"].get("total_minted", 0) + amount
            )
            contract["balance"] += amount  # Unauthorized mint

            return {
                **self._base_attack_result(
                    AttackType.QUBIT_LEGACY_FUNCTION.value, amount
                ),
                "success": True,
                "details": "Legacy deposit function minted tokens without proper locking or validation",
                "poc_steps": [
                    "Call legacy deposit with token=address(0)",
                    "Bypass new validation logic",
                ],
            }
        return self._base_attack_result(
            AttackType.QUBIT_LEGACY_FUNCTION.value,
            0,
            success=False,
            details="Contract not found",
        )

    def _enhanced_replay_attack(self, **kwargs) -> Dict[str, Any]:
        """Enhanced replay with nonce manipulation"""
        original_message = kwargs.get("message")
        if not original_message:
            # Create sample message
            original_message = CrossChainMessage(
                source_chain=1,
                target_chain=2,
                sender="0xuser",
                target_contract="0xbridge2",
                payload={"amount": 1000},
                nonce=42,
            )
            self.send_message(original_message)

        amount = original_message.payload.get("amount", 0)
        try:
            # Process original
            result1 = self._process_single_message(original_message)
            # Replay same message (ignore nonce check for vuln sim)
            replay_message = deepcopy(original_message)
            replay_message.nonce = original_message.nonce  # Same nonce for replay
            result2 = self._process_single_message(replay_message)
            return {
                **self._base_attack_result(AttackType.MESSAGE_REPLAY.value, amount * 2),
                "success": True,
                "details": "Replayed message with same nonce, double-minted",
                "poc_steps": [
                    "Capture valid message",
                    "Replay with same nonce before nonce update",
                ],
            }
        except Exception as e:
            return {
                **self._base_attack_result(AttackType.MESSAGE_REPLAY.value, 0),
                "success": False,
                "details": f"Replay prevented by nonce check: {str(e)}",
            }

    def _enhanced_signature_attack(self, **kwargs) -> Dict[str, Any]:
        """Enhanced invalid signature with forged proof"""
        chain_id = kwargs.get("chain_id", 1)
        contract_address = kwargs.get("contract_address", "0xbridge1")
        amount = kwargs.get("amount", 1000)

        fake_message = CrossChainMessage(
            source_chain=chain_id + 1,
            target_chain=chain_id,
            sender="0xattacker",
            target_contract=contract_address,
            payload={"amount": amount},
            nonce=999,
            signature="0xinvalid_sig",
            merkle_proof={"root": "0xinvalid_root", "proof": []},
        )

        try:
            # If validation weak, process
            if "weak_validation" in kwargs:  # Simulate vuln
                result = self._process_single_message(fake_message)
                return {
                    **self._base_attack_result(
                        AttackType.INVALID_SIGNATURE.value, amount
                    ),
                    "success": True,
                    "details": "Processed message with invalid signature and proof",
                    "poc_steps": [
                        "Forge invalid signature",
                        "Use weak ecrecover or no check",
                    ],
                }
            else:
                raise ValueError("Invalid signature")
        except Exception as e:
            return {
                **self._base_attack_result(AttackType.INVALID_SIGNATURE.value, 0),
                "success": False,
                "details": f"Signature validation blocked: {str(e)}",
            }

    def _out_of_order_attack(self, **kwargs) -> Dict[str, Any]:
        """Simulate out-of-order message processing"""
        chain_id = kwargs.get("chain_id", 1)
        contract_address = kwargs.get("contract_address", "0xbridge1")
        amount = kwargs.get("amount", 1000)

        # Send messages out of order
        msg1 = CrossChainMessage(
            source_chain=chain_id + 1,
            target_chain=chain_id,
            sender="0xuser",
            target_contract=contract_address,
            payload={"amount": amount},
            nonce=2,
        )
        msg2 = CrossChainMessage(
            source_chain=chain_id + 1,
            target_chain=chain_id,
            sender="0xuser",
            target_contract=contract_address,
            payload={"amount": amount},
            nonce=1,
        )
        self.send_message(msg1)  # Nonce 0 (auto)
        self.send_message(msg2)  # Nonce 1

        try:
            # Process out of order if vuln
            if "no_order_check" in kwargs:
                self.process_messages()
                return {
                    **self._base_attack_result(
                        AttackType.OUT_OF_ORDER_PROCESSING.value, amount * 2
                    ),
                    "success": True,
                    "details": "Processed out-of-order messages, potential double-spend",
                    "poc_steps": [
                        "Send nonce 2 first, then 1",
                        "Process without strict ordering",
                    ],
                }
            else:
                raise ValueError("Out of order detected")
        except Exception as e:
            return {
                **self._base_attack_result(AttackType.OUT_OF_ORDER_PROCESSING.value, 0),
                "success": False,
                "details": f"Order check prevented: {str(e)}",
            }

    def _validator_compromise_attack(self, **kwargs) -> Dict[str, Any]:
        """Simulate validator compromise for consensus bypass"""
        chain_id = kwargs.get("chain_id", 1)
        compromised_count = kwargs.get("compromised_validators", 3)
        amount = kwargs.get("amount", 1000)

        target_chain = self.chains[chain_id]
        if compromised_count >= len(target_chain.validators) // 2 + 1:
            fake_message = CrossChainMessage(
                source_chain=chain_id + 1,
                target_chain=chain_id,
                sender="0xcompromised",
                target_contract=kwargs.get("contract_address", "0xbridge1"),
                payload={"amount": amount},
                nonce=1,
            )
            try:
                # Bypass consensus
                result = self._process_single_message(fake_message)
                return {
                    **self._base_attack_result(
                        AttackType.VALIDATOR_COMPROMISE.value, amount
                    ),
                    "success": True,
                    "details": f"Compromised {compromised_count} validators bypassed consensus",
                    "poc_steps": [
                        "Compromise majority validators",
                        "Forge signatures for fake message",
                    ],
                }
            except Exception as e:
                return {
                    **self._base_attack_result(
                        AttackType.VALIDATOR_COMPROMISE.value, 0
                    ),
                    "success": False,
                    "details": f"Consensus held: {str(e)}",
                }
        return self._base_attack_result(
            AttackType.VALIDATOR_COMPROMISE.value,
            0,
            success=False,
            details="Insufficient compromised validators",
        )

    def _default_mapping_attack(self, **kwargs) -> Dict[str, Any]:
        """Simulate default mapping exploit (e.g., uninitialized confirmAt)"""
        chain_id = kwargs.get("chain_id", 1)
        contract_address = kwargs.get("contract_address", "0xbridge1")
        amount = kwargs.get("amount", 1000)

        contract = self.chains[chain_id].contracts.get(contract_address)
        if contract and 0 not in contract["state"].get("confirmAt", {}):
            # Default mapping allows key 0 to be true/unchecked
            contract["state"]["confirmAt"][0] = True  # Vuln default

            fake_message = CrossChainMessage(
                source_chain=chain_id + 1,
                target_chain=chain_id,
                sender="0xattacker",
                target_contract=contract_address,
                payload={"amount": amount, "key": 0},
                nonce=0,
            )

            try:
                result = self._process_single_message(fake_message)
                return {
                    **self._base_attack_result(
                        AttackType.DEFAULT_MAPPING_EXPLOIT.value, amount
                    ),
                    "success": True,
                    "details": "Default mapping value allowed unauthorized processing",
                    "poc_steps": [
                        "Use key=0 for uninitialized mapping",
                        "Assume default true for confirmation",
                    ],
                }
            except Exception as e:
                return {
                    **self._base_attack_result(
                        AttackType.DEFAULT_MAPPING_EXPLOIT.value, 0
                    ),
                    "success": False,
                    "details": f"Mapping check prevented: {str(e)}",
                }
        return self._base_attack_result(
            AttackType.DEFAULT_MAPPING_EXPLOIT.value,
            0,
            success=False,
            details="Contract not found",
        )

    def _base_attack_result(
        self, attack_type: str, amount: int, success: bool = True, details: str = ""
    ) -> Dict:
        """Base structure for attack results"""
        return {
            "attack_type": attack_type,
            "success": success,
            "details": details,
            "exploited_amount": amount if success else 0,
        }

    def _generate_poc(self, attack_type: AttackType, **kwargs) -> str:
        """Generate PoC code snippet for the attack"""
        poc_templates = {
            AttackType.NOMAD_CONFIRMAT_ZERO.value: """
// Nomad PoC
function exploitNomad() public {
    // Send message with root = 0
    bridge.processMessage(0, abi.encode(amount, token), 0); // root=0 bypasses
    // Withdraw minted tokens
}
            """,
            AttackType.QUBIT_LEGACY_FUNCTION.value: """
// Qubit PoC
function exploitQubit() public {
    // Call legacy deposit with address(0)
    legacyDeposit(address(0), amount);
    // Tokens minted without lock
}
            """,
        }
        return poc_templates.get(
            attack_type.value, "// Generic PoC\n// Implement attack logic here"
        )

    def _suggest_mitigation(self, attack_type: AttackType) -> str:
        """Suggest mitigations for the attack"""
        mitigations = {
            AttackType.NOMAD_CONFIRMAT_ZERO.value: "Initialize mappings with false; validate root != 0; use non-zero defaults",
            AttackType.QUBIT_LEGACY_FUNCTION.value: "Remove or disable legacy functions; add version checks; migrate all users",
        }
        return mitigations.get(attack_type.value, "Add proper validation and checks")

    def replay_historical_attack(
        self, attack_name: str, chain_id: int = 1, scale: float = 1.0
    ) -> Dict[str, Any]:
        """Replay a historical attack with scaled parameters"""
        if attack_name not in self.historical_attacks:
            return {"error": "Unknown attack"}

        hist = self.historical_attacks[attack_name]
        amount = int(hist.get("amount_exploited", 0) * scale)
        attack_type = (
            AttackType(attack_name.replace("_", "").upper())
            if attack_name in [a.value for a in AttackType]
            else AttackType.NOMAD_CONFIRMAT_ZERO
        )

        # Setup for replay
        self.add_chain(
            chain_id,
            ChainType.NOMAD_TESTNET
            if "nomad" in attack_name.lower()
            else ChainType.QUBIT_TESTNET,
        )
        self.deploy_contract(chain_id, "0xbridge", "// Bridge code with vuln")

        # Run simulation
        result = self.simulate_attack(attack_type, chain_id=chain_id, amount=amount)
        result["historical_replay"] = True
        result["original_amount"] = hist.get("amount_exploited", 0)
        result["scaled_amount"] = amount

        logger.info(
            f"Replayed {attack_name}: Success {result['success']}, Exploited {amount}"
        )
        return result

    def get_simulation_report(self, include_pocs: bool = True) -> Dict[str, Any]:
        """Enhanced report with attack history and mitigations"""
        report = {
            "chains": {cid: asdict(state) for cid, state in self.chains.items()},
            "messages_processed": len(self.messages),
            "messages_pending": len(self.message_queue),
            "attacks_simulated": self.attack_history,
            "vulnerabilities_found": [a for a in self.attack_history if a["success"]],
            "tvl_summary": {
                cid: state.total_value_locked for cid, state in self.chains.items()
            },
            "recommendations": [
                "Implement strict nonce ordering",
                "Validate all signatures and proofs",
                "Initialize mappings properly",
            ],
        }

        if include_pocs:
            report["pocs"] = {
                a["attack_type"]: a["poc_code"] for a in self.attack_history
            }

        return report

    def run_full_bridge_test(
        self, num_messages: int = 100, attack_probability: float = 0.1
    ) -> Dict[str, Any]:
        """Run full simulation test with random attacks"""
        # Setup multi-chain
        for i, chain_type in enumerate(
            [ChainType.ETHEREUM, ChainType.BSC, ChainType.POLYGON]
        ):
            self.add_chain(i + 1, chain_type)
            self.deploy_contract(i + 1, f"0xbridge{i + 1}", "// Bridge contract")

        # Send random messages
        for _ in range(num_messages):
            src = random.randint(1, 3)
            tgt = random.randint(1, 3)
            if src != tgt:
                msg = CrossChainMessage(
                    source_chain=src,
                    target_chain=tgt,
                    sender=f"0xuser{random.randint(1, 10)}",
                    target_contract=f"0xbridge{tgt}",
                    payload={"amount": random.randint(100, 10000), "token": "USDC"},
                    nonce=i,
                )
                self.send_message(msg)

                # Random attack
                if random.random() < attack_probability:
                    attack = random.choice(list(AttackType))
                    self.simulate_attack(attack, chain_id=tgt)

        # Process all
        while self.message_queue:
            self.process_messages()

        return self.get_simulation_report()


# Example usage and enhanced demo
def run_enhanced_bridge_simulation():
    """Demonstrate enhanced simulation with historical replay"""
    simulator = BridgeSimulator(verbose=True)

    # Multi-chain setup
    simulator.add_chain(1, ChainType.ETHEREUM)
    simulator.add_chain(137, ChainType.POLYGON)
    for chain_id in [1, 137]:
        simulator.deploy_contract(chain_id, "0xbridge", "// Vulnerable bridge code")

    # Replay historical attacks
    nomad_replay = simulator.replay_historical_attack(
        "nomad_confirmat_zero", chain_id=1
    )
    qubit_replay = simulator.replay_historical_attack(
        "qubit_legacy_function", chain_id=137, scale=0.1
    )  # Scaled down

    # Run custom attacks
    out_of_order = simulator.simulate_attack(
        AttackType.OUT_OF_ORDER_PROCESSING, chain_id=1
    )
    validator_comp = simulator.simulate_attack(
        AttackType.VALIDATOR_COMPROMISE, chain_id=137, compromised_validators=3
    )

    # Full test
    full_test = simulator.run_full_bridge_test(num_messages=50, attack_probability=0.2)

    report = simulator.get_simulation_report(include_pocs=True)
    report["historical_replays"] = [nomad_replay, qubit_replay]
    report["custom_attacks"] = [out_of_order, validator_comp]
    report["full_test"] = full_test

    # Save report
    with open("cross_chain_report.json", "w") as f:
        json.dump(report, f, indent=2)

    logger.info("Enhanced simulation complete. Check cross_chain_report.json")
    return report


if __name__ == "__main__":
    report = run_enhanced_bridge_simulation()
    print(json.dumps(report, indent=2, default=str))
