#!/usr/bin/env python3
"""
Economic Invariant Detector - Elite-tier vulnerability detection

Detects:
- Vuln #10: Economic rounding and share math drift
- Vuln #22: Invariant dependence on external token supply/LP tokens
- Vuln #28: Token-wrapped accounting mismatches
- Vuln #33: Business-logic prisoner's dilemma (game-theoretic exploits)

Author: Elite Web3 Bug Hunter
Category: Economic & Game Theory Vulnerabilities
"""

import re
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from base_elite_detector import (
    EliteDetector,
    VulnerabilityFinding,
    Severity,
    Confidence,
    SolidityParser,
    ContractInfo,
)


class EconomicInvariantDetector(EliteDetector):
    """
    Detects economic and game-theoretic vulnerabilities

    Covers:
    1. Rounding errors in share calculations enabling profit extraction
    2. External dependencies (LP tokens, rebasing tokens) breaking invariants
    3. Wrapper token exchange rate drift
    4. Game-theoretic exploits (rational attacker strategies)
    """

    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.vault_contracts: List[ContractInfo] = []
        self.wrapper_contracts: List[ContractInfo] = []

    def get_detector_name(self) -> str:
        return "economic_invariant"

    def get_vulnerability_ids(self) -> List[str]:
        return [
            "ROUNDING_DRIFT_001",
            "EXTERNAL_SUPPLY_001",
            "WRAPPER_MISMATCH_001",
            "GAME_THEORY_001",
        ]

    def detect(self, target_path: Path) -> List[VulnerabilityFinding]:
        """Main detection logic"""
        self.findings = []

        if target_path.is_file():
            self._analyze_file(target_path)
        else:
            for sol_file in self.scan_directory(target_path):
                self._analyze_file(sol_file)

        return self.findings

    def _analyze_file(self, file_path: Path) -> None:
        """Analyze a single Solidity file"""
        source = self.load_contract(file_path)
        if not source:
            return

        contracts = self.parse_contracts(source, str(file_path))

        for contract in contracts:
            if contract.is_interface or contract.is_library:
                continue

            # Classify contract type
            is_vault = self._is_vault_contract(contract)
            is_wrapper = self._is_wrapper_contract(contract)

            if is_vault:
                self.vault_contracts.append(contract)
            if is_wrapper:
                self.wrapper_contracts.append(contract)

            # Detect rounding errors in share calculations
            self._detect_rounding_vulnerabilities(contract)

            # Detect external supply dependencies
            self._detect_external_supply_dependencies(contract)

            # Detect wrapper accounting mismatches
            self._detect_wrapper_accounting_issues(contract)

            # Detect game-theoretic exploits
            self._detect_game_theory_exploits(contract)

    def _is_vault_contract(self, contract: ContractInfo) -> bool:
        """Check if contract is a vault/pool with share calculations"""
        vault_keywords = [
            "vault",
            "pool",
            "shares",
            "deposit",
            "withdraw",
            "totalShares",
            "totalAssets",
        ]
        source = contract.source_code or ""
        return any(keyword.lower() in source.lower() for keyword in vault_keywords)

    def _is_wrapper_contract(self, contract: ContractInfo) -> bool:
        """Check if contract wraps tokens (e.g., WETH, wrapped staking tokens)"""
        wrapper_keywords = [
            "wrap",
            "unwrap",
            "deposit",
            "withdraw",
            "exchangeRate",
            "convertTo",
        ]
        source = contract.source_code or ""
        return any(keyword.lower() in source.lower() for keyword in wrapper_keywords)

    def _detect_rounding_vulnerabilities(self, contract: ContractInfo) -> None:
        """
        Detect rounding errors in share math (Vuln #10)

        Pattern:
        1. Division operations in share calculations
        2. Integer division causing truncation
        3. Repeated operations accumulating drift
        """
        for func in contract.functions:
            func_body = func.get("body", "")

            # Look for share calculation patterns
            share_patterns = [
                r"(\w+)\s*=\s*\([^)]*\)\s*/\s*totalAssets",
                r"(\w+)\s*=\s*\([^)]*\)\s*/\s*totalShares",
                r"shares?\s*=\s*[^;]*\/",
                r"amount\s*=\s*[^;]*\/",
            ]

            has_division = any(
                re.search(pattern, func_body) for pattern in share_patterns
            )

            if not has_division:
                continue

            # Check for vulnerable patterns
            vulnerabilities = self._analyze_rounding_pattern(func_body, contract, func)

            for vuln in vulnerabilities:
                self._add_finding(
                    vulnerability_id="ROUNDING_DRIFT_001",
                    severity=vuln["severity"],
                    confidence=vuln["confidence"],
                    title=f"Rounding vulnerability in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' performs {vuln['operation']} with integer division. "
                        f"{vuln['issue']} This enables profitable rounding attacks where attackers "
                        f"can extract value through repeated small operations or inflation/deflation attacks."
                    ),
                    category="rounding_exploit",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    vulnerable_code=func_body[:400],
                    attack_vector=(
                        f"1. Attacker identifies rounding direction (up/down)\n"
                        f"2. {vuln['attack_step_2']}\n"
                        f"3. Repeated operations accumulate drift in attacker's favor\n"
                        f"4. Attacker withdraws more than deposited or manipulates share price"
                    ),
                    proof_of_concept=self._generate_rounding_poc(
                        contract.name, func["name"], vuln["poc_type"]
                    ),
                    remediation=(
                        f"1. Use higher precision (multiply by 1e18 before division)\n"
                        f"2. Add minimum deposit/withdrawal amounts\n"
                        f"3. Implement anti-inflation guards (virtual shares/assets)\n"
                        f"4. Consider rounding in protocol's favor consistently\n"
                        f"5. {vuln['specific_fix']}"
                    ),
                    economic_impact=vuln["economic_impact"],
                    exploitability="medium",
                    attack_complexity="low",
                    requires_flash_loan=vuln.get("requires_flash_loan", False),
                    requires_multi_tx=vuln.get("requires_multi_tx", True),
                    novelty="very_high",
                    rarity="rare",
                    human_only=True,
                )

    def _analyze_rounding_pattern(
        self, func_body: str, contract: ContractInfo, func: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze specific rounding vulnerability patterns"""
        vulnerabilities = []

        # Pattern 1: shares = (assets * totalShares) / totalAssets
        if re.search(r"shares?\s*=\s*\([^)]*\*[^)]*\)\s*/\s*totalAssets", func_body):
            # Check if there's protection against first depositor inflation
            has_virtual_shares = (
                "virtual" in func_body.lower() or "_DEAD_SHARES" in func_body
            )

            if not has_virtual_shares:
                vulnerabilities.append(
                    {
                        "operation": "share minting calculation",
                        "issue": "First depositor can inflate share price by donating assets directly to vault.",
                        "attack_step_2": "Make tiny first deposit (1 wei), donate large amount to vault",
                        "poc_type": "inflation",
                        "specific_fix": "Use virtual shares (like Uniswap V2) or burn first shares",
                        "severity": Severity.HIGH.value,
                        "confidence": Confidence.HIGH.value,
                        "economic_impact": "high",
                        "requires_flash_loan": True,
                    }
                )

        # Pattern 2: assets = (shares * totalAssets) / totalShares
        if re.search(
            r"(assets?|amount)\s*=\s*\([^)]*\*[^)]*\)\s*/\s*totalShares", func_body
        ):
            vulnerabilities.append(
                {
                    "operation": "asset redemption calculation",
                    "issue": "Rounding down in withdrawals allows repeated deposit-withdraw to extract value.",
                    "attack_step_2": "Repeatedly deposit and withdraw tiny amounts",
                    "poc_type": "grinding",
                    "specific_fix": "Round in favor of vault (round down on withdraw)",
                    "severity": Severity.MEDIUM.value,
                    "confidence": Severity.MEDIUM.value,
                    "economic_impact": "medium",
                    "requires_flash_loan": False,
                    "requires_multi_tx": True,
                }
            )

        # Pattern 3: Any division without clear precision handling
        if "/" in func_body and "1e18" not in func_body and "1e6" not in func_body:
            vulnerabilities.append(
                {
                    "operation": "division operation",
                    "issue": "Integer division without precision multiplier causes truncation.",
                    "attack_step_2": "Exploit truncation by timing operations or using specific amounts",
                    "poc_type": "truncation",
                    "specific_fix": "Multiply by precision constant (1e18) before division",
                    "severity": Severity.MEDIUM.value,
                    "confidence": Confidence.MEDIUM.value,
                    "economic_impact": "medium",
                    "requires_flash_loan": False,
                }
            )

        return vulnerabilities

    def _detect_external_supply_dependencies(self, contract: ContractInfo) -> None:
        """
        Detect external supply dependencies (Vuln #22)

        Pattern:
        1. Contract logic depends on external token.totalSupply()
        2. External contract can mint/burn, changing supply
        3. Breaks invariants in dependent contract
        """
        for func in contract.functions:
            func_body = func.get("body", "")

            # Look for totalSupply() calls on external tokens
            external_supply_patterns = [
                r"(\w+)\.totalSupply\(\)",
                r"IERC20\([^)]+\)\.totalSupply\(\)",
                r"lpToken\.totalSupply\(\)",
            ]

            uses_external_supply = any(
                re.search(pattern, func_body) for pattern in external_supply_patterns
            )

            if not uses_external_supply:
                continue

            # Check if used in critical calculations
            is_critical = self._is_critical_calculation(func_body)

            if is_critical:
                self._add_finding(
                    vulnerability_id="EXTERNAL_SUPPLY_001",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    title=f"External supply dependency in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' depends on external token totalSupply() for "
                        f"critical calculations. External contracts can mint/burn tokens, changing "
                        f"supply and breaking this contract's invariants. This enables manipulation "
                        f"of share prices, valuations, or reward distributions."
                    ),
                    category="external_supply_dependency",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    vulnerable_code=func_body[:400],
                    attack_vector=(
                        "1. Contract calculates value based on external token.totalSupply()\n"
                        "2. Attacker mints/burns external tokens (if permissioned) or influences mint\n"
                        "3. TotalSupply changes, breaking assumptions\n"
                        "4. Share price, rewards, or valuations are manipulated\n"
                        "5. Attacker profits from the discrepancy"
                    ),
                    proof_of_concept=self._generate_external_supply_poc(
                        contract.name, func["name"]
                    ),
                    remediation=(
                        "1. Don't depend on external mutable state for invariants\n"
                        "2. Track internal accounting instead of relying on totalSupply\n"
                        "3. Use snapshots or TWAP for supply readings\n"
                        "4. Validate supply hasn't changed unexpectedly\n"
                        "5. Consider rebasing tokens and their supply dynamics"
                    ),
                    economic_impact="high",
                    exploitability="medium",
                    attack_complexity="medium",
                    requires_flash_loan=False,
                    requires_multi_tx=True,
                    novelty="high",
                    rarity="uncommon",
                    human_only=True,
                )

    def _is_critical_calculation(self, func_body: str) -> bool:
        """Check if function performs critical financial calculations"""
        critical_keywords = [
            "shares",
            "price",
            "value",
            "reward",
            "rate",
            "ratio",
            "deposit",
            "withdraw",
            "mint",
            "burn",
            "redeem",
        ]
        return any(keyword in func_body.lower() for keyword in critical_keywords)

    def _detect_wrapper_accounting_issues(self, contract: ContractInfo) -> None:
        """
        Detect wrapper accounting mismatches (Vuln #28)

        Pattern:
        1. Contract wraps/unwraps tokens
        2. Assumes 1:1 exchange rate or uses cached rate
        3. Actual rate can drift (rebasing, yield-bearing tokens)
        """
        for func in contract.functions:
            func_name = func["name"]
            func_body = func.get("body", "")

            # Check for wrap/unwrap functions
            is_wrap_func = any(
                keyword in func_name.lower()
                for keyword in ["wrap", "deposit", "mint", "stake"]
            )
            is_unwrap_func = any(
                keyword in func_name.lower()
                for keyword in ["unwrap", "withdraw", "redeem", "unstake"]
            )

            if not (is_wrap_func or is_unwrap_func):
                continue

            # Check for 1:1 assumption (no rate conversion)
            has_rate_conversion = any(
                pattern in func_body
                for pattern in ["exchangeRate", "convertTo", "getRate", "rate()"]
            )

            # Check for balance tracking
            tracks_internal_balance = any(
                re.search(pattern, func_body)
                for pattern in [r"balance\[", r"deposits\[", r"totalDeposited"]
            )

            if tracks_internal_balance and not has_rate_conversion:
                self._add_finding(
                    vulnerability_id="WRAPPER_MISMATCH_001",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.HIGH.value,
                    title=f"Wrapper accounting mismatch in {contract.name}.{func_name}",
                    description=(
                        f"Function '{func_name}' tracks balances internally but doesn't account "
                        f"for exchange rate changes in wrapped tokens. If underlying token is "
                        f"rebasing, yield-bearing, or fee-on-transfer, internal accounting will "
                        f"diverge from actual balances, enabling theft or DOS."
                    ),
                    category="wrapper_accounting",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func_name],
                    vulnerable_code=func_body[:400],
                    attack_vector=(
                        "1. Contract assumes 1:1 wrapping without rate conversion\n"
                        "2. Underlying token rebases or accrues yield\n"
                        "3. Internal accounting diverges from actual balances\n"
                        "4. First withdrawer drains excess, or all users can't withdraw\n"
                        "5. Loss of funds or DOS"
                    ),
                    proof_of_concept=self._generate_wrapper_mismatch_poc(
                        contract.name, func_name
                    ),
                    remediation=(
                        "1. Always use actual balance checks: balanceOf(address(this))\n"
                        "2. Track internal accounting in shares, not tokens\n"
                        "3. Support tokens with dynamic balances explicitly\n"
                        "4. Use before/after balance checks for transfers\n"
                        "5. Document which token types are supported"
                    ),
                    economic_impact="critical",
                    exploitability="high",
                    attack_complexity="low",
                    requires_flash_loan=False,
                    requires_multi_tx=False,
                    novelty="high",
                    rarity="uncommon",
                    human_only=True,
                )

    def _detect_game_theory_exploits(self, contract: ContractInfo) -> None:
        """
        Detect game-theoretic exploits (Vuln #33)

        Pattern:
        1. Multi-user incentive systems (staking, rewards, auctions)
        2. First-mover or last-mover advantages
        3. Rational collusion or exit strategies
        """
        # Look for reward/incentive mechanisms
        has_rewards = any(
            var["name"].lower() in ["rewards", "reward", "incentive", "bonus"]
            for var in contract.state_variables
        )

        has_staking = any(
            var["name"].lower() in ["stake", "staked", "stakes", "deposits"]
            for var in contract.state_variables
        )

        has_distribution = any(
            func["name"].lower() in ["distribute", "claim", "harvest", "withdraw"]
            for func in contract.functions
        )

        if not (has_rewards or has_staking or has_distribution):
            return

        # Analyze distribution mechanism
        for func in contract.functions:
            func_name = func["name"].lower()
            func_body = func.get("body", "")

            # Check for distribution functions
            is_distribution = any(
                keyword in func_name
                for keyword in ["distribute", "claim", "harvest", "epoch", "round"]
            )

            if not is_distribution:
                continue

            # Look for game-theoretic vulnerabilities
            game_theory_issues = self._analyze_game_theory(func_body, contract, func)

            for issue in game_theory_issues:
                self._add_finding(
                    vulnerability_id="GAME_THEORY_001",
                    severity=issue["severity"],
                    confidence=issue["confidence"],
                    title=f"Game-theoretic exploit in {contract.name}.{func['name']}",
                    description=(
                        f"Function '{func['name']}' has {issue['issue_type']}. "
                        f"{issue['description']} Rational actors can {issue['exploitation']} "
                        f"to extract disproportionate value over time."
                    ),
                    category="game_theory_exploit",
                    file_path=contract.file_path,
                    line_numbers=[func["line"]],
                    affected_contracts=[contract.name],
                    affected_functions=[func["name"]],
                    vulnerable_code=func_body[:400],
                    attack_vector=issue["attack_vector"],
                    proof_of_concept=self._generate_game_theory_poc(
                        contract.name, func["name"], issue["issue_type"]
                    ),
                    remediation=issue["remediation"],
                    economic_impact="high",
                    exploitability="medium",
                    attack_complexity="high",
                    requires_flash_loan=False,
                    requires_multi_tx=True,
                    novelty="very_high",
                    rarity="extreme",
                    human_only=True,
                )

    def _analyze_game_theory(
        self, func_body: str, contract: ContractInfo, func: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze for game-theoretic vulnerabilities"""
        issues = []

        # Pattern 1: Proportional reward distribution
        if re.search(r"reward.*=.*stake.*\/.*totalStake", func_body):
            issues.append(
                {
                    "issue_type": "just-in-time staking advantage",
                    "description": (
                        "Rewards are distributed proportionally to current stake. "
                        "Rational actors can stake just before distribution and unstake after."
                    ),
                    "exploitation": "stake large amounts just before distribution, then immediately withdraw",
                    "attack_vector": (
                        "1. Monitor for upcoming reward distribution (predictable timing)\n"
                        "2. Flash loan or use large capital to stake just before distribution\n"
                        "3. Claim disproportionate rewards relative to time staked\n"
                        "4. Immediately unstake and repay loan\n"
                        "5. Repeat each epoch for risk-free profit"
                    ),
                    "remediation": (
                        "1. Implement minimum staking duration\n"
                        "2. Use time-weighted average stake for rewards\n"
                        "3. Add unstaking cooldown period\n"
                        "4. Penalize early withdrawal\n"
                        "5. Use snapshot-based rewards (past block)"
                    ),
                    "severity": Severity.HIGH.value,
                    "confidence": Confidence.HIGH.value,
                }
            )

        # Pattern 2: First/last mover advantage
        if "for" in func_body and re.search(r"(users|stakers|depositors)\[", func_body):
            issues.append(
                {
                    "issue_type": "sequential processing bias",
                    "description": (
                        "Users are processed sequentially in a loop. "
                        "Order-dependent processing creates first/last-mover advantages."
                    ),
                    "exploitation": "time transactions to be first/last in processing order",
                    "attack_vector": (
                        "1. Contract processes users in array order\n"
                        "2. Gas prices or mempool monitoring determine order\n"
                        "3. First user gets better exchange rate or depletes pool\n"
                        "4. Or last user benefits from accumulated state\n"
                        "5. Rational actors compete for favorable position"
                    ),
                    "remediation": (
                        "1. Use commit-reveal for fairness\n"
                        "2. Randomize processing order (VRF)\n"
                        "3. Make rewards order-independent\n"
                        "4. Batch process atomically with fair sharing\n"
                        "5. Use pro-rata distribution instead of sequential"
                    ),
                    "severity": Severity.MEDIUM.value,
                    "confidence": Confidence.MEDIUM.value,
                }
            )

        # Pattern 3: Exit race (last one out loses)
        has_exit = any(
            keyword in func_body.lower()
            for keyword in ["withdraw", "exit", "unstake", "redeem"]
        )
        has_decreasing_resource = (
            "totalRewards" in func_body or "remaining" in func_body
        )

        if has_exit and has_decreasing_resource:
            issues.append(
                {
                    "issue_type": "exit race condition",
                    "description": (
                        "Withdrawal function drains from limited pool. "
                        "Creates prisoner's dilemma where rational actors rush to exit."
                    ),
                    "exploitation": "monitor pool health and exit before others",
                    "attack_vector": (
                        "1. Pool has limited liquidity or declining value\n"
                        "2. Rational users recognize unsustainability\n"
                        "3. Each user's optimal strategy is to exit immediately\n"
                        "4. Bank run ensues, last users cannot withdraw\n"
                        "5. First movers profit, late movers lose everything"
                    ),
                    "remediation": (
                        "1. Ensure 1:1 backing or over-collateralization\n"
                        "2. Implement gradual withdrawal queues\n"
                        "3. Pro-rata distribution in shortfall scenarios\n"
                        "4. Circuit breakers to pause in crisis\n"
                        "5. Align incentives to discourage panic exits"
                    ),
                    "severity": Severity.CRITICAL.value,
                    "confidence": Confidence.MEDIUM.value,
                }
            )

        return issues

    # POC Generation Methods

    def _generate_rounding_poc(
        self, contract_name: str, func_name: str, poc_type: str
    ) -> str:
        """Generate POC for rounding exploits"""
        if poc_type == "inflation":
            return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {{
    function deposit(uint256 assets) external returns (uint256 shares);
    function donate(uint256 assets) external;
    function totalAssets() external view returns (uint256);
    function totalShares() external view returns (uint256);
}}

contract InflationAttack {{
    IVault vault;
    IERC20 asset;

    function attack() external {{
        // Step 1: Deposit 1 wei to get first shares
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(1); // Get 1 share

        // Step 2: Donate large amount to inflate share price
        // If donation goes directly to totalAssets without minting shares:
        vault.donate(1e18); // Now 1 share = 1e18 assets

        // Step 3: Next depositor gets rounded down to 0 shares
        // deposit(1e18 - 1) -> shares = (1e18-1) * 1 / 1e18 = 0 shares
        // Attacker steals depositor's funds

        // Step 4: Withdraw with inflated shares
        // withdraw(1 share) -> assets = 1 * 2e18 / 1 = 2e18 assets
        // Profit: 1e18 assets
    }}
}}
"""
        elif poc_type == "grinding":
            return f"""
// Grinding attack: Repeated small deposits/withdrawals to extract rounding errors
contract GrindingAttack {{
    IVault vault;

    function grind() external {{
        // Repeatedly deposit and withdraw to accumulate rounding errors
        for (uint i = 0; i < 1000; i++) {{
            uint shares = vault.deposit(1);  // Rounds down
            vault.withdraw(shares);  // Rounds down again
            // Each iteration: deposit 1, get 0 shares or get 1 share worth > 1 asset
        }}
    }}
}}
"""
        else:
            return f"""
// Truncation exploit: Use amounts that maximize rounding in attacker's favor
contract TruncationAttack {{
    function exploit(IVault vault) external {{
        // Find amounts where division truncates maximally
        // shares = (amount * totalShares) / totalAssets
        // Choose amount such that numerator < totalAssets
        // Result: get 0 shares but assets recorded
    }}
}}
"""

    def _generate_external_supply_poc(self, contract_name: str, func_name: str) -> str:
        """Generate POC for external supply dependency"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function calculateShare(address lpToken) external view returns (uint256);
}}

interface IMintableBurnable {{
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
    function totalSupply() external view returns (uint256);
}}

contract ExternalSupplyExploit {{
    IVulnerable target;
    IMintableBurnable lpToken;

    function attack() external {{
        // Step 1: Check current share calculation
        uint256 shareBefore = target.calculateShare(address(lpToken));

        // Step 2: If we can influence totalSupply (either directly or through governance)
        // Mint more tokens to dilute share calculations
        lpToken.mint(address(this), 1000e18);

        // Step 3: Share calculation now broken
        uint256 shareAfter = target.calculateShare(address(lpToken));
        // shareBefore != shareAfter, invariant broken

        // Step 4: Exploit the discrepancy
        // - Withdraw more than entitled
        // - Claim disproportionate rewards
        // - Manipulate price oracle that depends on supply
    }}
}}

// Mitigation: Don't trust external mutable state
contract SafeAlternative {{
    mapping(address => uint256) internal accountedSupply;

    function deposit(uint256 amount) external {{
        // Track internally instead of relying on external totalSupply
        accountedSupply[msg.sender] += amount;
    }}
}}
"""

    def _generate_wrapper_mismatch_poc(self, contract_name: str, func_name: str) -> str:
        """Generate POC for wrapper accounting mismatch"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRebasingToken {{
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function rebase() external; // Changes balances without transfers
}}

contract WrapperVulnerable {{
    IRebasingToken public underlying;
    mapping(address => uint256) public deposits; // BUG: Assumes 1:1

    function deposit(uint256 amount) external {{
        underlying.transfer(address(this), amount);
        deposits[msg.sender] += amount; // Tracks nominal amount
    }}

    function withdraw(uint256 amount) external {{
        deposits[msg.sender] -= amount;
        underlying.transfer(msg.sender, amount); // Assumes still available
    }}
}}

contract RebasingExploit {{
    function attack(WrapperVulnerable wrapper, IRebasingToken token) external {{
        // Setup: Multiple users deposit 100 tokens each
        // wrapper.deposits tracks: user1=100, user2=100 (total 200)
        // actual balance: 200 tokens

        // Step 1: Trigger negative rebase
        token.rebase(); // Balance drops to 150 tokens

        // Step 2: First withdrawer gets full amount
        wrapper.withdraw(100); // Success: gets 100 tokens

        // Step 3: Second withdrawer fails (only 50 left)
        // wrapper.withdraw(100) -> reverts, DOS

        // Or with positive rebase:
        // token.rebase() -> balance increases to 250
        // First withdrawer drains excess 50 tokens
    }}
}}

// Mitigation: Track shares, not nominal amounts
contract WrapperFixed {{
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function deposit(uint256 amount) external {{
        uint256 balBefore = underlying.balanceOf(address(this));
        underlying.transfer(address(this), amount);
        uint256 balAfter = underlying.balanceOf(address(this));

        uint256 actualDeposit = balAfter - balBefore;
        uint256 sharesToMint = totalShares == 0
            ? actualDeposit
            : (actualDeposit * totalShares) / balBefore;

        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
    }}
}}
"""

    def _generate_game_theory_poc(
        self, contract_name: str, func_name: str, issue_type: str
    ) -> str:
        """Generate POC for game-theoretic exploits"""
        return f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Game Theory Exploit: {issue_type}
// Rational actors can extract disproportionate value

contract GameTheoryExploit {{
    // Example: Just-in-time staking
    function jitStake(address stakingPool, uint256 amount) external {{
        // 1. Flash loan large amount
        // 2. Stake just before reward distribution
        // 3. Claim disproportionate rewards
        // 4. Unstake immediately
        // 5. Repay flash loan, keep profit
    }}
}}
"""


# CLI entry point
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python economic_invariant_detector.py <target_path> [--output output.json] [--verbose]"
        )
        sys.exit(1)

    target = Path(sys.argv[1])
    output = None
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if "--output" in sys.argv:
        output_idx = sys.argv.index("--output") + 1
        if output_idx < len(sys.argv):
            output = Path(sys.argv[output_idx])

    detector = EconomicInvariantDetector(verbose=verbose)
    findings = detector.detect(target)

    detector.print_summary()

    if output:
        detector.export_findings(output)
        print(f"✅ Results exported to {output}")

    sys.exit(0 if len(findings) == 0 else 1)
