// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRewardToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function notifyDeposit(address user, uint256 amount) external;
}

/**
 * @title VulnerablePool
 * @notice INTENTIONALLY VULNERABLE - For demonstration purposes only
 *
 * Vulnerabilities:
 * 1. Cross-contract reentrancy via notifyDeposit callback
 * 2. Privilege escalation - withdraw calls unprotected mint
 * 3. State inconsistency - totalDeposits vs token balances
 * 4. No reentrancy guard
 * 5. Flash loan attack vector
 */
contract VulnerablePool {
    IRewardToken public rewardToken;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public totalDeposits;
    uint256 public rewardRate = 100; // 1% per operation

    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);

    constructor(address _rewardToken) {
        rewardToken = IRewardToken(_rewardToken);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /**
     * @notice VULNERABLE: Cross-contract reentrancy
     * External call to notifyDeposit before state update
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");

        // VULNERABILITY: External call before state update
        rewardToken.notifyDeposit(msg.sender, msg.value);

        // State updates AFTER external call - classic reentrancy pattern
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;

        // Calculate rewards based on current totalDeposits
        uint256 reward = (msg.value * rewardRate) / 10000;
        rewards[msg.sender] += reward;

        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice VULNERABLE: Reads balance without protection
     * Can be exploited with flash loans to manipulate rewards
     */
    function calculateRewards(address user) public view returns (uint256) {
        // VULNERABILITY: Calculation based on ratio that can be manipulated
        uint256 userBalance = balances[user];
        if (totalDeposits == 0) return 0;

        uint256 poolShare = (userBalance * 10000) / totalDeposits;
        return poolShare * address(this).balance / 10000;
    }

    /**
     * @notice VULNERABLE: State change after external call
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Calculate and mint rewards - calls external contract
        uint256 reward = calculateRewards(msg.sender);

        // VULNERABILITY: External call to mint (user-controlled?)
        rewardToken.mint(msg.sender, reward);

        // State changes AFTER external call
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        // Transfer at the end
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdraw(msg.sender, amount);
    }

    /**
     * @notice VULNERABLE: No balance check
     */
    function claimRewards() external {
        uint256 reward = rewards[msg.sender];

        // VULNERABILITY: No require statement to check reward > 0
        // Could claim 0 rewards repeatedly

        rewards[msg.sender] = 0; // State update before external call (good)

        rewardToken.mint(msg.sender, reward);

        emit RewardClaimed(msg.sender, reward);
    }

    /**
     * @notice VULNERABLE: Protected function calls unprotected external function
     * Privilege escalation risk
     */
    function adminDistributeRewards(address[] calldata users, uint256[] calldata amounts)
        external
        onlyOwner
    {
        require(users.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < users.length; i++) {
            // VULNERABILITY: Calls mint without additional checks
            // If mint function has weak access control, this is a bypass vector
            rewardToken.mint(users[i], amounts[i]);
        }
    }

    /**
     * @notice Emergency withdraw for owner
     * VULNERABLE: Uses tx.origin instead of msg.sender
     */
    function emergencyWithdraw() external {
        // VULNERABILITY: tx.origin can be exploited via phishing
        require(tx.origin == owner, "Not owner");

        uint256 balance = address(this).balance;
        (bool success, ) = owner.call{value: balance}("");
        require(success, "Transfer failed");
    }

    /**
     * @notice Update reward rate
     * VULNERABLE: No sanity checks on new rate
     */
    function setRewardRate(uint256 newRate) external onlyOwner {
        // VULNERABILITY: No upper bound check
        // Owner could set to 10000 (100%) or higher
        rewardRate = newRate;
    }

    /**
     * @notice Get pool statistics
     * Used by frontend, could be manipulated in same transaction
     */
    function getPoolStats() external view returns (
        uint256 _totalDeposits,
        uint256 _rewardRate,
        uint256 _poolBalance
    ) {
        return (totalDeposits, rewardRate, address(this).balance);
    }

    receive() external payable {}
}
