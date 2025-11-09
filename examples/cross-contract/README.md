# Cross-Contract Vulnerability Examples

This directory contains intentionally vulnerable smart contracts that demonstrate **cross-contract vulnerabilities** - issues that only appear when analyzing multiple contracts together.

⚠️ **WARNING:** These contracts are INTENTIONALLY VULNERABLE. Never deploy them to mainnet or use them in production!

## Contracts

### 1. VulnerablePool.sol
A staking/deposit pool with multiple vulnerabilities:
- Cross-contract reentrancy via callback
- Privilege escalation through external calls
- State updates after external calls
- Flash loan attack vectors
- Missing balance validations

### 2. MaliciousToken.sol
A reward token that exploits the pool:
- Implements reentrancy attack via `notifyDeposit` callback
- No access control on `mint()` and `burn()`
- State inconsistency (totalSupply not updated correctly)
- Demonstrates how vulnerabilities span contracts

## Vulnerabilities Demonstrated

### 1. Cross-Contract Reentrancy Chain ⚠️ CRITICAL

**Location:** `VulnerablePool.deposit()` → `MaliciousToken.notifyDeposit()`

**The Attack:**
```solidity
// Pool calls token during deposit
function deposit() external payable {
    rewardToken.notifyDeposit(msg.sender, msg.value);  // External call
    balances[msg.sender] += msg.value;  // State update AFTER
    totalDeposits += msg.value;
}

// Token re-enters the pool
function notifyDeposit(address user, uint256 amount) external {
    IVulnerablePool(pool).deposit{value: 0.1 ether}();  // RE-ENTER!
}
```

**Impact:** Attacker can deposit multiple times but only send ETH once.

**Real-world equivalent:** DAO hack ($60M), Lendf.me ($25M)

### 2. Privilege Escalation ⚠️ HIGH

**Location:** `VulnerablePool.adminDistributeRewards()` → `MaliciousToken.mint()`

**The Issue:**
```solidity
// Pool: Protected function
function adminDistributeRewards(...) external onlyOwner {
    rewardToken.mint(users[i], amounts[i]);  // Calls external contract
}

// Token: No protection!
function mint(address to, uint256 amount) external {
    // Anyone can call this directly!
    balanceOf[to] += amount;
}
```

**Impact:** Attacker bypasses `onlyOwner` by calling `mint()` directly.

### 3. State Inconsistency ⚠️ HIGH

**Location:** `VulnerablePool.totalDeposits` vs `MaliciousToken.totalSupply`

**The Issue:**
- Pool tracks `totalDeposits`
- Token tracks `totalSupply` (but updates it inconsistently)
- No synchronization between contracts
- Accounting becomes incorrect

**Impact:** Protocol accounting breaks, rewards calculated incorrectly.

### 4. Flash Loan Attack Vector ⚠️ HIGH

**Location:** `VulnerablePool.calculateRewards()`

**The Attack:**
```solidity
function flashLoanAttack() external payable {
    // 1. Deposit huge amount (simulating flash loan)
    pool.deposit{value: 100 ether}();
    
    // 2. Now I'm 99% of the pool
    uint256 rewards = pool.calculateRewards(address(this));
    
    // 3. Claim inflated rewards
    pool.claimRewards();
    
    // 4. Withdraw original deposit
    pool.withdraw(100 ether);
}
```

**Impact:** Attacker manipulates reward calculations for profit.

### 5. Missing Business Logic Validation ⚠️ HIGH

**Issues:**
- `claimRewards()` has no `require(reward > 0)`
- `mint()` doesn't consistently update `totalSupply`
- No checks on `setRewardRate()` upper bound

## How to Test

### Run Cross-Contract Analysis

```bash
# From the root directory
./hunt examples/cross-contract/

# Or with full path
./hunt ~/tools/advanced-web3-bug-hunter/examples/cross-contract/
```

### Expected Output

The analyzer should detect:

```
🔗 Cross-Contract Analysis Complete:
  Contracts analyzed: 2
  External calls: 6
  Cross-contract vulnerabilities: 8-12

🚨 CRITICAL: 2-3
  - Cross-Contract Reentrancy Chain
  - Unsafe Delegatecall (if present)
  - Re-initialization vulnerability

⚠️ HIGH: 5-7
  - Privilege Escalation via External Call
  - Flash Loan Attack Vector
  - State Inconsistency
  - Access Control Bypass
  - Missing Balance Validation
```

### Detailed Findings

The tool will generate a report showing:

1. **Call Graph:**
   ```
   VulnerablePool.deposit
     └─> MaliciousToken.notifyDeposit
          └─> VulnerablePool.deposit (REENTRANCY!)
   ```

2. **Exploit Paths:**
   ```
   Attack: VulnerablePool.deposit → MaliciousToken.notifyDeposit → VulnerablePool.deposit
   ```

3. **Business Logic Violations:**
   - totalSupply invariant broken
   - Missing balance checks
   - Inconsistent access control

## Educational Value

### What You'll Learn

1. **Cross-Contract Reentrancy**
   - How callbacks enable reentrancy across contracts
   - Why single-contract analysis misses these
   - Proper mitigation (checks-effects-interactions)

2. **Privilege Escalation**
   - How protected functions calling unprotected ones creates bypass
   - Importance of consistent access control
   - Trust boundaries between contracts

3. **State Management**
   - Why shared state needs synchronization
   - Accounting invariants across contracts
   - Dangers of inconsistent updates

4. **Flash Loan Attacks**
   - How temporary balance manipulation works
   - Why balance-based calculations are dangerous
   - Need for snapshot-based accounting

5. **Business Logic**
   - Protocol-wide invariants vs per-contract checks
   - Importance of validation at every entry point
   - Edge cases in multi-contract interactions

## Fix Recommendations

### 1. Fix Reentrancy

```solidity
// Add reentrancy guard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecurePool is ReentrancyGuard {
    function deposit() external payable nonReentrant {
        // Update state FIRST
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        
        // Then make external calls
        rewardToken.notifyDeposit(msg.sender, msg.value);
    }
}
```

### 2. Fix Privilege Escalation

```solidity
// Add access control to token
contract SecureToken {
    address public pool;
    
    function mint(address to, uint256 amount) external {
        require(msg.sender == pool, "Only pool can mint");
        balanceOf[to] += amount;
        totalSupply += amount;  // Keep consistent!
    }
}
```

### 3. Fix Flash Loan Vulnerability

```solidity
// Use time-weighted average or snapshots
function calculateRewards(address user) public view returns (uint256) {
    // Use snapshot from beginning of block, not current balance
    uint256 userBalance = balanceSnapshots[user][block.number];
    uint256 totalSnapshot = totalDepositsSnapshots[block.number];
    return userBalance * rewardPool / totalSnapshot;
}
```

### 4. Add Validation

```solidity
function claimRewards() external {
    uint256 reward = rewards[msg.sender];
    require(reward > 0, "No rewards to claim");  // ADD THIS
    
    rewards[msg.sender] = 0;
    rewardToken.mint(msg.sender, reward);
}
```

## Comparison: Before vs After

### Before (Vulnerable)
```
✗ State updates after external calls
✗ No reentrancy protection
✗ Weak access control on mint/burn
✗ Balance-based reward calculation
✗ Missing validations
```

### After (Secure)
```
✓ State updates before external calls
✓ ReentrancyGuard on all entry points
✓ Strict access control (onlyPool modifier)
✓ Snapshot-based reward calculation
✓ Comprehensive validation checks
```

## Try It Yourself

### Step 1: Run Analysis
```bash
./hunt examples/cross-contract/
```

### Step 2: Review Findings
```bash
cat cross-contract_report.json | python -m json.tool
```

### Step 3: Understand Each Vulnerability
Read the output and match it to the code. Can you find all the issues?

### Step 4: Try to Exploit
Can you write a Foundry test that demonstrates the attack?

### Step 5: Fix and Verify
Make the contracts secure and re-run analysis.

## Additional Resources

- [SWC Registry](https://swcregistry.io/) - Smart contract weakness classification
- [Consensys Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Rekt News](https://rekt.news/) - Real hack post-mortems
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) - Secure implementations

## Questions?

These examples are designed to teach cross-contract security. If you:
- Found a vulnerability not detected by the tool → Open an issue!
- Want more examples → Create a PR!
- Have questions → Ask in discussions!

---

**Remember:** Understanding how attacks work is the first step to preventing them. Study these examples, understand the vulnerabilities, and apply the lessons to your own contracts.

**Stay safe! 🔐**