# Cross-Contract Analysis

## Overview

The **Cross-Contract Analysis** module analyzes multiple smart contracts together to find vulnerabilities that only appear when considering contract interactions, dependencies, and protocol-wide business logic.

## What's New? 🚀

Traditional tools analyze contracts **one at a time**, missing critical issues that span multiple contracts. Our cross-contract analyzer:

- ✅ **Loads all contracts** in your project simultaneously
- ✅ **Builds cross-contract call graphs** showing how contracts interact
- ✅ **Tracks state dependencies** across contracts
- ✅ **Validates protocol-wide business logic** and invariants
- ✅ **Finds vulnerabilities** that require understanding multiple contracts together

## Usage

### Analyze a Directory

```bash
# Analyze all contracts in a directory
./hunt contracts/

# Analyze entire project
./hunt ~/projects/my-defi-protocol/
```

When you point the tool at a **directory** instead of a single file, it automatically:
1. Loads all `.sol` files in the directory (recursively)
2. Parses contract structures and relationships
3. Builds cross-contract call graph
4. Detects cross-contract vulnerabilities
5. Validates protocol-wide business logic

### Analyze Single Contract (Traditional)

```bash
# Single contract analysis (no cross-contract features)
./hunt contracts/Token.sol
```

## Vulnerabilities Detected

### 1. Cross-Contract Reentrancy Chain ⚠️ CRITICAL

**What it finds:**
- Contract A calls Contract B
- Contract B can call back to Contract A
- Contract A modifies state after the external call

**Real-world impact:** Lendf.me hack ($25M), DAO hack ($60M)

**Example:**
```solidity
// Contract A
function withdraw() external {
    pool.notifyWithdraw(msg.sender);  // Calls Contract B
    balances[msg.sender] = 0;         // State change AFTER call
}

// Contract B (Malicious)
function notifyWithdraw(address user) external {
    ContractA(msg.sender).withdraw(); // Re-enters!
}
```

### 2. Privilege Escalation via External Call ⚠️ HIGH

**What it finds:**
- Protected function calls unprotected external function
- External function can modify important state
- Attacker bypasses access control

**Example:**
```solidity
// Contract A
function adminTransfer() external onlyOwner {
    token.transfer(recipient, amount);  // Calls unprotected function
}

// Contract B
function transfer() external {  // No access control!
    // Anyone can call this directly
}
```

### 3. State Inconsistency ⚠️ HIGH

**What it finds:**
- Multiple contracts modify similar state variables
- Updates are not properly synchronized
- State can become inconsistent

**Example:**
```solidity
// Contract A
uint256 public totalBalance;

// Contract B  
uint256 public totalBalance;

// Both contracts update their totalBalance independently
// Can lead to accounting errors
```

### 4. Unsafe Delegatecall ⚠️ CRITICAL

**What it finds:**
- Delegatecall with user-controlled target address
- Allows arbitrary code execution

**Real-world impact:** Parity Wallet hack ($150M)

**Example:**
```solidity
function execute(address target, bytes memory data) external {
    target.delegatecall(data);  // DANGEROUS!
}
```

### 5. Flash Loan Attack Vector ⚠️ HIGH

**What it finds:**
- Functions that read balance/reserves
- No reentrancy protection
- Can be exploited with flash loans

**Real-world impact:** Harvest Finance ($34M), Cream Finance ($130M)

### 6. Sandwich Attack Opportunity ⚠️ HIGH

**What it finds:**
- Functions that modify price/exchange rate
- No slippage protection
- Vulnerable to MEV attacks

**Real-world impact:** $1B+ lost to MEV in 2021-2023

### 7. Access Control Bypass ⚠️ CRITICAL

**What it finds:**
- Critical state can be modified via multiple paths
- Some paths have weaker access control
- Attacker can bypass intended restrictions

### 8. Circular Dependencies ⚠️ MEDIUM

**What it finds:**
- Contract A depends on Contract B
- Contract B depends on Contract A
- Creates deployment and upgrade issues

### 9. Proxy Storage Collision ⚠️ CRITICAL

**What it finds:**
- Storage variable conflicts in proxy patterns
- Can cause state corruption

**Real-world impact:** Audius hack ($6M)

### 10. Business Logic Violations ⚠️ HIGH

**What it finds:**
- Supply invariant violations (mint/burn doesn't update totalSupply)
- Balance validation missing (withdraw without balance check)
- Inconsistent access control patterns
- Re-initialization vulnerabilities

**Real-world impact:** Wormhole hack ($325M)

## Output Format

### Summary Statistics

```json
{
  "summary": {
    "total_contracts": 5,
    "total_functions": 87,
    "total_vulnerabilities": 12,
    "critical": 3,
    "high": 6,
    "medium": 2,
    "low": 1,
    "external_calls": 23,
    "contract_dependencies": 8
  }
}
```

### Call Graph

```json
{
  "call_graph": {
    "nodes": ["TokenA.transfer", "TokenB.mint", "Pool.deposit"],
    "external_calls": [
      {
        "from": "Pool.deposit",
        "to": "TokenA.transferFrom",
        "type": "call"
      }
    ]
  }
}
```

### Vulnerabilities

```json
{
  "vulnerabilities": [
    {
      "type": "cross_contract_reentrancy",
      "severity": "critical",
      "confidence": 0.85,
      "name": "Cross-Contract Reentrancy Chain",
      "description": "Pool.withdraw is vulnerable to reentrancy via Token",
      "contracts_involved": ["Pool", "Token"],
      "attack_scenario": "Attacker can exploit callback path: Pool.withdraw -> Token.burn -> Pool.withdraw",
      "exploit_path": ["Pool.withdraw", "Token.burn", "Pool.withdraw"],
      "affected_functions": ["withdraw", "burn"],
      "remediation": "Use checks-effects-interactions pattern or nonReentrant modifier",
      "references": ["Lendf.me hack ($25M)"]
    }
  ]
}
```

### Business Logic Invariants

```json
{
  "business_logic": {
    "invariants_checked": 8,
    "violations": [
      {
        "name": "Total Supply Invariant",
        "description": "mint should update totalSupply",
        "contracts": ["Token"],
        "violated": true,
        "evidence": "Token.mint modifies balances but not totalSupply"
      }
    ]
  }
}
```

## Architecture

### How It Works

```
1. Load Phase
   ├── Find all .sol files in directory
   ├── Parse each contract
   └── Extract structure (functions, state vars, calls)

2. Analysis Phase
   ├── Build call graph (cross-contract calls)
   ├── Analyze dependencies
   ├── Track state access patterns
   └── Map privilege boundaries

3. Detection Phase
   ├── Detect reentrancy chains
   ├── Find privilege escalation paths
   ├── Check state consistency
   ├── Validate business logic
   └── Check invariants

4. Reporting Phase
   ├── Rank by severity & confidence
   ├── Generate exploit paths
   └── Provide remediation advice
```

### Call Graph Structure

```
Pool.deposit
  └─> Token.transferFrom (external call)
       └─> Pool.updateBalance (callback)
            └─> REENTRANCY DETECTED!
```

## Comparison: Single vs Cross-Contract

| Feature | Single Contract | Cross-Contract |
|---------|----------------|----------------|
| Reentrancy within contract | ✅ | ✅ |
| Reentrancy across contracts | ❌ | ✅ |
| Privilege escalation | ❌ | ✅ |
| State inconsistency | ❌ | ✅ |
| Business logic validation | Partial | ✅ Full |
| Protocol-wide invariants | ❌ | ✅ |
| Access control bypass | ❌ | ✅ |

## Best Practices

### 1. Run Both Analyses

```bash
# First: Cross-contract analysis on the directory
./hunt contracts/

# Then: Detailed analysis on critical contracts
./hunt contracts/Pool.sol
./hunt contracts/Token.sol
```

### 2. Focus on Critical Paths

Pay special attention to:
- External calls between contracts
- Functions with access control modifiers
- State variables modified by multiple contracts
- Proxy/upgradeable patterns

### 3. Validate Business Logic

The tool checks common invariants, but you should also verify:
- Your specific protocol rules
- Economic incentive alignment
- Edge cases in multi-step operations

### 4. Review Call Graphs

Examine the call graph output to understand:
- Which contracts are tightly coupled
- Where circular dependencies exist
- Critical interaction points

## Examples

### Example 1: DeFi Protocol

```bash
./hunt ~/projects/my-defi/contracts/

# Finds:
# - Reentrancy in Pool -> Token callback
# - Flash loan vector in price oracle
# - Access control bypass in reward distribution
```

### Example 2: Token + Staking

```bash
./hunt ~/projects/staking-protocol/

# Finds:
# - State inconsistency between Token and Staking balances
# - Privilege escalation via unprotected Token.mint
# - Supply invariant violation in reward calculation
```

### Example 3: Proxy Pattern

```bash
./hunt ~/projects/upgradeable-contracts/

# Finds:
# - Storage collision between Proxy and Implementation
# - Re-initialization vulnerability
# - Delegatecall to user-controlled address
```

## Limitations

### What It Can Detect
- ✅ Structural vulnerabilities (reentrancy, access control)
- ✅ Common business logic errors
- ✅ Protocol-wide invariants
- ✅ Dangerous patterns (delegatecall, flash loans)

### What It Can't Detect
- ❌ Complex economic exploits requiring deep protocol knowledge
- ❌ Vulnerabilities in external dependencies (Chainlink, Uniswap)
- ❌ Issues in frontend or off-chain components
- ❌ Social engineering or governance attacks

### False Positives

The tool may flag issues that are actually safe if:
- There's custom protection logic it doesn't recognize
- The protocol design intentionally allows the pattern
- External contracts have guarantees not visible in code

**Always manually review findings!**

## Configuration

### Skip Directories

The analyzer automatically skips:
- `node_modules/`
- `lib/`
- `test/`

### Adjust Sensitivity

You can modify detection thresholds in the code:
- Confidence thresholds for each vulnerability type
- Maximum call graph depth
- State variable matching patterns

## Performance

### Scalability

- **Small projects** (< 10 contracts): < 5 seconds
- **Medium projects** (10-50 contracts): 10-30 seconds
- **Large projects** (50+ contracts): 30-60 seconds

### Memory Usage

- Analyzes contracts in memory
- No external tool dependencies for cross-contract analysis
- Lightweight parsing (regex-based)

## Integration with Other Tools

### Combine with Slither

```bash
# Run cross-contract analysis
./hunt contracts/

# Then run Slither for additional checks
slither contracts/
```

### Use with CI/CD

```bash
# In your CI pipeline
./hunt contracts/ --output cross-contract-report.json

# Parse results
python3 check_critical_vulns.py cross-contract-report.json
```

## Troubleshooting

### Issue: No contracts found

**Solution:** Make sure you're pointing to a directory with `.sol` files

```bash
ls contracts/*.sol  # Check files exist
./hunt contracts/   # Run analysis
```

### Issue: Parse errors

**Solution:** The tool uses regex parsing. Complex contracts may need manual review.

### Issue: Too many false positives

**Solution:** Focus on critical and high severity findings first. Review confidence scores.

## Contributing

Want to add more cross-contract vulnerability detectors? See:
- `advanced/cross_contract_analyzer.py` - Main analyzer
- `_detect_vulnerabilities()` - Add new detection methods
- `_validate_business_logic()` - Add invariant checks

## References

### Real-World Hacks Detected
- DAO ($60M) - Cross-contract reentrancy
- Parity Wallet ($150M) - Unsafe delegatecall
- Lendf.me ($25M) - Reentrancy chain
- Wormhole ($325M) - Re-initialization
- Cream Finance ($130M) - Flash loan attack
- Harvest Finance ($34M) - Flash loan attack
- Audius ($6M) - Storage collision

### Further Reading
- [Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [DeFi Security Summit](https://defisecuritysummit.org/)
- [Rekt News](https://rekt.news/) - Analysis of major hacks
- [Trail of Bits: Building Secure Contracts](https://github.com/crytic/building-secure-contracts)

---

**Next Steps:**
1. Run cross-contract analysis on your protocol
2. Review critical and high severity findings
3. Fix vulnerabilities
4. Re-run analysis to verify fixes
5. Consider professional audit for production code

**Questions?** Open an issue on GitHub or check the main README.md