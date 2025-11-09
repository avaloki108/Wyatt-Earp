# Quick Start: Cross-Contract Analysis

Get started with cross-contract vulnerability detection in 2 minutes!

## What Is It?

Cross-contract analysis finds vulnerabilities that span multiple smart contracts - the kind that cost projects millions in exploits:
- Cross-contract reentrancy ($60M DAO hack)
- Privilege escalation via external calls
- State inconsistencies across contracts
- Protocol-wide business logic flaws

## Installation

Already installed the tool? You're ready! Cross-contract analysis is built-in.

If not:

```bash
# Clone repo
git clone <your-repo-url>
cd advanced-web3-bug-hunter

# Setup environment
./setup.sh

# Or manually:
uv venv
source .venv/bin/activate
uv pip install -r requirements-core.txt
```

## Usage

### Analyze a Directory (Cross-Contract)

```bash
# Analyze all contracts in a directory
./hunt contracts/

# Analyze your DeFi project
./hunt ~/projects/my-protocol/contracts/
```

That's it! The tool automatically:
1. Finds all `.sol` files
2. Parses contract structures
3. Builds cross-contract call graph
4. Detects vulnerabilities spanning contracts
5. Validates business logic

### Analyze Single Contract (Traditional)

```bash
# Single file analysis (no cross-contract)
./hunt MyContract.sol
```

## Example: Test with Vulnerable Contracts

```bash
# Test on provided examples
./hunt examples/cross-contract/

# Should find 8-17 vulnerabilities including:
# - Cross-contract reentrancy
# - Privilege escalation
# - State inconsistency
# - Flash loan vectors
# - Business logic violations
```

## Expected Output

```
[0/9] Running Cross-Contract Analysis...
🔗 Analyzing contract interactions, dependencies, and protocol-wide vulnerabilities...

📊 Cross-Contract Analysis Complete:
  Contracts analyzed: 2
  External calls: 6
  Cross-contract vulnerabilities: 8

  🚨 CRITICAL: 2
  ⚠️  HIGH: 5
```

## View Results

```bash
# View JSON report
cat *_report.json | python -m json.tool

# Or check the summary printed to console
```

## What It Finds

### 1. Cross-Contract Reentrancy ⚠️ CRITICAL
Contract A calls Contract B, which calls back to Contract A before state updates.

### 2. Privilege Escalation ⚠️ HIGH
Protected function calls unprotected external function, bypassing access control.

### 3. State Inconsistency ⚠️ HIGH
Multiple contracts modify shared state without synchronization.

### 4. Flash Loan Attack Vector ⚠️ HIGH
Balance-based calculations without reentrancy protection.

### 5. Business Logic Violations ⚠️ HIGH
- Supply invariants broken (mint/burn doesn't update totalSupply)
- Missing balance checks
- Inconsistent access control
- Re-initialization vulnerabilities

[See CROSS_CONTRACT_ANALYSIS.md for all 10 vulnerability types]

## Understanding Results

### Call Graph
Shows how contracts interact:
```
Pool.deposit
  └─> Token.transferFrom
       └─> Pool.updateBalance (callback - REENTRANCY!)
```

### Exploit Paths
Shows attack sequences:
```
Attack: Pool.deposit → Token.notifyDeposit → Pool.deposit
```

### Business Logic
Validates protocol-wide invariants:
```
✗ Token.mint modifies balances but not totalSupply
✗ Pool.withdraw has no balance check
```

## Common Scenarios

### DeFi Protocol
```bash
./hunt ~/projects/defi-protocol/contracts/

# Finds:
# - Reentrancy in Pool → Token interactions
# - Flash loan vectors in price oracles
# - Access control gaps in reward distribution
```

### Token + Staking
```bash
./hunt ~/projects/staking/contracts/

# Finds:
# - State inconsistency between Token and Staking
# - Privilege escalation via unprotected mint
# - Supply invariant violations
```

### Upgradeable Contracts
```bash
./hunt ~/projects/proxy-contracts/contracts/

# Finds:
# - Storage collisions in proxy patterns
# - Re-initialization vulnerabilities
# - Unsafe delegatecalls
```

## Tips for Best Results

### 1. Organize Your Contracts
```
contracts/
├── core/          # Core protocol contracts
├── tokens/        # Token contracts
├── interfaces/    # Interfaces
└── libraries/     # Libraries
```

### 2. Run Both Analyses
```bash
# First: Protocol-wide view
./hunt contracts/

# Then: Deep dive on critical contracts
./hunt contracts/core/Pool.sol
./hunt contracts/tokens/RewardToken.sol
```

### 3. Focus on Critical Findings
Start with CRITICAL and HIGH severity issues. Medium and low can wait.

### 4. Understand the Context
The tool shows WHY something is vulnerable, not just THAT it's vulnerable.

## Configuration

### Skip Directories
Automatically skips:
- `node_modules/`
- `lib/`
- `test/`

### Adjust Sensitivity
All detectors are enabled by default. No configuration needed!

## Performance

- **Small projects** (< 10 contracts): ~5 seconds
- **Medium projects** (10-50 contracts): ~30 seconds
- **Large projects** (50+ contracts): ~60 seconds

## Troubleshooting

### "No contracts found"
Make sure you're pointing to a directory with `.sol` files:
```bash
ls contracts/*.sol  # Verify files exist
./hunt contracts/   # Then analyze
```

### "Permission denied"
Make sure hunt script is executable:
```bash
chmod +x hunt
./hunt contracts/
```

### Too many false positives?
Focus on high-confidence findings (>70%) first.

## Learn More

- **CROSS_CONTRACT_ANALYSIS.md** - Complete documentation
- **examples/cross-contract/** - Vulnerable contract examples
- **FEATURE_SUMMARY.md** - Technical details

## Real-World Impact

These vulnerabilities have caused:
- **$60M** - DAO (cross-contract reentrancy)
- **$150M** - Parity Wallet (unsafe delegatecall)
- **$325M** - Wormhole (re-initialization)
- **$130M** - Cream Finance (flash loan)

Don't be next!

## Support

- Found a bug? Open an issue
- Need help? Check the docs
- Want to contribute? PRs welcome!

---

**Ready?** `./hunt examples/cross-contract/` to see it in action!