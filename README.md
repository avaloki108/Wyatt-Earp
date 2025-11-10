# Advanced Web3 Bug Hunter

AI-powered smart contract security analyzer that finds vulnerabilities other tools miss.

## Quick Start

```bash
# Analyze a contract
./hunt Contract.sol

# Scan entire directory (with cross-contract analysis!)
./hunt ~/projects/my-defi-protocol/

# Quick scan (no AI)
./hunt Contract.sol --quick
```

## Features

- **🔗 Cross-contract analysis** - Find vulnerabilities across multiple contracts (NEW!)
- **20+ DeFi vulnerability patterns** - ERC-4626 inflation, sandwich attacks, oracle manipulation
- **Z3 symbolic execution** - Mathematical proof of exploitability
- **AI reasoning** - Grok/Claude/OpenAI powered analysis
- **Auto-learning** - Gets smarter with every contract analyzed
- **PoC generation** - Automatic exploit demonstrations

## Installation

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements-core.txt

# Set API key (optional, for AI analysis)
export XAI_API_KEY="your-grok-key"

# Test it
./hunt examples/VulnerableVault.sol
```

## What It Finds

**Real vulnerabilities worth millions:**
- Cross-contract reentrancy chains ($60M DAO, $25M Lendf.me)
- ERC-4626 inflation attacks ($80M+ Rari, Hundred)
- Privilege escalation via external calls
- Oracle manipulation ($130M Cream)
- Flash loan exploits ($34M Harvest)
- Access control bypass across contracts
- State inconsistencies between contracts
- And 20+ more patterns

**🆕 Cross-Contract Analysis:**
- Analyzes multiple contracts together
- Finds vulnerabilities spanning contract interactions
- Validates protocol-wide business logic
- Detects reentrancy chains, privilege escalation, state races
- See [CROSS_CONTRACT_ANALYSIS.md](CROSS_CONTRACT_ANALYSIS.md) for details

## Usage

```bash
# Basic analysis
./hunt Contract.sol

# With AI (recommended)
./hunt Contract.sol --no-fuzzing

# Full analysis (includes fuzzing)
./hunt Contract.sol

# View results
cat *_report.json | python -m json.tool
```

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get started in 2 minutes
- **[INSTALL.md](INSTALL.md)** - Detailed installation
- **[USAGE.md](USAGE.md)** - Complete usage guide

## Output Example

```json
{
  "summary": {
    "total_findings": 17,
    "critical": 1,
    "high": 14,
    "medium": 2
  },
  "vulnerabilities": [
    {
      "severity": "critical",
      "name": "first_depositor_inflation_attack",
      "description": "ERC-4626 share inflation vulnerability",
      "attack": "Attacker deposits 1 wei, donates tokens, inflates share price",
      "remediation": "Mint dead shares on initialization"
    }
  ]
}
```

## Why This Tool?

**vs Standard Tools:**
| Feature | Slither/Mythril | This Tool |
|---------|-----------------|-----------|
| Detection patterns | ~50 generic | 20+ DeFi-specific |
| False positives | 80-90% | 30-50% |
| AI reasoning | ❌ | ✅ Multi-agent |
| Learns from findings | ❌ | ✅ Auto-generates detectors |
| PoC generation | ❌ | ✅ Automatic |

**Unique capabilities:**
- Finds logic flaws senior auditors catch
- Mathematical proof with Z3 solver
- References real $500M+ exploits
- Copy-paste remediation code
- Gets smarter over time

## Requirements

- Python 3.8+
- z3-solver (installed automatically)
- Optional: Echidna (for fuzzing), Foundry (for testing)

## License

MIT

---

**Start hunting:** `./hunt examples/VulnerableVault.sol`
