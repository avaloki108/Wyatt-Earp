# 🚀 Quick Start - Modular Elite Detectors

## Run All Detectors (Recommended)

```bash
python bug_bounty_workflow/scripts/run_all_elite_detectors.py \
  /path/to/contracts \
  --output report.json \
  --verbose
```

## Run Individual Detector

```bash
python detectors/reentrancy_hooks_detector.py /path/to/contracts --output results.json
```

## Example: Audit Injective

```bash
python bug_bounty_workflow/scripts/run_all_elite_detectors.py \
  /home/dok/web3/Injective/injective-core/injective-chain/modules/evm/tests/solidity \
  --output injective_report.json --verbose
```

## Active Detectors (7/15)

✅ Storage Collision | Flash Loan | State Desync | Oracle Manipulation
✅ Reentrancy & Hooks | Timing Dependency | Economic Invariants

**Coverage: 14/33 vulnerability patterns**

See `README_MODULAR_ARCHITECTURE.md` for details.
