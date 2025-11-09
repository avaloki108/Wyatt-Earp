# 🗺️ Elite Detector Module Map

## Current Architecture (7 Detectors)

```
base_elite_detector.py (Abstract Base Class)
│
├── storage_collision_detector.py (✅ Working)
│   └── Vuln #3: Storage layout collisions
│
├── flash_loan_simulator.py (✅ Working)
│   └── Vuln #2: Flash-loan manipulation
│
├── state_desync_analyzer.py (✅ Working)
│   └── Vuln #1: Multi-tx invariant breaks
│
├── oracle_manipulation_detector.py (✅ Working)
│   └── Vuln #7: Oracle price manipulation
│
├── reentrancy_hooks_detector.py (✅ NEW - Complete)
│   ├── Vuln #6: Phantom reentrancy
│   ├── Vuln #14: Token hooks (ERC777)
│   └── Vuln #29: Callback privilege escalation
│
├── timing_dependency_detector.py (✅ NEW - Complete)
│   ├── Vuln #12: Timestamp manipulation
│   ├── Vuln #20: Modifier state mutation
│   └── Vuln #24: Batch race conditions
│
└── economic_invariant_detector.py (✅ NEW - Complete)
    ├── Vuln #10: Rounding drift
    ├── Vuln #22: External supply dependency
    ├── Vuln #28: Wrapper accounting mismatch
    └── Vuln #33: Game-theoretic exploits
```

## Next Phase (8 More Detectors Needed)

```
base_elite_detector.py
│
├── upgrade_safety_detector.py (🚧 TODO)
│   ├── Vuln #4: Delegatecall gadget chaining
│   ├── Vuln #5: Constructor assumptions
│   └── Vuln #30: Compiler/optimizer artifacts
│
├── governance_security_detector.py (🚧 TODO)
│   ├── Vuln #9: Snapshot gaming
│   ├── Vuln #19: tx.origin misuse
│   └── Vuln #27: Relayer/keeper trust
│
├── token_standard_detector.py (🚧 TODO)
│   ├── Vuln #8: Permit/nonce replay
│   ├── Vuln #15: Cross-protocol assumptions
│   ├── Vuln #18: Non-standard ERC20
│   └── Vuln #32: Allowance race windows
│
├── dos_gas_detector.py (🚧 TODO)
│   ├── Vuln #13: Gas griefing
│   └── Vuln #25: Resource exhaustion
│
├── cryptographic_weakness_detector.py (🚧 TODO)
│   └── Vuln #26: Bad RNG, weak domain separation
│
├── offchain_trust_detector.py (🚧 TODO)
│   ├── Vuln #16: Event trust misuse
│   └── Vuln #31: View/pure shadow state
│
├── lowlevel_safety_detector.py (🚧 TODO)
│   ├── Vuln #11: Forced Ether (selfdestruct)
│   ├── Vuln #17: Calldata packing ambiguities
│   └── Vuln #21: Assembly memory assumptions
│
└── crosschain_bridge_detector.py (🚧 TODO)
    └── Vuln #23: Bridge reordering, finality assumptions
```

## Coverage Progress

**Phase 1 (Current):** 14/33 vulnerabilities ✅ (42% complete)
**Phase 2 (Next):** 19/33 vulnerabilities 🚧 (remaining 58%)

**Total Goal:** 33/33 vulnerabilities (100% coverage)

## Detector Complexity

| Detector | Lines | Patterns | Complexity | Status |
|----------|-------|----------|------------|--------|
| Storage Collision | 653 | 1 | High | ✅ |
| Flash Loan | 818 | 1 | Very High | ✅ |
| State Desync | 717 | 1 | High | ✅ |
| Oracle Manipulation | 802 | 1 | High | ✅ |
| Reentrancy & Hooks | 584 | 3 | Medium | ✅ |
| Timing Dependency | 725 | 3 | Medium | ✅ |
| Economic Invariant | 792 | 4 | High | ✅ |
| **Phase 1 Total** | **5,091** | **14** | - | **Done** |
| Upgrade Safety | ~600 | 3 | Medium | 🚧 |
| Governance Security | ~500 | 3 | Low | 🚧 |
| Token Standard | ~700 | 4 | High | 🚧 |
| DOS & Gas | ~400 | 2 | Low | 🚧 |
| Cryptographic | ~300 | 1 | Low | 🚧 |
| Off-chain Trust | ~400 | 2 | Low | 🚧 |
| Low-level Safety | ~600 | 3 | High | 🚧 |
| Cross-chain Bridge | ~500 | 1 | Medium | 🚧 |
| **Phase 2 Total** | **~4,000** | **19** | - | **TODO** |
| **Grand Total** | **~9,091** | **33** | - | **47% Done** |
