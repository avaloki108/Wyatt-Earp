#!/usr/bin/env python3
"""
Demo script showing all advanced modules in action
Run this to see what the tool can do
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from advanced.symbolic_execution_engine import AdvancedSymbolicExecutor, SymbolicState, VarType
from advanced.novel_vulnerability_patterns import NovelPatternDetector
from advanced.behavioral_anomaly_detector import BehavioralAnomalyDetector
from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.enhanced_fuzzing_orchestrator import EnhancedFuzzingOrchestrator, FuzzingConfig, FuzzingStrategy


def demo_symbolic_execution():
    """Demonstrate symbolic execution capabilities"""
    print("="*70)
    print(" DEMO 1: Advanced Symbolic Execution")
    print("="*70)

    executor = AdvancedSymbolicExecutor()

    # Create symbolic variables
    user_input = executor.create_symbolic_var("userInput", VarType.UINT256, tainted=True)
    balance = executor.create_symbolic_var("balance", VarType.UINT256)

    # Analyze integer overflow
    print("\n[1] Integer Overflow Analysis:")
    overflows = executor.analyze_integer_overflow_conditions(user_input, balance, "add")

    if overflows:
        vuln = overflows[0]
        print(f"✓ Found vulnerability: {vuln['type']}")
        print(f"  Operation: {vuln['operation']}")
        print(f"  Exploitable: {vuln['exploitable']}")
        print("  Example values:")
        for var, val in vuln['example_values'].items():
            print(f"    {var} = {val}")

        # Generate PoC
        print("\n  Proof of Concept:")
        poc = executor.generate_exploit_pocs(vuln)
        print(poc[:300] + "...")
    else:
        print("  No overflows found")

    # Flash loan analysis
    print("\n[2] Flash Loan Attack Analysis:")
    initial_state = SymbolicState(
        variables={},
        constraints=[],
        balances={},
        storage={},
        call_stack=[],
        msg_sender=None,
        msg_value=None,
        block_timestamp=None,
        block_number=None
    )

    operations = [
        ("swap", {"amount_in": "flash_loan_amount"}),
        ("borrow", {"collateral_factor": 75}),
        ("liquidate", {"bonus": 10})
    ]

    flash_attacks = executor.analyze_flash_loan_attack_vectors(initial_state, operations)

    if flash_attacks:
        attack = flash_attacks[0]
        print(f"✓ Found attack vector: {attack['type']}")
        print(f"  Severity: {attack['severity']}")
        print(f"  Description: {attack['description']}")

        # Generate PoC
        print("\n  Proof of Concept:")
        poc = executor.generate_exploit_pocs(attack)
        print(poc[:300] + "...")
    else:
        print("  No flash loan attacks found")

    print("\n✓ Symbolic execution demo complete\n")


def demo_pattern_detection():
    """Demonstrate novel pattern detection"""
    print("="*70)
    print(" DEMO 2: Novel Vulnerability Pattern Detection")
    print("="*70)

    # Example vulnerable contract
    vulnerable_contract = """
    contract VulnerableVault {
        mapping(address => uint256) public balances;
        uint256 public totalSupply;
        uint256 public totalShares;

        function deposit(uint256 amount) public {
            uint256 shares;
            if (totalShares == 0) {
                shares = amount;  // First depositor inflation!
            } else {
                shares = (amount * totalShares) / totalSupply;
            }
            balances[msg.sender] += amount;
            totalShares += shares;
        }

        function swap(uint256 amountIn) public {
            // No slippage protection!
            uint256 amountOut = calculateSwap(amountIn);
            executeSwap(amountIn, amountOut);
        }

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            msg.sender.call{value: amount}("");  // Reentrancy!
            balances[msg.sender] -= amount;
        }
    }
    """

    detector = NovelPatternDetector()
    patterns = detector.detect_all_patterns(vulnerable_contract, "VulnerableVault")

    print(f"\n✓ Found {len(patterns)} vulnerability patterns:\n")

    # Group by severity
    critical = [p for p in patterns if p.severity == "critical"]
    high = [p for p in patterns if p.severity == "high"]

    if critical:
        print(f"CRITICAL ({len(critical)}):")
        for i, pattern in enumerate(critical[:3], 1):
            print(f"  {i}. {pattern.name}")
            print(f"     {pattern.description}")
            print(f"     Attack: {pattern.attack_vector}")
            print()

    if high:
        print(f"HIGH ({len(high)}):")
        for i, pattern in enumerate(high[:3], 1):
            print(f"  {i}. {pattern.name}")
            print(f"     {pattern.description}")
            print()

    print("✓ Pattern detection demo complete\n")


def demo_anomaly_detection():
    """Demonstrate behavioral anomaly detection"""
    print("="*70)
    print(" DEMO 3: Behavioral Anomaly Detection")
    print("="*70)

    suspicious_contract = """
    contract SuspiciousContract {
        address owner;
        address[] users;

        function _backdoor() external {
            if (msg.sender == 0x1234567890123456789012345678901234567890) {
                selfdestruct(payable(msg.sender));
            }
        }

        function complexFunction(uint a, uint b, uint c) public {
            if (a > 10) {
                if (b < 20) {
                    for (uint i = 0; i < 100; i++) {
                        if (c == i) {
                            doSomething();
                        }
                    }
                } else if (b > 50) {
                    doSomethingElse();
                }
            }
        }

        function batchTransfer() public {
            for (uint i = 0; i < users.length; i++) {
                users[i].call{value: 1 ether}("");
            }
        }

        function withdraw() public {
            msg.sender.call{value: amount}("");
            balance[msg.sender] = 0;
        }
    }
    """

    detector = BehavioralAnomalyDetector()
    anomalies = detector.analyze_contract(suspicious_contract, "SuspiciousContract")

    print(f"\n✓ Found {len(anomalies)} behavioral anomalies:\n")

    # Show top anomalies
    critical = [a for a in anomalies if a.severity == "critical"]
    high = [a for a in anomalies if a.severity == "high"]

    if critical:
        print(f"CRITICAL ({len(critical)}):")
        for i, anomaly in enumerate(critical[:3], 1):
            print(f"  {i}. [{anomaly.anomaly_type.value}] {anomaly.name}")
            print(f"     {anomaly.description}")
            if anomaly.potential_exploit:
                print(f"     Exploit: {anomaly.potential_exploit}")
            print()

    if high:
        print(f"HIGH ({len(high)}):")
        for i, anomaly in enumerate(high[:3], 1):
            print(f"  {i}. [{anomaly.anomaly_type.value}] {anomaly.name}")
            print(f"     {anomaly.description}")
            print()

    print("✓ Anomaly detection demo complete\n")


def demo_llm_reasoning():
    """Demonstrate LLM reasoning (mock)"""
    print("="*70)
    print(" DEMO 4: Multi-Agent LLM Reasoning")
    print("="*70)

    print("\nNOTE: This uses mock LLM responses for demo purposes.")
    print("To use real LLM analysis, set OPENAI_API_KEY environment variable.\n")

    reasoner = AdvancedLLMReasoner()

    sample_contract = """
    contract DeFiProtocol {
        function borrow(uint amount) public {
            require(collateral[msg.sender] >= amount * 150 / 100);
            balance[msg.sender] += amount;
        }

        function liquidate(address user) public {
            if (collateral[user] < debt[user] * 150 / 100) {
                // Liquidation logic
            }
        }
    }
    """

    static_results = {
        "patterns": ["oracle_dependency", "liquidation_logic"],
        "complexity": "high"
    }

    print("[1] Running multi-agent analysis...")
    results = reasoner.analyze_contract_multi_agent(sample_contract, static_results, "lending")

    print(f"\n✓ Completed {len(results)} reasoning modes:\n")

    for result in results[:3]:  # Show first 3
        print(f"  Mode: {result.mode.value}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Findings: {len(result.findings)}")
        print(f"  Attack scenarios: {len(result.attack_scenarios)}")
        print(f"  Property tests: {len(result.property_tests)}")
        print()

    print("✓ LLM reasoning demo complete\n")


def demo_enhanced_fuzzing():
    """Demonstrate enhanced fuzzing"""
    print("="*70)
    print(" DEMO 5: Enhanced Fuzzing Orchestrator")
    print("="*70)

    print("\n[1] Coverage-Guided Fuzzing:")
    config1 = FuzzingConfig(
        strategy=FuzzingStrategy.COVERAGE_GUIDED,
        max_iterations=1000
    )
    orchestrator1 = EnhancedFuzzingOrchestrator(config1)
    print(f"  Strategy: {config1.strategy.value}")
    print(f"  Max iterations: {config1.max_iterations}")
    print("  Focus: Maximize code coverage")

    print("\n[2] Mutation-Based Fuzzing:")
    config2 = FuzzingConfig(
        strategy=FuzzingStrategy.MUTATION_BASED,
        max_iterations=500
    )
    print(f"  Strategy: {config2.strategy.value}")
    print("  Mutations: Overflow triggers, precision loss, edge values")

    print("\n[3] Adversarial Fuzzing:")
    config3 = FuzzingConfig(
        strategy=FuzzingStrategy.ADVERSARIAL,
        max_iterations=300
    )
    print(f"  Strategy: {config3.strategy.value}")
    print("  Focus: Property-breaking inputs")

    print("\n✓ Enhanced fuzzing demo complete\n")


def main():
    """Run all demos"""
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                                                                      ║")
    print("║        Advanced Web3 Bug Hunter - Interactive Demo                  ║")
    print("║                                                                      ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print("\n")
    print("This demo showcases all advanced modules:")
    print("1. Symbolic Execution with Z3")
    print("2. Novel Pattern Detection (17+ DeFi patterns)")
    print("3. Behavioral Anomaly Detection")
    print("4. Multi-Agent LLM Reasoning")
    print("5. Enhanced Fuzzing Strategies")
    print("\n")

    print("\n")

    try:
        # Run all demos
        demo_symbolic_execution()
        demo_pattern_detection()
        demo_anomaly_detection()
        demo_llm_reasoning()
        demo_enhanced_fuzzing()

        print("="*70)
        print(" DEMO COMPLETE")
        print("="*70)
        print("\nAll modules demonstrated successfully!")
        print("\nNext steps:")
        print("1. Run on real contract:")
        print("   python advanced_bug_hunter.py examples/VulnerableVault.sol")
        print("\n2. With LLM analysis:")
        print("   python advanced_bug_hunter.py Contract.sol --openai-key YOUR_KEY")
        print("\n3. Read documentation:")
        print("   - QUICKSTART.md - Quick start guide")
        print("   - ADVANCED_USAGE.md - Detailed usage")
        print("   - README_ADVANCED.md - Full documentation")
        print("\n")

    except KeyboardInterrupt:
        print("\n\nDemo interrupted. Thanks for watching!")
        sys.exit(0)
    except Exception as e:
        print(f"\nError during demo: {e}")
        print("This is normal for the demo - some features require additional setup.")
        print("See QUICKSTART.md for full setup instructions.")


if __name__ == "__main__":
    main()
