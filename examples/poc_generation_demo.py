#!/usr/bin/env python3
"""
Example: Automated PoC Generation Demo
Demonstrates the automated PoC generation capabilities
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.poc_generator import (
    AutomatedPoCGenerator,
    PoCGenerator,
    SafetyValidator,
    PoCFramework
)


class ExampleVulnerability:
    """Example vulnerability for demonstration"""
    def __init__(self, name, vuln_type, severity="high", confidence=0.9):
        self.name = name
        self.type = vuln_type
        self.severity = severity
        self.confidence = confidence
        self.description = f"Detected {name} vulnerability"
        self.exploit_scenario = f"Attacker can exploit {name} to drain funds"


async def demo_poc_generation():
    """Demonstrate PoC generation for various vulnerability types"""
    
    print("="*70)
    print(" AUTOMATED PoC GENERATION DEMO")
    print("="*70)
    
    # Example vulnerable contract
    vulnerable_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable to reentrancy - state updated after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
"""
    
    print("\n1. Safety Validation Demo")
    print("-" * 70)
    validator = SafetyValidator()
    
    # Test safe code
    safe_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
contract SafeTest is Test {
    function testSafe() public {
        console.log("Safe test");
    }
}"""
    
    safe_result = validator.validate(safe_code)
    print(f"Safe code validation: {safe_result['safe']}")
    print(f"Checks passed: {sum(safe_result['checks'].values())}/{len(safe_result['checks'])}")
    
    # Test unsafe code
    unsafe_code = """
contract UnsafeTest {
    string rpc = "https://mainnet.infura.io/v3/key";
}"""
    
    unsafe_result = validator.validate(unsafe_code)
    print(f"\nUnsafe code validation: {unsafe_result['safe']}")
    print(f"Warnings: {len(unsafe_result['warnings'])}")
    for warning in unsafe_result['warnings']:
        print(f"  {warning}")
    
    print("\n2. Template-Based PoC Generation")
    print("-" * 70)
    generator = PoCGenerator(PoCFramework.FOUNDRY)
    
    # Generate PoC for reentrancy
    reentrancy_vuln = ExampleVulnerability(
        "Reentrancy Attack",
        "reentrancy",
        severity="critical",
        confidence=0.95
    )
    
    poc_code = generator.generate_poc(
        reentrancy_vuln,
        vulnerable_contract,
        "VulnerableVault"
    )
    
    print(f"✓ Generated PoC for {reentrancy_vuln.name}")
    print("  Template used: foundry_reentrancy")
    print(f"  Code length: {len(poc_code)} characters")
    print("  First 300 chars:")
    print(f"  {poc_code[:300]}...")
    
    # Validate generated PoC
    poc_validation = validator.validate(poc_code)
    print(f"\n  Safety validation: {poc_validation['safe']}")
    
    print("\n3. Multi-Vulnerability PoC Generation")
    print("-" * 70)
    
    vulnerabilities = [
        ExampleVulnerability("Reentrancy", "reentrancy", "critical", 0.95),
        ExampleVulnerability("Oracle Manipulation", "oracle_manipulation", "high", 0.85),
        ExampleVulnerability("Flash Loan Attack", "flash_loan", "high", 0.80),
        ExampleVulnerability("Access Control", "access_control", "medium", 0.75),
    ]
    
    for i, vuln in enumerate(vulnerabilities, 1):
        poc = generator.generate_poc(vuln, vulnerable_contract, "VulnerableVault")
        validation = validator.validate(poc)
        
        print(f"\n  [{i}] {vuln.name}")
        print(f"      Severity: {vuln.severity} | Confidence: {vuln.confidence:.0%}")
        print(f"      PoC generated: ✓ ({len(poc)} chars)")
        print(f"      Safety validated: {'✓' if validation['safe'] else '✗'}")
    
    print("\n4. Automated PoC Generator with Strategy Selection")
    print("-" * 70)
    
    auto_generator = AutomatedPoCGenerator()
    
    # Generate PoC with automatic strategy selection
    for vuln in vulnerabilities[:2]:  # Test first 2
        result = await auto_generator.generate_poc(
            vuln,
            vulnerable_contract,
            "VulnerableVault",
            strategy="auto"
        )
        
        print(f"\n  {vuln.name}:")
        print(f"    Strategy selected: {result.get('strategy_used', 'N/A')}")
        print(f"    Success: {result.get('success', False)}")
        print(f"    Safety validated: {result.get('safety_validated', False)}")
        print(f"    Variants generated: {result.get('variants_generated', 0)}")
        print(f"    Safe variants: {result.get('variants_safe', 0)}")
    
    print("\n5. Statistics")
    print("-" * 70)
    stats = auto_generator.get_statistics()
    print(f"  Total PoCs generated: {stats['total_generated']}")
    print(f"  Safety validated: {stats['safety_validated']}")
    print(f"  Exploits demonstrated: {stats['exploits_demonstrated']}")
    
    print("\n" + "="*70)
    print(" DEMO COMPLETED SUCCESSFULLY")
    print("="*70)
    print("\nKey Features Demonstrated:")
    print("  ✓ Safety validation with multiple checks")
    print("  ✓ Template-based PoC generation")
    print("  ✓ Multi-vulnerability support")
    print("  ✓ Automatic strategy selection")
    print("  ✓ Statistics tracking")
    print("\nNext Steps:")
    print("  - Run with actual vulnerable contracts")
    print("  - Enable sandbox execution (requires Foundry)")
    print("  - Integrate with full analysis pipeline")
    print("  - Export PoCs for manual testing")


if __name__ == "__main__":
    print("Starting Automated PoC Generation Demo...\n")
    asyncio.run(demo_poc_generation())
