"""
Example usage of the AI Hypothesis System
Demonstrates the complete workflow
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from advanced.ai_hypothesis_system import AIHypothesisSystem


# Example vulnerable contract
EXAMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: Reentrancy - external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
"""


def main():
    """Run example analysis"""
    
    print("="*70)
    print("AI HYPOTHESIS SYSTEM - Example Usage")
    print("="*70)
    
    # Initialize system (without LLM client - will use pattern-based fallback)
    system = AIHypothesisSystem(
        llm_client=None,  # Would be LLM client in production
        symbolic_executor=None,  # Would be symbolic executor in production
        enable_poc_generation=True,
        enable_learning=True
    )
    
    # Analyze contract
    report = system.analyze_contract(
        contract_code=EXAMPLE_CONTRACT,
        contract_name="VulnerableVault",
        contract_type="vault",
        static_analysis_results=None,
        generate_pocs=True
    )
    
    # Export reports
    output_dir = "/tmp/hypothesis_system_output"
    os.makedirs(output_dir, exist_ok=True)
    
    system.export_report(report, f"{output_dir}/report.json", format="json")
    system.export_report(report, f"{output_dir}/report.md", format="markdown")
    
    print(f"\n✓ Reports exported to {output_dir}/")
    
    # Show system statistics
    print("\n" + "="*70)
    print("SYSTEM STATISTICS")
    print("="*70)
    
    stats = system.get_system_statistics()
    
    print(f"\nTotal Analyses: {stats['total_analyses']}")
    
    if 'hypothesis_engine' in stats and stats['hypothesis_engine']:
        hyp_stats = stats['hypothesis_engine']
        print("\nHypothesis Engine:")
        print(f"  Total Hypotheses: {hyp_stats.get('total_hypotheses', 0)}")
        print(f"  Verified: {hyp_stats.get('verified_count', 0)}")
        print(f"  Rejected: {hyp_stats.get('rejected_count', 0)}")
    
    if 'verification_pipeline' in stats and stats['verification_pipeline']:
        ver_stats = stats['verification_pipeline']
        print("\nVerification Pipeline:")
        print(f"  Total Verifications: {ver_stats.get('total_verifications', 0)}")
        print(f"  Verified: {ver_stats.get('verified_count', 0)}")
        print(f"  Rejected: {ver_stats.get('rejected_count', 0)}")
    
    # Optimize system based on results
    print("\n" + "="*70)
    print("SYSTEM OPTIMIZATION")
    print("="*70)
    
    system.optimize_system()
    
    print("\n" + "="*70)
    print("Example complete!")
    print(f"Check {output_dir}/ for detailed reports")
    print("="*70)


if __name__ == "__main__":
    main()
