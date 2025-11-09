#!/usr/bin/env python3
"""
Simple Multi-Agent Audit Demo
Shows the different agent roles and how they work together
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def show_agent_architecture():
    """Show the multi-agent architecture"""
    
    print("🎯 Multi-Agent Audit Architecture")
    print("=" * 50)
    
    print("\n🤖 Available Agent Systems:")
    print("1. 🎭 Dual-Phase LLM (Auditor + Critic)")
    print("   - Auditor: High recall, finds everything")
    print("   - Critic: High precision, filters false positives")
    
    print("\n2. 🧠 Advanced LLM Reasoner")
    print("   - Adversarial Agent: Think like attacker")
    print("   - Defensive Agent: Think like auditor")
    print("   - Economic Agent: Analyze incentives")
    print("   - Composability Agent: Cross-protocol analysis")
    print("   - Formal Agent: Mathematical verification")
    
    print("\n3. 💡 AI Hypothesis System")
    print("   - Creative vulnerability discovery")
    print("   - Pattern matching from historical exploits")
    print("   - Cross-contract analysis")
    
    print("\n4. 🕸️ LangGraph Orchestrator")
    print("   - DAG-based agent coordination")
    print("   - Multi-stage reasoning pipeline")
    print("   - Agent communication and state sharing")
    
    print("\n5. 🔗 Prompt Chain Orchestrator")
    print("   - Multi-stage prompt chaining")
    print("   - Divergent exploration")
    print("   - Analogical reasoning")
    print("   - Technical validation")

def show_workflow():
    """Show the multi-agent workflow"""
    
    print("\n🔄 Multi-Agent Workflow")
    print("=" * 30)
    
    workflow_steps = [
        "1. 📄 Contract Analysis",
        "   - Parse Solidity code",
        "   - Extract functions, variables, modifiers",
        "   - Identify external calls, state changes",
        "",
        "2. 🎭 Dual-Phase Analysis",
        "   - Auditor Agent: Generate vulnerability hypotheses",
        "   - Critic Agent: Validate and filter findings",
        "",
        "3. 🧠 Multi-Agent Reasoning",
        "   - Adversarial: Find attack vectors",
        "   - Defensive: Find security gaps",
        "   - Economic: Find MEV/arbitrage opportunities",
        "   - Composability: Find integration issues",
        "   - Formal: Mathematical verification",
        "",
        "4. 💡 AI Hypothesis System",
        "   - Creative vulnerability discovery",
        "   - Pattern matching from learned exploits",
        "   - Cross-contract interaction analysis",
        "",
        "5. 🕸️ LangGraph Orchestration",
        "   - Coordinate all agents",
        "   - Share findings between agents",
        "   - Iterative refinement",
        "",
        "6. 🔗 Prompt Chain Processing",
        "   - Divergent exploration (creative)",
        "   - Analogical reasoning (historical)",
        "   - Technical validation (precise)",
        "   - Exploit synthesis (actionable)",
        "",
        "7. 📊 Synthesis & Reporting",
        "   - Combine all agent findings",
        "   - Rank by severity and confidence",
        "   - Generate PoCs for high-priority issues",
        "   - Create comprehensive report"
    ]
    
    for step in workflow_steps:
        print(step)

def show_agent_specializations():
    """Show detailed agent specializations"""
    
    print("\n🎭 Agent Specializations")
    print("=" * 30)
    
    agents = {
        "🔍 Adversarial Agent": {
            "temperature": "0.8 (Creative)",
            "focus": "Attack vectors, exploit scenarios",
            "prompt_style": "Think like a sophisticated attacker",
            "finds": "Reentrancy, flash loans, oracle manipulation, MEV"
        },
        "🛡️ Defensive Agent": {
            "temperature": "0.3 (Precise)",
            "focus": "Security controls, access patterns",
            "prompt_style": "Think like a security auditor",
            "finds": "Missing access controls, input validation, state consistency"
        },
        "💰 Economic Agent": {
            "temperature": "0.5 (Balanced)",
            "focus": "Economic incentives, tokenomics",
            "prompt_style": "Analyze economic game theory",
            "finds": "MEV opportunities, arbitrage, economic attacks"
        },
        "🔗 Composability Agent": {
            "temperature": "0.6 (Analytical)",
            "focus": "Cross-protocol interactions",
            "prompt_style": "Analyze protocol integrations",
            "finds": "Integration vulnerabilities, cross-contract issues"
        },
        "📐 Formal Agent": {
            "temperature": "0.2 (Logical)",
            "focus": "Mathematical verification",
            "prompt_style": "Formal verification reasoning",
            "finds": "Invariant violations, mathematical proofs"
        },
        "🎯 Auditor Agent": {
            "temperature": "0.7 (Thorough)",
            "focus": "High recall vulnerability detection",
            "prompt_style": "Find everything, even uncertain",
            "finds": "All possible vulnerabilities (may include false positives)"
        },
        "🔬 Critic Agent": {
            "temperature": "0.4 (Critical)",
            "focus": "High precision filtering",
            "prompt_style": "Validate and filter findings",
            "finds": "Validates findings, reduces false positives"
        }
    }
    
    for agent_name, details in agents.items():
        print(f"\n{agent_name}")
        print(f"  Temperature: {details['temperature']}")
        print(f"  Focus: {details['focus']}")
        print(f"  Style: {details['prompt_style']}")
        print(f"  Finds: {details['finds']}")

def show_usage_examples():
    """Show how to use the multi-agent system"""
    
    print("\n💻 Usage Examples")
    print("=" * 20)
    
    print("\n1. 🚀 Quick Multi-Agent Analysis:")
    print("   ./hunt Contract.sol --no-fuzzing")
    print("   # Uses all agents: reasoning, dual-phase, hypothesis, langgraph")
    
    print("\n2. 🎭 Dual-Phase Analysis Only:")
    print("   python -c \"")
    print("   from advanced.dual_phase_llm import DualPhaseLLM")
    print("   from advanced.llm_providers import LLMClient, LLMProvider")
    print("   ")
    print("   llm = LLMClient(LLMProvider.GROK, api_key='your-key')")
    print("   dual_phase = DualPhaseLLM(llm)")
    print("   result = dual_phase.analyze_contract(contract_code, 'Contract')")
    print("   \"")
    
    print("\n3. 🧠 Multi-Agent Reasoning:")
    print("   python -c \"")
    print("   from advanced.llm_reasoning_engine import AdvancedLLMReasoner")
    print("   ")
    print("   reasoner = AdvancedLLMReasoner()")
    print("   results = reasoner.analyze_contract_multi_agent(contract_code)")
    print("   \"")
    
    print("\n4. 💡 AI Hypothesis System:")
    print("   python -c \"")
    print("   from advanced.ai_hypothesis_system import AIHypothesisSystem")
    print("   ")
    print("   hypothesis = AIHypothesisSystem(llm_client)")
    print("   report = hypothesis.analyze_contract(contract_code)")
    print("   \"")

def main():
    """Main demonstration"""
    
    print("🎯 Advanced Web3 Bug Hunter - Multi-Agent Audit Environment")
    print("=" * 70)
    
    show_agent_architecture()
    show_workflow()
    show_agent_specializations()
    show_usage_examples()
    
    print("\n✨ Key Benefits of Multi-Agent Approach:")
    print("=" * 40)
    print("• 🎯 Specialized expertise: Each agent has unique focus")
    print("• 🔄 Collaborative analysis: Agents build on each other's findings")
    print("• 🧠 Diverse perspectives: Attack, defense, economic, formal views")
    print("• 📊 Comprehensive coverage: No vulnerability type missed")
    print("• 🎭 Balanced approach: High recall + high precision")
    print("• 🔗 Cross-validation: Multiple agents verify findings")
    print("• 💡 Creative discovery: Novel attack vectors found")
    print("• 📈 Continuous learning: Gets smarter with each analysis")

if __name__ == "__main__":
    main()
