#!/usr/bin/env python3
"""
Multi-Agent Audit Environment Demo
Shows how to use the tool like Claude's code analysis with specialized agents
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.dual_phase_llm import DualPhaseLLM
from advanced.langgraph_orchestrator import LangGraphOrchestrator
from advanced.llm_providers import LLMClient, LLMProvider
from advanced.ai_hypothesis_system import AIHypothesisSystem
from advanced.prompt_chaining import PromptChainOrchestrator

def setup_multi_agent_environment():
    """Setup the multi-agent audit environment"""
    
    # Create LLM client
    llm_client = LLMClient(
        provider=LLMProvider.GROK,
        api_key=os.getenv('XAI_API_KEY'),
        model='grok-beta'
    )
    
    print("🤖 Multi-Agent Audit Environment Setup")
    print("=" * 50)
    
    # Initialize different agent systems
    agents = {
        "reasoning_engine": AdvancedLLMReasoner(
            openai_key=None,
            anthropic_key=None
        ),
        "dual_phase": DualPhaseLLM(llm_client),
        "langgraph": LangGraphOrchestrator(llm_client),
        "hypothesis_system": AIHypothesisSystem(
            llm_client=llm_client,
            enable_poc_generation=True,
            enable_learning=True
        ),
        "prompt_chain": PromptChainOrchestrator(llm_client)
    }
    
    return agents, llm_client

def demonstrate_agent_roles():
    """Show the different agent roles and their specializations"""
    
    print("\n🎭 Agent Roles & Specializations")
    print("=" * 50)
    
    agents_info = {
        "🔍 Adversarial Agent": {
            "role": "Think like an attacker",
            "specialization": "Find exploit vectors, attack scenarios",
            "temperature": "0.8 (creative)",
            "focus": "How can this be broken?"
        },
        "🛡️ Defensive Agent": {
            "role": "Think like an auditor", 
            "specialization": "Find security issues, access control",
            "temperature": "0.3 (precise)",
            "focus": "What security controls are missing?"
        },
        "💰 Economic Agent": {
            "role": "Analyze economic incentives",
            "specialization": "MEV, arbitrage, economic attacks",
            "temperature": "0.5 (balanced)",
            "focus": "How can economic incentives be exploited?"
        },
        "🔗 Composability Agent": {
            "role": "Cross-protocol interactions",
            "specialization": "Integration vulnerabilities, protocol interactions",
            "temperature": "0.6 (analytical)",
            "focus": "How does this interact with other protocols?"
        },
        "📐 Formal Agent": {
            "role": "Mathematical verification",
            "specialization": "Formal verification, mathematical proofs",
            "temperature": "0.2 (logical)",
            "focus": "Can this be mathematically proven secure?"
        },
        "🎯 Auditor Agent": {
            "role": "High recall vulnerability detection",
            "specialization": "Find everything, even uncertain findings",
            "temperature": "0.7 (thorough)",
            "focus": "What could possibly be wrong?"
        },
        "🔬 Critic Agent": {
            "role": "High precision filtering",
            "specialization": "Filter false positives, validate findings",
            "temperature": "0.4 (critical)",
            "focus": "Is this finding actually valid?"
        }
    }
    
    for agent_name, info in agents_info.items():
        print(f"\n{agent_name}")
        print(f"  Role: {info['role']}")
        print(f"  Specialization: {info['specialization']}")
        print(f"  Temperature: {info['temperature']}")
        print(f"  Focus: {info['focus']}")

def run_multi_agent_analysis(contract_path: str):
    """Run a comprehensive multi-agent analysis"""
    
    print(f"\n🔬 Multi-Agent Analysis: {contract_path}")
    print("=" * 50)
    
    # Setup environment
    agents, llm_client = setup_multi_agent_environment()
    
    # Read contract
    with open(contract_path, 'r') as f:
        contract_code = f.read()
    
    contract_name = Path(contract_path).stem
    
    print(f"\n📄 Analyzing: {contract_name}")
    print(f"📏 Code length: {len(contract_code)} characters")
    
    # Run different agent analyses
    results = {}
    
    # 1. Dual-Phase Analysis (Auditor + Critic)
    print("\n🎭 Phase 1: Auditor Agent (High Recall)")
    print("-" * 30)
    try:
        dual_phase_result = agents["dual_phase"].analyze_contract(
            contract_code=contract_code,
            contract_name=contract_name,
            confidence_threshold=0.5
        )
        results["dual_phase"] = dual_phase_result
        print(f"✅ Found {len(dual_phase_result.vulnerabilities)} potential vulnerabilities")
        print(f"⏱️  Audit time: {dual_phase_result.audit_time:.2f}s")
        print(f"⏱️  Critic time: {dual_phase_result.critic_time:.2f}s")
    except Exception as e:
        print(f"❌ Dual-phase analysis failed: {e}")
    
    # 2. Multi-Agent Reasoning
    print("\n🧠 Multi-Agent Reasoning")
    print("-" * 30)
    try:
        reasoning_results = agents["reasoning_engine"].analyze_contract_multi_agent(
            contract_code=contract_code,
            static_analysis_results={},
            contract_type=contract_name
        )
        results["reasoning"] = reasoning_results
        print(f"✅ Completed {len(reasoning_results)} reasoning modes")
        for result in reasoning_results:
            print(f"  - {result.mode.value}: {result.confidence:.2f} confidence")
    except Exception as e:
        print(f"❌ Multi-agent reasoning failed: {e}")
    
    # 3. AI Hypothesis System
    print("\n💡 AI Hypothesis System")
    print("-" * 30)
    try:
        hypothesis_report = agents["hypothesis_system"].analyze_contract(
            contract_code=contract_code,
            contract_name=contract_name,
            contract_type=contract_name,
            static_analysis_results={},
            generate_pocs=True
        )
        results["hypothesis"] = hypothesis_report
        print(f"✅ Generated {len(hypothesis_report.hypotheses)} hypotheses")
        print(f"📊 Confidence: {hypothesis_report.average_confidence:.2f}")
    except Exception as e:
        print(f"❌ AI hypothesis system failed: {e}")
    
    # 4. LangGraph Orchestration (if available)
    print("\n🕸️ LangGraph Orchestration")
    print("-" * 30)
    try:
        langgraph_result = agents["langgraph"].run(
            contract_code=contract_code,
            static_analysis_results={},
            contract_type=contract_name
        )
        results["langgraph"] = langgraph_result
        print(f"✅ Executed {len(langgraph_result.agent_runs)} agent runs")
        print(f"🔄 Iterations: {langgraph_result.iterations}")
        print(f"🎯 Final decision: {langgraph_result.final_decision}")
    except Exception as e:
        print(f"❌ LangGraph orchestration failed: {e}")
    
    return results

def main():
    """Main demonstration"""
    
    print("🎯 Advanced Web3 Bug Hunter - Multi-Agent Audit Environment")
    print("=" * 70)
    
    # Check API key
    if not os.getenv('XAI_API_KEY'):
        print("❌ XAI_API_KEY not found. Please set it in your environment.")
        return
    
    # Show agent roles
    demonstrate_agent_roles()
    
    # Test with example contract
    contract_path = "examples/VulnerableVault.sol"
    
    if not Path(contract_path).exists():
        print(f"❌ Contract not found: {contract_path}")
        return
    
    # Run multi-agent analysis
    results = run_multi_agent_analysis(contract_path)
    
    # Summary
    print("\n📊 Analysis Summary")
    print("=" * 30)
    print(f"✅ Completed {len(results)} agent analyses")
    
    if "dual_phase" in results:
        result = results["dual_phase"]
        print(f"🎭 Dual-Phase: {len(result.vulnerabilities)} vulnerabilities found")
        print(f"📈 False positive rate: {result.false_positive_rate:.2%}")
    
    if "reasoning" in results:
        print(f"🧠 Multi-Agent: {len(results['reasoning'])} reasoning modes completed")
    
    if "hypothesis" in results:
        print(f"💡 AI Hypothesis: {len(results['hypothesis'].hypotheses)} hypotheses generated")
    
    if "langgraph" in results:
        print(f"🕸️ LangGraph: {len(results['langgraph'].agent_runs)} agent runs executed")

if __name__ == "__main__":
    main()
