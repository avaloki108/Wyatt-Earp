# 🎯 Multi-Agent Audit Environment Guide

This guide shows you how to use the Advanced Web3 Bug Hunter as a sophisticated multi-agent audit environment, similar to Claude's code analysis capabilities.

## 🤖 Multi-Agent Architecture

The tool uses **7 specialized AI agents** working together:

### 🎭 **Dual-Phase Agents**
- **Auditor Agent**: High recall - finds everything, even uncertain findings
- **Critic Agent**: High precision - filters false positives, validates findings

### 🧠 **Reasoning Agents**
- **Adversarial Agent**: Think like an attacker (temperature: 0.8)
- **Defensive Agent**: Think like an auditor (temperature: 0.3)
- **Economic Agent**: Analyze economic incentives (temperature: 0.5)
- **Composability Agent**: Cross-protocol interactions (temperature: 0.6)
- **Formal Agent**: Mathematical verification (temperature: 0.2)

### 💡 **Specialized Systems**
- **AI Hypothesis System**: Creative vulnerability discovery
- **LangGraph Orchestrator**: DAG-based agent coordination
- **Prompt Chain Orchestrator**: Multi-stage reasoning pipeline

## 🚀 Quick Start

### **Basic Multi-Agent Analysis**
```bash
# Activate environment
source .venv/bin/activate

# Set API key
export XAI_API_KEY="your-grok-key"

# Run full multi-agent analysis
./hunt Contract.sol --no-fuzzing
```

### **What Happens During Analysis**
1. **📄 Contract Parsing**: Extract functions, variables, external calls
2. **🎭 Dual-Phase Analysis**: Auditor finds issues, Critic validates them
3. **🧠 Multi-Agent Reasoning**: 5 specialized agents analyze from different angles
4. **💡 AI Hypothesis System**: Creative vulnerability discovery
5. **🕸️ LangGraph Orchestration**: Coordinate all agents, share findings
6. **🔗 Prompt Chain Processing**: Multi-stage reasoning pipeline
7. **📊 Synthesis**: Combine findings, generate PoCs, create report

## 🎭 Agent Specializations

### **🔍 Adversarial Agent**
- **Role**: Think like a sophisticated attacker
- **Focus**: Attack vectors, exploit scenarios
- **Finds**: Reentrancy, flash loans, oracle manipulation, MEV
- **Temperature**: 0.8 (Creative)

### **🛡️ Defensive Agent**
- **Role**: Think like a security auditor
- **Focus**: Security controls, access patterns
- **Finds**: Missing access controls, input validation, state consistency
- **Temperature**: 0.3 (Precise)

### **💰 Economic Agent**
- **Role**: Analyze economic game theory
- **Focus**: Economic incentives, tokenomics
- **Finds**: MEV opportunities, arbitrage, economic attacks
- **Temperature**: 0.5 (Balanced)

### **🔗 Composability Agent**
- **Role**: Analyze protocol integrations
- **Focus**: Cross-protocol interactions
- **Finds**: Integration vulnerabilities, cross-contract issues
- **Temperature**: 0.6 (Analytical)

### **📐 Formal Agent**
- **Role**: Mathematical verification reasoning
- **Focus**: Mathematical verification
- **Finds**: Invariant violations, mathematical proofs
- **Temperature**: 0.2 (Logical)

## 🔄 Multi-Agent Workflow

### **Stage 1: Contract Analysis**
- Parse Solidity code
- Extract functions, variables, modifiers
- Identify external calls, state changes

### **Stage 2: Dual-Phase Analysis**
- **Auditor Agent**: Generate vulnerability hypotheses
- **Critic Agent**: Validate and filter findings

### **Stage 3: Multi-Agent Reasoning**
- **Adversarial**: Find attack vectors
- **Defensive**: Find security gaps
- **Economic**: Find MEV/arbitrage opportunities
- **Composability**: Find integration issues
- **Formal**: Mathematical verification

### **Stage 4: AI Hypothesis System**
- Creative vulnerability discovery
- Pattern matching from learned exploits
- Cross-contract interaction analysis

### **Stage 5: LangGraph Orchestration**
- Coordinate all agents
- Share findings between agents
- Iterative refinement

### **Stage 6: Prompt Chain Processing**
- **Divergent exploration** (creative)
- **Analogical reasoning** (historical)
- **Technical validation** (precise)
- **Exploit synthesis** (actionable)

### **Stage 7: Synthesis & Reporting**
- Combine all agent findings
- Rank by severity and confidence
- Generate PoCs for high-priority issues
- Create comprehensive report

## 💻 Usage Examples

### **1. Full Multi-Agent Analysis**
```bash
# All agents working together
./hunt Contract.sol --no-fuzzing
```

### **2. Cross-Contract Analysis**
```bash
# Analyze multiple contracts together
./hunt contracts/ --no-fuzzing
```

### **3. Custom Agent Configuration**
```python
from advanced.dual_phase_llm import DualPhaseLLM
from advanced.llm_providers import LLMClient, LLMProvider

# Setup LLM client
llm = LLMClient(LLMProvider.GROK, api_key="your-key")

# Dual-phase analysis
dual_phase = DualPhaseLLM(llm)
result = dual_phase.analyze_contract(contract_code, "Contract")

# Multi-agent reasoning
from advanced.llm_reasoning_engine import AdvancedLLMReasoner
reasoner = AdvancedLLMReasoner()
results = reasoner.analyze_contract_multi_agent(contract_code)
```

### **4. AI Hypothesis System**
```python
from advanced.ai_hypothesis_system import AIHypothesisSystem

hypothesis = AIHypothesisSystem(llm_client)
report = hypothesis.analyze_contract(
    contract_code=contract_code,
    contract_name="Contract",
    generate_pocs=True
)
```

## 📊 Understanding the Output

### **Agent Contributions**
Each agent contributes different types of findings:

- **Adversarial Agent**: Attack scenarios, exploit vectors
- **Defensive Agent**: Security gaps, missing controls
- **Economic Agent**: MEV opportunities, arbitrage
- **Composability Agent**: Integration vulnerabilities
- **Formal Agent**: Mathematical proofs, invariants

### **Confidence Scoring**
- **High Confidence (0.8-1.0)**: Likely real vulnerabilities
- **Medium Confidence (0.5-0.8)**: Needs manual review
- **Low Confidence (0.0-0.5)**: Possible false positives

### **Severity Levels**
- **Critical**: Immediate threat, can cause total loss
- **High**: Significant impact, can cause major losses
- **Medium**: Moderate impact, can cause losses
- **Low**: Minor impact, best practice violations

## 🎯 Key Benefits

### **🎯 Specialized Expertise**
Each agent has unique focus and expertise:
- Adversarial thinking for attack vectors
- Defensive thinking for security gaps
- Economic analysis for MEV/arbitrage
- Formal verification for mathematical proofs

### **🔄 Collaborative Analysis**
Agents build on each other's findings:
- Share insights between agents
- Cross-validate findings
- Iterative refinement
- Comprehensive coverage

### **🧠 Diverse Perspectives**
Multiple viewpoints on the same code:
- Attacker perspective
- Auditor perspective
- Economic perspective
- Mathematical perspective

### **📊 Comprehensive Coverage**
No vulnerability type missed:
- Traditional vulnerabilities
- Novel attack vectors
- Economic exploits
- Integration issues

### **🎭 Balanced Approach**
High recall + high precision:
- Auditor finds everything
- Critic filters false positives
- Best of both worlds

## 🔧 Advanced Configuration

### **Custom Agent Temperatures**
```python
# Adjust agent creativity vs precision
adversarial_temp = 0.8  # More creative
defensive_temp = 0.3    # More precise
economic_temp = 0.5      # Balanced
```

### **Focus on Specific Vulnerability Types**
```python
# Edit config.py to focus on specific patterns
ENABLED_PATTERNS = [
    "reentrancy",
    "oracle_manipulation", 
    "flash_loan_attack",
    "economic_exploit"
]
```

### **Custom Prompt Templates**
```yaml
# Edit advanced/prompt_chain_config.yaml
prompt_templates:
  adversarial: |
    You are a sophisticated attacker...
    Focus on: {{focus_areas}}
    Temperature: {{temperature}}
```

## 🚀 Best Practices

### **1. Always Use Multi-Agent Analysis**
```bash
# Don't skip AI analysis
./hunt Contract.sol --no-fuzzing  # Good
./hunt Contract.sol --quick       # Less comprehensive
```

### **2. Validate High-Severity Findings**
- Review critical findings manually
- Write PoC tests for high-confidence issues
- Cross-reference with other tools

### **3. Use Cross-Contract Analysis**
```bash
# Analyze entire protocols
./hunt protocol/ --no-fuzzing
```

### **4. Leverage Learning System**
- Tool gets smarter with each analysis
- Patterns learned from previous scans
- Adaptive weights based on accuracy

### **5. Combine with Manual Review**
- Use as starting point for manual audit
- Focus on high-confidence findings
- Validate with formal verification

## 🎯 Comparison with Claude Code Analysis

| Feature | Claude Code Analysis | Advanced Web3 Bug Hunter |
|---------|---------------------|-------------------------|
| **Multi-Agent** | ✅ Multiple perspectives | ✅ 7 specialized agents |
| **Specialized Expertise** | ✅ General coding | ✅ Web3 security focused |
| **Learning** | ❌ Static | ✅ Continuous learning |
| **Cross-Contract** | ❌ Single file | ✅ Multi-contract analysis |
| **Economic Analysis** | ❌ Limited | ✅ MEV/arbitrage focus |
| **Formal Verification** | ❌ Limited | ✅ Z3 symbolic execution |
| **PoC Generation** | ❌ No | ✅ Automatic exploit demos |
| **Historical Patterns** | ❌ Limited | ✅ Learned from real exploits |

## 🎉 Conclusion

The Advanced Web3 Bug Hunter provides a sophisticated multi-agent audit environment that rivals and exceeds Claude's code analysis capabilities for smart contract security. With 7 specialized agents, continuous learning, and comprehensive coverage, it's the most advanced Web3 security analysis tool available.

**Start using it today:**
```bash
source .venv/bin/activate
export XAI_API_KEY="your-key"
./hunt Contract.sol --no-fuzzing
```
