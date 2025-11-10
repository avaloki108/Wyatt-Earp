# Weaponized Cognitive Architecture

## Overview

The Weaponized Cognitive Architecture is an advanced AI-powered vulnerability detection system that combines multiple specialized agents, exploit templates, external knowledge ingestion, and self-upgrading learning capabilities to find security vulnerabilities in smart contracts.

## Architecture Components

### 1. Multi-Agent LLM Orchestra (LangGraph DAG)

Located in: `advanced/langgraph_orchestrator.py`

The system uses 5 specialized agents orchestrated through a LangGraph Directed Acyclic Graph (DAG):

#### Agents:

1. **Hunter Agent** (Temperature: 0.8)
   - Role: Initial vulnerability hypothesis generation
   - Uses high creativity to explore novel attack vectors
   - Analyzes contract code and static analysis results
   - Outputs: List of vulnerability hypotheses

2. **Analogical Reasoner** (Temperature: 0.65)
   - Role: Enhance hypotheses with historical context
   - Draws parallels to known exploits (DAO, Wormhole, etc.)
   - Uses learned patterns from exploit database
   - Outputs: Enhanced hypotheses with historical references

3. **Skeptical Validator** (Temperature: 0.35)
   - Role: Critical evaluation of hypotheses
   - Filters false positives
   - Can trigger rewrites if quality is low
   - Outputs: Validated and rejected hypotheses

4. **Exploit Synthesizer** (Temperature: 0.3)
   - Role: Generate concrete exploit scenarios
   - Creates step-by-step attack plans
   - Matches to exploit templates
   - Outputs: Executable exploit scenarios

5. **Self-Evaluation Agent** (Temperature: 0.25)
   - Role: Final quality check
   - Assesses confidence and completeness
   - Can trigger rewrites if needed
   - Outputs: Final assessment and approval

#### Workflow:

```
START → Hunter → Analogical Reasoner → Skeptical Validator
                                              ↓
                                         [Decision]
                                              ↓
                    ┌─────────────────────────┴─────────────────┐
                    ↓                                           ↓
              Exploit Synthesizer                         [Terminate]
                    ↓
            Self-Evaluation
                    ↓
              [Final Decision]
                    ↓
        ┌───────────┴────────────┐
        ↓                        ↓
    [Approve]               [Rewrite] → (back to Hunter)
```

**Key Features:**
- Conditional routing based on agent decisions
- Shared memory for state propagation
- Rewrite loops for quality improvement (max iterations: configurable)
- LangGraph checkpointing for state persistence

### 2. Exploit Flow Template Library

Located in: `templates/exploit_flows/`, `advanced/exploit_template_loader.py`

#### Template Structure (YAML):

```yaml
metadata:
  id: template-id
  name: Exploit Pattern Name
  description: Detailed description
  severity: critical|high|medium|low
  tags: [tag1, tag2]
  vulnerability_classes: [vuln_type1, vuln_type2]

stages:
  - name: Stage Name
    objective: What to accomplish
    actions: [action1, action2]
    detection_signatures:
      onchain: [signature1]
      offchain: [signature2]
    poc_snippet: |
      // Code example

detection_signatures:
  onchain: [patterns]
  offchain: [patterns]

poc_skeletons:
  foundry:
    code: |
      // Full PoC template
  hardhat:
    code: |
      // Full PoC template

historical_references:
  - incident: Historical exploit name
    year: 2021
    details: What happened
    link: URL

provenance:
  source: Where template came from
  confidence: high|medium|low

metrics:
  usage_count: 0
  execution_count: 0
  success_count: 0
  success_rate: 0.0
```

#### Available Templates:

1. **State Desynchronization** - Cross-contract state race conditions
2. **Type Confusion** - Type casting vulnerabilities
3. **Flash Loan Cascade** - Multi-step flash loan exploits
4. **Bridge Replay** - Cross-chain replay attacks
5. **Cross-Chain Fee Desync** - Fee manipulation across chains
6. **Optimistic Oracle Drift** - Oracle manipulation
7. **Gas Griefing** - DoS via gas exhaustion
8. **Signature Malleability** - Signature replay attacks
9. **Governance Queue Manipulation** - DAO voting exploits
10. **Liquidity Pool Rounding** - Precision loss exploits

**Template Features:**
- Usage tracking and success rate metrics
- Historical exploit references
- Multi-framework PoC skeletons (Foundry, Hardhat)
- Detection signatures for both on-chain and off-chain monitoring
- Provenance tracking for template sources

### 3. External Knowledge Ingestion Pipeline

Located in: `advanced/data_sources/`, `advanced/auto_learning.py`

#### Data Sources:

1. **SmartBugs Wild** (`smartbugs/smartbugs-wild`)
   - Dataset of real-world vulnerable contracts
   - Updated regularly with new samples

2. **DeFiHackLabs** (`SunWeb3Sec/DeFiHackLabs`)
   - Proof-of-concept exploits for major DeFi hacks
   - Foundry-based exploit demonstrations

3. **Cyfrin/Aderyn** (`Cyfrin/aderyn`)
   - Detection rule updates from Aderyn static analyzer
   - Rust-based detector patterns

4. **Solodit** (`Solodit/solodit_content`)
   - Audit reports and vulnerability findings
   - Markdown-based security findings

#### Fetcher Features:

- **Rate Limiting**: Respects GitHub API limits
- **Authentication**: Supports GitHub tokens for higher limits
- **Pagination**: Automatically fetches all available data
- **Incremental Updates**: Tracks processed records to avoid duplicates
- **Code Artifact Collection**: Extracts Solidity code snippets
- **Provenance Tracking**: Records source and timestamp for all data

#### Enhanced Pattern Extraction:

Located in: `advanced/enhanced_pattern_extraction.py`

Uses LLM to extract reusable vulnerability patterns:

```python
extractor = EnhancedPatternExtractor(llm_client)

# Extract from hack report
pattern = extractor.extract_from_hack_record(hack_record)

# Extract from code
patterns = extractor.extract_from_code_artifact(code_artifact)

# Batch extraction
all_patterns = extractor.batch_extract(hack_records)
```

**Extraction Process:**
1. Build chain-of-thought prompt with hack details
2. Query LLM for structured pattern extraction
3. Parse and validate response
4. Add provenance metadata
5. Deduplicate patterns
6. Store with metrics

### 4. Self-Upgrading Learning System

Located in: `advanced/adaptive_learning.py`

#### Components:

##### 4.1 Prompt Optimizer

Tracks effectiveness of prompts per agent/stage:

```python
optimizer = PromptOptimizer()

# Track results
optimizer.track_hypothesis_result(
    prompt_stage="hunter",
    temperature=0.8,
    was_successful=True
)

# Get optimized temperature
temp = optimizer.get_optimized_temperature("hunter")

# Get recommendations
recommendations = optimizer.get_recommendations()
```

**Features:**
- Success rate calculation
- Average temperature tracking
- Automatic temperature adjustment
- Performance recommendations

##### 4.2 Verification Tuner

Auto-tunes verification layer weights:

```python
tuner = VerificationTuner()

# Record accuracy
tuner.record_layer_accuracy("static", 0.9)
tuner.record_layer_accuracy("symbolic", 0.7)

# Adjust weights
tuner.adjust_weights(min_samples=10)

# Get current weights
weights = tuner.get_weights()
```

**Verification Layers:**
- Static analysis (Slither, Mythril)
- Symbolic execution (Z3)
- Dynamic testing (Echidna)
- Behavioral analysis (custom)

**Features:**
- Accuracy tracking per layer
- Proportional weight adjustment
- Automatic normalization
- Persistent state

##### 4.3 Pattern Learner

Extracts new patterns from successful detections:

```python
learner = PatternLearner()

# Extract patterns from verified vulnerabilities
new_patterns = learner.extract_patterns(verified_vulns)

# Get all learned patterns
patterns = learner.get_patterns()
```

**Features:**
- Automatic pattern signature generation
- Deduplication
- Metadata enrichment
- Temporal tracking

##### 4.4 User Feedback Processor

Integrates user feedback for continuous improvement:

```python
processor = UserFeedbackProcessor()

# Process feedback
feedback = processor.process_feedback(
    vulnerability_id="vuln-001",
    feedback_type="false_positive",
    pattern_name="reentrancy",
    details={"reason": "Protected by mutex"}
)

# Get summary
summary = processor.get_feedback_summary()
```

**Feedback Types:**
- `confirmed` - Vulnerability is real
- `false_positive` - Not a vulnerability
- `severity_adjustment` - Severity needs correction

##### 4.5 Adaptive Learning System

Coordinates all learning components:

```python
system = AdaptiveLearningSystem()

# Process scan results
result = await system.process_scan_results(
    scan_results,
    user_feedback=feedback_dict
)

# Get metrics
metrics = system.get_comprehensive_metrics()

# Save/load state
state = system.save_state()
system.load_state(state)
```

**Integration:**
- Automatic pattern extraction
- Prompt optimization
- Weight tuning
- Feedback processing
- State persistence

### 5. Template Integration

Located in: `advanced/template_integration.py`

Connects templates with multi-agent analysis:

```python
analyzer = TemplateEnhancedAnalyzer(llm_client)

# Analyze with template enhancement
result = analyzer.analyze_with_templates(
    contract_code=code,
    static_analysis_results=static_results,
    contract_type="vault",
    vulnerability_hints=["reentrancy", "oracle_manipulation"]
)

# Get template recommendations
recommendations = analyzer.get_template_recommendations(
    contract_type="dex",
    past_findings=past_vulns
)
```

**Features:**
- Automatic template selection based on hints
- Finding-to-template matching
- Usage tracking
- Success rate metrics
- Template recommendations

### 6. Continuous Learning Scheduler

Located in: `scripts/continuous_learning.py`

Scheduled ingestion of new exploit intelligence:

```bash
# Run daily ingestion
python scripts/continuous_learning.py --days 1

# GitHub only
python scripts/continuous_learning.py --github-only --days 7
```

**Cron Example:**
```bash
# Daily at 2 AM
0 2 * * * cd /path/to/Wyatt-Earp && python scripts/continuous_learning.py --days 1
```

## Usage Examples

### Basic Multi-Agent Analysis

```python
from advanced.langgraph_orchestrator import LangGraphOrchestrator
from llm.llm_integration import LLMIntegration

# Initialize
llm = LLMIntegration()
orchestrator = LangGraphOrchestrator(llm)

# Run analysis
result = orchestrator.run(
    contract_code=solidity_code,
    static_analysis_results=slither_results,
    contract_type="vault"
)

# Access results
for agent_run in result.agent_runs:
    print(f"Agent: {agent_run.name}")
    print(f"Decision: {agent_run.decision}")
```

### Template-Enhanced Analysis

```python
from advanced.template_integration import TemplateEnhancedAnalyzer

analyzer = TemplateEnhancedAnalyzer(llm)

result = analyzer.analyze_with_templates(
    contract_code=code,
    static_analysis_results=static_results,
    vulnerability_hints=["flash_loan", "oracle"]
)

# Enhanced findings with templates
for finding in result["template_enhanced_findings"]:
    print(f"Finding: {finding['name']}")
    if "matched_template" in finding:
        template = finding["matched_template"]
        print(f"Template: {template['name']}")
        print(f"Historical refs: {template['historical_references']}")
```

### Continuous Learning

```python
from advanced.auto_learning import AutoLearner
from advanced.enhanced_pattern_extraction import EnhancedPatternExtractor

learner = AutoLearner()
extractor = EnhancedPatternExtractor(llm)

# Fetch and learn from recent hacks
new_patterns = learner.learn_from_github_exploits(days=7)

# Extract patterns with enhanced LLM
records = learner.fetch_recent_hacks(days=1)
enhanced_patterns = extractor.batch_extract(records)

# Get summary
summary = extractor.summarize_extraction_session(enhanced_patterns)
```

## Testing

Comprehensive test suite with 139+ tests:

```bash
# Run all tests
pytest tests/ -v

# Run specific test suites
pytest tests/test_langgraph_integration.py -v
pytest tests/test_exploit_templates.py -v
pytest tests/test_knowledge_ingestion.py -v
pytest tests/test_self_upgrading.py -v
```

## Configuration

### LangGraph Configuration

Edit `advanced/prompt_chain_config.yaml`:

```yaml
langgraph:
  model: gpt-4-turbo
  max_rewrites: 1
  agents:
    hunter:
      temperature: 0.85
      prompt: |
        You are the Hunter Agent...
    # ... other agents
```

### Template Directory

Templates in: `templates/exploit_flows/*.yaml`

Add new templates following the YAML structure documented above.

### Environment Variables

```bash
# GitHub API token for higher rate limits
export GITHUB_TOKEN="ghp_..."

# LLM API keys
export XAI_API_KEY="..."
export OPENAI_API_KEY="..."
export ANTHROPIC_API_KEY="..."
```

## Performance Metrics

The system tracks:
- **Prompt effectiveness**: Success rate per agent/stage
- **Template success rates**: Which templates find vulnerabilities
- **Verification accuracy**: Per-layer accuracy metrics
- **Pattern quality**: Confidence and validation rates
- **User feedback**: False positive vs. true positive rates

## Future Enhancements

Potential additions:
1. Real-time exploit monitoring via websockets
2. Integration with on-chain monitoring tools
3. Automated PoC execution in sandboxes
4. Cross-chain vulnerability correlation
5. Community pattern sharing network
6. Advanced graph analysis for multi-contract vulnerabilities

## References

- LangGraph: https://github.com/langchain-ai/langgraph
- SmartBugs Wild: https://github.com/smartbugs/smartbugs-wild
- DeFiHackLabs: https://github.com/SunWeb3Sec/DeFiHackLabs
- Cyfrin Aderyn: https://github.com/Cyfrin/aderyn
- Solodit: https://github.com/Solodit/solodit_content
