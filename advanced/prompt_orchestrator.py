"""
Prompt Orchestrator - Multi-Stage LLM Prompt Chaining
Orchestrates different prompt strategies and tracks effectiveness
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import hashlib


class PromptStrategy(Enum):
    """Different prompt strategies for different analysis stages"""
    ADVERSARIAL = "adversarial"  # Think like an attacker
    DEFENSIVE = "defensive"  # Think like an auditor
    CREATIVE = "creative"  # Explore novel patterns
    TECHNICAL = "technical"  # Deep technical analysis
    ECONOMIC = "economic"  # Economic incentive analysis
    COMPOSABILITY = "composability"  # Cross-protocol analysis


@dataclass
class PromptTemplate:
    """Template for LLM prompts"""
    name: str
    strategy: PromptStrategy
    template: str
    temperature: float
    max_tokens: int
    system_message: str = ""
    variables: List[str] = field(default_factory=list)
    
    
@dataclass
class PromptResult:
    """Result from executing a prompt"""
    prompt_id: str
    strategy: PromptStrategy
    prompt_used: str
    response: str
    temperature: float
    timestamp: str
    success: bool
    error_message: str = ""
    tokens_used: int = 0
    

@dataclass
class PromptFeedback:
    """Feedback on prompt effectiveness"""
    prompt_id: str
    strategy: PromptStrategy
    success_rate: float
    avg_confidence: float
    hypotheses_generated: int
    true_positives: int
    false_positives: int
    effectiveness_score: float
    last_updated: str


class PromptOrchestrator:
    """
    Orchestrates multi-stage LLM prompting with feedback loops
    Optimizes prompts based on historical success rates
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.prompt_templates: Dict[str, PromptTemplate] = {}
        self.prompt_history: List[PromptResult] = []
        self.prompt_feedback: Dict[str, PromptFeedback] = {}
        self._initialize_templates()
        
    def _initialize_templates(self):
        """Initialize standard prompt templates"""
        
        # Adversarial prompt
        self.register_template(PromptTemplate(
            name="adversarial_discovery",
            strategy=PromptStrategy.ADVERSARIAL,
            template="""You are an expert ethical hacker analyzing smart contracts.
Think like an attacker. Find vulnerabilities that could be exploited for profit.

Contract Type: {contract_type}
Contract Code:
```solidity
{contract_code}
```

Known Issues:
{static_results}

Find exploitable vulnerabilities. For each:
1. Attack vector
2. Exploit scenario (step-by-step)
3. Potential profit/impact
4. Required conditions
5. Difficulty level

Focus on: reentrancy, oracle manipulation, economic exploits, access control bypasses.

Output as JSON: {{"vulnerabilities": [...]}}""",
            temperature=0.7,
            max_tokens=2000,
            system_message="You are a security researcher finding exploitable bugs.",
            variables=["contract_type", "contract_code", "static_results"]
        ))
        
        # Creative exploration prompt
        self.register_template(PromptTemplate(
            name="creative_exploration",
            strategy=PromptStrategy.CREATIVE,
            template="""You are a creative security researcher discovering novel vulnerabilities.
Think beyond standard patterns. Explore unconventional attack vectors.

Contract Code:
```solidity
{contract_code}
```

Generate NOVEL vulnerability hypotheses. Think creatively about:
- Unusual state transition bugs
- Economic incentive manipulation
- Cross-contract race conditions
- Oracle manipulation techniques
- Composability risks
- Edge cases in math operations

For each hypothesis:
1. Type of vulnerability
2. Description
3. Why it's novel/unconventional
4. Attack scenario
5. Confidence level (0.0-1.0)

Output as JSON: {{"hypotheses": [...]}}""",
            temperature=0.9,
            max_tokens=2500,
            system_message="You are discovering novel vulnerabilities.",
            variables=["contract_code"]
        ))
        
        # Technical validation prompt
        self.register_template(PromptTemplate(
            name="technical_validation",
            strategy=PromptStrategy.TECHNICAL,
            template="""You are a technical auditor validating vulnerability hypotheses.

Hypotheses to validate:
{hypotheses}

Contract Code:
```solidity
{contract_code}
```

For each hypothesis, provide technical analysis:
1. Is it technically feasible?
2. Specific code patterns that enable/prevent it
3. Required preconditions
4. Proof of concept outline
5. Updated confidence (0.0-1.0)
6. Specific line numbers involved

Be precise and technical. Reject implausible hypotheses.

Output as JSON: {{"validated_hypotheses": [...]}}""",
            temperature=0.3,
            max_tokens=3000,
            system_message="You are validating vulnerabilities with technical precision.",
            variables=["hypotheses", "contract_code"]
        ))
        
        # Economic analysis prompt
        self.register_template(PromptTemplate(
            name="economic_analysis",
            strategy=PromptStrategy.ECONOMIC,
            template="""You are a DeFi economist analyzing economic vulnerabilities.

Contract Code:
```solidity
{contract_code}
```

Analyze economic attack vectors:
1. Flash loan attacks
2. MEV opportunities
3. Incentive misalignment
4. Economic arbitrage exploits
5. Governance manipulation
6. Token economic flaws

For each vulnerability:
- Economic mechanism involved
- Profit calculation
- Required capital
- Impact on protocol

Output as JSON: {{"economic_vulnerabilities": [...]}}""",
            temperature=0.6,
            max_tokens=2000,
            system_message="You are analyzing economic vulnerabilities.",
            variables=["contract_code"]
        ))
        
        # Cross-protocol analysis prompt
        self.register_template(PromptTemplate(
            name="cross_protocol_analysis",
            strategy=PromptStrategy.COMPOSABILITY,
            template="""You are analyzing cross-protocol and composability risks.

Contract Code:
```solidity
{contract_code}
```

Contract Type: {contract_type}

Analyze:
1. External dependencies and risks
2. Bridge vulnerabilities
3. Cross-chain issues
4. Oracle dependencies
5. Protocol integration flaws
6. Composability attack vectors

For each risk:
- Dependency chain
- Failure modes
- Attack scenarios
- Mitigation difficulty

Output as JSON: {{"composability_risks": [...]}}""",
            temperature=0.7,
            max_tokens=2000,
            system_message="You are analyzing cross-protocol risks.",
            variables=["contract_code", "contract_type"]
        ))
        
    def register_template(self, template: PromptTemplate):
        """Register a new prompt template"""
        self.prompt_templates[template.name] = template
        
    def execute_prompt(self,
                      template_name: str,
                      variables: Dict[str, Any],
                      custom_temperature: Optional[float] = None) -> PromptResult:
        """
        Execute a prompt template with given variables
        """
        if template_name not in self.prompt_templates:
            raise ValueError(f"Template '{template_name}' not found")
            
        template = self.prompt_templates[template_name]
        
        # Fill template with variables
        try:
            prompt = template.template.format(**variables)
        except KeyError as e:
            return PromptResult(
                prompt_id=self._generate_id(),
                strategy=template.strategy,
                prompt_used="",
                response="",
                temperature=template.temperature,
                timestamp=datetime.now().isoformat(),
                success=False,
                error_message=f"Missing variable: {e}"
            )
        
        # Use custom temperature if provided
        temperature = custom_temperature if custom_temperature is not None else template.temperature
        
        # Execute LLM call
        result = self._call_llm(
            prompt=prompt,
            temperature=temperature,
            max_tokens=template.max_tokens,
            system_message=template.system_message,
            strategy=template.strategy
        )
        
        # Store in history
        self.prompt_history.append(result)
        
        return result
    
    def execute_chain(self,
                     chain_config: List[Dict[str, Any]],
                     initial_variables: Dict[str, Any]) -> List[PromptResult]:
        """
        Execute a chain of prompts where each can use results from previous
        
        chain_config: List of dicts with 'template' and optional 'variable_mapper'
        """
        results = []
        variables = initial_variables.copy()
        
        for step in chain_config:
            template_name = step['template']
            variable_mapper = step.get('variable_mapper', None)
            
            # Map variables from previous results if mapper provided
            if variable_mapper and results:
                mapped_vars = variable_mapper(results, variables)
                variables.update(mapped_vars)
            
            # Execute prompt
            result = self.execute_prompt(template_name, variables)
            results.append(result)
            
            # Add result to variables for next step
            variables[f'result_{len(results)}'] = result.response
            
        return results
    
    def optimize_prompt(self,
                       template_name: str,
                       feedback_data: Dict[str, Any]) -> PromptTemplate:
        """
        Optimize a prompt template based on feedback
        Adjusts temperature, length, or template content
        """
        if template_name not in self.prompt_templates:
            raise ValueError(f"Template '{template_name}' not found")
            
        template = self.prompt_templates[template_name]
        
        # Calculate effectiveness metrics
        success_rate = feedback_data.get('success_rate', 0.5)
        false_positive_rate = feedback_data.get('false_positive_rate', 0.5)
        
        # Adjust temperature based on performance
        if false_positive_rate > 0.5:
            # Too many false positives, reduce creativity
            template.temperature = max(0.1, template.temperature - 0.1)
        elif success_rate > 0.8 and false_positive_rate < 0.3:
            # Good performance, can increase creativity slightly
            template.temperature = min(0.95, template.temperature + 0.05)
        
        # Update feedback tracking
        self._update_prompt_feedback(template_name, feedback_data)
        
        return template
    
    def get_best_prompts_for_strategy(self, strategy: PromptStrategy, top_n: int = 3) -> List[str]:
        """Get the most effective prompts for a given strategy"""
        strategy_prompts = [
            (name, feedback) 
            for name, template in self.prompt_templates.items()
            for feedback_name, feedback in self.prompt_feedback.items()
            if template.strategy == strategy and feedback_name == name
        ]
        
        # Sort by effectiveness score
        strategy_prompts.sort(key=lambda x: x[1].effectiveness_score, reverse=True)
        
        return [name for name, _ in strategy_prompts[:top_n]]
    
    def _call_llm(self,
                  prompt: str,
                  temperature: float,
                  max_tokens: int,
                  system_message: str,
                  strategy: PromptStrategy) -> PromptResult:
        """Call LLM with error handling"""
        prompt_id = self._generate_id()
        
        if not self.llm_client:
            return PromptResult(
                prompt_id=prompt_id,
                strategy=strategy,
                prompt_used=prompt,
                response="{}",
                temperature=temperature,
                timestamp=datetime.now().isoformat(),
                success=False,
                error_message="No LLM client configured"
            )
        
        try:
            # Call LLM client
            response = self.llm_client.query_llm(
                prompt=prompt,
                temperature=temperature
            )
            
            return PromptResult(
                prompt_id=prompt_id,
                strategy=strategy,
                prompt_used=prompt,
                response=response,
                temperature=temperature,
                timestamp=datetime.now().isoformat(),
                success=True,
                tokens_used=len(prompt.split()) + len(response.split())  # Rough estimate
            )
            
        except Exception as e:
            return PromptResult(
                prompt_id=prompt_id,
                strategy=strategy,
                prompt_used=prompt,
                response="",
                temperature=temperature,
                timestamp=datetime.now().isoformat(),
                success=False,
                error_message=str(e)
            )
    
    def _update_prompt_feedback(self, template_name: str, feedback_data: Dict[str, Any]):
        """Update feedback tracking for a prompt"""
        if template_name not in self.prompt_templates:
            return
            
        template = self.prompt_templates[template_name]
        
        # Calculate effectiveness score
        success_rate = feedback_data.get('success_rate', 0.0)
        true_positives = feedback_data.get('true_positives', 0)
        false_positives = feedback_data.get('false_positives', 0)
        
        total_findings = true_positives + false_positives
        precision = true_positives / total_findings if total_findings > 0 else 0.0
        
        effectiveness_score = (success_rate * 0.5) + (precision * 0.5)
        
        feedback = PromptFeedback(
            prompt_id=template_name,
            strategy=template.strategy,
            success_rate=success_rate,
            avg_confidence=feedback_data.get('avg_confidence', 0.0),
            hypotheses_generated=feedback_data.get('hypotheses_generated', 0),
            true_positives=true_positives,
            false_positives=false_positives,
            effectiveness_score=effectiveness_score,
            last_updated=datetime.now().isoformat()
        )
        
        self.prompt_feedback[template_name] = feedback
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return hashlib.sha256(
            f"{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
    
    def get_prompt_statistics(self) -> Dict[str, Any]:
        """Get statistics about prompt usage and effectiveness"""
        if not self.prompt_history:
            return {
                "total_prompts_executed": 0,
                "success_rate": 0.0,
                "by_strategy": {}
            }
        
        total = len(self.prompt_history)
        successful = len([r for r in self.prompt_history if r.success])
        
        by_strategy = {}
        for result in self.prompt_history:
            strategy = result.strategy.value
            if strategy not in by_strategy:
                by_strategy[strategy] = {"total": 0, "successful": 0}
            by_strategy[strategy]["total"] += 1
            if result.success:
                by_strategy[strategy]["successful"] += 1
        
        return {
            "total_prompts_executed": total,
            "success_rate": successful / total if total > 0 else 0.0,
            "by_strategy": by_strategy,
            "avg_tokens_per_prompt": sum(r.tokens_used for r in self.prompt_history) / total if total > 0 else 0,
            "total_feedback_entries": len(self.prompt_feedback)
        }
    
    def export_feedback(self, filepath: str):
        """Export prompt feedback to JSON file"""
        data = {
            "templates": {
                name: {
                    "strategy": template.strategy.value,
                    "temperature": template.temperature,
                    "max_tokens": template.max_tokens
                }
                for name, template in self.prompt_templates.items()
            },
            "feedback": {
                name: {
                    "strategy": feedback.strategy.value,
                    "success_rate": feedback.success_rate,
                    "effectiveness_score": feedback.effectiveness_score,
                    "true_positives": feedback.true_positives,
                    "false_positives": feedback.false_positives,
                    "last_updated": feedback.last_updated
                }
                for name, feedback in self.prompt_feedback.items()
            },
            "statistics": self.get_prompt_statistics()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def import_feedback(self, filepath: str):
        """Import prompt feedback from JSON file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if 'feedback' in data:
                for name, feedback_data in data['feedback'].items():
                    if name in self.prompt_templates:
                        strategy = PromptStrategy(feedback_data['strategy'])
                        feedback = PromptFeedback(
                            prompt_id=name,
                            strategy=strategy,
                            success_rate=feedback_data['success_rate'],
                            avg_confidence=feedback_data.get('avg_confidence', 0.0),
                            hypotheses_generated=feedback_data.get('hypotheses_generated', 0),
                            true_positives=feedback_data['true_positives'],
                            false_positives=feedback_data['false_positives'],
                            effectiveness_score=feedback_data['effectiveness_score'],
                            last_updated=feedback_data['last_updated']
                        )
                        self.prompt_feedback[name] = feedback
                        
            print(f"✓ Imported prompt feedback from {filepath}")
        except Exception as e:
            print(f"Error importing feedback: {e}")
