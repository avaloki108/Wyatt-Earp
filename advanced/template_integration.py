"""
Integration module connecting exploit templates with LLM-based vulnerability analysis.
Enhances the multi-agent workflow with template-guided exploit generation.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path

from .exploit_template_loader import ExploitTemplateLoader, ExploitTemplateDefinition
from .langgraph_orchestrator import LangGraphOrchestrator


class TemplateEnhancedAnalyzer:
    """
    Connects exploit flow templates with the LangGraph multi-agent orchestrator.
    Enhances vulnerability analysis with proven exploit patterns.
    """
    
    def __init__(
        self,
        llm_client: Any,
        template_loader: Optional[ExploitTemplateLoader] = None,
        orchestrator: Optional[LangGraphOrchestrator] = None
    ):
        """
        Initialize the template-enhanced analyzer.
        
        Args:
            llm_client: LLM client for agent execution
            template_loader: Optional ExploitTemplateLoader instance
            orchestrator: Optional LangGraphOrchestrator instance
        """
        self.llm_client = llm_client
        self.template_loader = template_loader or ExploitTemplateLoader()
        self.orchestrator = orchestrator or LangGraphOrchestrator(llm_client)
        
    def analyze_with_templates(
        self,
        contract_code: str,
        static_analysis_results: Optional[Dict[str, Any]] = None,
        contract_type: str = "unknown",
        vulnerability_hints: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze contract using multi-agent orchestrator enhanced with exploit templates.
        
        Args:
            contract_code: Solidity contract source code
            static_analysis_results: Results from static analysis tools
            contract_type: Type of contract (e.g., "vault", "dex", "lending")
            vulnerability_hints: Optional list of suspected vulnerability types
            
        Returns:
            Dictionary containing analysis results with template-enhanced findings
        """
        # Get relevant templates based on vulnerability hints or contract type
        relevant_templates = self._get_relevant_templates(
            vulnerability_hints=vulnerability_hints,
            contract_type=contract_type,
            static_analysis=static_analysis_results
        )
        
        # Run multi-agent analysis
        result = self.orchestrator.run(
            contract_code=contract_code,
            static_analysis_results=static_analysis_results,
            contract_type=contract_type
        )
        
        # Enhance results with template matching
        enhanced_findings = self._match_findings_to_templates(
            agent_result=result,
            templates=relevant_templates
        )
        
        # Record template usage for learning
        for finding in enhanced_findings:
            if "matched_template" in finding:
                template_id = finding["matched_template"]["template_id"]
                success = finding.get("confidence", 0) > 0.7
                context = {
                    "contract_type": contract_type,
                    "severity": finding.get("severity", "unknown")
                }
                self.template_loader.record_usage(template_id, success=success, context=context)
        
        return {
            "multi_agent_result": result,
            "template_enhanced_findings": enhanced_findings,
            "relevant_templates": [t.to_dict() for t in relevant_templates],
            "template_statistics": self._get_template_statistics()
        }
        
    def _get_relevant_templates(
        self,
        vulnerability_hints: Optional[List[str]] = None,
        contract_type: str = "unknown",
        static_analysis: Optional[Dict[str, Any]] = None
    ) -> List[ExploitTemplateDefinition]:
        """
        Get templates relevant to the suspected vulnerabilities.
        
        Args:
            vulnerability_hints: List of vulnerability class hints
            contract_type: Type of contract
            static_analysis: Static analysis results
            
        Returns:
            List of relevant exploit templates
        """
        relevant = []
        
        # Get templates by vulnerability class hints
        if vulnerability_hints:
            for hint in vulnerability_hints:
                templates = self.template_loader.get_templates_for_class(hint)
                relevant.extend(templates)
        
        # Get templates from static analysis detectors
        if static_analysis and "detectors" in static_analysis:
            for detector_type in static_analysis["detectors"].keys():
                templates = self.template_loader.get_templates_for_class(detector_type)
                relevant.extend(templates)
        
        # If no hints, get high-severity templates as defaults
        if not relevant:
            all_templates = list(self.template_loader.list_templates())
            relevant = [
                t for t in all_templates
                if t.severity in ["critical", "high"]
            ][:5]  # Limit to top 5
        
        # Remove duplicates
        seen_ids = set()
        unique_templates = []
        for template in relevant:
            if template.template_id not in seen_ids:
                unique_templates.append(template)
                seen_ids.add(template.template_id)
        
        # Sort by success rate (if available) and severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        unique_templates.sort(
            key=lambda t: (
                -t.metrics.get("success_rate", 0.5),
                severity_order.get(t.severity, 5)
            )
        )
        
        return unique_templates[:10]  # Return top 10
        
    def _match_findings_to_templates(
        self,
        agent_result: Any,
        templates: List[ExploitTemplateDefinition]
    ) -> List[Dict[str, Any]]:
        """
        Match multi-agent findings to exploit templates.
        
        Args:
            agent_result: Result from LangGraphOrchestrator
            templates: List of relevant templates
            
        Returns:
            List of enhanced findings with template matches
        """
        enhanced = []
        
        # Extract hypotheses and scenarios from agent result
        hypotheses = agent_result.shared_state.get("validated_hypotheses", [])
        scenarios = agent_result.shared_state.get("exploit_scenarios", [])
        
        # Combine hypotheses and scenarios
        all_findings = []
        
        # Process hypotheses
        for hyp in hypotheses:
            if isinstance(hyp, dict):
                all_findings.append({
                    "type": "hypothesis",
                    "name": hyp.get("name", "unknown"),
                    "severity": hyp.get("severity", "medium"),
                    "confidence": hyp.get("confidence", 0.5),
                    "description": hyp.get("description", "")
                })
        
        # Process scenarios
        for scenario in scenarios:
            if isinstance(scenario, dict):
                all_findings.append({
                    "type": "exploit_scenario",
                    "name": scenario.get("name", "unknown"),
                    "severity": scenario.get("severity", "medium"),
                    "confidence": scenario.get("confidence", 0.5),
                    "description": scenario.get("description", ""),
                    "steps": scenario.get("steps", [])
                })
        
        # Match each finding to best template
        for finding in all_findings:
            best_match = self._find_best_template_match(finding, templates)
            
            enhanced_finding = finding.copy()
            if best_match:
                enhanced_finding["matched_template"] = {
                    "template_id": best_match.template_id,
                    "name": best_match.name,
                    "stages": [stage.to_dict() for stage in best_match.stages],
                    "historical_references": best_match.historical_references,
                    "poc_skeletons": best_match.poc_skeletons,
                    "detection_signatures": best_match.detection_signatures
                }
            
            enhanced.append(enhanced_finding)
        
        return enhanced
        
    def _find_best_template_match(
        self,
        finding: Dict[str, Any],
        templates: List[ExploitTemplateDefinition]
    ) -> Optional[ExploitTemplateDefinition]:
        """
        Find the best matching template for a finding.
        
        Args:
            finding: Finding from multi-agent analysis
            templates: List of candidate templates
            
        Returns:
            Best matching template or None
        """
        if not templates:
            return None
        
        finding_name = finding.get("name", "").lower()
        finding_desc = finding.get("description", "").lower()
        
        # Score each template
        scores = []
        for template in templates:
            score = 0.0
            
            # Check name match
            template_name = template.name.lower()
            if finding_name in template_name or template_name in finding_name:
                score += 0.4
            
            # Check vulnerability class match
            for vuln_class in template.vulnerability_classes:
                if vuln_class.lower() in finding_name or vuln_class.lower() in finding_desc:
                    score += 0.3
            
            # Check tag match
            for tag in template.tags:
                if tag.lower() in finding_name or tag.lower() in finding_desc:
                    score += 0.1
            
            # Bonus for high success rate
            success_rate = template.metrics.get("success_rate", 0.0)
            score += success_rate * 0.2
            
            scores.append((score, template))
        
        # Return best match if score is above threshold
        scores.sort(reverse=True, key=lambda x: x[0])
        best_score, best_template = scores[0]
        
        if best_score >= 0.3:  # Minimum threshold
            return best_template
        
        return None
        
    def _get_template_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about template usage and effectiveness.
        
        Returns:
            Dictionary with template statistics
        """
        all_templates = list(self.template_loader.list_templates())
        
        total_usage = sum(
            t.metrics.get("usage_count", 0) for t in all_templates
        )
        
        total_executions = sum(
            t.metrics.get("execution_count", 0) for t in all_templates
        )
        
        avg_success_rate = 0.0
        if all_templates:
            avg_success_rate = sum(
                t.metrics.get("success_rate", 0.0) for t in all_templates
            ) / len(all_templates)
        
        most_used = sorted(
            all_templates,
            key=lambda t: t.metrics.get("usage_count", 0),
            reverse=True
        )[:5]
        
        highest_success = sorted(
            all_templates,
            key=lambda t: t.metrics.get("success_rate", 0.0),
            reverse=True
        )[:5]
        
        return {
            "total_templates": len(all_templates),
            "total_usage": total_usage,
            "total_executions": total_executions,
            "average_success_rate": avg_success_rate,
            "most_used_templates": [
                {"id": t.template_id, "name": t.name, "usage": t.metrics.get("usage_count", 0)}
                for t in most_used
            ],
            "highest_success_templates": [
                {"id": t.template_id, "name": t.name, "success_rate": t.metrics.get("success_rate", 0.0)}
                for t in highest_success
            ]
        }
        
    def get_template_recommendations(
        self,
        contract_type: str,
        past_findings: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get recommended templates based on contract type and past findings.
        
        Args:
            contract_type: Type of contract
            past_findings: Optional list of past vulnerability findings
            
        Returns:
            List of recommended template IDs with reasoning
        """
        recommendations = []
        
        # Get all templates
        all_templates = list(self.template_loader.list_templates())
        
        # Score templates based on various factors
        for template in all_templates:
            score = 0.0
            reasons = []
            
            # High success rate
            success_rate = template.metrics.get("success_rate", 0.0)
            if success_rate > 0.7:
                score += 0.3
                reasons.append(f"High success rate ({success_rate:.1%})")
            
            # Frequently used
            usage_count = template.metrics.get("usage_count", 0)
            if usage_count > 10:
                score += 0.2
                reasons.append(f"Frequently used ({usage_count} times)")
            
            # Critical severity
            if template.severity == "critical":
                score += 0.3
                reasons.append("Critical severity")
            elif template.severity == "high":
                score += 0.2
                reasons.append("High severity")
            
            # Match with past findings
            if past_findings:
                for finding in past_findings:
                    finding_name = finding.get("name", "").lower()
                    for vuln_class in template.vulnerability_classes:
                        if vuln_class.lower() in finding_name:
                            score += 0.2
                            reasons.append(f"Matches past finding: {finding_name}")
                            break
            
            if score > 0.3:  # Only recommend if above threshold
                recommendations.append({
                    "template_id": template.template_id,
                    "name": template.name,
                    "score": score,
                    "reasons": reasons,
                    "severity": template.severity,
                    "success_rate": success_rate
                })
        
        # Sort by score
        recommendations.sort(key=lambda x: x["score"], reverse=True)
        
        return recommendations[:10]  # Top 10 recommendations


__all__ = ["TemplateEnhancedAnalyzer"]
