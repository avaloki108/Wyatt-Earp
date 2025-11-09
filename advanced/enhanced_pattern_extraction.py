"""
Enhanced LLM-based pattern extraction for continuous learning.
Uses structured prompts to extract vulnerability patterns from external sources.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

LOGGER = logging.getLogger(__name__)


class EnhancedPatternExtractor:
    """
    Advanced LLM-based pattern extraction from exploit reports and code.
    Uses chain-of-thought prompting for better pattern quality.
    """
    
    def __init__(self, llm_client: Any):
        """
        Initialize the pattern extractor.
        
        Args:
            llm_client: LLM client with query_llm method
        """
        self.llm = llm_client
        
    def extract_from_hack_record(self, hack: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract a vulnerability pattern from a hack record using LLM analysis.
        
        Args:
            hack: Dictionary containing hack information
            
        Returns:
            Extracted pattern or None if extraction fails
        """
        # Build comprehensive analysis prompt
        prompt = self._build_extraction_prompt(hack)
        
        try:
            # Query LLM with structured prompt
            response = self.llm.query_llm(
                prompt,
                model="gpt-4",  # Use best available model
                temperature=0.3  # Lower temperature for more precise extraction
            )
            
            # Parse response
            pattern = self._parse_llm_response(response)
            
            # Enhance with provenance
            pattern["provenance"] = {
                "source": hack.get("source", "unknown"),
                "source_id": hack.get("uid", "unknown"),
                "extracted_at": datetime.now().isoformat(),
                "extraction_method": "llm_enhanced",
                "original_title": hack.get("title", "")
            }
            
            # Validate pattern structure
            if self._validate_pattern(pattern):
                return pattern
            else:
                LOGGER.warning("Extracted pattern failed validation: %s", pattern.get("name"))
                return None
                
        except Exception as e:
            LOGGER.error("Failed to extract pattern from hack: %s", e)
            return None
            
    def extract_from_code_artifact(self, artifact: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract patterns from code artifacts (Solidity files, patches, etc.).
        
        Args:
            artifact: Code artifact from GitHub or other source
            
        Returns:
            List of extracted patterns
        """
        patterns = []
        
        files = artifact.get("files", [])
        for file_info in files:
            if not file_info.get("filename", "").endswith((".sol", ".vy")):
                continue
                
            # Get code content
            code = file_info.get("raw_preview") or file_info.get("patch", "")
            if not code:
                continue
                
            try:
                pattern = self._extract_from_code(code, file_info)
                if pattern:
                    patterns.append(pattern)
            except Exception as e:
                LOGGER.debug("Failed to extract from code: %s", e)
                
        return patterns
        
    def _build_extraction_prompt(self, hack: Dict[str, Any]) -> str:
        """
        Build a comprehensive chain-of-thought prompt for pattern extraction.
        
        Args:
            hack: Hack information
            
        Returns:
            Formatted prompt string
        """
        title = hack.get("title", "Unknown Hack")
        description = hack.get("description", "")
        code = hack.get("exploit_code_snippet", "")
        severity = hack.get("impact", hack.get("severity", "medium"))
        
        prompt = f"""You are a smart contract security expert analyzing a recent exploit.

EXPLOIT DETAILS:
Title: {title}
Description: {description}
Severity: {severity}

CODE SNIPPET:
```solidity
{code}
```

TASK:
Extract a reusable vulnerability pattern from this exploit that can be used to detect similar vulnerabilities in other contracts.

ANALYSIS STEPS:
1. Identify the root cause vulnerability type
2. Determine the attack vector and preconditions
3. Extract detection signatures (function patterns, state patterns)
4. Formulate remediation guidance
5. Identify similar historical exploits

RESPOND IN JSON FORMAT:
{{
  "name": "Brief, descriptive pattern name (e.g., 'TWAP Oracle Manipulation')",
  "vulnerability_class": "Main vulnerability category (e.g., 'oracle_manipulation', 'reentrancy')",
  "severity": "critical|high|medium|low",
  "description": "Detailed explanation of the vulnerability pattern",
  "attack_vector": "Step-by-step attack execution",
  "preconditions": ["List of conditions required for exploit"],
  "detection_signatures": {{
    "function_patterns": ["Solidity function signatures to detect"],
    "state_patterns": ["State variable patterns"],
    "event_patterns": ["Event emission patterns"]
  }},
  "remediation": "Specific fix recommendation",
  "similar_exploits": ["Names of similar historical exploits"],
  "confidence": 0.0-1.0
}}

Provide ONLY the JSON response, no additional text.
"""
        return prompt
        
    def _extract_from_code(self, code: str, file_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract pattern directly from vulnerable code.
        
        Args:
            code: Solidity or Vyper code
            file_info: File metadata
            
        Returns:
            Extracted pattern or None
        """
        prompt = f"""Analyze this smart contract code for vulnerabilities and extract a detection pattern.

FILENAME: {file_info.get('filename', 'Unknown')}
CODE:
```solidity
{code[:2000]}  
```

Identify any vulnerability patterns and respond in JSON format:
{{
  "name": "Pattern name",
  "vulnerability_class": "Vulnerability type",
  "severity": "Severity level",
  "description": "Description",
  "detection_signatures": {{
    "function_patterns": ["Patterns"],
    "state_patterns": ["Patterns"]
  }},
  "remediation": "Fix recommendation",
  "confidence": 0.0-1.0
}}

If no clear vulnerability is found, respond with {{"found": false}}.
"""
        
        try:
            response = self.llm.query_llm(prompt, model="gpt-4", temperature=0.2)
            pattern = self._parse_llm_response(response)
            
            if pattern and pattern.get("found") is not False:
                pattern["provenance"] = {
                    "source": "code_analysis",
                    "filename": file_info.get("filename"),
                    "extracted_at": datetime.now().isoformat()
                }
                return pattern
        except Exception as e:
            LOGGER.debug("Code extraction failed: %s", e)
            
        return None
        
    def _parse_llm_response(self, response: Any) -> Dict[str, Any]:
        """
        Parse LLM response into structured pattern.
        
        Args:
            response: Raw LLM response
            
        Returns:
            Parsed pattern dictionary
        """
        # Handle if response is already a dict
        if isinstance(response, dict):
            return response
            
        # Try to parse as JSON
        if isinstance(response, str):
            # Clean up response - remove markdown code blocks if present
            cleaned = response.strip()
            if cleaned.startswith("```"):
                # Remove code block markers
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1] if len(lines) > 2 else lines)
            
            # Remove "json" language identifier if present
            cleaned = cleaned.replace("```json", "").replace("```", "").strip()
            
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                # Try to find JSON object in text
                start = cleaned.find("{")
                end = cleaned.rfind("}") + 1
                if start >= 0 and end > start:
                    try:
                        return json.loads(cleaned[start:end])
                    except json.JSONDecodeError:
                        pass
        
        # Fallback: return empty dict
        LOGGER.warning("Failed to parse LLM response as JSON")
        return {}
        
    def _validate_pattern(self, pattern: Dict[str, Any]) -> bool:
        """
        Validate that extracted pattern has required fields.
        
        Args:
            pattern: Pattern dictionary to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ["name", "vulnerability_class", "severity"]
        
        # Check required fields present
        for field in required_fields:
            if field not in pattern or not pattern[field]:
                return False
                
        # Check severity is valid
        valid_severities = ["critical", "high", "medium", "low", "informational"]
        if pattern["severity"] not in valid_severities:
            return False
            
        return True
        
    def batch_extract(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract patterns from multiple hack records in batch.
        
        Args:
            records: List of hack records
            
        Returns:
            List of extracted patterns
        """
        patterns = []
        
        for record in records:
            # Extract from description
            pattern = self.extract_from_hack_record(record)
            if pattern:
                patterns.append(pattern)
                
            # Extract from code artifacts if present
            artifacts = record.get("artifacts", {})
            if artifacts:
                code_patterns = self.extract_from_code_artifact(artifacts)
                patterns.extend(code_patterns)
                
        # Deduplicate by pattern name
        seen_names = set()
        unique_patterns = []
        for pattern in patterns:
            name = pattern.get("name", "")
            if name and name not in seen_names:
                unique_patterns.append(pattern)
                seen_names.add(name)
                
        return unique_patterns
        
    def summarize_extraction_session(
        self,
        extracted_patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate summary statistics for an extraction session.
        
        Args:
            extracted_patterns: List of patterns extracted in session
            
        Returns:
            Summary statistics
        """
        if not extracted_patterns:
            return {
                "total_extracted": 0,
                "message": "No patterns extracted"
            }
            
        # Count by severity
        by_severity = {}
        for pattern in extracted_patterns:
            sev = pattern.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
        # Count by vulnerability class
        by_class = {}
        for pattern in extracted_patterns:
            vuln_class = pattern.get("vulnerability_class", "unknown")
            by_class[vuln_class] = by_class.get(vuln_class, 0) + 1
            
        # Average confidence
        confidences = [p.get("confidence", 0.5) for p in extracted_patterns]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        return {
            "total_extracted": len(extracted_patterns),
            "by_severity": by_severity,
            "by_vulnerability_class": by_class,
            "average_confidence": avg_confidence,
            "pattern_names": [p.get("name", "unnamed") for p in extracted_patterns]
        }


__all__ = ["EnhancedPatternExtractor"]
