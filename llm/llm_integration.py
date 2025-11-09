import json
from typing import List, Dict, Any, Optional
import os


class LLMVulnerabilityAnalyzer:
    def __init__(
        self, api_key: Optional[str] = None, model: str = "gpt-4-turbo-preview"
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not provided")

        # Lazy import openai to avoid dependency issues
        try:
            import openai

            openai.api_key = self.api_key
            self._openai = openai
        except ImportError:
            raise ImportError(
                "openai package required for OpenAI LLM: pip install openai"
            )

        self.model = model

    def analyze_contract_logic(
        self, contract_code: str, slither_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use LLM to analyze contract logic and infer potential vulnerabilities
        """
        prompt = f"""
        Analyze the following Solidity contract for potential logic flaws and vulnerabilities.
        Consider cross-contract interactions, state management, and novel attack vectors.

        Contract Code:
        {contract_code}

        Slither Analysis Results:
        {json.dumps(slither_output, indent=2)}

        Provide:
        1. Potential logic flaws not detected by standard tools
        2. Novel attack scenarios
        3. Recommendations for additional property tests
        4. Areas requiring deeper analysis

        Focus on Web3-specific vulnerabilities like:
        - Cross-contract reentrancy
        - Flash loan attacks
        - Oracle manipulation
        - Governance attacks
        - Complex DeFi logic flaws
        """
        response = self._generate_response(prompt)
        analysis = response
        return self._parse_llm_response(analysis)

    def analyze_contract_logic_with_prompt(
        self, contract_code: str, slither_output: Dict[str, Any], custom_prompt: str
    ) -> Dict[str, Any]:
        """
        Use LLM to analyze contract logic with a custom prompt
        """
        base_prompt = f"""
        Contract Code:
        {contract_code}

        Slither Analysis Results:
        {json.dumps(slither_output, indent=2)}

        {custom_prompt}
        """
        response = self._generate_response(base_prompt)
        return {"raw_response": response, "prompt_type": "custom"}

    def generate_fuzzing_properties(
        self, contract_code: str, vulnerabilities: List[str]
    ) -> List[str]:
        """
        Generate property-based tests based on LLM analysis
        """
        prompt = f"""
        Based on the following contract code and identified vulnerabilities,
        generate Solidity property tests for Echidna fuzzing.

        Contract Code:
        {contract_code}

        Identified Vulnerabilities:
        {", ".join(vulnerabilities)}

        Generate 5-10 property functions that would help detect these vulnerabilities.
        Each property should be a boolean function starting with 'echidna_'.
        """
        response = self._generate_response(prompt)
        properties = self._extract_properties(response)
        return properties

    def _generate_response(self, prompt: str) -> str:
        """
        Generate LLM response - Updated for OpenAI v1.0+
        """
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.3,
            )
            return response.choices[0].message.content
        except Exception as e:
            # Fallback to basic analysis if LLM fails
            return f"LLM Error: {str(e)}. Falling back to static analysis only."

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        # Parse LLM response into structured format
        # This would need more sophisticated parsing in production
        return {
            "logic_flaws": [],
            "attack_scenarios": [],
            "property_suggestions": [],
            "analysis_areas": [],
            "raw_response": response,
        }

    def _extract_properties(self, properties_text: str) -> List[str]:
        # Extract property function names from LLM response
        # Simple implementation - would need improvement
        lines = properties_text.split("\n")
        properties = []
        for line in lines:
            if line.strip().startswith("function echidna_"):
                prop_name = line.split("function ")[1].split("(")[0]
                properties.append(prop_name)
        return properties


# Local LLM alternative using transformers
class LocalLLMAnalyzer:
    def __init__(self, model_path: str = "microsoft/DialoGPT-medium"):
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer

            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForCausalLM.from_pretrained(model_path)
        except ImportError:
            raise ImportError("transformers library required for local LLM")

    def analyze_contract_logic(
        self, contract_code: str, slither_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Implement local LLM analysis
        # This is a placeholder - actual implementation would be more complex
        return {"local_analysis": "Placeholder for local LLM analysis"}

    def analyze_contract_logic_with_prompt(
        self, contract_code: str, slither_output: Dict[str, Any], custom_prompt: str
    ) -> Dict[str, Any]:
        # Placeholder for local LLM with custom prompt
        return {"local_analysis": "Placeholder for local LLM with custom prompt"}
