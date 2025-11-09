"""
LLM Provider Integration
Supports multiple LLM providers: Grok (x.ai), Claude (Anthropic), OpenAI
"""

import os
import requests
from typing import List, Dict, Optional
from enum import Enum


class LLMProvider(Enum):
    GROK = "grok"
    CLAUDE = "claude"
    OPENAI = "openai"


class LLMClient:
    """Unified LLM client supporting multiple providers"""

    def __init__(
        self,
        provider: LLMProvider = LLMProvider.GROK,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        self.provider = provider
        self.api_key = api_key or self._get_api_key()
        self.model = model or self._get_default_model()

        if not self.api_key:
            raise ValueError(f"API key not found for provider: {provider.value}")

    def _get_api_key(self) -> Optional[str]:
        """Get API key from environment based on provider"""
        env_vars = {
            LLMProvider.GROK: "XAI_API_KEY",
            LLMProvider.CLAUDE: "ANTHROPIC_API_KEY",
            LLMProvider.OPENAI: "OPENAI_API_KEY"
        }
        return os.getenv(env_vars[self.provider])

    def _get_default_model(self) -> str:
        """Get default model for provider"""
        defaults = {
            LLMProvider.GROK: "grok-4-latest",
            LLMProvider.CLAUDE: "claude-3-5-sonnet-20241022",
            LLMProvider.OPENAI: "gpt-4-turbo-preview"
        }
        return defaults[self.provider]

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """Send chat completion request to LLM"""

        if self.provider == LLMProvider.GROK:
            return self._grok_chat(messages, temperature, max_tokens)
        elif self.provider == LLMProvider.CLAUDE:
            return self._claude_chat(messages, temperature, max_tokens)
        elif self.provider == LLMProvider.OPENAI:
            return self._openai_chat(messages, temperature, max_tokens)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _grok_chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int
    ) -> str:
        """Grok (x.ai) API implementation"""

        url = "https://api.x.ai/v1/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        payload = {
            "messages": messages,
            "model": self.model,
            "stream": False,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()

            result = response.json()
            return result["choices"][0]["message"]["content"]

        except requests.exceptions.RequestException as e:
            raise Exception(f"Grok API error: {str(e)}")

    def _claude_chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int
    ) -> str:
        """Claude (Anthropic) API implementation"""

        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

        client = anthropic.Anthropic(api_key=self.api_key)

        # Convert messages format for Claude
        # Claude needs system message separate
        system_message = None
        claude_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            else:
                claude_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_message or "You are a helpful assistant.",
                messages=claude_messages
            )

            return response.content[0].text

        except Exception as e:
            raise Exception(f"Claude API error: {str(e)}")

    def _openai_chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int
    ) -> str:
        """OpenAI API implementation"""

        try:
            import openai
        except ImportError:
            raise ImportError("openai package required: pip install openai")

        client = openai.OpenAI(api_key=self.api_key)

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )

            return response.choices[0].message.content

        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")


def test_llm_connection(provider: LLMProvider, api_key: Optional[str] = None) -> bool:
    """Test connection to LLM provider"""

    try:
        client = LLMClient(provider=provider, api_key=api_key)

        test_messages = [
            {
                "role": "system",
                "content": "You are a test assistant."
            },
            {
                "role": "user",
                "content": "Testing. Just say 'OK' and nothing else."
            }
        ]

        response = client.chat_completion(test_messages, temperature=0, max_tokens=10)

        print(f"✓ {provider.value.upper()} connection successful!")
        print(f"  Response: {response[:50]}")
        return True

    except Exception as e:
        print(f"✗ {provider.value.upper()} connection failed: {str(e)}")
        return False


# Example usage
if __name__ == "__main__":
    print("Testing LLM Providers...")
    print("=" * 60)

    # Test Grok
    print("\n1. Testing Grok (x.ai)...")
    grok_key = "your-grok-api-key-here"
    test_llm_connection(LLMProvider.GROK, grok_key)

    # Test Claude
    print("\n2. Testing Claude (Anthropic)...")
    claude_key = os.getenv("ANTHROPIC_API_KEY")
    if claude_key:
        test_llm_connection(LLMProvider.CLAUDE, claude_key)
    else:
        print("  Skipped - no ANTHROPIC_API_KEY set")

    # Test OpenAI
    print("\n3. Testing OpenAI...")
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        test_llm_connection(LLMProvider.OPENAI, openai_key)
    else:
        print("  Skipped - no OPENAI_API_KEY set")

    print("\n" + "=" * 60)
    print("Testing complete!")
