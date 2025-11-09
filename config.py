"""
Configuration Management for Advanced Web3 Bug Hunter
Auto-loads Grok API key and settings
"""

import os
from pathlib import Path
from typing import Optional


class Config:
    """Configuration with smart defaults and auto-loading"""

    def __init__(self):
        # Try to load .env file
        self._load_env()

        # LLM Configuration
        self.llm_provider: Optional[str] = self._get_env("DEFAULT_LLM_PROVIDER", "grok")
        self.use_llm = self._get_env("USE_LLM", "true").lower() == "true"
        self.use_fuzzing = self._get_env("USE_FUZZING", "true").lower() == "true"

        # API Keys with smart fallback
        self.grok_key = self._get_grok_key()
        self.claude_key = os.getenv("ANTHROPIC_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")

        # Auto-select available LLM
        if not self.grok_key and not self.claude_key and not self.openai_key:
            self.use_llm = False
            self.llm_provider = None
        elif not self.grok_key and self.llm_provider == "grok":
            # Fallback to available provider
            if self.claude_key:
                self.llm_provider = "claude"
            elif self.openai_key:
                self.llm_provider = "openai"
            else:
                self.use_llm = False

    def _load_env(self):
        """Load .env file if exists"""
        env_file = Path(__file__).parent / ".env"
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        os.environ.setdefault(key.strip(), value.strip())

    def _get_env(self, key: str, default: str = "") -> str:
        """Get environment variable with default"""
        return os.getenv(key, default)

    def _get_grok_key(self) -> Optional[str]:
        """Get Grok API key with multiple fallback sources"""
        # Try environment variable first
        key = os.getenv("XAI_API_KEY")
        if key:
            return key

        # Try reading from .env file directly
        env_file = Path(__file__).parent / ".env"
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    if line.startswith("XAI_API_KEY="):
                        key = line.split("=", 1)[1].strip()
                        if key and not key.startswith("#"):
                            return key

        return None

    def get_llm_key(self) -> Optional[str]:
        """Get API key for current provider"""
        if self.llm_provider == "grok":
            return self.grok_key
        elif self.llm_provider == "claude":
            return self.claude_key
        elif self.llm_provider == "openai":
            return self.openai_key
        return None

    def summary(self) -> str:
        """Get configuration summary"""
        lines = [
            "Configuration:",
            f"  LLM Provider: {self.llm_provider or 'disabled'}",
            f"  LLM Enabled: {self.use_llm}",
            f"  Fuzzing Enabled: {self.use_fuzzing}",
        ]

        if self.use_llm:
            key = self.get_llm_key()
            if key:
                lines.append(f"  API Key: {'*' * 8}{key[-8:]}")
            else:
                lines.append("  API Key: NOT FOUND")

        return "\n".join(lines)


# Global config instance
config = Config()


if __name__ == "__main__":
    # Test configuration
    print("=" * 60)
    print("Advanced Web3 Bug Hunter - Configuration")
    print("=" * 60)
    print()
    print(config.summary())
    print()

    if config.use_llm and config.get_llm_key():
        print(f"✓ {config.llm_provider.upper()} is configured and ready!")
    elif config.use_llm:
        print(f"✗ LLM enabled but no API key found for {config.llm_provider}")
        print("  Set XAI_API_KEY environment variable or edit .env file")
    else:
        print("  LLM analysis is disabled")
