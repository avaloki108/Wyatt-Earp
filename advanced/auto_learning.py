"""
Auto-Learning Module for Web3 Bug Hunter
Dynamically extracts vulnerability patterns from recent hacks and updates detectors
Sources: Rekt.news, PeckShield, Twitter alerts, GitHub exploit repos, dark web feeds (mocked for demo)
Uses LLM to analyze hack descriptions and generate new detection rules
"""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from advanced.data_sources import (
    CyfrinAderynFetcher,
    DeFiHackLabsFetcher,
    HackRecord,
    SmartBugsWildFetcher,
    SoloditContentFetcher,
)
from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.novel_vulnerability_patterns import NovelPatternDetector


LOGGER = logging.getLogger(__name__)

class AutoLearner:
    """
    Auto-Learning system that learns from new hacks and updates vulnerability patterns
    """
    
    def __init__(self, llm_reasoner: Optional[AdvancedLLMReasoner] = None):
        self.llm = llm_reasoner or AdvancedLLMReasoner()
        self.storage_dir = Path("patterns")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.patterns_file = self.storage_dir / "learned_patterns.json"
        self.provenance_log = self.storage_dir / "pattern_provenance.jsonl"
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.source_fetchers = [
            SmartBugsWildFetcher(token=self.github_token),
            DeFiHackLabsFetcher(token=self.github_token),
            CyfrinAderynFetcher(token=self.github_token),
            SoloditContentFetcher(token=self.github_token),
        ]
        self.learned_patterns: List[Dict[str, Any]] = self._load_learned_patterns()
        self.processed_hack_ids: Set[str] = {
            pattern.get("provenance", {}).get("source_id")
            for pattern in self.learned_patterns
            if pattern.get("provenance", {}).get("source_id")
        }
    
    def _load_learned_patterns(self) -> List[Dict[str, Any]]:
        """Load previously learned patterns"""
        if self.patterns_file.exists():
            try:
                with self.patterns_file.open('r', encoding='utf-8') as handle:
                    data = json.load(handle)
                    if isinstance(data, list):
                        return data
            except json.JSONDecodeError as exc:
                LOGGER.warning("Failed to decode learned patterns file %s: %s", self.patterns_file, exc)
            except OSError as exc:
                LOGGER.warning("Failed to load learned patterns from %s: %s", self.patterns_file, exc)
        return []

    def _save_learned_patterns(self):
        """Save learned patterns to file"""
        try:
            with self.patterns_file.open('w', encoding='utf-8') as handle:
                json.dump(self.learned_patterns, handle, indent=2)
        except OSError as exc:
            LOGGER.error("Failed to persist learned patterns to %s: %s", self.patterns_file, exc)
    
    def fetch_recent_hacks(self, days: int = 7) -> List[Dict[str, Any]]:
        """Fetch and normalize recent hack reports from configured sources."""

        since = datetime.utcnow() - timedelta(days=days)
        deduped: Dict[str, HackRecord] = {}

        for fetcher in self.source_fetchers:
            try:
                records = fetcher.fetch(since)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning(
                    "Failed to ingest records from %s/%s: %s",
                    getattr(fetcher, "owner", "unknown"),
                    getattr(fetcher, "repo", "unknown"),
                    exc,
                )
                continue

            for record in records:
                if record.discovered_at < since:
                    continue
                existing = deduped.get(record.uid)
                if not existing or record.discovered_at > existing.discovered_at:
                    deduped[record.uid] = record

        ordered_records = sorted(deduped.values(), key=lambda r: r.discovered_at, reverse=True)
        return [record.to_learning_payload() for record in ordered_records]
    
    def _fetch_github_exploits(self, days: int = 7) -> List[Dict[str, Any]]:
        """Fetch recent exploits from GitHub-backed sources only."""

        since = datetime.utcnow() - timedelta(days=days)
        deduped: Dict[str, HackRecord] = {}
        for fetcher in self.source_fetchers:
            if not getattr(fetcher, "provides_code_artifacts", False):
                continue

            try:
                records = fetcher.fetch(since)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning(
                    "Failed to fetch GitHub exploits from %s/%s: %s",
                    getattr(fetcher, "owner", "unknown"),
                    getattr(fetcher, "repo", "unknown"),
                    exc,
                )
                continue

            for record in records:
                if record.discovered_at < since:
                    continue
                existing = deduped.get(record.uid)
                if not existing or record.discovered_at > existing.discovered_at:
                    deduped[record.uid] = record

        ordered_records = sorted(deduped.values(), key=lambda r: r.discovered_at, reverse=True)
        return [record.to_learning_payload() for record in ordered_records]
    
    def extract_pattern_from_hack(self, hack: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM to extract vulnerability pattern from hack description
        Returns structured pattern for detector integration
        """
        prompt = f"""
        Analyze this recent hack and extract the vulnerability pattern:
        
        Hack: {hack['title']}
        Description: {hack['description']}
        Code Snippet: {hack['exploit_code_snippet']}
        Impact: {hack['impact']}
        
        Extract:
        1. Pattern Name (e.g., "TWAP Oracle Manipulation")
        2. Solidity Signature (function patterns to detect)
        3. Detection Rule (SlithIR or AST patterns)
        4. Severity
        5. Fix Recommendation
        6. Attack Vector Description
        
        Respond in JSON format only.
        """
        
        response = self.llm.query_llm(prompt, model="gpt-4")  # Or Grok/Claude
        
        try:
            pattern = json.loads(response)
            pattern["source_hack"] = hack["title"]
            pattern["date_learned"] = datetime.now().isoformat()
            return pattern
        except json.JSONDecodeError:
            # Fallback mock pattern
            return {
                "name": "Extracted Pattern from " + hack["title"],
                "solidity_signature": "function updatePrice(uint price)",
                "detection_rule": "No check for block.timestamp difference",
                "severity": hack["impact"],
                "fix": "Add TWAP with sufficient lookback period",
                "attack_vector": "Flash loan + oracle manipulation",
                "source_hack": hack["title"],
                "date_learned": datetime.now().isoformat()
            }
    
    def learn_from_recent_hacks(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Main learning loop: Fetch hacks -> Extract patterns -> Update detectors
        """
        new_patterns = []
        recent_hacks = self.fetch_recent_hacks(days)
        
        for hack in recent_hacks:
            pattern = self._ingest_hack(hack)
            if pattern:
                new_patterns.append(pattern)

        if new_patterns:
            self._save_learned_patterns()
            self._update_detectors(new_patterns)

        return new_patterns
    
    def _update_detectors(self, new_patterns: List[Dict[str, Any]]):
        """
        Integrate new patterns into NovelPatternDetector
        In production: Dynamically update detector rules
        Demo: Log and suggest manual integration
        """
        detector = NovelPatternDetector()

        for pattern in new_patterns:
            # Add to detector's patterns (extend the class)
            detector.patterns.append({
                "name": pattern["name"],
                "description": pattern["attack_vector"],
                "severity": pattern["severity"],
                "solidity_patterns": [pattern["solidity_signature"]],
                "detection_function": self._generate_detection_function(pattern)
            })

        # Save updated detector state (serialize)
        detector_path = self.storage_dir / "updated_detector.json"
        with detector_path.open("w", encoding="utf-8") as handle:
            json.dump({"patterns": detector.patterns}, handle, indent=2)

        LOGGER.info("Updated detectors with %s new pattern(s)", len(new_patterns))
        LOGGER.info("Manual follow-up: Integrate into novel_vulnerability_patterns.py")

    def _generate_detection_function(self, pattern: Dict[str, Any]) -> str:
        """
        Generate Python detection code from learned pattern
        """
        return f"""
def detect_{pattern['name'].lower().replace(' ', '_')}(contract_code: str) -> bool:
    # Generated from hack: {pattern['source_hack']}
    patterns = [
        r"function\\s+{pattern['solidity_signature']}",
        r"no\\s+overflow\\s+check",  # Example
    ]
    for p in patterns:
        if re.search(p, contract_code):
            return True
    return False
"""

    def _log_provenance(self, pattern: Dict[str, Any]) -> None:
        provenance = pattern.get("provenance")
        if not provenance:
            return

        entry = {
            "pattern_name": pattern.get("name"),
            "severity": pattern.get("severity"),
            "provenance": provenance,
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            with self.provenance_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError as exc:
            LOGGER.warning("Failed to log provenance for %s: %s", pattern.get("name"), exc)

    def _ingest_hack(self, hack: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        hack_id = hack.get("id")
        if hack_id and hack_id in self.processed_hack_ids:
            return None

        pattern = self.extract_pattern_from_hack(hack)
        pattern.setdefault("source_hack", hack.get("title"))
        pattern.setdefault("date_learned", datetime.utcnow().isoformat())
        pattern["provenance"] = {
            "source_id": hack_id,
            "source": hack.get("source"),
            "references": hack.get("references", []),
            "ingested_at": datetime.utcnow().isoformat(),
        }

        if any(existing.get("name") == pattern["name"] for existing in self.learned_patterns):
            return None

        self.learned_patterns.append(pattern)
        if hack_id:
            self.processed_hack_ids.add(hack_id)
        LOGGER.info("Learned new pattern %s from %s", pattern.get("name"), hack.get("title"))
        self._log_provenance(pattern)
        return pattern
    
    def get_learned_patterns_summary(self) -> str:
        """Summary of learned patterns"""
        if not self.learned_patterns:
            return "No learned patterns yet. Run learn_from_recent_hacks() to start."
        
        summary = f"📚 Learned Patterns ({len(self.learned_patterns)} total):\n"
        for p in self.learned_patterns[-3:]:  # Last 3
            summary += f"- {p['name']} (from {p['source_hack']}, {p['severity']})\n"
        return summary
    
    def learn_from_github_exploits(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Specialized learning from GitHub exploit repositories
        Searches for recent Solidity exploits and extracts patterns
        """
        github_exploits = self._fetch_github_exploits(days)
        new_patterns: List[Dict[str, Any]] = []

        for exploit in github_exploits:
            pattern = self._ingest_hack(exploit)
            if not pattern:
                continue
            pattern["source_type"] = "github_exploit"
            new_patterns.append(pattern)

        if new_patterns:
            self._save_learned_patterns()
            self._update_detectors(new_patterns)

        return new_patterns

# Demo usage
if __name__ == "__main__":
    learner = AutoLearner()
    new_patterns = learner.learn_from_recent_hacks(days=7)
    print(learner.get_learned_patterns_summary())
    
    # Integrate into main tool
    print("\n🔗 To use in analysis: from advanced.auto_learning import AutoLearner")
    print("learner = AutoLearner(); learner.learn_from_recent_hacks()")
    
    # GitHub-specific learning
    print("\n🔄 Learning from GitHub exploit repos...")
    github_patterns = learner.learn_from_github_exploits(days=30)
    print(f"Learned {len(github_patterns)} patterns from GitHub")