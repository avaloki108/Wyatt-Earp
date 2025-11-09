"""
Feedback Loop System
Learns from discovered vulnerabilities and automatically:
1. Adds them to custom detector library
2. Generates fuzzing invariants
3. Updates LLM prompts with new patterns
4. Builds pattern database
"""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import re


@dataclass
class LearnedVulnerability:
    """A vulnerability that was found and learned from"""
    id: str
    timestamp: str
    contract_name: str
    vulnerability_type: str
    severity: str
    description: str
    affected_code: str
    attack_scenario: str
    detector_pattern: str  # Regex or AST pattern to detect similar issues
    fuzzing_invariant: Optional[str] = None  # Echidna property to test
    slither_detector_code: Optional[str] = None  # Custom Slither detector
    llm_prompt_addition: Optional[str] = None  # Addition to LLM prompt


class VulnerabilityDatabase:
    """
    Database of learned vulnerabilities
    Stores patterns and generates detectors
    """

    def __init__(self, db_path: str = "vulnerability_database.json"):
        self.db_path = Path(db_path)
        self.vulnerabilities: List[LearnedVulnerability] = []
        self._load_database()

    def _load_database(self):
        """Load existing vulnerability database"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        vuln = LearnedVulnerability(**item)
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                print(f"Warning: Could not load database: {e}")

    def save_database(self):
        """Save vulnerability database"""
        try:
            data = [asdict(v) for v in self.vulnerabilities]
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving database: {e}")

    def add_vulnerability(self, vuln: LearnedVulnerability):
        """Add a new learned vulnerability"""
        self.vulnerabilities.append(vuln)
        self.save_database()

    def search_similar(self, pattern: str) -> List[LearnedVulnerability]:
        """Find similar vulnerabilities by pattern"""
        results = []
        for vuln in self.vulnerabilities:
            if pattern.lower() in vuln.vulnerability_type.lower():
                results.append(vuln)
        return results

    def get_by_type(self, vuln_type: str) -> List[LearnedVulnerability]:
        """Get all vulnerabilities of a specific type"""
        return [v for v in self.vulnerabilities if v.vulnerability_type == vuln_type]

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        types = {}
        severities = {}

        for vuln in self.vulnerabilities:
            types[vuln.vulnerability_type] = types.get(vuln.vulnerability_type, 0) + 1
            severities[vuln.severity] = severities.get(vuln.severity, 0) + 1

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "types": types,
            "severities": severities,
            "most_common_type": max(types.items(), key=lambda x: x[1])[0] if types else None
        }


class PatternExtractor:
    """
    Extracts patterns from vulnerabilities to create detectors
    """

    @staticmethod
    def extract_code_pattern(affected_code: str, vuln_type: str) -> str:
        """
        Extract a pattern from the vulnerable code
        Returns a regex pattern that can detect similar code
        """

        # Normalize code
        code = affected_code.strip()

        # Different patterns for different vulnerability types
        if "reentrancy" in vuln_type.lower():
            # Pattern: external call followed by state change
            return r"\.(call|transfer|send)\s*\{.*?\}\s*\(.*?\);?\s*\n.*?=\s*"

        elif "access" in vuln_type.lower() or "authorization" in vuln_type.lower():
            # Pattern: state-changing function without access control
            return r"function\s+\w+\s*\([^)]*\)\s+public\s+(?!onlyOwner|onlyAdmin)"

        elif "overflow" in vuln_type.lower() or "underflow" in vuln_type.lower():
            # Pattern: unchecked arithmetic
            return r"(?<!unchecked\s{)\s*[+\-*/]\s*(?!})"

        elif "oracle" in vuln_type.lower():
            # Pattern: oracle usage without staleness check
            return r"latestAnswer\(\)|latestRoundData\(\)"

        elif "flash.?loan" in vuln_type.lower():
            # Pattern: flash loan without protection
            return r"flashLoan|borrow.*repay"

        else:
            # Generic pattern: extract function signature
            func_match = re.search(r"function\s+(\w+)", code)
            if func_match:
                return f"function\\s+{func_match.group(1)}"

        return ""

    @staticmethod
    def generate_slither_detector(vuln: LearnedVulnerability) -> str:
        """
        Generate a custom Slither detector for this vulnerability
        Returns Python code for a Slither detector
        """

        detector_name = vuln.vulnerability_type.replace(" ", "").replace("-", "")

        template = f'''"""
Custom Slither Detector: {detector_name}
Auto-generated from learned vulnerability: {vuln.id}
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class {detector_name}Detector(AbstractDetector):
    """
    Detects: {vuln.description}

    Learned from: {vuln.contract_name}
    Date: {vuln.timestamp}
    """

    ARGUMENT = "{vuln.vulnerability_type.lower().replace(" ", "-")}"
    HELP = "{vuln.description}"
    IMPACT = DetectorClassification.{vuln.severity.upper()}
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation"
    WIKI_TITLE = "{vuln.vulnerability_type}"
    WIKI_DESCRIPTION = "{vuln.description}"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
{vuln.affected_code}
```

Attack scenario:
{vuln.attack_scenario}
"""

    WIKI_RECOMMENDATION = "Review the identified code pattern and apply appropriate mitigations."

    def _detect(self):
        """Detect the vulnerability pattern"""
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                # TODO: Implement detection logic based on pattern:
                # {vuln.detector_pattern}

                # Placeholder detection
                if self._matches_pattern(function):
                    info = [function, " matches vulnerability pattern\\n"]
                    res = self.generate_result(info)
                    results.append(res)

        return results

    def _matches_pattern(self, function):
        """Check if function matches the vulnerability pattern"""
        # Implement pattern matching logic here
        # For now, return False
        return False
'''

        return template

    @staticmethod
    def generate_echidna_invariant(vuln: LearnedVulnerability) -> str:
        """
        Generate an Echidna invariant test for this vulnerability
        Returns Solidity property function
        """

        # Generate invariant based on vulnerability type
        if "reentrancy" in vuln.vulnerability_type.lower():
            return """
    bool private locked;

    function echidna_no_reentrancy() public returns (bool) {
        return !locked; // Should never be true during normal execution
    }
"""

        elif "balance" in vuln.vulnerability_type.lower():
            return """
    function echidna_balance_invariant() public view returns (bool) {
        // Sum of all balances should equal total supply
        return getTotalBalances() == totalSupply;
    }
"""

        elif "access" in vuln.vulnerability_type.lower():
            return """
    function echidna_only_owner_can_mint() public view returns (bool) {
        // Critical functions should only be called by owner
        return msg.sender == owner || !functionWasCalled();
    }
"""

        else:
            return f"""
    function echidna_custom_invariant() public view returns (bool) {{
        // Auto-generated invariant for: {vuln.description}
        // TODO: Implement specific check
        return true;
    }}
"""


class FeedbackLoop:
    """
    Main feedback loop system
    Learns from vulnerabilities and improves detection
    """

    def __init__(self, db_path: str = "web3-bug-hunter/learned_vulnerabilities.json"):
        self.db = VulnerabilityDatabase(db_path)
        self.pattern_extractor = PatternExtractor()

    def learn_from_finding(self,
                          contract_name: str,
                          vulnerability_type: str,
                          severity: str,
                          description: str,
                          affected_code: str,
                          attack_scenario: str) -> LearnedVulnerability:
        """
        Learn from a discovered vulnerability
        Automatically generates detector, invariant, and LLM prompt
        """

        # Generate unique ID
        vuln_id = self._generate_id(contract_name, vulnerability_type)

        # Extract pattern
        pattern = self.pattern_extractor.extract_code_pattern(affected_code, vulnerability_type)

        # Generate Slither detector
        slither_code = self.pattern_extractor.generate_slither_detector(
            LearnedVulnerability(
                id=vuln_id,
                timestamp=datetime.now().isoformat(),
                contract_name=contract_name,
                vulnerability_type=vulnerability_type,
                severity=severity,
                description=description,
                affected_code=affected_code,
                attack_scenario=attack_scenario,
                detector_pattern=pattern
            )
        )

        # Generate Echidna invariant
        echidna_invariant = self.pattern_extractor.generate_echidna_invariant(
            LearnedVulnerability(
                id=vuln_id,
                timestamp=datetime.now().isoformat(),
                contract_name=contract_name,
                vulnerability_type=vulnerability_type,
                severity=severity,
                description=description,
                affected_code=affected_code,
                attack_scenario=attack_scenario,
                detector_pattern=pattern
            )
        )

        # Generate LLM prompt addition
        llm_prompt = f"""
When analyzing contracts, specifically look for:
- Type: {vulnerability_type}
- Pattern: {description}
- Example affected code:
  ```
  {affected_code}
  ```
- Attack scenario: {attack_scenario}
"""

        # Create learned vulnerability
        vuln = LearnedVulnerability(
            id=vuln_id,
            timestamp=datetime.now().isoformat(),
            contract_name=contract_name,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            affected_code=affected_code,
            attack_scenario=attack_scenario,
            detector_pattern=pattern,
            fuzzing_invariant=echidna_invariant,
            slither_detector_code=slither_code,
            llm_prompt_addition=llm_prompt
        )

        # Add to database
        self.db.add_vulnerability(vuln)

        # Save detector to file
        self._save_detector(vuln)

        print(f"✓ Learned from vulnerability: {vuln_id}")
        print(f"  - Pattern extracted: {pattern[:50]}...")
        print(f"  - Detector generated: {vulnerability_type}Detector")
        print("  - Invariant generated: echidna_custom_invariant")

        return vuln

    def _generate_id(self, contract_name: str, vuln_type: str) -> str:
        """Generate unique vulnerability ID"""
        data = f"{contract_name}:{vuln_type}:{datetime.now().isoformat()}"
        hash_val = hashlib.md5(data.encode()).hexdigest()[:8]
        return f"LEARNED-{hash_val.upper()}"

    def _save_detector(self, vuln: LearnedVulnerability):
        """Save generated detector to file"""
        detectors_dir = Path("web3-bug-hunter/custom_detectors")
        detectors_dir.mkdir(parents=True, exist_ok=True)

        detector_file = detectors_dir / f"{vuln.vulnerability_type.replace(' ', '_').lower()}.py"

        if vuln.slither_detector_code:
            with open(detector_file, 'w') as f:
                f.write(vuln.slither_detector_code)

    def get_enhanced_llm_prompt(self) -> str:
        """
        Get enhanced LLM prompt that includes all learned patterns
        """
        base_prompt = """You are an expert smart contract auditor with knowledge of real-world exploits.

Pay special attention to these vulnerability patterns learned from actual findings:

"""

        for vuln in self.db.vulnerabilities:
            if vuln.llm_prompt_addition:
                base_prompt += vuln.llm_prompt_addition + "\n"

        return base_prompt

    def get_all_detectors(self) -> List[str]:
        """Get list of all generated detectors"""
        return [v.slither_detector_code for v in self.db.vulnerabilities if v.slither_detector_code]

    def get_all_invariants(self) -> List[str]:
        """Get list of all generated invariants"""
        return [v.fuzzing_invariant for v in self.db.vulnerabilities if v.fuzzing_invariant]

    def export_detector_library(self, output_dir: str = "web3-bug-hunter/custom_detectors"):
        """Export all detectors to a directory"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for vuln in self.db.vulnerabilities:
            if vuln.slither_detector_code:
                filename = f"{vuln.vulnerability_type.replace(' ', '_').lower()}_detector.py"
                filepath = output_path / filename

                with open(filepath, 'w') as f:
                    f.write(vuln.slither_detector_code)

        # Create __init__.py
        init_file = output_path / "__init__.py"
        with open(init_file, 'w') as f:
            f.write("# Auto-generated custom detectors\n")

        print(f"✓ Exported {len(self.db.vulnerabilities)} detectors to {output_dir}")

    def generate_report(self) -> Dict[str, Any]:
        """Generate feedback loop report"""
        stats = self.db.get_statistics()

        return {
            "database_stats": stats,
            "total_patterns_learned": len(self.db.vulnerabilities),
            "detectors_generated": sum(1 for v in self.db.vulnerabilities if v.slither_detector_code),
            "invariants_generated": sum(1 for v in self.db.vulnerabilities if v.fuzzing_invariant),
            "llm_enhancements": sum(1 for v in self.db.vulnerabilities if v.llm_prompt_addition),
            "recent_learnings": [
                {
                    "id": v.id,
                    "type": v.vulnerability_type,
                    "timestamp": v.timestamp
                }
                for v in sorted(self.db.vulnerabilities, key=lambda x: x.timestamp, reverse=True)[:10]
            ]
        }


# Example usage
if __name__ == "__main__":
    print("="*70)
    print("FEEDBACK LOOP SYSTEM - Learning from Vulnerabilities")
    print("="*70)

    # Create feedback loop
    feedback = FeedbackLoop()

    # Example: Learn from a reentrancy vulnerability
    print("\n📚 Learning from discovered reentrancy vulnerability...")

    vuln = feedback.learn_from_finding(
        contract_name="VulnerableBank",
        vulnerability_type="reentrancy",
        severity="critical",
        description="Classic reentrancy in withdraw function",
        affected_code="""
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // State update AFTER external call
}
""",
        attack_scenario="Attacker can recursively call withdraw before balance is updated, draining the contract"
    )

    print(f"\n✓ Vulnerability learned: {vuln.id}")

    # Learn from another vulnerability
    print("\n📚 Learning from oracle manipulation vulnerability...")

    vuln2 = feedback.learn_from_finding(
        contract_name="DeFiProtocol",
        vulnerability_type="oracle_manipulation",
        severity="high",
        description="Oracle price used without staleness check",
        affected_code="""
function getPrice() public view returns (uint256) {
    (, int256 price, , ,) = priceFeed.latestRoundData();
    return uint256(price);  // No timestamp check!
}
""",
        attack_scenario="Attacker can exploit stale oracle prices during network issues or oracle downtime"
    )

    print(f"✓ Vulnerability learned: {vuln2.id}")

    # Generate report
    print("\n" + "="*70)
    print("FEEDBACK LOOP REPORT")
    print("="*70)

    report = feedback.generate_report()

    print(f"\nTotal patterns learned: {report['total_patterns_learned']}")
    print(f"Detectors generated: {report['detectors_generated']}")
    print(f"Invariants generated: {report['invariants_generated']}")
    print(f"LLM enhancements: {report['llm_enhancements']}")

    print("\nDatabase statistics:")
    print(f"  Total vulnerabilities: {report['database_stats']['total_vulnerabilities']}")
    print(f"  By type: {report['database_stats']['types']}")
    print(f"  By severity: {report['database_stats']['severities']}")

    # Export detectors
    print("\n📦 Exporting detector library...")
    feedback.export_detector_library()

    # Show enhanced LLM prompt
    print("\n📝 Enhanced LLM Prompt (first 500 chars):")
    print(feedback.get_enhanced_llm_prompt()[:500] + "...")

    print("\n" + "="*70)
    print("✅ Feedback loop demonstration complete!")
    print("="*70)
