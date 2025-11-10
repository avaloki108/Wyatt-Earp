#!/usr/bin/env python3
"""
Base Elite Detector - Foundation for all modular vulnerability detectors

Provides common infrastructure, utilities, and interfaces for specialized detectors.
Each detector focuses on 2-5 related vulnerability patterns.

Author: Elite Web3 Bug Hunter
"""

import re
import json
import hashlib
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    """Detection confidence levels"""

    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.5


@dataclass
class VulnerabilityFinding:
    """
    Standard finding format for all elite detectors

    Designed to capture:
    - What: vulnerability type and description
    - Where: file, lines, contracts, functions
    - Why: proof of concept and attack vector
    - How to fix: remediation guidance
    - Impact: economic, exploitability, rarity
    """

    # Core identification
    detector_name: str
    vulnerability_id: str  # e.g., "MULTI_TX_INVARIANT_001"
    severity: str
    confidence: float

    # Description
    title: str
    description: str
    category: str

    # Location
    file_path: str
    line_numbers: List[int]
    affected_contracts: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)

    # Technical details
    vulnerable_code: Optional[str] = None
    attack_vector: Optional[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None

    # Impact assessment
    economic_impact: str = "medium"  # critical/high/medium/low
    exploitability: str = "medium"  # trivial/easy/medium/hard
    attack_complexity: str = "medium"  # low/medium/high

    # Metadata
    requires_flash_loan: bool = False
    requires_multi_tx: bool = False
    requires_governance: bool = False
    time_window: Optional[str] = None  # e.g., "immediate", "1 block", "1 day"

    # Detection quality indicators
    novelty: str = "high"  # very_high/high/medium/low
    rarity: str = "rare"  # extreme/rare/uncommon/common
    human_only: bool = True  # True if automated tools typically miss this

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON export"""
        return {k: v for k, v in asdict(self).items() if v is not None}

    def get_hash(self) -> str:
        """Generate unique hash for deduplication"""
        key = f"{self.detector_name}:{self.file_path}:{self.vulnerability_id}:{sorted(self.line_numbers)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class ContractInfo:
    """Parsed contract information"""

    name: str
    file_path: str
    start_line: int
    end_line: int
    inherits: List[str] = field(default_factory=list)
    is_interface: bool = False
    is_abstract: bool = False
    is_library: bool = False
    state_variables: List[Dict[str, Any]] = field(default_factory=list)
    functions: List[Dict[str, Any]] = field(default_factory=list)
    modifiers: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    source_code: Optional[str] = None


class SolidityParser:
    """
    Lightweight Solidity parser for common patterns

    Provides utilities for:
    - Contract extraction
    - Function parsing
    - State variable analysis
    - Inheritance chain resolution
    - Call graph construction
    """

    @staticmethod
    def extract_contracts(source: str, file_path: str) -> List[ContractInfo]:
        """Extract all contracts from Solidity source"""
        contracts = []
        lines = source.split("\n")

        # Pattern: contract Name is Parent1, Parent2 {
        contract_pattern = re.compile(
            r"^\s*(abstract\s+)?(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{",
            re.MULTILINE,
        )

        for match in contract_pattern.finditer(source):
            is_abstract = match.group(1) is not None
            contract_type = match.group(2)
            name = match.group(3)
            inherits_str = match.group(4)

            # Find start line
            start_pos = match.start()
            start_line = source[:start_pos].count("\n") + 1

            # Find end of contract (matching braces)
            brace_count = 0
            end_pos = start_pos
            for i, char in enumerate(source[start_pos:], start=start_pos):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i
                        break

            end_line = source[:end_pos].count("\n") + 1

            # Parse inheritance
            inherits = []
            if inherits_str:
                inherits = [p.strip() for p in inherits_str.split(",")]

            # Extract contract body
            contract_body = source[match.end() : end_pos]

            contract_info = ContractInfo(
                name=name,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                inherits=inherits,
                is_interface=(contract_type == "interface"),
                is_abstract=is_abstract,
                is_library=(contract_type == "library"),
                source_code=contract_body,
            )

            # Parse state variables
            contract_info.state_variables = SolidityParser.extract_state_variables(
                contract_body, start_line
            )

            # Parse functions
            contract_info.functions = SolidityParser.extract_functions(
                contract_body, start_line
            )

            # Parse modifiers
            contract_info.modifiers = SolidityParser.extract_modifiers(
                contract_body, start_line
            )

            contracts.append(contract_info)

        return contracts

    @staticmethod
    def extract_state_variables(
        contract_body: str, base_line: int
    ) -> List[Dict[str, Any]]:
        """Extract state variable declarations"""
        variables = []

        # Pattern for state variables (simplified)
        var_pattern = re.compile(
            r"^\s*(mapping\([^)]+\)|[\w\[\]]+)\s+(public|private|internal)?\s*(constant|immutable)?\s+(\w+)\s*(?:=\s*([^;]+))?\s*;",
            re.MULTILINE,
        )

        for match in var_pattern.finditer(contract_body):
            var_type = match.group(1)
            visibility = match.group(2) or "internal"
            mutability = match.group(3)
            name = match.group(4)
            initializer = match.group(5)

            line_offset = contract_body[: match.start()].count("\n")

            variables.append(
                {
                    "name": name,
                    "type": var_type,
                    "visibility": visibility,
                    "mutability": mutability,
                    "initializer": initializer,
                    "line": base_line + line_offset,
                }
            )

        return variables

    @staticmethod
    def extract_functions(contract_body: str, base_line: int) -> List[Dict[str, Any]]:
        """Extract function declarations"""
        functions = []

        # Pattern for functions
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\([^)]*\)\s*(external|public|internal|private)?\s*(view|pure|payable)?\s*(returns\s*\([^)]*\))?\s*(?:(\w+)\s*)*\{",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(contract_body):
            name = match.group(1)
            visibility = match.group(2) or "public"
            state_mutability = match.group(3)
            returns = match.group(4)

            line_offset = contract_body[: match.start()].count("\n")

            # Extract function body
            brace_count = 0
            start_pos = match.end() - 1
            end_pos = start_pos
            for i, char in enumerate(contract_body[start_pos:], start=start_pos):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i
                        break

            body = contract_body[start_pos : end_pos + 1]

            functions.append(
                {
                    "name": name,
                    "visibility": visibility,
                    "state_mutability": state_mutability,
                    "returns": returns,
                    "line": base_line + line_offset,
                    "body": body,
                }
            )

        return functions

    @staticmethod
    def extract_modifiers(contract_body: str, base_line: int) -> List[Dict[str, Any]]:
        """Extract modifier declarations"""
        modifiers = []

        mod_pattern = re.compile(r"modifier\s+(\w+)\s*\([^)]*\)\s*\{", re.MULTILINE)

        for match in mod_pattern.finditer(contract_body):
            name = match.group(1)
            line_offset = contract_body[: match.start()].count("\n")

            modifiers.append({"name": name, "line": base_line + line_offset})

        return modifiers

    @staticmethod
    def find_external_calls(code: str) -> List[Dict[str, Any]]:
        """Find external contract calls in code"""
        calls = []

        # Pattern: address.call(...), contract.function(...)
        call_patterns = [
            r"(\w+)\.call\{?([^}]*)?\}?\(",  # low-level call
            r"(\w+)\.delegatecall\{?([^}]*)?\}?\(",  # delegatecall
            r"(\w+)\.staticcall\{?([^}]*)?\}?\(",  # staticcall
            r"(\w+)\.(\w+)\(",  # high-level call
        ]

        for pattern in call_patterns:
            for match in re.finditer(pattern, code):
                calls.append(
                    {
                        "target": match.group(1),
                        "type": "call" if "call" in match.group(0) else "function",
                        "snippet": match.group(0),
                    }
                )

        return calls

    @staticmethod
    def find_assembly_blocks(code: str) -> List[str]:
        """Find inline assembly blocks"""
        asm_pattern = re.compile(r"assembly\s*\{([^}]+)\}", re.DOTALL)
        return [match.group(1) for match in asm_pattern.finditer(code)]


class EliteDetector(ABC):
    """
    Abstract base class for all elite detectors

    Each detector should:
    1. Inherit from this class
    2. Implement detect() method
    3. Use _add_finding() to register vulnerabilities
    4. Provide clear POC and remediation
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[VulnerabilityFinding] = []
        self.contracts: Dict[str, ContractInfo] = {}
        self.parser = SolidityParser()

    @abstractmethod
    def detect(self, target_path: Path) -> List[VulnerabilityFinding]:
        """
        Main detection method - must be implemented by subclasses

        Args:
            target_path: Path to Solidity file or directory

        Returns:
            List of vulnerability findings
        """
        pass

    @abstractmethod
    def get_detector_name(self) -> str:
        """Return detector name (e.g., 'reentrancy_hooks')"""
        pass

    @abstractmethod
    def get_vulnerability_ids(self) -> List[str]:
        """Return list of vulnerability IDs this detector covers"""
        pass

    def _add_finding(self, **kwargs) -> None:
        """
        Helper to create and add a finding

        Usage:
            self._add_finding(
                vulnerability_id="MULTI_TX_001",
                severity=Severity.HIGH.value,
                confidence=Confidence.HIGH.value,
                title="Cross-block invariant violation",
                description="...",
                ...
            )
        """
        # Set detector name automatically
        kwargs["detector_name"] = self.get_detector_name()

        # Create finding
        finding = VulnerabilityFinding(**kwargs)

        # Deduplicate
        finding_hash = finding.get_hash()
        if not any(f.get_hash() == finding_hash for f in self.findings):
            self.findings.append(finding)

            if self.verbose:
                print(f"[{finding.severity.upper()}] {finding.title}")
                print(f"  → {finding.file_path}:{finding.line_numbers}")

    def scan_directory(self, directory: Path) -> List[Path]:
        """Find all Solidity files in directory"""
        sol_files = []
        for path in directory.rglob("*.sol"):
            # Skip common test/mock directories
            if any(
                skip in str(path) for skip in ["node_modules", "test", "mock", ".git"]
            ):
                continue
            sol_files.append(path)
        return sol_files

    def load_contract(self, file_path: Path) -> str:
        """Load Solidity source code"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            if self.verbose:
                print(f"Error reading {file_path}: {e}")
            return ""

    def parse_contracts(self, source: str, file_path: str) -> List[ContractInfo]:
        """Parse contracts from source"""
        return self.parser.extract_contracts(source, file_path)

    def export_findings(self, output_path: Path) -> None:
        """Export findings to JSON file"""
        report = {
            "detector": self.get_detector_name(),
            "vulnerability_coverage": self.get_vulnerability_ids(),
            "total_findings": len(self.findings),
            "severity_breakdown": {
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        if self.verbose:
            print(f"\n✅ Exported {len(self.findings)} findings to {output_path}")

    def print_summary(self) -> None:
        """Print detection summary to console"""
        print(f"\n{'=' * 60}")
        print(f"Detector: {self.get_detector_name()}")
        print(f"{'=' * 60}")
        print(f"Total findings: {len(self.findings)}")

        by_severity = {}
        for finding in self.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")

        print(f"{'=' * 60}\n")


# Common patterns and utilities used across detectors

PROXY_KEYWORDS = [
    "delegatecall",
    "Proxy",
    "Upgradeable",
    "ERC1967",
    "TransparentUpgradeable",
    "UUPSUpgradeable",
    "BeaconProxy",
    "implementation",
    "upgradeTo",
]

REENTRANCY_PATTERNS = [
    r"\.call\{value:",
    r"\.transfer\(",
    r"\.send\(",
    r"payable\([^)]+\)\.call",
]

TIMING_PATTERNS = [
    "block.timestamp",
    "block.number",
    "now",
]

ORACLE_KEYWORDS = [
    "oracle",
    "price",
    "feed",
    "chainlink",
    "twap",
    "getPrice",
    "latestAnswer",
]

GOVERNANCE_KEYWORDS = ["vote", "proposal", "quorum", "snapshot", "governor", "timelock"]

FLASH_LOAN_KEYWORDS = [
    "flashLoan",
    "executeOperation",
    "onFlashLoan",
    "borrow",
    "repay",
]


def extract_function_calls(code: str) -> List[str]:
    """Extract all function calls from code"""
    pattern = r"(\w+)\s*\("
    return list(set(re.findall(pattern, code)))


def has_reentrancy_guard(code: str) -> bool:
    """Check if code has reentrancy guard"""
    return bool(re.search(r"(nonReentrant|ReentrancyGuard|_locked)", code))


def has_time_dependency(code: str) -> bool:
    """Check if code depends on block timing"""
    return any(pattern in code for pattern in TIMING_PATTERNS)
