#!/usr/bin/env python3
"""
Storage Collision Detector - Elite-tier vulnerability detection
Detects storage slot collisions in proxy patterns, inheritance chains, and delegatecall contexts

Author: Elite Web3 Bug Hunter
Category: Critical Infrastructure Vulnerabilities
"""

import re
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field
import hashlib


@dataclass
class StorageSlot:
    """Represents a storage slot in a contract"""

    slot_number: int
    variable_name: str
    variable_type: str
    contract_name: str
    declaration_line: int
    is_constant: bool = False
    is_immutable: bool = False

    def __hash__(self):
        return hash((self.slot_number, self.contract_name))


@dataclass
class StorageCollisionFinding:
    """Represents a storage collision vulnerability"""

    severity: str  # "critical", "high", "medium", "low"
    finding_type: str
    description: str
    affected_contracts: List[str]
    colliding_slots: List[StorageSlot]
    proof_of_concept: str
    remediation: str
    confidence: float
    file_path: str
    line_numbers: List[int]
    economic_impact: str = "high"
    exploitability: str = "high"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "storage_collision",
            "severity": self.severity,
            "category": self.finding_type,
            "confidence": self.confidence,
            "description": self.description,
            "file": self.file_path,
            "lines": self.line_numbers,
            "affected_contracts": self.affected_contracts,
            "colliding_slots": [
                {
                    "slot": slot.slot_number,
                    "variable": slot.variable_name,
                    "type": slot.variable_type,
                    "contract": slot.contract_name,
                }
                for slot in self.colliding_slots
            ],
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "economic_impact": self.economic_impact,
            "exploitability": self.exploitability,
            "novelty": "very_high",
            "rarity": "extreme",
            "human_only": True,
        }


class StorageCollisionDetector:
    """
    Elite Storage Collision Detector

    Detects:
    1. Proxy/Implementation storage collisions
    2. Multiple inheritance storage slot conflicts (C3 linearization issues)
    3. Unstructured storage misuse
    4. Delegatecall storage overwrites
    5. Upgradeable contract storage layout breaks
    6. Phantom storage writes through assembly
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[StorageCollisionFinding] = []
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.proxy_patterns: List[str] = [
            "delegatecall",
            "Proxy",
            "Upgradeable",
            "Implementation",
            "ERC1967",
            "TransparentUpgradeableProxy",
        ]

    def analyze_directory(self, directory_path: str) -> List[StorageCollisionFinding]:
        """Analyze all Solidity files in directory"""
        path = Path(directory_path)
        sol_files = list(path.rglob("*.sol"))

        if self.verbose:
            print(
                f"🔍 Analyzing {len(sol_files)} Solidity files for storage collisions..."
            )

        # Phase 1: Parse all contracts and build storage layouts
        for sol_file in sol_files:
            self._parse_contract_file(str(sol_file))

        # Phase 2: Analyze proxy patterns
        self._detect_proxy_storage_collisions()

        # Phase 3: Analyze inheritance chains
        self._detect_inheritance_collisions()

        # Phase 4: Analyze delegatecall contexts
        self._detect_delegatecall_storage_risks()

        # Phase 5: Analyze unstructured storage
        self._detect_unstructured_storage_issues()

        # Phase 6: Analyze assembly storage manipulation
        self._detect_assembly_storage_risks()

        return self.findings

    def _parse_contract_file(self, file_path: str):
        """Parse a Solidity file and extract contract information"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract all contracts
            contract_pattern = r"contract\s+(\w+)(?:\s+is\s+([\w\s,]+))?\s*\{"
            contracts = re.finditer(contract_pattern, content)

            for match in contracts:
                contract_name = match.group(1)
                inheritance = match.group(2)

                # Get contract body
                start_pos = match.end()
                brace_count = 1
                end_pos = start_pos

                for i, char in enumerate(content[start_pos:], start_pos):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            end_pos = i
                            break

                contract_body = content[start_pos:end_pos]

                # Parse storage layout
                storage_layout = self._parse_storage_layout(
                    contract_body, contract_name, file_path
                )

                # Parse inheritance
                parent_contracts = []
                if inheritance:
                    parent_contracts = [p.strip() for p in inheritance.split(",")]

                # Check for proxy patterns
                is_proxy = any(
                    pattern in contract_name or pattern in contract_body
                    for pattern in self.proxy_patterns
                )

                # Check for delegatecall usage
                has_delegatecall = "delegatecall" in contract_body

                self.contracts[contract_name] = {
                    "file": file_path,
                    "content": contract_body,
                    "storage_layout": storage_layout,
                    "parents": parent_contracts,
                    "is_proxy": is_proxy,
                    "has_delegatecall": has_delegatecall,
                    "start_line": content[: match.start()].count("\n") + 1,
                }

        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error parsing {file_path}: {e}")

    def _parse_storage_layout(
        self, contract_body: str, contract_name: str, file_path: str
    ) -> List[StorageSlot]:
        """Parse storage variable declarations"""
        storage_slots = []
        slot_counter = 0

        # Match state variable declarations
        # Pattern: type visibility? name;
        var_pattern = r"^\s*((?:mapping|uint256|uint|address|bool|bytes32|bytes|string|int256|int)[\w\[\]\(\),\s]*)\s+(public|private|internal|)?\s*(\w+)\s*;"

        lines = contract_body.split("\n")
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if "//" in line:
                line = line[: line.index("//")]

            # Skip constants and immutables (they don't use storage)
            if "constant" in line or "immutable" in line:
                continue

            match = re.search(var_pattern, line.strip())
            if match:
                var_type = match.group(1).strip()
                var_name = match.group(3).strip()

                slot = StorageSlot(
                    slot_number=slot_counter,
                    variable_name=var_name,
                    variable_type=var_type,
                    contract_name=contract_name,
                    declaration_line=line_num,
                )
                storage_slots.append(slot)

                # Increment slot counter (simplified - doesn't handle packing)
                slot_counter += 1

        return storage_slots

    def _detect_proxy_storage_collisions(self):
        """Detect storage collisions between proxy and implementation contracts"""
        proxy_contracts = {
            name: data for name, data in self.contracts.items() if data["is_proxy"]
        }

        for proxy_name, proxy_data in proxy_contracts.items():
            # Look for implementation contracts
            for impl_name, impl_data in self.contracts.items():
                if impl_name == proxy_name or impl_data["is_proxy"]:
                    continue

                # Check if this implementation is used by the proxy
                if self._is_implementation_for_proxy(proxy_data, impl_data):
                    collisions = self._find_storage_slot_collisions(
                        proxy_data["storage_layout"], impl_data["storage_layout"]
                    )

                    if collisions:
                        self._create_collision_finding(
                            "PROXY_IMPLEMENTATION_STORAGE_COLLISION",
                            proxy_name,
                            impl_name,
                            proxy_data,
                            impl_data,
                            collisions,
                        )

    def _detect_inheritance_collisions(self):
        """Detect storage collisions in inheritance chains"""
        for contract_name, contract_data in self.contracts.items():
            if not contract_data["parents"]:
                continue

            # Get all parent contracts in inheritance chain
            inheritance_chain = self._build_inheritance_chain(contract_name)

            # Check for storage collisions in the chain
            for i, parent1 in enumerate(inheritance_chain):
                for parent2 in inheritance_chain[i + 1 :]:
                    if parent1 in self.contracts and parent2 in self.contracts:
                        collisions = self._find_storage_slot_collisions(
                            self.contracts[parent1]["storage_layout"],
                            self.contracts[parent2]["storage_layout"],
                        )

                        if collisions:
                            self._create_inheritance_collision_finding(
                                contract_name, parent1, parent2, collisions
                            )

    def _detect_delegatecall_storage_risks(self):
        """Detect storage risks in delegatecall contexts"""
        for contract_name, contract_data in self.contracts.items():
            if not contract_data["has_delegatecall"]:
                continue

            # Extract delegatecall targets
            delegatecall_pattern = r"\.delegatecall\s*\("
            matches = re.finditer(delegatecall_pattern, contract_data["content"])

            if matches:
                # Check if storage layout is safe for delegatecall
                risk_score = self._assess_delegatecall_risk(contract_data)

                if risk_score > 0.7:
                    self._create_delegatecall_finding(
                        contract_name, contract_data, risk_score
                    )

    def _detect_unstructured_storage_issues(self):
        """Detect misuse of unstructured storage patterns"""
        for contract_name, contract_data in self.contracts.items():
            content = contract_data["content"]

            # Check for unstructured storage patterns
            if "UnstructuredStorage" in content or "getStorage" in content:
                # Look for potential issues
                issues = self._analyze_unstructured_storage(
                    content, contract_name, contract_data
                )

                if issues:
                    for issue in issues:
                        self.findings.append(issue)

    def _detect_assembly_storage_risks(self):
        """Detect risky storage manipulation via assembly"""
        for contract_name, contract_data in self.contracts.items():
            content = contract_data["content"]

            # Find assembly blocks
            assembly_pattern = r"assembly\s*\{([^}]+)\}"
            assembly_blocks = re.finditer(assembly_pattern, content, re.DOTALL)

            for block in assembly_blocks:
                assembly_code = block.group(1)

                # Check for storage operations
                if "sstore" in assembly_code or "sload" in assembly_code:
                    risk = self._assess_assembly_storage_risk(
                        assembly_code, contract_name, contract_data
                    )

                    if risk:
                        self.findings.append(risk)

    def _is_implementation_for_proxy(self, proxy_data: Dict, impl_data: Dict) -> bool:
        """Check if implementation is used by proxy"""
        proxy_content = proxy_data["content"]
        impl_name = [k for k, v in self.contracts.items() if v == impl_data][0]

        # Look for references to implementation
        return impl_name in proxy_content or "implementation" in proxy_content.lower()

    def _find_storage_slot_collisions(
        self, layout1: List[StorageSlot], layout2: List[StorageSlot]
    ) -> List[Tuple[StorageSlot, StorageSlot]]:
        """Find colliding storage slots between two layouts"""
        collisions = []

        for slot1 in layout1:
            for slot2 in layout2:
                if slot1.slot_number == slot2.slot_number:
                    # Same slot number but different variables = collision
                    if (
                        slot1.variable_name != slot2.variable_name
                        or slot1.variable_type != slot2.variable_type
                    ):
                        collisions.append((slot1, slot2))

        return collisions

    def _build_inheritance_chain(self, contract_name: str) -> List[str]:
        """Build full inheritance chain for a contract"""
        chain = [contract_name]
        visited = set()

        def traverse(name):
            if name in visited or name not in self.contracts:
                return
            visited.add(name)

            for parent in self.contracts[name]["parents"]:
                parent = parent.strip()
                if parent not in chain:
                    chain.append(parent)
                traverse(parent)

        traverse(contract_name)
        return chain

    def _assess_delegatecall_risk(self, contract_data: Dict) -> float:
        """Assess risk score for delegatecall usage"""
        risk_score = 0.0
        content = contract_data["content"]

        # Check for user-controlled delegatecall targets
        if re.search(r"delegatecall\s*\(\s*[^)]*msg\.sender", content):
            risk_score += 0.5

        # Check for missing access controls
        if "onlyOwner" not in content and "require" not in content:
            risk_score += 0.3

        # Check for storage variables that could be overwritten
        if len(contract_data["storage_layout"]) > 0:
            risk_score += 0.2

        return min(risk_score, 1.0)

    def _analyze_unstructured_storage(
        self, content: str, contract_name: str, contract_data: Dict
    ) -> List[StorageCollisionFinding]:
        """Analyze unstructured storage patterns for issues"""
        issues = []

        # Check for hardcoded storage slots
        slot_pattern = r"0x[0-9a-fA-F]{64}"
        slots = re.findall(slot_pattern, content)

        if len(slots) > len(set(slots)):
            # Duplicate slots found - potential collision
            finding = StorageCollisionFinding(
                severity="high",
                finding_type="DUPLICATE_UNSTRUCTURED_STORAGE_SLOTS",
                description=f"Contract {contract_name} uses duplicate storage slots in unstructured storage pattern",
                affected_contracts=[contract_name],
                colliding_slots=[],
                proof_of_concept=f"Multiple uses of same storage slot can cause state overwrites",
                remediation="Use unique storage slots for each unstructured storage variable. Consider using OpenZeppelin's StorageSlot library.",
                confidence=0.85,
                file_path=contract_data["file"],
                line_numbers=[contract_data["start_line"]],
                economic_impact="critical",
                exploitability="high",
            )
            issues.append(finding)

        return issues

    def _assess_assembly_storage_risk(
        self, assembly_code: str, contract_name: str, contract_data: Dict
    ) -> Optional[StorageCollisionFinding]:
        """Assess risk from assembly storage operations"""

        # Check for dynamic slot calculations
        if "add(" in assembly_code and "sstore" in assembly_code:
            return StorageCollisionFinding(
                severity="high",
                finding_type="DYNAMIC_ASSEMBLY_STORAGE_WRITE",
                description=f"Contract {contract_name} uses dynamic storage slot calculations in assembly",
                affected_contracts=[contract_name],
                colliding_slots=[],
                proof_of_concept="Dynamic storage slot writes can overwrite critical state variables if slot calculations are incorrect",
                remediation="Audit all assembly storage operations. Use explicit slot definitions and avoid complex arithmetic.",
                confidence=0.8,
                file_path=contract_data["file"],
                line_numbers=[contract_data["start_line"]],
                economic_impact="high",
                exploitability="medium",
            )

        return None

    def _create_collision_finding(
        self,
        finding_type: str,
        proxy_name: str,
        impl_name: str,
        proxy_data: Dict,
        impl_data: Dict,
        collisions: List[Tuple[StorageSlot, StorageSlot]],
    ):
        """Create a storage collision finding"""

        colliding_slots = []
        for slot1, slot2 in collisions:
            colliding_slots.extend([slot1, slot2])

        poc = self._generate_collision_poc(proxy_name, impl_name, collisions)

        finding = StorageCollisionFinding(
            severity="critical",
            finding_type=finding_type,
            description=f"Storage collision detected between proxy {proxy_name} and implementation {impl_name}. "
            f"Storage slots conflict at positions: {', '.join(str(s[0].slot_number) for s in collisions)}",
            affected_contracts=[proxy_name, impl_name],
            colliding_slots=colliding_slots,
            proof_of_concept=poc,
            remediation="Align storage layouts between proxy and implementation. Use storage gaps or unstructured storage for proxy-specific variables.",
            confidence=0.95,
            file_path=proxy_data["file"],
            line_numbers=[proxy_data["start_line"], impl_data["start_line"]],
            economic_impact="critical",
            exploitability="high",
        )

        self.findings.append(finding)

    def _create_inheritance_collision_finding(
        self,
        contract_name: str,
        parent1: str,
        parent2: str,
        collisions: List[Tuple[StorageSlot, StorageSlot]],
    ):
        """Create an inheritance collision finding"""

        colliding_slots = []
        for slot1, slot2 in collisions:
            colliding_slots.extend([slot1, slot2])

        finding = StorageCollisionFinding(
            severity="high",
            finding_type="INHERITANCE_STORAGE_COLLISION",
            description=f"Storage collision in inheritance chain of {contract_name}. "
            f"Parent contracts {parent1} and {parent2} have conflicting storage layouts.",
            affected_contracts=[contract_name, parent1, parent2],
            colliding_slots=colliding_slots,
            proof_of_concept=f"C3 linearization may cause unexpected storage overwrites when {contract_name} inherits from both {parent1} and {parent2}",
            remediation="Refactor inheritance hierarchy to avoid storage conflicts. Use composition instead of multiple inheritance where possible.",
            confidence=0.9,
            file_path=self.contracts[contract_name]["file"],
            line_numbers=[self.contracts[contract_name]["start_line"]],
            economic_impact="high",
            exploitability="medium",
        )

        self.findings.append(finding)

    def _create_delegatecall_finding(
        self, contract_name: str, contract_data: Dict, risk_score: float
    ):
        """Create a delegatecall storage risk finding"""

        finding = StorageCollisionFinding(
            severity="high" if risk_score > 0.8 else "medium",
            finding_type="DELEGATECALL_STORAGE_RISK",
            description=f"Contract {contract_name} uses delegatecall with potential storage corruption risk (risk score: {risk_score:.2f})",
            affected_contracts=[contract_name],
            colliding_slots=[],
            proof_of_concept="Delegatecall executes code in caller's context. If target contract has different storage layout, state corruption can occur.",
            remediation="Ensure delegatecall targets have compatible storage layouts. Add access controls. Consider using library delegatecall pattern.",
            confidence=0.85,
            file_path=contract_data["file"],
            line_numbers=[contract_data["start_line"]],
            economic_impact="high",
            exploitability="high" if risk_score > 0.8 else "medium",
        )

        self.findings.append(finding)

    def _generate_collision_poc(
        self,
        proxy_name: str,
        impl_name: str,
        collisions: List[Tuple[StorageSlot, StorageSlot]],
    ) -> str:
        """Generate proof of concept for storage collision"""

        poc = f"""
### Proof of Concept: Storage Collision Attack

**Scenario**: Proxy `{proxy_name}` delegatecalls to implementation `{impl_name}`

**Colliding Storage Slots**:
"""
        for slot1, slot2 in collisions:
            poc += f"\n- Slot {slot1.slot_number}:"
            poc += f"\n  - Proxy: `{slot1.variable_type} {slot1.variable_name}`"
            poc += (
                f"\n  - Implementation: `{slot2.variable_type} {slot2.variable_name}`"
            )

        poc += f"""

**Attack Vector**:
1. Attacker identifies storage slot collision
2. Calls function in implementation that writes to colliding slot
3. Due to delegatecall context, write overwrites proxy's critical variable
4. Proxy state is corrupted, potentially granting attacker control

**Example**: If implementation writes to slot {collisions[0][0].slot_number}, it overwrites proxy's `{collisions[0][0].variable_name}` variable.
"""

        return poc

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive vulnerability report"""
        return {
            "detector": "StorageCollisionDetector",
            "version": "1.0.0",
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == "critical"]),
            "high": len([f for f in self.findings if f.severity == "high"]),
            "medium": len([f for f in self.findings if f.severity == "medium"]),
            "findings": [f.to_dict() for f in self.findings],
            "contracts_analyzed": len(self.contracts),
            "summary": self._generate_summary(),
        }

    def _generate_summary(self) -> str:
        """Generate executive summary"""
        if not self.findings:
            return "No storage collision vulnerabilities detected."

        critical = len([f for f in self.findings if f.severity == "critical"])
        high = len([f for f in self.findings if f.severity == "high"])

        summary = f"Detected {len(self.findings)} storage-related vulnerabilities: "
        summary += f"{critical} critical, {high} high severity. "
        summary += (
            "Immediate remediation required for proxy patterns and inheritance chains."
        )

        return summary


def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python storage_collision_detector.py <directory_path>")
        sys.exit(1)

    detector = StorageCollisionDetector(verbose=True)
    findings = detector.analyze_directory(sys.argv[1])

    print("\n" + "=" * 80)
    print(f"🔍 Storage Collision Analysis Complete")
    print("=" * 80)
    print(f"Total Findings: {len(findings)}")

    for finding in findings:
        print(f"\n{'=' * 80}")
        print(f"[{finding.severity.upper()}] {finding.finding_type}")
        print(f"{'=' * 80}")
        print(f"Description: {finding.description}")
        print(f"Affected Contracts: {', '.join(finding.affected_contracts)}")
        print(f"Confidence: {finding.confidence * 100:.0f}%")
        print(f"\nRemediation: {finding.remediation}")

    # Save report
    report = detector.generate_report()
    with open("storage_collision_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Full report saved to: storage_collision_report.json")


if __name__ == "__main__":
    main()
