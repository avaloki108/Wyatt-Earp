"""
Fuzzing Executor - Actual execution of Echidna and Foundry fuzzers
Wires up the fuzzing orchestrator to real tools
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import yaml
import time


@dataclass
class FuzzingResult:
    """Unified fuzzing result"""

    tool: str  # "echidna" or "foundry"
    success: bool
    tests_run: int
    tests_passed: int
    tests_failed: int
    coverage_percent: float
    vulnerabilities: List[Dict[str, Any]]
    execution_time: float
    raw_output: str
    failed_invariants: List[str]


class EchidnaExecutor:
    """Execute Echidna property-based fuzzer"""

    def __init__(self, contract_path: str):
        self.contract_path = Path(contract_path)
        self.project_root = self.contract_path.parent

    def check_installed(self) -> bool:
        """Check if Echidna is installed"""
        try:
            result = subprocess.run(
                ["echidna", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def generate_config(
        self, test_limit: int = 10000, timeout: int = 300, coverage: bool = True
    ) -> str:
        """Generate Echidna configuration file"""
        config = {
            "testLimit": test_limit,
            "timeout": timeout,
            "coverage": coverage,
            "corpusDir": "echidna-corpus",
            "format": "json",
            "quiet": False,
            "crytic-args": ["--solc-remaps", "@=node_modules/@"],
        }

        config_path = self.project_root / "echidna.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)

        return str(config_path)

    def create_property_test(self, contract_name: str, properties: List[str]) -> str:
        """
        Create Echidna property test contract

        properties: List of invariant descriptions
        Example: ["balance should never decrease", "total supply equals sum of balances"]
        """

        # Generate property functions
        property_functions = []
        for i, prop in enumerate(properties):
            func_name = f"echidna_property_{i}"

            # Simple heuristic to convert description to test
            if "never" in prop.lower() and "decrease" in prop.lower():
                property_functions.append(f"""
    uint256 private initialBalance;

    function echidna_{i}_balance_never_decreases() public returns (bool) {{
        if (initialBalance == 0) {{
            initialBalance = address(this).balance;
            return true;
        }}
        return address(this).balance >= initialBalance;
    }}
""")
            elif "equal" in prop.lower():
                property_functions.append(f"""
    function echidna_{i}_invariant_holds() public view returns (bool) {{
        // Property: {prop}
        // Auto-generated - customize as needed
        return true; // Placeholder
    }}
""")
            else:
                property_functions.append(f"""
    function echidna_{i}_custom_property() public view returns (bool) {{
        // Property: {prop}
        // Auto-generated - customize as needed
        return true; // Placeholder
    }}
""")

        test_contract = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{self.contract_path.name}";

contract EchidnaTest {{
    {contract_name} target;

    constructor() {{
        target = new {contract_name}();
    }}

    {"".join(property_functions)}
}}
"""

        test_path = self.project_root / f"Echidna{contract_name}Test.sol"
        with open(test_path, "w") as f:
            f.write(test_contract)

        return str(test_path)

    def run(
        self,
        contract_name: str,
        test_contract: Optional[str] = None,
        config_path: Optional[str] = None,
        timeout: int = 300,
    ) -> FuzzingResult:
        """Run Echidna fuzzer"""

        if not self.check_installed():
            return FuzzingResult(
                tool="echidna",
                success=False,
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                coverage_percent=0.0,
                vulnerabilities=[],
                execution_time=0.0,
                raw_output="Echidna not installed. Install: https://github.com/crytic/echidna",
                failed_invariants=[],
            )

        start_time = time.time()

        # Generate config if not provided
        if not config_path:
            config_path = self.generate_config(timeout=timeout)

        # Use test contract or main contract
        target = test_contract or str(self.contract_path)

        cmd = ["echidna", target, "--contract", contract_name, "--config", config_path]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
                cwd=str(self.project_root),
            )

            execution_time = time.time() - start_time

            # Parse Echidna output
            vulnerabilities = self._parse_echidna_output(result.stdout + result.stderr)

            return FuzzingResult(
                tool="echidna",
                success=result.returncode == 0,
                tests_run=len(vulnerabilities),
                tests_passed=sum(1 for v in vulnerabilities if v["passed"]),
                tests_failed=sum(1 for v in vulnerabilities if not v["passed"]),
                coverage_percent=self._extract_coverage(result.stdout),
                vulnerabilities=vulnerabilities,
                execution_time=execution_time,
                raw_output=result.stdout + "\n" + result.stderr,
                failed_invariants=[
                    v["property"] for v in vulnerabilities if not v["passed"]
                ],
            )

        except subprocess.TimeoutExpired:
            return FuzzingResult(
                tool="echidna",
                success=False,
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                coverage_percent=0.0,
                vulnerabilities=[],
                execution_time=timeout,
                raw_output="Timeout exceeded",
                failed_invariants=[],
            )
        except Exception as e:
            return FuzzingResult(
                tool="echidna",
                success=False,
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                coverage_percent=0.0,
                vulnerabilities=[],
                execution_time=time.time() - start_time,
                raw_output=f"Error: {str(e)}",
                failed_invariants=[],
            )

    def _parse_echidna_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Echidna output for vulnerabilities"""
        vulnerabilities = []

        lines = output.split("\n")
        for line in lines:
            if "echidna_" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    property_name = parts[0].strip()
                    status = parts[1].strip().lower()

                    passed = "passed" in status or "ok" in status

                    vulnerabilities.append(
                        {
                            "property": property_name,
                            "passed": passed,
                            "severity": "high" if not passed else "info",
                            "description": f"Property {property_name} {'passed' if passed else 'FAILED'}",
                        }
                    )

        return vulnerabilities

    def _extract_coverage(self, output: str) -> float:
        """Extract coverage percentage from output"""
        # Echidna doesn't always report coverage clearly
        # This is a simple heuristic
        if "coverage" in output.lower():
            # Try to extract percentage
            import re

            match = re.search(r"(\d+(?:\.\d+)?)\s*%", output)
            if match:
                return float(match.group(1))
        return 0.0


class FoundryExecutor:
    """Execute Foundry (Forge) fuzzer"""

    def __init__(self, contract_path: str):
        self.contract_path = Path(contract_path)
        self.project_root = self.contract_path.parent

    def check_installed(self) -> bool:
        """Check if Foundry is installed"""
        try:
            result = subprocess.run(
                ["forge", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def setup_foundry_project(self) -> bool:
        """Initialize Foundry project if not already done"""
        foundry_toml = self.project_root / "foundry.toml"

        if not foundry_toml.exists():
            try:
                subprocess.run(
                    ["forge", "init", "--force"],
                    cwd=str(self.project_root),
                    capture_output=True,
                    timeout=30,
                )
                return True
            except (subprocess.SubprocessError, OSError, TimeoutError):
                return False
        return True

    def create_fuzz_test(self, contract_name: str, invariants: List[str]) -> str:
        """
        Create Foundry fuzz test

        invariants: List of invariant descriptions
        """

        test_functions = []
        for i, invariant in enumerate(invariants):
            # Generate fuzz test with random inputs
            test_functions.append(f"""
    function testFuzz_{i}_invariant(uint256 amount, address user) public {{
        // Invariant: {invariant}
        vm.assume(user != address(0));
        vm.assume(amount > 0 && amount < type(uint128).max);

        // TODO: Implement actual invariant test
        assertTrue(true, "{invariant}");
    }}
""")

        test_contract = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../{self.contract_path.name}";

contract {contract_name}FuzzTest is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    {"".join(test_functions)}

    // Invariant test - runs after every function call
    function invariant_basic_sanity() public {{
        // Basic sanity checks
        assertTrue(address(target) != address(0));
    }}
}}
"""

        test_dir = self.project_root / "test"
        test_dir.mkdir(exist_ok=True)

        test_path = test_dir / f"{contract_name}.fuzz.t.sol"
        with open(test_path, "w") as f:
            f.write(test_contract)

        return str(test_path)

    def run(
        self,
        contract_name: str,
        test_contract: Optional[str] = None,
        fuzz_runs: int = 10000,
        timeout: int = 300,
    ) -> FuzzingResult:
        """Run Foundry fuzzer"""

        if not self.check_installed():
            return FuzzingResult(
                tool="foundry",
                success=False,
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                coverage_percent=0.0,
                vulnerabilities=[],
                execution_time=0.0,
                raw_output="Foundry not installed. Install: https://getfoundry.sh",
                failed_invariants=[],
            )

        start_time = time.time()

        # Setup project
        self.setup_foundry_project()

        cmd = [
            "forge",
            "test",
            "--fuzz-runs",
            str(fuzz_runs),
            "-vvv",  # Verbose output
            "--json",
        ]

        if test_contract:
            cmd.extend(["--match-path", test_contract])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
                cwd=str(self.project_root),
            )

            execution_time = time.time() - start_time

            # Parse Foundry JSON output
            vulnerabilities = self._parse_foundry_output(result.stdout)

            return FuzzingResult(
                tool="foundry",
                success=result.returncode == 0,
                tests_run=len(vulnerabilities),
                tests_passed=sum(1 for v in vulnerabilities if v["passed"]),
                tests_failed=sum(1 for v in vulnerabilities if not v["passed"]),
                coverage_percent=self._extract_coverage(result.stdout),
                vulnerabilities=vulnerabilities,
                execution_time=execution_time,
                raw_output=result.stdout + "\n" + result.stderr,
                failed_invariants=[
                    v["test"] for v in vulnerabilities if not v["passed"]
                ],
            )

        except subprocess.TimeoutExpired:
            return FuzzingResult(
                tool="foundry",
                success=False,
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                coverage_percent=0.0,
                vulnerabilities=[],
                execution_time=timeout,
                raw_output="Timeout exceeded",
                failed_invariants=[],
            )
        except Exception as e:
            return FuzzingResult(
                tool="foundry",
                success=False,
                tests_run=0,
                tests_passed=0,
                tests_failed=0,
                coverage_percent=0.0,
                vulnerabilities=[],
                execution_time=time.time() - start_time,
                raw_output=f"Error: {str(e)}",
                failed_invariants=[],
            )

    def _parse_foundry_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Foundry JSON output"""
        vulnerabilities = []

        try:
            # Try to parse as JSON
            data = json.loads(output)

            for test_name, test_data in data.items():
                if isinstance(test_data, dict):
                    passed = test_data.get("success", False)

                    vulnerabilities.append(
                        {
                            "test": test_name,
                            "passed": passed,
                            "severity": "high" if not passed else "info",
                            "description": test_data.get(
                                "reason",
                                f"Test {test_name} {'passed' if passed else 'FAILED'}",
                            ),
                            "gas_used": test_data.get("gasUsed", 0),
                        }
                    )
        except json.JSONDecodeError:
            # Fall back to text parsing
            lines = output.split("\n")
            for line in lines:
                if "[PASS]" in line or "[FAIL]" in line:
                    passed = "[PASS]" in line
                    test_name = line.split("]")[1].strip() if "]" in line else line

                    vulnerabilities.append(
                        {
                            "test": test_name,
                            "passed": passed,
                            "severity": "high" if not passed else "info",
                            "description": f"Test {test_name} {'passed' if passed else 'FAILED'}",
                        }
                    )

        return vulnerabilities

    def _extract_coverage(self, output: str) -> float:
        """Extract coverage from Foundry output"""
        # Foundry reports coverage differently
        if "coverage" in output.lower():
            import re

            match = re.search(r"(\d+(?:\.\d+)?)\s*%", output)
            if match:
                return float(match.group(1))
        return 0.0


class UnifiedFuzzer:
    """Unified interface for all fuzzers"""

    def __init__(self, contract_path: str):
        self.contract_path = contract_path
        self.echidna = EchidnaExecutor(contract_path)
        self.foundry = FoundryExecutor(contract_path)

    def run_all(
        self,
        contract_name: str,
        invariants: List[str],
        fuzz_runs: int = 10000,
        timeout: int = 300,
    ) -> Dict[str, FuzzingResult]:
        """Run all available fuzzers"""

        results = {}

        # Run Echidna
        print("Running Echidna fuzzer...")
        echidna_result = self.echidna.run(contract_name=contract_name, timeout=timeout)
        results["echidna"] = echidna_result

        # Run Foundry
        print("Running Foundry fuzzer...")
        foundry_result = self.foundry.run(
            contract_name=contract_name, fuzz_runs=fuzz_runs, timeout=timeout
        )
        results["foundry"] = foundry_result

        return results

    def get_combined_report(self, results: Dict[str, FuzzingResult]) -> Dict[str, Any]:
        """Combine results from all fuzzers"""

        all_vulnerabilities = []
        total_tests = 0
        total_failed = 0

        for tool, result in results.items():
            total_tests += result.tests_run
            total_failed += result.tests_failed

            for vuln in result.vulnerabilities:
                vuln["tool"] = tool
                all_vulnerabilities.append(vuln)

        return {
            "summary": {
                "total_tests": total_tests,
                "total_passed": total_tests - total_failed,
                "total_failed": total_failed,
                "tools_used": list(results.keys()),
                "success_rate": (total_tests - total_failed) / total_tests
                if total_tests > 0
                else 0.0,
            },
            "vulnerabilities": all_vulnerabilities,
            "tool_results": {tool: asdict(result) for tool, result in results.items()},
        }


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python fuzzer_executor.py <contract_path> <contract_name>")
        sys.exit(1)

    contract_path = sys.argv[1]
    contract_name = sys.argv[2]

    fuzzer = UnifiedFuzzer(contract_path)

    # Example invariants
    invariants = [
        "User balance should never exceed total supply",
        "Total supply should equal sum of all balances",
        "Withdrawals should never exceed deposits",
    ]

    print(f"Fuzzing {contract_name}...")
    results = fuzzer.run_all(
        contract_name=contract_name, invariants=invariants, fuzz_runs=5000, timeout=120
    )

    report = fuzzer.get_combined_report(results)

    print("\n" + "=" * 70)
    print("FUZZING REPORT")
    print("=" * 70)
    print(f"Total tests: {report['summary']['total_tests']}")
    print(f"Passed: {report['summary']['total_passed']}")
    print(f"Failed: {report['summary']['total_failed']}")
    print(f"Success rate: {report['summary']['success_rate'] * 100:.1f}%")

    if report["vulnerabilities"]:
        print(f"\nVulnerabilities found: {len(report['vulnerabilities'])}")
        for vuln in report["vulnerabilities"]:
            if not vuln.get("passed", True):
                print(
                    f"  [{vuln['tool']}] {vuln.get('test', vuln.get('property', 'Unknown'))}"
                )
