"""
Enhanced Fuzzing Orchestrator
Intelligent fuzzing with coverage-guided mutations, adaptive strategies,
and integration with symbolic execution for maximum vulnerability discovery
"""

from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from enum import Enum
import subprocess


class FuzzingStrategy(Enum):
    RANDOM = "random"
    COVERAGE_GUIDED = "coverage_guided"
    SYMBOLIC_GUIDED = "symbolic_guided"
    MUTATION_BASED = "mutation_based"
    GRAMMAR_BASED = "grammar_based"
    ADVERSARIAL = "adversarial"


@dataclass
class FuzzingConfig:
    """Configuration for fuzzing campaign"""

    strategy: FuzzingStrategy
    max_iterations: int = 10000
    max_time_seconds: int = 3600
    corpus_dir: str = "corpus"
    crash_dir: str = "crashes"
    coverage_target: float = 0.90
    use_symbolic_execution: bool = True
    use_llm_guidance: bool = False


@dataclass
class FuzzingResult:
    """Result from fuzzing campaign"""

    strategy: FuzzingStrategy
    iterations_run: int
    coverage_achieved: float
    vulnerabilities_found: List[Dict[str, Any]]
    interesting_inputs: List[Any]
    execution_time: float
    crash_count: int


class EnhancedFuzzingOrchestrator:
    """
    Advanced fuzzing orchestrator that combines multiple fuzzing strategies
    with symbolic execution and LLM guidance for maximum effectiveness
    """

    def __init__(self, config: FuzzingConfig):
        self.config = config
        self.coverage_data: Dict[str, Set[int]] = {}
        self.corpus: List[Any] = []
        self.crashes: List[Any] = []
        self.interesting_inputs: List[Any] = []

    def run_fuzzing_campaign(
        self,
        contract_path: str,
        property_functions: List[str],
        symbolic_constraints: Optional[List[Any]] = None,
    ) -> FuzzingResult:
        """
        Run comprehensive fuzzing campaign with multiple strategies
        """
        print(f"Starting fuzzing campaign with strategy: {self.config.strategy.value}")

        if self.config.strategy == FuzzingStrategy.COVERAGE_GUIDED:
            return self._coverage_guided_fuzzing(contract_path, property_functions)
        elif self.config.strategy == FuzzingStrategy.SYMBOLIC_GUIDED:
            return self._symbolic_guided_fuzzing(
                contract_path, property_functions, symbolic_constraints
            )
        elif self.config.strategy == FuzzingStrategy.MUTATION_BASED:
            return self._mutation_based_fuzzing(contract_path, property_functions)
        elif self.config.strategy == FuzzingStrategy.ADVERSARIAL:
            return self._adversarial_fuzzing(contract_path, property_functions)
        else:
            return self._random_fuzzing(contract_path, property_functions)

    def _coverage_guided_fuzzing(
        self, contract_path: str, property_functions: List[str]
    ) -> FuzzingResult:
        """
        Coverage-guided fuzzing (like AFL/libFuzzer)
        Prioritizes inputs that increase code coverage
        """
        print("Running coverage-guided fuzzing...")

        vulnerabilities = []
        iterations = 0
        coverage = 0.0

        # Generate initial corpus
        self._generate_initial_corpus(contract_path)

        while (
            iterations < self.config.max_iterations
            and coverage < self.config.coverage_target
        ):
            # Select input from corpus
            input_data = self._select_from_corpus()

            # Mutate input
            mutated_input = self._mutate_input(input_data)

            # Execute with Echidna
            result = self._execute_echidna(contract_path, mutated_input)

            # Update coverage
            new_coverage = self._extract_coverage(result)
            if new_coverage > coverage:
                coverage = new_coverage
                self.corpus.append(mutated_input)
                print(f"New coverage: {coverage:.2%} at iteration {iterations}")

            # Check for property violations
            violations = self._check_property_violations(result, property_functions)
            if violations:
                vulnerabilities.extend(violations)
                self.crashes.append(mutated_input)

            iterations += 1

        return FuzzingResult(
            strategy=FuzzingStrategy.COVERAGE_GUIDED,
            iterations_run=iterations,
            coverage_achieved=coverage,
            vulnerabilities_found=vulnerabilities,
            interesting_inputs=self.interesting_inputs,
            execution_time=0.0,
            crash_count=len(self.crashes),
        )

    def _symbolic_guided_fuzzing(
        self,
        contract_path: str,
        property_functions: List[str],
        symbolic_constraints: Optional[List[Any]] = None,
    ) -> FuzzingResult:
        """
        Symbolic execution guided fuzzing
        Uses symbolic constraints to generate targeted inputs
        """
        print("Running symbolic-guided fuzzing...")

        from .symbolic_execution_engine import AdvancedSymbolicExecutor

        executor = AdvancedSymbolicExecutor()
        vulnerabilities = []
        targeted_inputs = []

        # Use symbolic execution to find interesting paths
        if symbolic_constraints:
            # Generate inputs that satisfy constraints
            targeted_inputs = self._generate_from_constraints(symbolic_constraints)

            for input_data in targeted_inputs:
                result = self._execute_echidna(contract_path, input_data)

                violations = self._check_property_violations(result, property_functions)
                if violations:
                    vulnerabilities.extend(violations)

        return FuzzingResult(
            strategy=FuzzingStrategy.SYMBOLIC_GUIDED,
            iterations_run=len(targeted_inputs) if symbolic_constraints else 0,
            coverage_achieved=0.0,
            vulnerabilities_found=vulnerabilities,
            interesting_inputs=[],
            execution_time=0.0,
            crash_count=len(vulnerabilities),
        )

    def _mutation_based_fuzzing(
        self, contract_path: str, property_functions: List[str]
    ) -> FuzzingResult:
        """
        Mutation-based fuzzing with smart mutations
        """
        print("Running mutation-based fuzzing...")

        vulnerabilities = []
        iterations = 0

        # Start with interesting base cases
        base_inputs = self._generate_interesting_base_cases()

        for base_input in base_inputs:
            for _ in range(100):  # Mutate each base input multiple times
                mutated = self._smart_mutate(base_input)

                result = self._execute_echidna(contract_path, mutated)

                violations = self._check_property_violations(result, property_functions)
                if violations:
                    vulnerabilities.extend(violations)

                iterations += 1

        return FuzzingResult(
            strategy=FuzzingStrategy.MUTATION_BASED,
            iterations_run=iterations,
            coverage_achieved=0.0,
            vulnerabilities_found=vulnerabilities,
            interesting_inputs=[],
            execution_time=0.0,
            crash_count=len(vulnerabilities),
        )

    def _adversarial_fuzzing(
        self, contract_path: str, property_functions: List[str]
    ) -> FuzzingResult:
        """
        Adversarial fuzzing - generate inputs specifically designed to break properties
        """
        print("Running adversarial fuzzing...")

        vulnerabilities = []
        adversarial_inputs = []

        # Generate adversarial inputs for each property
        for prop in property_functions:
            adversarial_inputs = self._generate_adversarial_inputs(prop)

            for input_data in adversarial_inputs:
                result = self._execute_echidna(contract_path, input_data)

                violations = self._check_property_violations(result, [prop])
                if violations:
                    vulnerabilities.extend(violations)

        return FuzzingResult(
            strategy=FuzzingStrategy.ADVERSARIAL,
            iterations_run=len(adversarial_inputs) * len(property_functions)
            if adversarial_inputs
            else 0,
            coverage_achieved=0.0,
            vulnerabilities_found=vulnerabilities,
            interesting_inputs=[],
            execution_time=0.0,
            crash_count=len(vulnerabilities),
        )

    def _random_fuzzing(
        self, contract_path: str, property_functions: List[str]
    ) -> FuzzingResult:
        """Basic random fuzzing with Echidna"""
        print("Running random fuzzing with Echidna...")

        # Run Echidna with default configuration
        result = subprocess.run(
            ["echidna", contract_path, "--test-limit", str(self.config.max_iterations)],
            capture_output=True,
            text=True,
            timeout=self.config.max_time_seconds,
        )

        vulnerabilities = self._parse_echidna_output(result.stdout)

        return FuzzingResult(
            strategy=FuzzingStrategy.RANDOM,
            iterations_run=self.config.max_iterations,
            coverage_achieved=0.0,
            vulnerabilities_found=vulnerabilities,
            interesting_inputs=[],
            execution_time=0.0,
            crash_count=len(vulnerabilities),
        )

    def _generate_initial_corpus(self, contract_path: str):
        """Generate initial fuzzing corpus with interesting values"""
        self.corpus = [
            # Interesting numbers
            {"value": 0},
            {"value": 1},
            {"value": 2**256 - 1},  # MAX_UINT256
            {"value": 2**255},  # Half of max
            {"value": 2**128},
            {"value": 10**18},  # 1 ether in wei
            # Edge cases
            {"value": -1},
            {"value": 2**256},  # Overflow
            # Common amounts
            {"value": 100 * 10**18},
            {"value": 1000000 * 10**18},
        ]

    def _select_from_corpus(self) -> Any:
        """Select input from corpus (prefer inputs with high coverage)"""
        if not self.corpus:
            return {"value": 0}

        # Simple random selection for now
        # In production, use coverage-weighted selection
        import random

        return random.choice(self.corpus)

    def _mutate_input(self, input_data: Any) -> Any:
        """Mutate input data"""
        import random

        mutated = input_data.copy()

        if "value" in mutated:
            # Apply random mutation
            mutation_type = random.choice(
                ["bit_flip", "arithmetic", "interesting_value"]
            )

            if mutation_type == "bit_flip":
                # Flip random bit
                value = mutated["value"]
                bit_position = random.randint(0, 255)
                mutated["value"] = value ^ (1 << bit_position)

            elif mutation_type == "arithmetic":
                # Add/subtract random amount
                delta = random.choice([1, -1, 100, -100, 10**18, -(10**18)])
                mutated["value"] = max(0, mutated["value"] + delta)

            elif mutation_type == "interesting_value":
                # Replace with interesting value
                mutated["value"] = random.choice([0, 1, 2**256 - 1, 10**18])

        return mutated

    def _smart_mutate(self, input_data: Any) -> Any:
        """Smart mutation based on vulnerability patterns"""
        import random

        mutated = input_data.copy()

        # Mutations targeting specific vulnerability classes
        mutation_strategy = random.choice(
            [
                "overflow_trigger",
                "underflow_trigger",
                "precision_loss",
                "zero_value",
                "max_value",
            ]
        )

        if mutation_strategy == "overflow_trigger":
            mutated["value"] = 2**256 - 2
        elif mutation_strategy == "underflow_trigger":
            mutated["value"] = 1
        elif mutation_strategy == "precision_loss":
            mutated["value"] = 3  # Triggers rounding in divisions
        elif mutation_strategy == "zero_value":
            mutated["value"] = 0
        elif mutation_strategy == "max_value":
            mutated["value"] = 2**256 - 1

        return mutated

    def _execute_echidna(self, contract_path: str, input_data: Any) -> Dict[str, Any]:
        """Execute Echidna with given input"""
        # In production, this would actually run Echidna
        # For now, return mock result
        return {
            "coverage": 0.75,
            "properties": {
                "echidna_balance_conservation": True,
                "echidna_no_reentrancy": True,
            },
        }

    def _extract_coverage(self, result: Dict[str, Any]) -> float:
        """Extract coverage from execution result"""
        return result.get("coverage", 0.0)

    def _check_property_violations(
        self, result: Dict[str, Any], property_functions: List[str]
    ) -> List[Dict[str, Any]]:
        """Check if any properties were violated"""
        violations = []

        properties = result.get("properties", {})
        for prop_name in property_functions:
            if prop_name in properties and not properties[prop_name]:
                violations.append(
                    {
                        "property": prop_name,
                        "severity": "high",
                        "description": f"Property {prop_name} violated",
                    }
                )

        return violations

    def _generate_from_constraints(self, constraints: List[Any]) -> List[Any]:
        """Generate inputs that satisfy symbolic constraints"""
        # Use Z3 to generate satisfying assignments
        inputs = []

        # Simplified - in production, use actual Z3 solver
        inputs.append({"value": 1000})
        inputs.append({"value": 2**200})

        return inputs

    def _generate_interesting_base_cases(self) -> List[Any]:
        """Generate interesting base cases for mutation"""
        return [
            {"value": 0},
            {"value": 1},
            {"value": 100},
            {"value": 10**18},
            {"value": 2**128},
            {"value": 2**255},
            {"value": 2**256 - 1},
        ]

    def _generate_adversarial_inputs(self, property_name: str) -> List[Any]:
        """Generate inputs designed to break specific property"""
        adversarial = []

        # Analyze property to determine adversarial inputs
        if "balance" in property_name.lower():
            # Try to break balance conservation
            adversarial.extend(
                [
                    {"value": 0},  # Zero transfer
                    {"value": 2**256 - 1},  # Max transfer
                ]
            )

        if "overflow" in property_name.lower():
            # Try to trigger overflow
            adversarial.extend(
                [
                    {"value": 2**256 - 1},
                    {"value": 2**255 + 2**254},
                ]
            )

        if "reentrancy" in property_name.lower():
            # Simulate reentrancy conditions
            adversarial.extend(
                [
                    {"value": 100, "reentrant": True},
                ]
            )

        return adversarial

    def _parse_echidna_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Echidna output for vulnerabilities"""
        vulnerabilities = []

        lines = output.split("\n")
        for line in lines:
            if "FAILED" in line or "failed" in line:
                vulnerabilities.append(
                    {
                        "type": "property_violation",
                        "description": line,
                        "severity": "high",
                    }
                )

        return vulnerabilities

    def generate_fuzzing_report(self, results: List[FuzzingResult]) -> str:
        """Generate comprehensive fuzzing report"""
        report = "# Enhanced Fuzzing Campaign Report\n\n"

        for result in results:
            report += f"## Strategy: {result.strategy.value}\n"
            report += f"- Iterations: {result.iterations_run}\n"
            report += f"- Coverage: {result.coverage_achieved:.2%}\n"
            report += f"- Vulnerabilities: {len(result.vulnerabilities_found)}\n"
            report += f"- Crashes: {result.crash_count}\n\n"

            if result.vulnerabilities_found:
                report += "### Vulnerabilities Found:\n"
                for vuln in result.vulnerabilities_found:
                    report += f"- {vuln.get('property', 'Unknown')}: {vuln.get('description', '')}\n"
                report += "\n"

        return report


def demonstrate_enhanced_fuzzing():
    """Demonstrate enhanced fuzzing orchestrator"""

    # Configure fuzzing campaign
    configs = [
        FuzzingConfig(strategy=FuzzingStrategy.COVERAGE_GUIDED, max_iterations=5000),
        FuzzingConfig(strategy=FuzzingStrategy.MUTATION_BASED, max_iterations=3000),
        FuzzingConfig(strategy=FuzzingStrategy.ADVERSARIAL, max_iterations=1000),
    ]

    property_functions = [
        "echidna_balance_conservation",
        "echidna_no_overflow",
        "echidna_no_reentrancy",
        "echidna_access_control",
    ]

    results = []

    for config in configs:
        print(f"\n{'=' * 60}")
        print(f"Running fuzzing with strategy: {config.strategy.value}")
        print(f"{'=' * 60}")

        orchestrator = EnhancedFuzzingOrchestrator(config)

        result = orchestrator.run_fuzzing_campaign(
            contract_path="./vulnerable_contract.sol",
            property_functions=property_functions,
        )

        results.append(result)

        print("\nResults:")
        print(f"  Iterations: {result.iterations_run}")
        print(f"  Coverage: {result.coverage_achieved:.2%}")
        print(f"  Vulnerabilities: {len(result.vulnerabilities_found)}")

    # Generate report
    print(f"\n{'=' * 60}")
    print("FINAL REPORT")
    print(f"{'=' * 60}")

    report = orchestrator.generate_fuzzing_report(results)
    print(report)

    return results


if __name__ == "__main__":
    results = demonstrate_enhanced_fuzzing()
    print(f"\nTotal fuzzing strategies tested: {len(results)}")
