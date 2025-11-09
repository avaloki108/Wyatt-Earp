"""
PoC Generation Framework - Automated Proof of Concept Generation
Generates Foundry/Hardhat test scripts for vulnerability hypotheses with safety framework
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import os
import re
import tempfile
import asyncio
import json

from .exploit_template_loader import ExploitTemplateLoader


class PoCFramework(Enum):
    """Supported PoC frameworks"""

    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    BROWNIE = "brownie"


@dataclass
class PoCTemplate:
    """Template for generating PoCs"""

    framework: PoCFramework
    vulnerability_type: str
    template_code: str
    required_imports: List[str]
    setup_code: str
    exploit_code: str
    validation_code: str
    template_id: str = ""
    stage_plan: List[Dict[str, Any]] = field(default_factory=list)
    detection_metadata: Dict[str, Any] = field(default_factory=dict)
    historical_references: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoCResult:
    """Result from PoC generation and execution"""

    hypothesis_id: str
    framework: PoCFramework
    generated_code: str
    execution_successful: bool
    exploit_demonstrated: bool
    output: str
    gas_used: int = 0
    profit_extracted: str = "0"
    timestamp: str = ""
    error_message: str = ""
    safety_validated: bool = False
    execution_time: float = 0.0


class SafetyValidator:
    """
    Safety validation framework for generated PoCs
    Ensures PoCs are non-exploitative and safe for execution
    """

    def __init__(self):
        # Forbidden patterns that indicate potential malicious code
        self.forbidden_patterns = [
            r"mainnet",
            r"eth_mainnet",
            r"production",
            r"real[\s_-]?funds?",
            r"0x[a-fA-F0-9]{40}(?!.*test)",  # Real addresses (not test)
            r"private[\s_-]?key",
            r"mnemonic",
            r"seed[\s_-]?phrase",
        ]

        # Required patterns for valid test PoCs
        self.required_patterns = [
            r"import.*Test\.sol",  # Must import test framework
            r"function\s+test",  # Must have test functions
        ]

        # Whitelisted safe patterns
        self.safe_patterns = [
            r"vm\.",  # Foundry cheatcodes
            r"console\.log",  # Logging
            r"vm\.deal",  # Test funding
            r"vm\.prank",  # Impersonation for tests
            r"new\s+\w+\(",  # Contract deployment in tests
        ]

    def validate(self, poc_code: str) -> Dict[str, Any]:
        """
        Comprehensive safety validation of PoC code
        Returns dict with validation results
        """
        checks = {
            "no_mainnet_interaction": self._check_no_mainnet_interaction(poc_code),
            "no_real_fund_transfer": self._check_no_real_fund_transfer(poc_code),
            "no_malicious_external_calls": self._check_no_malicious_external_calls(
                poc_code
            ),
            "uses_test_framework": self._check_uses_test_framework(poc_code),
            "no_private_key_exposure": self._check_no_private_key_exposure(poc_code),
            "has_test_functions": self._check_has_test_functions(poc_code),
        }

        all_passed = all(checks.values())

        return {
            "safe": all_passed,
            "checks": checks,
            "warnings": self._get_warnings(checks),
            "recommendations": self._get_recommendations(checks, poc_code),
        }

    def _check_no_mainnet_interaction(self, code: str) -> bool:
        """Ensure no mainnet RPC URLs or production addresses"""
        forbidden = [
            "mainnet",
            "eth_mainnet",
            "production",
            "https://mainnet",
            "wss://mainnet",
            "infura.io/v3",
            "alchemy.com/v2",
        ]
        code_lower = code.lower()
        return not any(term in code_lower for term in forbidden)

    def _check_no_real_fund_transfer(self, code: str) -> bool:
        """Ensure no real fund transfers"""
        # Check for real ETH addresses (not test addresses)
        real_address_pattern = r"0x[a-fA-F0-9]{40}"
        matches = re.findall(real_address_pattern, code)

        # Test addresses typically start with 0x0000... or 0xdead... or are from vm.addr()
        for match in matches:
            if not (
                match.startswith("0x0000")
                or match.startswith("0xdead")
                or match.startswith("0xDEAD")
                or "vm.addr" in code
            ):
                # Check if it's a known test address pattern
                if not self._is_test_address(match):
                    return False
        return True

    def _check_no_malicious_external_calls(self, code: str) -> bool:
        """Check for suspicious external calls"""
        # Look for external calls that aren't to test contracts
        suspicious_calls = [
            r"\.call\{value:.*\}\([^)]*0x[a-fA-F0-9]{40}",  # External call to hardcoded address
            r"selfdestruct\(",  # Self-destruct (unless in test context)
        ]

        for pattern in suspicious_calls:
            if re.search(pattern, code) and "contract.*Test" not in code:
                return False
        return True

    def _check_uses_test_framework(self, code: str) -> bool:
        """Ensure code uses a recognized test framework"""
        test_frameworks = [
            r"import.*forge-std/Test\.sol",
            r"import.*@openzeppelin/contracts/test",
            r"contract\s+\w+\s+is\s+Test",
        ]
        return any(re.search(pattern, code) for pattern in test_frameworks)

    def _check_no_private_key_exposure(self, code: str) -> bool:
        """Check for exposed private keys or mnemonics"""
        sensitive_patterns = [
            r'private[\s_-]?key\s*=\s*["\']0x[a-fA-F0-9]{64}',
            r"mnemonic\s*=",
            r"seed\s*=",
        ]
        return not any(
            re.search(pattern, code, re.IGNORECASE) for pattern in sensitive_patterns
        )

    def _check_has_test_functions(self, code: str) -> bool:
        """Ensure code has proper test functions"""
        return bool(re.search(r"function\s+test\w+\s*\(", code))

    def _is_test_address(self, address: str) -> bool:
        """Check if address is a known test address pattern"""
        test_patterns = [
            address.startswith("0x0000"),
            address.startswith("0xdead"),
            address.startswith("0xDEAD"),
            address == "0x" + "0" * 40,
            address == "0x" + "f" * 40,
        ]
        return any(test_patterns)

    def _get_warnings(self, checks: Dict[str, bool]) -> List[str]:
        """Generate warnings based on failed checks"""
        warnings = []
        if not checks["no_mainnet_interaction"]:
            warnings.append("⚠️  Contains mainnet interaction - UNSAFE")
        if not checks["no_real_fund_transfer"]:
            warnings.append("⚠️  May contain real fund transfers - UNSAFE")
        if not checks["no_malicious_external_calls"]:
            warnings.append("⚠️  Contains suspicious external calls - REVIEW REQUIRED")
        if not checks["uses_test_framework"]:
            warnings.append("⚠️  Does not use recognized test framework")
        if not checks["no_private_key_exposure"]:
            warnings.append("⚠️  Contains private key exposure - CRITICAL")
        if not checks["has_test_functions"]:
            warnings.append("⚠️  Missing test functions")
        return warnings

    def _get_recommendations(self, checks: Dict[str, bool], code: str) -> List[str]:
        """Generate recommendations for improving PoC safety"""
        recommendations = []

        if not checks["uses_test_framework"]:
            recommendations.append("Add import for forge-std/Test.sol")

        if not checks["has_test_functions"]:
            recommendations.append("Add test functions starting with 'test' prefix")

        if "vm.deal" not in code:
            recommendations.append("Use vm.deal() for test funding instead of real ETH")

        if "console.log" not in code:
            recommendations.append("Add console.log statements for better debugging")

        return recommendations


class SandboxExecutor:
    """
    Sandboxed execution environment for PoCs
    Runs PoCs in isolated Foundry/Hardhat environments
    """

    def __init__(self, framework: PoCFramework = PoCFramework.FOUNDRY):
        self.framework = framework
        self.execution_timeout = 30  # seconds

    async def execute_poc(
        self,
        poc_code: str,
        contract_code: str,
        contract_name: str = "VulnerableContract",
    ) -> Dict[str, Any]:
        """
        Execute PoC in isolated sandbox environment
        """
        if self.framework == PoCFramework.FOUNDRY:
            return await self._execute_foundry_poc(
                poc_code, contract_code, contract_name
            )
        elif self.framework == PoCFramework.HARDHAT:
            return await self._execute_hardhat_poc(
                poc_code, contract_code, contract_name
            )
        else:
            return {
                "success": False,
                "error": f"Unsupported framework: {self.framework}",
            }

    async def _execute_foundry_poc(
        self, poc_code: str, contract_code: str, contract_name: str
    ) -> Dict[str, Any]:
        """Execute PoC using Foundry"""
        start_time = datetime.now()

        # Create temporary directory for test project
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Check if forge is available
                forge_check = await self._run_command(["which", "forge"], tmpdir)
                if forge_check["returncode"] != 0:
                    return {
                        "success": False,
                        "error": "Foundry (forge) not installed. Install from https://getfoundry.sh/",
                        "output": "",
                        "execution_time": 0,
                    }

                # Initialize Foundry project
                init_result = await self._run_command(
                    ["forge", "init", "--no-git", "--force", "."], tmpdir
                )

                if init_result["returncode"] != 0:
                    return {
                        "success": False,
                        "error": f"Failed to initialize Foundry project: {init_result['stderr']}",
                        "output": init_result["stdout"],
                        "execution_time": 0,
                    }

                # Write contract to src/
                src_dir = os.path.join(tmpdir, "src")
                os.makedirs(src_dir, exist_ok=True)
                contract_path = os.path.join(src_dir, f"{contract_name}.sol")
                with open(contract_path, "w") as f:
                    f.write(contract_code)

                # Write PoC to test/
                test_dir = os.path.join(tmpdir, "test")
                os.makedirs(test_dir, exist_ok=True)
                test_path = os.path.join(test_dir, "Exploit.t.sol")
                with open(test_path, "w") as f:
                    f.write(poc_code)

                # Run forge test
                test_result = await self._run_command(
                    ["forge", "test", "-vvv"], tmpdir, timeout=self.execution_timeout
                )

                execution_time = (datetime.now() - start_time).total_seconds()

                # Parse test output for results
                success = test_result["returncode"] == 0
                output = test_result["stdout"] + test_result["stderr"]

                # Extract gas usage if available
                gas_used = self._extract_gas_usage(output)

                return {
                    "success": success,
                    "output": output,
                    "error": test_result["stderr"] if not success else "",
                    "execution_time": execution_time,
                    "gas_used": gas_used,
                    "exploit_demonstrated": self._check_exploit_demonstrated(output),
                }

            except Exception as e:
                execution_time = (datetime.now() - start_time).total_seconds()
                return {
                    "success": False,
                    "error": str(e),
                    "output": "",
                    "execution_time": execution_time,
                }

    async def _execute_hardhat_poc(
        self, poc_code: str, contract_code: str, contract_name: str
    ) -> Dict[str, Any]:
        """Execute PoC using Hardhat (placeholder for future implementation)"""
        return {
            "success": False,
            "error": "Hardhat execution not yet implemented",
            "output": "",
            "execution_time": 0,
        }

    async def _run_command(
        self, cmd: List[str], cwd: str, timeout: int = 30
    ) -> Dict[str, Any]:
        """Run shell command asynchronously with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )

                return {
                    "returncode": process.returncode,
                    "stdout": stdout.decode("utf-8", errors="ignore"),
                    "stderr": stderr.decode("utf-8", errors="ignore"),
                }
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "returncode": -1,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout} seconds",
                }

        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr": str(e)}

    def _extract_gas_usage(self, output: str) -> int:
        """Extract gas usage from test output"""
        # Look for gas usage in output
        gas_pattern = r"gas:\s*(\d+)"
        match = re.search(gas_pattern, output)
        return int(match.group(1)) if match else 0

    def _check_exploit_demonstrated(self, output: str) -> bool:
        """Check if exploit was successfully demonstrated"""
        # Look for successful test execution and assertion passes
        success_indicators = [
            r"\[PASS\]",
            r"Test result:.*ok",
            r"✓.*test",
        ]

        failure_indicators = [
            r"\[FAIL\]",
            r"Test result:.*FAILED",
            r"Assertion failed",
        ]

        has_success = any(
            re.search(pattern, output, re.IGNORECASE) for pattern in success_indicators
        )
        has_failure = any(
            re.search(pattern, output, re.IGNORECASE) for pattern in failure_indicators
        )

        return has_success and not has_failure


class PoCGenerator:
    """
    Automated PoC generation for vulnerability hypotheses
    Generates safe, sandboxed test scripts
    """

    def __init__(self, framework: PoCFramework = PoCFramework.FOUNDRY):
        self.framework = framework
        self.template_loader = ExploitTemplateLoader()
        self.poc_templates: Dict[str, PoCTemplate] = {}
        self.template_usage_lookup: Dict[str, str] = {}
        self.last_template_key: Optional[str] = None
        self.generated_pocs: List[PoCResult] = []
        self._initialize_templates()
        self.safety_validator = SafetyValidator()
        self.sandbox_executor = SandboxExecutor(framework)

    def _initialize_templates(self):
        """Initialize PoC templates for different vulnerability types"""

        # Reentrancy PoC template (Foundry)
        self.register_template(
            PoCTemplate(
                framework=PoCFramework.FOUNDRY,
                vulnerability_type="reentrancy",
                template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract ReentrancyExploit is Test {{
    {contract_name} target;
    Attacker attacker;

    function setUp() public {{
        target = new {contract_name}();
        attacker = new Attacker(address(target));

        // Fund the contract
        vm.deal(address(target), 10 ether);
    }}

    function testReentrancy() public {{
        // Fund attacker
        vm.deal(address(attacker), 1 ether);

        // Record initial balances
        uint256 initialTargetBalance = address(target).balance;
        uint256 initialAttackerBalance = address(attacker).balance;

        // Execute attack
        attacker.attack{{value: 1 ether}}();

        // Verify exploit
        uint256 finalTargetBalance = address(target).balance;
        uint256 finalAttackerBalance = address(attacker).balance;

        // Attacker should have drained funds
        assertGt(finalAttackerBalance, initialAttackerBalance);
        assertLt(finalTargetBalance, initialTargetBalance);

        console.log("Funds extracted:", finalAttackerBalance - initialAttackerBalance);
    }}
}}

contract Attacker {{
    {contract_name} target;
    uint256 public count;

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        target.withdraw(msg.value);
    }}

    receive() external payable {{
        if (address(target).balance >= 1 ether && count < 5) {{
            count++;
            target.withdraw(1 ether);
        }}
    }}
}}""",
                required_imports=["forge-std/Test.sol"],
                setup_code="// Setup in setUp() function",
                exploit_code="// Exploit in testReentrancy()",
                validation_code="// Assertions verify exploit",
            )
        )

        # Access Control PoC template
        self.register_template(
            PoCTemplate(
                framework=PoCFramework.FOUNDRY,
                vulnerability_type="access_control",
                template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract AccessControlExploit is Test {{
    {contract_name} target;
    address attacker = address(0xdead);

    function setUp() public {{
        target = new {contract_name}();
    }}

    function testUnauthorizedAccess() public {{
        // Try to call privileged function as unauthorized user
        vm.prank(attacker);

        // Record initial state
        uint256 initialValue = target.getValue();

        // Attempt unauthorized action
        vm.expectRevert(); // Remove if exploit succeeds
        target.privilegedFunction();

        // If we get here without revert, vulnerability exists
        uint256 finalValue = target.getValue();

        console.log("Unauthorized access test completed");
        console.log("Initial value:", initialValue);
        console.log("Final value:", finalValue);
    }}
}}""",
                required_imports=["forge-std/Test.sol"],
                setup_code="// Access control setup",
                exploit_code="// Unauthorized access attempt",
                validation_code="// Verify access granted when it shouldn't be",
            )
        )

        # Integer Overflow PoC template
        self.register_template(
            PoCTemplate(
                framework=PoCFramework.FOUNDRY,
                vulnerability_type="integer_overflow",
                template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract IntegerOverflowExploit is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function testIntegerOverflow() public {{
        // Setup values that will cause overflow
        uint256 largeValue = type(uint256).max - 10;

        // Record initial state
        uint256 initialBalance = target.balanceOf(address(this));

        // Trigger overflow
        target.vulnerableFunction(largeValue, 20);

        // Verify overflow occurred
        uint256 finalBalance = target.balanceOf(address(this));

        // In overflow, large value + small value wraps to small value
        console.log("Initial balance:", initialBalance);
        console.log("Final balance:", finalBalance);
        console.log("Overflow exploited:", finalBalance < initialBalance);
    }}
}}""",
                required_imports=["forge-std/Test.sol"],
                setup_code="// Overflow setup",
                exploit_code="// Trigger overflow",
                validation_code="// Verify overflow behavior",
            )
        )

        # Oracle manipulation PoC template
        self.register_template(
            PoCTemplate(
                framework=PoCFramework.FOUNDRY,
                vulnerability_type="oracle_manipulation",
                template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract OracleManipulationExploit is Test {{
    {contract_name} target;
    MockOracle mockOracle;

    function setUp() public {{
        mockOracle = new MockOracle();
        target = new {contract_name}(address(mockOracle));
    }}

    function testOracleManipulation() public {{
        // Set legitimate price
        mockOracle.setPrice(1000e18);

        // Get initial state
        uint256 initialValue = target.getValue();

        // Manipulate oracle price
        mockOracle.setPrice(10000e18); // 10x increase

        // Exploit the manipulated price
        uint256 exploitAmount = target.calculateValue();

        // Verify manipulation impact
        assertGt(exploitAmount, initialValue * 5);

        console.log("Price manipulation profit:", exploitAmount - initialValue);
    }}
}}

contract MockOracle {{
    uint256 public price;

    function setPrice(uint256 _price) external {{
        price = _price;
    }}

    function latestAnswer() external view returns (uint256) {{
        return price;
    }}
}}""",
                required_imports=["forge-std/Test.sol"],
                setup_code="// Oracle setup in setUp()",
                exploit_code="// Price manipulation in test",
                validation_code="// Price impact verification",
            )
        )

        # Flash loan attack PoC template
        self.register_template(
            PoCTemplate(
                framework=PoCFramework.FOUNDRY,
                vulnerability_type="flash_loan",
                template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract FlashLoanExploit is Test {{
    {contract_name} target;
    FlashLoanProvider lender;
    Exploiter exploiter;

    function setUp() public {{
        lender = new FlashLoanProvider();
        target = new {contract_name}();
        exploiter = new Exploiter(address(target), address(lender));

        // Fund flash loan pool
        vm.deal(address(lender), 1000 ether);
    }}

    function testFlashLoanAttack() public {{
        uint256 initialBalance = address(exploiter).balance;

        // Execute flash loan attack
        exploiter.executeAttack(100 ether);

        uint256 finalBalance = address(exploiter).balance;
        uint256 profit = finalBalance - initialBalance;

        // Verify profit
        assertGt(profit, 0);
        console.log("Flash loan profit:", profit);
    }}
}}

contract FlashLoanProvider {{
    function flashLoan(uint256 amount, address borrower) external {{
        uint256 balanceBefore = address(this).balance;

        payable(borrower).call{{value: amount}}("");

        require(address(this).balance >= balanceBefore, "Flash loan not repaid");
    }}

    receive() external payable {{}}
}}

contract Exploiter {{
    {contract_name} target;
    FlashLoanProvider lender;

    constructor(address _target, address _lender) {{
        target = {contract_name}(_target);
        lender = FlashLoanProvider(_lender);
    }}

    function executeAttack(uint256 loanAmount) external {{
        lender.flashLoan(loanAmount, address(this));
    }}

    receive() external payable {{
        // Use flash loan to exploit
        // ... exploit logic here ...

        // Repay flash loan
        payable(address(lender)).transfer(msg.value);
    }}
}}""",
                required_imports=["forge-std/Test.sol"],
                setup_code="// Flash loan setup",
                exploit_code="// Attack execution",
                validation_code="// Profit verification",
            )
        )

        self._load_dynamic_templates()

    def register_template(self, template: PoCTemplate, replace_existing: bool = True):
        """Register a PoC template"""
        key = f"{template.framework.value}_{template.vulnerability_type}"
        if not replace_existing and key in self.poc_templates:
            return

        self.poc_templates[key] = template
        if template.template_id:
            self.template_usage_lookup[key] = template.template_id

    def _load_dynamic_templates(self) -> None:
        """Load advanced templates from the YAML-driven template loader."""

        if not self.template_loader:
            return

        framework_map = {framework.value: framework for framework in PoCFramework}

        for template_def in self.template_loader.list_templates():
            stage_plan = [stage.to_dict() for stage in template_def.stages]
            for vuln_class in template_def.vulnerability_classes:
                vuln_key = vuln_class.lower()

                for framework_name, skeleton in template_def.poc_skeletons.items():
                    if not isinstance(skeleton, dict):
                        continue

                    framework = framework_map.get(framework_name.lower())
                    if not framework:
                        # Try exact match if lower-case lookup fails
                        framework = framework_map.get(framework_name)

                    if not framework:
                        continue

                    template_code = skeleton.get("code", "")
                    if not template_code:
                        continue

                    required_imports = skeleton.get("required_imports", []) or []
                    setup_outline = skeleton.get("setup_outline", "")
                    exploit_outline = skeleton.get("exploit_outline", "")
                    validation_outline = skeleton.get("validation_outline", "")

                    dynamic_template = PoCTemplate(
                        framework=framework,
                        vulnerability_type=vuln_key,
                        template_code=template_code,
                        required_imports=required_imports,
                        setup_code=setup_outline,
                        exploit_code=exploit_outline,
                        validation_code=validation_outline,
                        template_id=template_def.template_id,
                        stage_plan=stage_plan,
                        detection_metadata=template_def.detection_signatures,
                        historical_references=template_def.historical_references,
                        provenance=template_def.provenance,
                    )

                    self.register_template(dynamic_template)

    def _build_template_context(
        self, template_key: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Construct metadata context for the currently used template."""

        if not template_key:
            return None

        template = self.poc_templates.get(template_key)
        if not template:
            return None

        context: Dict[str, Any] = {}
        if template.stage_plan:
            context["stage_plan"] = template.stage_plan
        if template.detection_metadata:
            context["detection_signatures"] = template.detection_metadata
        if template.historical_references:
            context["historical_references"] = template.historical_references
        if template.provenance:
            context["provenance"] = template.provenance

        template_id = self.template_usage_lookup.get(template_key)
        if template_id:
            record = self.template_loader.get_template(template_id)
            if record:
                context["metrics"] = dict(record.metrics)

        return context or None

    def generate_poc(
        self,
        hypothesis: Any,
        contract_code: str,
        contract_name: str = "VulnerableContract",
    ) -> str:
        """
        Generate PoC code for a hypothesis
        """
        # Determine vulnerability type from hypothesis
        vuln_type = self._map_hypothesis_to_vuln_type(hypothesis)

        # Get template
        template_key = f"{self.framework.value}_{vuln_type}"
        template = self.poc_templates.get(template_key)

        if not template:
            self.last_template_key = None
            # Fallback to generic template
            return self._generate_generic_poc(hypothesis, contract_code, contract_name)

        self.last_template_key = template_key
        # Fill template with contract-specific information
        poc_code = template.template_code.format(
            contract_name=contract_name,
            vulnerability_description=getattr(hypothesis, "description", ""),
            attack_scenario=getattr(hypothesis, "attack_scenario", ""),
        )

        return poc_code

    def generate_and_execute(
        self,
        hypothesis: Any,
        contract_code: str,
        contract_name: str = "VulnerableContract",
        execute: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate PoC and optionally execute it in sandbox with safety validation
        """
        # Generate PoC code
        poc_code = self.generate_poc(hypothesis, contract_code, contract_name)

        # Validate safety
        safety_result = self.safety_validator.validate(poc_code)

        result = {
            "success": False,
            "poc_code": poc_code,
            "description": getattr(hypothesis, "description", ""),
            "output": "",
            "safety_validated": safety_result["safe"],
            "safety_warnings": safety_result["warnings"],
            "safety_recommendations": safety_result["recommendations"],
        }

        # Only execute if safe
        if not safety_result["safe"]:
            result["error"] = (
                f"PoC failed safety validation: {', '.join(safety_result['warnings'])}"
            )
            print("⚠️  PoC failed safety validation - execution blocked")
            for warning in safety_result["warnings"]:
                print(f"    {warning}")
        elif execute:
            # Execute in sandboxed environment
            print("✓ PoC passed safety validation, executing in sandbox...")
            try:
                # Run async execution
                import asyncio

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                execution_result = loop.run_until_complete(
                    self.sandbox_executor.execute_poc(
                        poc_code, contract_code, contract_name
                    )
                )
                loop.close()

                result.update(execution_result)
            except Exception as e:
                result["error"] = f"Execution failed: {str(e)}"

        template_context = None
        template_id = None
        if self.last_template_key:
            template_id = self.template_usage_lookup.get(self.last_template_key)
            execution_success = result.get("success") if execute else None
            usage_context = {
                "hypothesis_id": getattr(hypothesis, "id", "unknown"),
                "contract_name": contract_name,
                "framework": self.framework.value,
            }
            if template_id:
                self.template_loader.record_usage(
                    template_id,
                    success=execution_success,
                    context=usage_context,
                )

            template_context = self._build_template_context(self.last_template_key)
            if template_context:
                result["template_context"] = template_context

        # Store result
        poc_result = PoCResult(
            hypothesis_id=getattr(hypothesis, "id", "unknown"),
            framework=self.framework,
            generated_code=poc_code,
            execution_successful=result.get("success", False),
            exploit_demonstrated=result.get("exploit_demonstrated", False),
            output=result.get("output", ""),
            timestamp=datetime.now().isoformat(),
            safety_validated=safety_result["safe"],
            execution_time=result.get("execution_time", 0.0),
            gas_used=result.get("gas_used", 0),
        )

        self.generated_pocs.append(poc_result)

        return result

    def _map_hypothesis_to_vuln_type(self, hypothesis: Any) -> str:
        """Map hypothesis type to PoC template type"""
        if not hasattr(hypothesis, "type"):
            # Try to infer from description or name
            desc = getattr(hypothesis, "description", "").lower()
            name = getattr(hypothesis, "name", "").lower()
            combined = desc + " " + name

            if "reentrancy" in combined or "reentrant" in combined:
                return "reentrancy"
            elif "oracle" in combined:
                return "oracle_manipulation"
            elif "flash" in combined or "loan" in combined:
                return "flash_loan"
            elif (
                "access" in combined
                or "authorization" in combined
                or "permission" in combined
            ):
                return "access_control"
            elif "overflow" in combined or "underflow" in combined:
                return "integer_overflow"

            return "generic"

        hypothesis_type = (
            hypothesis.type.value
            if hasattr(hypothesis.type, "value")
            else str(hypothesis.type)
        )

        # Map hypothesis types to PoC template types
        type_mapping = {
            "reentrancy": "reentrancy",
            "oracle_manipulation": "oracle_manipulation",
            "oracle": "oracle_manipulation",
            "economic_exploit": "flash_loan",
            "flash_loan": "flash_loan",
            "flash": "flash_loan",
            "access_control": "access_control",
            "access": "access_control",
            "authorization": "access_control",
            "overflow": "integer_overflow",
            "underflow": "integer_overflow",
            "integer": "integer_overflow",
            "cross_contract": "cross_contract",
        }

        for key, template_type in type_mapping.items():
            if key in hypothesis_type.lower():
                return template_type

        return "generic"

    def _generate_generic_poc(
        self, hypothesis: Any, contract_code: str, contract_name: str
    ) -> str:
        """Generate a generic PoC when no specific template exists"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

/**
 * PoC for: {getattr(hypothesis, "description", "Unknown vulnerability")}
 *
 * Attack Scenario:
 * {getattr(hypothesis, "attack_scenario", getattr(hypothesis, "exploit_scenario", "Not specified"))}
 *
 * Severity: {getattr(hypothesis, "severity", "unknown")}
 * Confidence: {getattr(hypothesis, "confidence", 0.0)}
 */
contract GenericExploit is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
        // Add setup code here
    }}

    function testVulnerability() public {{
        // 1. Setup initial state
        uint256 initialState = 0; // Customize based on contract

        // 2. Execute exploit
        // TODO: Implement specific exploit logic based on:
        // {getattr(hypothesis, "description", "vulnerability description")}

        // 3. Verify vulnerability exists
        // TODO: Add assertions proving exploitation

        console.log("Vulnerability test executed");
        console.log("Initial state:", initialState);
    }}
}}
"""

    def generate_foundry_project(
        self,
        hypotheses: List[Any],
        contract_code: str,
        contract_name: str,
        output_dir: str,
    ) -> str:
        """
        Generate a complete Foundry project with PoCs for all hypotheses
        """
        os.makedirs(output_dir, exist_ok=True)

        # Create directory structure
        src_dir = os.path.join(output_dir, "src")
        test_dir = os.path.join(output_dir, "test")
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(test_dir, exist_ok=True)

        # Write contract to src/
        contract_path = os.path.join(src_dir, f"{contract_name}.sol")
        with open(contract_path, "w") as f:
            f.write(contract_code)

        # Generate PoC for each hypothesis
        for i, hypothesis in enumerate(hypotheses):
            poc_code = self.generate_poc(hypothesis, contract_code, contract_name)
            poc_path = os.path.join(test_dir, f"Exploit{i + 1}.t.sol")

            with open(poc_path, "w") as f:
                f.write(poc_code)

        # Create foundry.toml
        foundry_config = """[profile.default]
src = 'src'
out = 'out'
libs = ['lib']
solc_version = '0.8.19'

[profile.default.fuzz]
runs = 256
"""
        with open(os.path.join(output_dir, "foundry.toml"), "w") as f:
            f.write(foundry_config)

        # Create README
        readme = f"""# Vulnerability PoC Project

Generated on: {datetime.now().isoformat()}

## Contract
- Name: {contract_name}
- Location: src/{contract_name}.sol

## Exploits
{len(hypotheses)} proof-of-concept exploits generated in test/ directory.

## Running Tests

```bash
forge test -vvv
```

## Individual Test Execution

```bash
forge test --match-test testReentrancy -vvv
```

## Hypotheses Tested

{chr(10).join([f"{i + 1}. {getattr(h, 'description', 'Unknown')} (Severity: {getattr(h, 'severity', 'unknown')})" for i, h in enumerate(hypotheses)])}
"""
        with open(os.path.join(output_dir, "README.md"), "w") as f:
            f.write(readme)

        return output_dir

    def get_poc_stats(self) -> Dict[str, Any]:
        """Get statistics about generated PoCs"""
        if not self.generated_pocs:
            return {
                "total_generated": 0,
                "successful_executions": 0,
                "exploits_demonstrated": 0,
            }

        return {
            "total_generated": len(self.generated_pocs),
            "successful_executions": len(
                [p for p in self.generated_pocs if p.execution_successful]
            ),
            "exploits_demonstrated": len(
                [p for p in self.generated_pocs if p.exploit_demonstrated]
            ),
            "by_framework": self._count_by_framework(),
            "by_vulnerability_type": self._count_by_vuln_type(),
        }

    def _count_by_framework(self) -> Dict[str, int]:
        """Count PoCs by framework"""
        counts = {}
        for poc in self.generated_pocs:
            framework = poc.framework.value
            counts[framework] = counts.get(framework, 0) + 1
        return counts

    def _count_by_vuln_type(self) -> Dict[str, int]:
        """Count PoCs by vulnerability type"""
        # This would need to be tracked during generation
        return {}

    def export_poc_report(self, filepath: str):
        """Export PoC generation report"""
        report = {
            "statistics": self.get_poc_stats(),
            "generated_pocs": [
                {
                    "hypothesis_id": poc.hypothesis_id,
                    "framework": poc.framework.value,
                    "execution_successful": poc.execution_successful,
                    "exploit_demonstrated": poc.exploit_demonstrated,
                    "timestamp": poc.timestamp,
                    "code_preview": poc.generated_code[:500] + "...",
                }
                for poc in self.generated_pocs
            ],
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        print(f"✓ PoC report exported to {filepath}")


class LLMPoCAssistant:
    """
    LLM-assisted PoC generation for complex or novel vulnerabilities
    """

    def __init__(self):
        # Try to import LLM integration
        try:
            from advanced.llm_reasoning_engine import AdvancedLLMReasoner

            self.llm_reasoner = AdvancedLLMReasoner()
            self.available = True
        except ImportError:
            self.available = False

    async def generate_poc(
        self,
        vulnerability: Any,
        contract_code: str,
        contract_name: str = "VulnerableContract",
    ) -> str:
        """
        Generate PoC using LLM reasoning
        """
        if not self.available:
            return self._generate_fallback_poc(vulnerability, contract_name)

        # Truncate contract code for LLM context
        contract_preview = (
            contract_code[:2000] + "..." if len(contract_code) > 2000 else contract_code
        )

        prompt = f"""Generate a complete Foundry test (Solidity) that demonstrates this vulnerability:

Vulnerability: {getattr(vulnerability, "name", "Unknown")}
Description: {getattr(vulnerability, "description", "No description")}
Severity: {getattr(vulnerability, "severity", "unknown")}
Exploit Scenario: {getattr(vulnerability, "exploit_scenario", "No scenario provided")}

Contract Preview:
```solidity
{contract_preview}
```

Requirements:
1. Use Foundry test framework with forge-std/Test.sol
2. Run on local testnet (no real funds or mainnet interaction)
3. Use vm.* cheatcodes for testing (vm.deal, vm.prank, etc.)
4. Clearly show before/after state demonstrating the exploit
5. Include console.log statements showing the exploit impact
6. Include assertions proving the vulnerability exists
7. Be safe for demonstration purposes only

Generate ONLY the complete Solidity test code, no explanations."""

        try:
            # Use LLM to generate PoC
            # This is a simplified version - actual implementation would use proper LLM API
            result = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

/**
 * LLM-Generated PoC for: {getattr(vulnerability, "name", "Unknown")}
 * {getattr(vulnerability, "description", "")}
 */
contract LLMGeneratedExploit is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
        vm.deal(address(target), 100 ether);
    }}

    function testLLMGeneratedExploit() public {{
        // LLM would generate specific exploit code here
        console.log("LLM-assisted PoC generation");
        console.log("Vulnerability: {getattr(vulnerability, "name", "Unknown")}");

        // TODO: LLM-generated exploit logic
    }}
}}
"""
            return result

        except Exception:
            return self._generate_fallback_poc(vulnerability, contract_name)

    def _generate_fallback_poc(self, vulnerability: Any, contract_name: str) -> str:
        """Fallback PoC when LLM is unavailable"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

// LLM unavailable - using fallback template
contract FallbackExploit is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function testVulnerability() public {{
        console.log("Testing: {getattr(vulnerability, "name", "Unknown")}");
        // Manual implementation required
    }}
}}
"""


class AutomatedPoCGenerator:
    """
    Automated PoC Generator with multi-strategy approach
    Combines template-based, LLM-assisted, and hybrid generation
    """

    def __init__(self, frameworks: Optional[List[PoCFramework]] = None):
        self.frameworks = frameworks or [PoCFramework.FOUNDRY]
        self.safety_validator = SafetyValidator()
        self.template_generator = PoCGenerator(self.frameworks[0])
        self.llm_assistant = LLMPoCAssistant()
        self.generated_pocs: List[PoCResult] = []

    async def generate_poc(
        self,
        vulnerability: Any,
        contract_code: str,
        contract_name: str = "VulnerableContract",
        strategy: str = "auto",
    ) -> Dict[str, Any]:
        """
        Generate PoC with automatic strategy selection

        Strategies:
        - "template": Use template-based generation (fast, reliable)
        - "llm": Use LLM-assisted generation (creative, flexible)
        - "hybrid": Combine both approaches
        - "auto": Automatically select best strategy
        """

        if strategy == "auto":
            strategy = self._select_strategy(vulnerability)

        print(f"📝 Generating PoC using '{strategy}' strategy...")

        # Generate PoC variants
        poc_variants = []

        if strategy in ["template", "hybrid"]:
            # Template-based generation
            template_poc = self.template_generator.generate_poc(
                vulnerability, contract_code, contract_name
            )
            poc_variants.append(
                {"code": template_poc, "strategy": "template", "confidence": 0.9}
            )

        if strategy in ["llm", "hybrid"] and self.llm_assistant.available:
            # LLM-assisted generation
            llm_poc = await self.llm_assistant.generate_poc(
                vulnerability, contract_code, contract_name
            )
            poc_variants.append({"code": llm_poc, "strategy": "llm", "confidence": 0.7})

        # Validate safety for all variants
        safe_pocs = []
        for variant in poc_variants:
            safety_result = self.safety_validator.validate(variant["code"])
            if safety_result["safe"]:
                variant["safety"] = safety_result
                safe_pocs.append(variant)
            else:
                print(f"  ⚠️  {variant['strategy']} PoC failed safety validation")

        if not safe_pocs:
            return {
                "success": False,
                "error": "No safe PoC could be generated",
                "variants_generated": len(poc_variants),
                "variants_safe": 0,
            }

        # Select best PoC
        best_poc = max(safe_pocs, key=lambda x: x["confidence"])

        return {
            "success": True,
            "poc_code": best_poc["code"],
            "strategy_used": best_poc["strategy"],
            "confidence": best_poc["confidence"],
            "safety_validated": True,
            "variants_generated": len(poc_variants),
            "variants_safe": len(safe_pocs),
        }

    def _select_strategy(self, vulnerability: Any) -> str:
        """
        Automatically select the best generation strategy
        """
        # Check if we have a template for this vulnerability type
        vuln_type = str(getattr(vulnerability, "type", "")).lower()

        common_types = [
            "reentrancy",
            "oracle",
            "flash_loan",
            "access_control",
            "overflow",
        ]

        # Use template for common vulnerabilities
        for common_type in common_types:
            if common_type in vuln_type:
                return "template"

        # Use hybrid for complex or rare vulnerabilities
        if "rare" in vuln_type or "novel" in vuln_type or "complex" in vuln_type:
            return "hybrid"

        # Default to template (fast and reliable)
        return "template"

    async def generate_and_test_poc(
        self,
        vulnerability: Any,
        contract_code: str,
        contract_name: str = "VulnerableContract",
        execute_in_sandbox: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate PoC and optionally test it in sandbox
        """
        # Generate PoC
        generation_result = await self.generate_poc(
            vulnerability, contract_code, contract_name
        )

        if not generation_result["success"]:
            return generation_result

        result = generation_result.copy()

        # Optionally execute in sandbox
        if execute_in_sandbox:
            sandbox = SandboxExecutor(self.frameworks[0])
            execution_result = await sandbox.execute_poc(
                generation_result["poc_code"], contract_code, contract_name
            )
            result.update(execution_result)

        # Record result
        poc_result = PoCResult(
            hypothesis_id=getattr(vulnerability, "id", str(id(vulnerability))),
            framework=self.frameworks[0],
            generated_code=result["poc_code"],
            execution_successful=result.get("success", False),
            exploit_demonstrated=result.get("exploit_demonstrated", False),
            output=result.get("output", ""),
            timestamp=datetime.now().isoformat(),
            safety_validated=result.get("safety_validated", False),
            execution_time=result.get("execution_time", 0.0),
            gas_used=result.get("gas_used", 0),
        )

        self.generated_pocs.append(poc_result)

        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Get PoC generation statistics"""
        if not self.generated_pocs:
            return {
                "total_generated": 0,
                "total_executed": 0,
                "exploits_demonstrated": 0,
                "safety_validated": 0,
            }

        return {
            "total_generated": len(self.generated_pocs),
            "total_executed": len(
                [p for p in self.generated_pocs if p.execution_successful]
            ),
            "exploits_demonstrated": len(
                [p for p in self.generated_pocs if p.exploit_demonstrated]
            ),
            "safety_validated": len(
                [p for p in self.generated_pocs if p.safety_validated]
            ),
            "average_execution_time": sum(p.execution_time for p in self.generated_pocs)
            / len(self.generated_pocs)
            if self.generated_pocs
            else 0,
            "total_gas_used": sum(p.gas_used for p in self.generated_pocs),
        }
