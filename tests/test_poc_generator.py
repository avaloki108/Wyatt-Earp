"""
Tests for PoC Generator Module
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.poc_generator import (
    SafetyValidator,
    PoCGenerator,
    AutomatedPoCGenerator,
    PoCFramework
)


class MockVulnerability:
    """Mock vulnerability for testing"""
    def __init__(self, name, vuln_type, severity="high", confidence=0.9):
        self.name = name
        self.type = vuln_type
        self.severity = severity
        self.confidence = confidence
        self.description = f"Test vulnerability: {name}"
        self.exploit_scenario = "Test exploit scenario"


class TestSafetyValidator:
    """Test SafetyValidator class"""
    
    def test_safe_poc_validation(self):
        """Test that safe PoC code passes validation"""
        validator = SafetyValidator()
        
        safe_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract SafeTest is Test {
    function testSomething() public {
        console.log("Testing");
    }
}
"""
        result = validator.validate(safe_code)
        assert result['safe']
        assert result['checks']['uses_test_framework']
        assert result['checks']['has_test_functions']
        assert result['checks']['no_mainnet_interaction']
    
    def test_unsafe_mainnet_interaction(self):
        """Test that code with mainnet interaction fails validation"""
        validator = SafetyValidator()
        
        unsafe_code = """
pragma solidity ^0.8.0;

contract UnsafeTest {
    // Using mainnet RPC
    string constant RPC = "https://mainnet.infura.io/v3/key";
}
"""
        result = validator.validate(unsafe_code)
        assert not result['safe']
        assert not result['checks']['no_mainnet_interaction']
    
    def test_missing_test_framework(self):
        """Test that code without test framework fails validation"""
        validator = SafetyValidator()
        
        code_without_test = """
pragma solidity ^0.8.0;

contract NotATest {
    function doSomething() public {}
}
"""
        result = validator.validate(code_without_test)
        assert not result['safe']
        assert not result['checks']['uses_test_framework']
    
    def test_private_key_exposure(self):
        """Test that code with private key exposure fails validation"""
        validator = SafetyValidator()
        
        unsafe_code = """
pragma solidity ^0.8.0;

contract UnsafeTest {
    string private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
}
"""
        result = validator.validate(unsafe_code)
        # This should fail validation
        assert not result['safe'] or len(result['warnings']) > 0


class TestPoCGenerator:
    """Test PoCGenerator class"""
    
    def test_poc_generator_initialization(self):
        """Test PoC generator initialization"""
        generator = PoCGenerator(PoCFramework.FOUNDRY)
        assert generator.framework == PoCFramework.FOUNDRY
        assert len(generator.poc_templates) > 0
    
    def test_template_registration(self):
        """Test template registration"""
        generator = PoCGenerator()
        
        # Should have templates for common vulnerability types
        assert 'foundry_reentrancy' in generator.poc_templates
        assert 'foundry_oracle_manipulation' in generator.poc_templates
        assert 'foundry_flash_loan' in generator.poc_templates
    
    def test_vulnerability_type_mapping(self):
        """Test mapping of vulnerability types to templates"""
        generator = PoCGenerator()
        
        # Test reentrancy mapping
        reentrancy_vuln = MockVulnerability("Reentrancy Attack", "reentrancy")
        vuln_type = generator._map_hypothesis_to_vuln_type(reentrancy_vuln)
        assert vuln_type == "reentrancy"
        
        # Test oracle mapping
        oracle_vuln = MockVulnerability("Oracle Manipulation", "oracle_manipulation")
        vuln_type = generator._map_hypothesis_to_vuln_type(oracle_vuln)
        assert vuln_type == "oracle_manipulation"
        
        # Test access control mapping
        access_vuln = MockVulnerability("Access Control", "access_control")
        vuln_type = generator._map_hypothesis_to_vuln_type(access_vuln)
        assert vuln_type == "access_control"
    
    def test_poc_code_generation(self):
        """Test PoC code generation"""
        generator = PoCGenerator()
        
        vuln = MockVulnerability("Test Reentrancy", "reentrancy")
        contract_code = "contract TestContract {}"
        
        poc_code = generator.generate_poc(vuln, contract_code, "TestContract")
        
        # Verify generated code has required elements
        assert "SPDX-License-Identifier" in poc_code
        assert "import" in poc_code
        assert "Test" in poc_code
        assert "function test" in poc_code
    
    def test_generic_poc_generation(self):
        """Test generic PoC generation for unknown vulnerability types"""
        generator = PoCGenerator()
        
        vuln = MockVulnerability("Unknown Vuln", "unknown_type")
        contract_code = "contract TestContract {}"
        
        poc_code = generator.generate_poc(vuln, contract_code, "TestContract")
        
        # Should still generate valid Solidity test code
        assert "pragma solidity" in poc_code
        assert "Test" in poc_code
        assert "function test" in poc_code


class TestAutomatedPoCGenerator:
    """Test AutomatedPoCGenerator class"""
    
    def test_automated_generator_initialization(self):
        """Test automated generator initialization"""
        generator = AutomatedPoCGenerator()
        assert generator.frameworks == [PoCFramework.FOUNDRY]
        assert generator.safety_validator is not None
        assert generator.template_generator is not None
    
    def test_strategy_selection(self):
        """Test automatic strategy selection"""
        generator = AutomatedPoCGenerator()
        
        # Common vulnerability should use template
        common_vuln = MockVulnerability("Reentrancy", "reentrancy")
        strategy = generator._select_strategy(common_vuln)
        assert strategy == "template"
        
        # Rare vulnerability should use hybrid
        rare_vuln = MockVulnerability("Rare Vuln", "rare_vulnerability")
        strategy = generator._select_strategy(rare_vuln)
        assert strategy == "hybrid"
    
    def test_statistics_generation(self):
        """Test statistics generation"""
        generator = AutomatedPoCGenerator()
        
        stats = generator.get_statistics()
        assert 'total_generated' in stats
        assert 'total_executed' in stats
        assert 'exploits_demonstrated' in stats
        assert 'safety_validated' in stats


class TestPoCTemplates:
    """Test PoC template quality"""
    
    def test_reentrancy_template_validity(self):
        """Test reentrancy template is valid Solidity"""
        generator = PoCGenerator()
        template = generator.poc_templates.get('foundry_reentrancy')
        
        assert template is not None
        assert template.vulnerability_type == "reentrancy"
        assert "reentrancy" in template.template_code.lower() or "reentrant" in template.template_code.lower()
        assert "function test" in template.template_code
    
    def test_oracle_template_validity(self):
        """Test oracle manipulation template is valid"""
        generator = PoCGenerator()
        template = generator.poc_templates.get('foundry_oracle_manipulation')
        
        assert template is not None
        assert template.vulnerability_type == "oracle_manipulation"
        assert "oracle" in template.template_code.lower()
        assert "price" in template.template_code.lower()
    
    def test_flash_loan_template_validity(self):
        """Test flash loan template is valid"""
        generator = PoCGenerator()
        template = generator.poc_templates.get('foundry_flash_loan')
        
        assert template is not None
        assert template.vulnerability_type == "flash_loan"
        assert "flash" in template.template_code.lower()
        assert "loan" in template.template_code.lower()


def test_safety_validator_integration():
    """Test integration between SafetyValidator and PoCGenerator"""
    generator = PoCGenerator()
    validator = SafetyValidator()
    
    vuln = MockVulnerability("Test Vuln", "reentrancy")
    poc_code = generator.generate_poc(vuln, "contract Test {}", "Test")
    
    # Generated PoC should pass safety validation
    result = validator.validate(poc_code)
    assert result['safe']


if __name__ == "__main__":
    # Run tests
    print("Running PoC Generator Tests...")
    
    # Test SafetyValidator
    print("\n1. Testing SafetyValidator...")
    test_sv = TestSafetyValidator()
    test_sv.test_safe_poc_validation()
    test_sv.test_unsafe_mainnet_interaction()
    test_sv.test_missing_test_framework()
    print("   ✓ SafetyValidator tests passed")
    
    # Test PoCGenerator
    print("\n2. Testing PoCGenerator...")
    test_pg = TestPoCGenerator()
    test_pg.test_poc_generator_initialization()
    test_pg.test_template_registration()
    test_pg.test_vulnerability_type_mapping()
    test_pg.test_poc_code_generation()
    test_pg.test_generic_poc_generation()
    print("   ✓ PoCGenerator tests passed")
    
    # Test AutomatedPoCGenerator
    print("\n3. Testing AutomatedPoCGenerator...")
    test_apg = TestAutomatedPoCGenerator()
    test_apg.test_automated_generator_initialization()
    test_apg.test_strategy_selection()
    test_apg.test_statistics_generation()
    print("   ✓ AutomatedPoCGenerator tests passed")
    
    # Test Templates
    print("\n4. Testing PoC Templates...")
    test_templates = TestPoCTemplates()
    test_templates.test_reentrancy_template_validity()
    test_templates.test_oracle_template_validity()
    test_templates.test_flash_loan_template_validity()
    print("   ✓ Template tests passed")
    
    # Integration test
    print("\n5. Testing Integration...")
    test_safety_validator_integration()
    print("   ✓ Integration tests passed")
    
    print("\n✓ All tests passed!")
