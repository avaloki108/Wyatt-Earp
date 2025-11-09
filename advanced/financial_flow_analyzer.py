#!/usr/bin/env python3
"""
Financial Flow Analyzer - Advanced financial analysis for Web3 vulnerabilities
Analyzes economic flows, token movements, and financial attack vectors
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import asyncio

@dataclass
class FinancialFlow:
    """Represents a financial flow in the system"""
    source: str
    destination: str
    amount: str
    token: str
    function: str
    contract: str
    line_number: int
    flow_type: str  # "transfer", "mint", "burn", "swap", "liquidity"
    risk_level: str  # "low", "medium", "high", "critical"

@dataclass
class EconomicImpact:
    """Represents the economic impact of a vulnerability"""
    max_loss: float
    probability: float
    expected_loss: float
    affected_tokens: List[str]
    affected_contracts: List[str]
    impact_type: str  # "direct", "indirect", "cascading"

class FinancialFlowAnalyzer:
    """
    Advanced financial flow analyzer for Web3 vulnerability research
    Identifies economic attack vectors and financial vulnerabilities
    """
    
    def __init__(self):
        self.flows = []
        self.economic_impacts = []
        self.financial_patterns = {
            'transfer_functions': [
                'transfer', 'transferFrom', 'safeTransfer', 'safeTransferFrom',
                'mint', 'burn', 'approve', 'allowance'
            ],
            'swap_functions': [
                'swap', 'swapExactTokensForTokens', 'swapTokensForExactTokens',
                'addLiquidity', 'removeLiquidity'
            ],
            'lending_functions': [
                'borrow', 'repay', 'liquidation', 'flashLoan', 'deposit', 'withdraw'
            ],
            'staking_functions': [
                'stake', 'unstake', 'claim', 'reward', 'delegate'
            ]
        }
        
        self.risk_indicators = {
            'high_risk': [
                'unchecked', 'unchecked_', 'assembly', 'selfdestruct',
                'delegatecall', 'callcode', 'suicide'
            ],
            'medium_risk': [
                'external', 'public', 'payable', 'reentrancy'
            ],
            'low_risk': [
                'view', 'pure', 'internal', 'private'
            ]
        }
    
    async def analyze_financial_flows(self, target_path: str) -> List[FinancialFlow]:
        """
        Analyze financial flows in the target codebase
        """
        print(f"💰 Analyzing financial flows in {target_path}")
        
        self.flows = []
        
        # Find all Solidity files
        solidity_files = self._find_solidity_files(target_path)
        
        for file_path in solidity_files:
            await self._analyze_file_financial_flows(file_path)
        
        # Analyze economic impact
        await self._analyze_economic_impact()
        
        print(f"  📊 Found {len(self.flows)} financial flows")
        print(f"  🎯 High risk flows: {len([f for f in self.flows if f.risk_level == 'high'])}")
        print(f"  🔴 Critical flows: {len([f for f in self.flows if f.risk_level == 'critical'])}")
        
        return self.flows
    
    def _find_solidity_files(self, target_path: str) -> List[str]:
        """Find all Solidity files in the target path"""
        solidity_files = []
        target_path = Path(target_path)
        
        for file_path in target_path.rglob("*.sol"):
            solidity_files.append(str(file_path))
        
        return solidity_files
    
    async def _analyze_file_financial_flows(self, file_path: str):
        """Analyze financial flows in a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Look for financial function calls
                for pattern_type, functions in self.financial_patterns.items():
                    for func in functions:
                        if func in line:
                            flow = self._extract_financial_flow(
                                line, line_num, file_path, func, pattern_type
                            )
                            if flow:
                                self.flows.append(flow)
        
        except Exception as e:
            print(f"  ⚠️  Error analyzing {file_path}: {e}")
    
    def _extract_financial_flow(self, line: str, line_num: int, file_path: str, 
                              func: str, pattern_type: str) -> Optional[FinancialFlow]:
        """Extract financial flow information from a line"""
        try:
            # Determine risk level based on context
            risk_level = self._assess_risk_level(line)
            
            # Extract contract name from file path
            contract_name = Path(file_path).stem
            
            # Determine flow type based on function
            flow_type = self._determine_flow_type(func, pattern_type)
            
            # Extract token information if present
            token = self._extract_token_info(line)
            
            flow = FinancialFlow(
                source="unknown",  # Would need more sophisticated analysis
                destination="unknown",
                amount="variable",  # Would need more sophisticated analysis
                token=token,
                function=func,
                contract=contract_name,
                line_number=line_num,
                flow_type=flow_type,
                risk_level=risk_level
            )
            
            return flow
            
        except Exception as e:
            return None
    
    def _assess_risk_level(self, line: str) -> str:
        """Assess the risk level of a financial operation"""
        line_lower = line.lower()
        
        # Check for high-risk indicators
        for indicator in self.risk_indicators['high_risk']:
            if indicator in line_lower:
                return 'critical'
        
        # Check for medium-risk indicators
        for indicator in self.risk_indicators['medium_risk']:
            if indicator in line_lower:
                return 'high'
        
        # Check for low-risk indicators
        for indicator in self.risk_indicators['low_risk']:
            if indicator in line_lower:
                return 'low'
        
        return 'medium'
    
    def _determine_flow_type(self, func: str, pattern_type: str) -> str:
        """Determine the type of financial flow"""
        if pattern_type == 'transfer_functions':
            if func in ['mint', 'burn']:
                return 'mint' if func == 'mint' else 'burn'
            return 'transfer'
        elif pattern_type == 'swap_functions':
            return 'swap'
        elif pattern_type == 'lending_functions':
            return 'lending'
        elif pattern_type == 'staking_functions':
            return 'staking'
        else:
            return 'other'
    
    def _extract_token_info(self, line: str) -> str:
        """Extract token information from a line"""
        # Look for common token patterns
        token_patterns = [
            r'ERC20\s*\(\s*(\w+)\s*\)',
            r'(\w+)\s*\.\s*transfer',
            r'(\w+)\s*\.\s*\.\s*transfer',
            r'token\s*=\s*(\w+)',
            r'address\s+(\w+)\s*;'
        ]
        
        for pattern in token_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    async def _analyze_economic_impact(self):
        """Analyze the economic impact of identified flows"""
        self.economic_impacts = []
        
        # Group flows by contract
        contract_flows = {}
        for flow in self.flows:
            if flow.contract not in contract_flows:
                contract_flows[flow.contract] = []
            contract_flows[flow.contract].append(flow)
        
        # Analyze each contract's economic impact
        for contract, flows in contract_flows.items():
            impact = self._calculate_contract_impact(contract, flows)
            if impact:
                self.economic_impacts.append(impact)
    
    def _calculate_contract_impact(self, contract: str, flows: List[FinancialFlow]) -> Optional[EconomicImpact]:
        """Calculate economic impact for a contract"""
        try:
            # Count high-risk flows
            high_risk_flows = [f for f in flows if f.risk_level in ['high', 'critical']]
            
            # Calculate impact metrics
            max_loss = len(high_risk_flows) * 1000000  # Simplified calculation
            probability = min(0.1 * len(high_risk_flows), 1.0)
            expected_loss = max_loss * probability
            
            # Get affected tokens and contracts
            affected_tokens = list(set([f.token for f in flows if f.token != 'unknown']))
            affected_contracts = [contract]
            
            # Determine impact type
            if len(high_risk_flows) > 5:
                impact_type = 'cascading'
            elif len(high_risk_flows) > 2:
                impact_type = 'indirect'
            else:
                impact_type = 'direct'
            
            return EconomicImpact(
                max_loss=max_loss,
                probability=probability,
                expected_loss=expected_loss,
                affected_tokens=affected_tokens,
                affected_contracts=affected_contracts,
                impact_type=impact_type
            )
            
        except Exception as e:
            return None
    
    def generate_financial_report(self, output_dir: str) -> Dict[str, Any]:
        """Generate a comprehensive financial analysis report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_flows": len(self.flows),
            "economic_impacts": len(self.economic_impacts),
            "risk_distribution": {
                "critical": len([f for f in self.flows if f.risk_level == 'critical']),
                "high": len([f for f in self.flows if f.risk_level == 'high']),
                "medium": len([f for f in self.flows if f.risk_level == 'medium']),
                "low": len([f for f in self.flows if f.risk_level == 'low'])
            },
            "flow_types": {},
            "top_risks": [],
            "economic_summary": {
                "total_max_loss": sum(impact.max_loss for impact in self.economic_impacts),
                "total_expected_loss": sum(impact.expected_loss for impact in self.economic_impacts),
                "affected_contracts": len(set(contract for impact in self.economic_impacts for contract in impact.affected_contracts))
            }
        }
        
        # Analyze flow types
        flow_types = {}
        for flow in self.flows:
            if flow.flow_type not in flow_types:
                flow_types[flow.flow_type] = 0
            flow_types[flow.flow_type] += 1
        report["flow_types"] = flow_types
        
        # Identify top risks
        high_risk_flows = [f for f in self.flows if f.risk_level in ['high', 'critical']]
        top_risks = sorted(high_risk_flows, key=lambda x: x.risk_level, reverse=True)[:10]
        
        for flow in top_risks:
            report["top_risks"].append({
                "contract": flow.contract,
                "function": flow.function,
                "line": flow.line_number,
                "risk_level": flow.risk_level,
                "flow_type": flow.flow_type,
                "token": flow.token
            })
        
        # Save report
        report_path = os.path.join(output_dir, "financial_analysis_report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def get_high_risk_flows(self) -> List[FinancialFlow]:
        """Get all high-risk financial flows"""
        return [f for f in self.flows if f.risk_level in ['high', 'critical']]
    
    def get_flows_by_contract(self, contract: str) -> List[FinancialFlow]:
        """Get all flows for a specific contract"""
        return [f for f in self.flows if f.contract == contract]
    
    def get_flows_by_type(self, flow_type: str) -> List[FinancialFlow]:
        """Get all flows of a specific type"""
        return [f for f in self.flows if f.flow_type == flow_type]


# Example usage and testing
if __name__ == "__main__":
    async def test_analyzer():
        analyzer = FinancialFlowAnalyzer()
        
        # Test with a sample path
        test_path = "/tmp/test_contracts"
        flows = await analyzer.analyze_financial_flows(test_path)
        
        print(f"Found {len(flows)} financial flows")
        for flow in flows[:5]:  # Show first 5 flows
            print(f"  {flow.contract}.{flow.function} (line {flow.line_number}) - {flow.risk_level}")
    
    # Run test if called directly
    asyncio.run(test_analyzer())
