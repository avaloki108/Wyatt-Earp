#!/usr/bin/env python3
"""
Scope Analyzer - Intelligently reads and follows scope.txt files for bug bounty hunts
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScopeInfo:
    """Parsed scope information"""
    target_path: str
    scope_file: str
    in_scope_contracts: List[str]
    out_of_scope_contracts: List[str]
    in_scope_functions: List[str]
    out_of_scope_functions: List[str]
    severity_focus: List[str]
    vulnerability_types: List[str]
    exclusions: List[str]
    special_instructions: List[str]
    bounty_platform: Optional[str]
    max_prize: Optional[str]
    confidence_threshold: float = 0.7


class ScopeAnalyzer:
    """
    Intelligently analyzes scope.txt files and provides guidance for bug bounty hunts
    """
    
    def __init__(self):
        self.scope_patterns = {
            'in_scope': [
                r'in.?scope[:\s]+(.*?)(?:\n|$)',
                r'include[:\s]+(.*?)(?:\n|$)',
                r'target[:\s]+(.*?)(?:\n|$)',
                r'audit[:\s]+(.*?)(?:\n|$)'
            ],
            'out_of_scope': [
                r'out.?of.?scope[:\s]+(.*?)(?:\n|$)',
                r'exclude[:\s]+(.*?)(?:\n|$)',
                r'not.?in.?scope[:\s]+(.*?)(?:\n|$)',
                r'ignore[:\s]+(.*?)(?:\n|$)'
            ],
            'severity': [
                r'severity[:\s]+(.*?)(?:\n|$)',
                r'priority[:\s]+(.*?)(?:\n|$)',
                r'focus[:\s]+(.*?)(?:\n|$)',
                r'look.?for[:\s]+(.*?)(?:\n|$)'
            ],
            'vulnerability_types': [
                r'vulnerability[:\s]+(.*?)(?:\n|$)',
                r'bug.?type[:\s]+(.*?)(?:\n|$)',
                r'attack[:\s]+(.*?)(?:\n|$)',
                r'exploit[:\s]+(.*?)(?:\n|$)'
            ],
            'exclusions': [
                r'exclude[:\s]+(.*?)(?:\n|$)',
                r'not.?allowed[:\s]+(.*?)(?:\n|$)',
                r'forbidden[:\s]+(.*?)(?:\n|$)',
                r'prohibited[:\s]+(.*?)(?:\n|$)'
            ],
            'instructions': [
                r'instruction[:\s]+(.*?)(?:\n|$)',
                r'note[:\s]+(.*?)(?:\n|$)',
                r'important[:\s]+(.*?)(?:\n|$)',
                r'warning[:\s]+(.*?)(?:\n|$)'
            ],
            'platform': [
                r'platform[:\s]+(.*?)(?:\n|$)',
                r'bounty[:\s]+(.*?)(?:\n|$)',
                r'program[:\s]+(.*?)(?:\n|$)',
                r'submit[:\s]+(.*?)(?:\n|$)'
            ],
            'prize': [
                r'prize[:\s]+(.*?)(?:\n|$)',
                r'reward[:\s]+(.*?)(?:\n|$)',
                r'max[:\s]+(.*?)(?:\n|$)',
                r'budget[:\s]+(.*?)(?:\n|$)'
            ]
        }
    
    def find_scope_file(self, target_path: str) -> Optional[str]:
        """
        Intelligently find the scope.txt file in the target directory
        """
        target_path = Path(target_path)
        
        # Look for scope.txt in the target directory
        scope_candidates = [
            target_path / "scope.txt",
            target_path / "SCOPE.txt",
            target_path / "scope.md",
            target_path / "SCOPE.md",
            target_path / "bug-bounty.md",
            target_path / "security.md",
            target_path / "audit.md"
        ]
        
        for scope_file in scope_candidates:
            if scope_file.exists():
                return str(scope_file)
        
        # Look in subdirectories (common patterns)
        subdir_patterns = [
            "docs/",
            "documentation/",
            "security/",
            "audit/",
            "bounty/",
            "scope/"
        ]
        
        for pattern in subdir_patterns:
            for scope_file in scope_candidates:
                full_path = target_path / pattern / scope_file.name
                if full_path.exists():
                    return str(full_path)
        
        return None
    
    def read_scope_file(self, scope_file: str) -> str:
        """
        Read the scope file with proper encoding handling
        """
        try:
            with open(scope_file, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            with open(scope_file, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading scope file {scope_file}: {e}")
            return ""
    
    def parse_scope_content(self, content: str) -> Dict[str, List[str]]:
        """
        Parse scope content using pattern matching
        """
        parsed = {
            'in_scope': [],
            'out_of_scope': [],
            'severity': [],
            'vulnerability_types': [],
            'exclusions': [],
            'instructions': [],
            'platform': [],
            'prize': []
        }
        
        content_lower = content.lower()
        
        for category, patterns in self.scope_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content_lower, re.MULTILINE | re.DOTALL)
                for match in matches:
                    # Clean up the match
                    cleaned = match.strip()
                    if cleaned and cleaned not in parsed[category]:
                        parsed[category].append(cleaned)
        
        return parsed
    
    def extract_contracts(self, scope_items: List[str]) -> Tuple[List[str], List[str]]:
        """
        Extract contract names from scope items
        """
        in_scope = []
        out_of_scope = []
        
        for item in scope_items:
            # Look for .sol files or contract names
            if '.sol' in item or 'contract' in item.lower():
                # Extract contract names
                contracts = re.findall(r'([A-Za-z0-9_]+\.sol)', item)
                for contract in contracts:
                    if 'not' in item.lower() or 'exclude' in item.lower():
                        out_of_scope.append(contract)
                    else:
                        in_scope.append(contract)
        
        return in_scope, out_of_scope
    
    def extract_functions(self, scope_items: List[str]) -> Tuple[List[str], List[str]]:
        """
        Extract function names from scope items
        """
        in_scope = []
        out_of_scope = []
        
        for item in scope_items:
            # Look for function names (typically camelCase or snake_case)
            functions = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*\([^)]*\))', item)
            for func in functions:
                if 'not' in item.lower() or 'exclude' in item.lower():
                    out_of_scope.append(func)
                else:
                    in_scope.append(func)
        
        return in_scope, out_of_scope
    
    def analyze_scope(self, target_path: str) -> Optional[ScopeInfo]:
        """
        Analyze the scope for a target directory
        """
        # Find scope file
        scope_file = self.find_scope_file(target_path)
        if not scope_file:
            print(f"⚠️  No scope.txt file found in {target_path}")
            return None
        
        print(f"📋 Found scope file: {scope_file}")
        
        # Read scope content
        content = self.read_scope_file(scope_file)
        if not content:
            print(f"❌ Could not read scope file: {scope_file}")
            return None
        
        # Parse scope content
        parsed = self.parse_scope_content(content)
        
        # Extract contracts and functions
        in_scope_contracts, out_of_scope_contracts = self.extract_contracts(
            parsed['in_scope'] + parsed['out_of_scope']
        )
        in_scope_functions, out_of_scope_functions = self.extract_functions(
            parsed['in_scope'] + parsed['out_of_scope']
        )
        
        # Determine bounty platform
        platform = None
        if parsed['platform']:
            platform_text = ' '.join(parsed['platform']).lower()
            if 'immunefi' in platform_text:
                platform = 'immunefi'
            elif 'hackenproof' in platform_text:
                platform = 'hackenproof'
            elif 'hackerone' in platform_text:
                platform = 'hackerone'
            elif 'sherlock' in platform_text:
                platform = 'sherlock'
        
        # Extract prize information
        prize = None
        if parsed['prize']:
            prize_text = ' '.join(parsed['prize'])
            # Look for monetary amounts
            amounts = re.findall(r'\$?(\d+(?:,\d{3})*(?:\.\d{2})?)\s*(?:k|K|thousand|million|billion)?', prize_text)
            if amounts:
                prize = f"${amounts[0]}"
        
        # Determine confidence threshold based on scope clarity
        confidence_threshold = 0.7
        if len(parsed['in_scope']) > 3 and len(parsed['exclusions']) > 0:
            confidence_threshold = 0.8  # Clear scope
        elif len(parsed['in_scope']) < 2:
            confidence_threshold = 0.6  # Vague scope
        
        return ScopeInfo(
            target_path=target_path,
            scope_file=scope_file,
            in_scope_contracts=in_scope_contracts,
            out_of_scope_contracts=out_of_scope_contracts,
            in_scope_functions=in_scope_functions,
            out_of_scope_functions=out_of_scope_functions,
            severity_focus=parsed['severity'],
            vulnerability_types=parsed['vulnerability_types'],
            exclusions=parsed['exclusions'],
            special_instructions=parsed['instructions'],
            bounty_platform=platform,
            max_prize=prize,
            confidence_threshold=confidence_threshold
        )
    
    def generate_scope_guidance(self, scope_info: ScopeInfo) -> Dict[str, Any]:
        """
        Generate guidance for the bug bounty hunt based on scope
        """
        guidance = {
            'target_contracts': scope_info.in_scope_contracts,
            'excluded_contracts': scope_info.out_of_scope_contracts,
            'target_functions': scope_info.in_scope_functions,
            'excluded_functions': scope_info.out_of_scope_functions,
            'severity_focus': scope_info.severity_focus,
            'vulnerability_types': scope_info.vulnerability_types,
            'exclusions': scope_info.exclusions,
            'special_instructions': scope_info.special_instructions,
            'bounty_platform': scope_info.bounty_platform,
            'max_prize': scope_info.max_prize,
            'confidence_threshold': scope_info.confidence_threshold,
            'agent_priorities': self._determine_agent_priorities(scope_info),
            'hunting_strategy': self._generate_hunting_strategy(scope_info)
        }
        
        return guidance
    
    def _determine_agent_priorities(self, scope_info: ScopeInfo) -> Dict[str, int]:
        """
        Determine agent priorities based on scope
        """
        priorities = {}
        
        # Base priorities for all agents
        base_priorities = {
            'hunter-alpha': 5,  # Reentrancy
            'hunter-beta': 5,  # Access control
            'hunter-gamma': 4,  # Mathematical
            'hunter-delta': 4,  # Oracle
            'hunter-epsilon': 4,  # Flash loan
            'hunter-zeta': 3,  # Bridge
            'hunter-eta': 3,  # Governance
            'hunter-theta': 3,  # Signature
            'hunter-iota': 2,  # Edge cases
            'hunter-kappa': 2,  # Novel attacks
        }
        
        # Adjust priorities based on scope
        scope_text = ' '.join(scope_info.vulnerability_types + scope_info.severity_focus).lower()
        
        if 'reentrancy' in scope_text or 'callback' in scope_text:
            priorities['hunter-alpha'] = 8
        if 'access' in scope_text or 'permission' in scope_text or 'role' in scope_text:
            priorities['hunter-beta'] = 8
        if 'math' in scope_text or 'precision' in scope_text or 'overflow' in scope_text:
            priorities['hunter-gamma'] = 8
        if 'oracle' in scope_text or 'price' in scope_text or 'feed' in scope_text:
            priorities['hunter-delta'] = 8
        if 'flash' in scope_text or 'loan' in scope_text or 'mev' in scope_text:
            priorities['hunter-epsilon'] = 8
        if 'bridge' in scope_text or 'cross' in scope_text or 'chain' in scope_text:
            priorities['hunter-zeta'] = 8
        if 'governance' in scope_text or 'voting' in scope_text or 'proposal' in scope_text:
            priorities['hunter-eta'] = 8
        if 'signature' in scope_text or 'sign' in scope_text or 'auth' in scope_text:
            priorities['hunter-theta'] = 8
        
        # Apply base priorities for unset agents
        for agent, priority in base_priorities.items():
            if agent not in priorities:
                priorities[agent] = priority
        
        return priorities
    
    def _generate_hunting_strategy(self, scope_info: ScopeInfo) -> Dict[str, Any]:
        """
        Generate hunting strategy based on scope
        """
        strategy = {
            'focus_areas': [],
            'excluded_areas': [],
            'hunting_approach': 'comprehensive',
            'confidence_threshold': scope_info.confidence_threshold,
            'platform_optimization': scope_info.bounty_platform
        }
        
        # Determine focus areas
        if scope_info.in_scope_contracts:
            strategy['focus_areas'].extend(scope_info.in_scope_contracts)
        if scope_info.in_scope_functions:
            strategy['focus_areas'].extend(scope_info.in_scope_functions)
        
        # Determine excluded areas
        if scope_info.out_of_scope_contracts:
            strategy['excluded_areas'].extend(scope_info.out_of_scope_contracts)
        if scope_info.out_of_scope_functions:
            strategy['excluded_areas'].extend(scope_info.out_of_scope_functions)
        
        # Determine hunting approach
        if len(scope_info.in_scope_contracts) == 1:
            strategy['hunting_approach'] = 'focused'
        elif len(scope_info.in_scope_contracts) > 5:
            strategy['hunting_approach'] = 'broad'
        
        return strategy
    
    def save_scope_analysis(self, scope_info: ScopeInfo, guidance: Dict[str, Any], output_dir: str):
        """
        Save scope analysis to output directory
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Save scope info
        scope_data = {
            'target_path': scope_info.target_path,
            'scope_file': scope_info.scope_file,
            'in_scope_contracts': scope_info.in_scope_contracts,
            'out_of_scope_contracts': scope_info.out_of_scope_contracts,
            'in_scope_functions': scope_info.in_scope_functions,
            'out_of_scope_functions': scope_info.out_of_scope_functions,
            'severity_focus': scope_info.severity_focus,
            'vulnerability_types': scope_info.vulnerability_types,
            'exclusions': scope_info.exclusions,
            'special_instructions': scope_info.special_instructions,
            'bounty_platform': scope_info.bounty_platform,
            'max_prize': scope_info.max_prize,
            'confidence_threshold': scope_info.confidence_threshold,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        scope_file = os.path.join(output_dir, 'scope_analysis.json')
        with open(scope_file, 'w') as f:
            json.dump(scope_data, f, indent=2)
        
        # Save guidance
        guidance_file = os.path.join(output_dir, 'scope_guidance.json')
        with open(guidance_file, 'w') as f:
            json.dump(guidance, f, indent=2)
        
        print(f"📋 Scope analysis saved to {scope_file}")
        print(f"🎯 Scope guidance saved to {guidance_file}")


def main():
    """Main entry point for scope analyzer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scope_analyzer.py <target_path> [output_dir]")
        sys.exit(1)
    
    target_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "scope_analysis"
    
    analyzer = ScopeAnalyzer()
    
    # Analyze scope
    scope_info = analyzer.analyze_scope(target_path)
    if not scope_info:
        print("❌ No scope information found")
        sys.exit(1)
    
    # Generate guidance
    guidance = analyzer.generate_scope_guidance(scope_info)
    
    # Save analysis
    analyzer.save_scope_analysis(scope_info, guidance, output_dir)
    
    # Print summary
    print("\n📋 Scope Analysis Summary:")
    print(f"  Target: {scope_info.target_path}")
    print(f"  Scope File: {scope_info.scope_file}")
    print(f"  In-Scope Contracts: {len(scope_info.in_scope_contracts)}")
    print(f"  Out-of-Scope Contracts: {len(scope_info.out_of_scope_contracts)}")
    print(f"  Bounty Platform: {scope_info.bounty_platform or 'Unknown'}")
    print(f"  Max Prize: {scope_info.max_prize or 'Unknown'}")
    print(f"  Confidence Threshold: {scope_info.confidence_threshold}")


if __name__ == "__main__":
    main()

