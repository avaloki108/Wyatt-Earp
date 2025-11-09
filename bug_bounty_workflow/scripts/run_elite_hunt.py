#!/usr/bin/env python3
"""
Elite Hunting Phase - Runs all 4 elite detectors + advanced pattern detector
Integrates into the multi-agent workflow at Phase 4 (Hunter agents)
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from detectors.storage_collision_detector import StorageCollisionDetector
from detectors.flash_loan_simulator import FlashLoanSimulator  
from detectors.state_desync_analyzer import StateDesyncAnalyzer
from detectors.oracle_manipulation_detector import OracleManipulationDetector
from detectors.advanced_pattern_detector import AdvancedPatternDetector

def run_elite_hunt(target_path: str, output_dir: str):
    """Run all elite detectors"""
    
    print("\n🎯 ELITE HUNTING PHASE - Running all 5 detectors")
    print("=" * 80)
    
    all_findings = []
    
    # 1. Storage Collision Detector
    print("\n[1/5] 🗄️  Storage Collision Detector...")
    storage_detector = StorageCollisionDetector(verbose=False)
    storage_findings = storage_detector.analyze_directory(target_path)
    all_findings.extend([f.to_dict() for f in storage_findings])
    print(f"   ✓ Found {len(storage_findings)} storage issues")
    
    # 2. Flash Loan Simulator  
    print("\n[2/5] 💰 Flash Loan Economic Simulator...")
    flash_simulator = FlashLoanSimulator(verbose=False)
    flash_findings = flash_simulator.analyze_directory(target_path)
    all_findings.extend([f.to_dict() for f in flash_findings])
    print(f"   ✓ Found {len(flash_findings)} flash loan attacks")
    
    # 3. State Desync Analyzer
    print("\n[3/5] 🔄 State Desynchronization Analyzer...")
    state_analyzer = StateDesyncAnalyzer(verbose=False)
    state_findings = state_analyzer.analyze_directory(target_path)
    all_findings.extend([f.to_dict() for f in state_findings])
    print(f"   ✓ Found {len(state_findings)} state desync issues")
    
    # 4. Oracle Manipulation Detector
    print("\n[4/5] 🔮 Oracle Manipulation Detector...")
    oracle_detector = OracleManipulationDetector(verbose=False)
    oracle_findings = oracle_detector.analyze_directory(target_path)
    all_findings.extend([f.to_dict() for f in oracle_findings])
    print(f"   ✓ Found {len(oracle_findings)} oracle vulnerabilities")
    
    # 5. Advanced Pattern Detector (ALL 33+ patterns)
    print("\n[5/5] 🧠 Advanced Pattern Detector (33+ patterns)...")
    pattern_detector = AdvancedPatternDetector(verbose=False)
    pattern_findings = pattern_detector.analyze_directory(target_path)
    all_findings.extend([f.to_dict() for f in pattern_findings])
    print(f"   ✓ Found {len(pattern_findings)} advanced pattern vulnerabilities")
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 ELITE HUNT COMPLETE")
    print("=" * 80)
    print(f"Total Findings: {len(all_findings)}")
    
    critical = len([f for f in all_findings if f.get('severity') == 'critical'])
    high = len([f for f in all_findings if f.get('severity') == 'high'])
    medium = len([f for f in all_findings if f.get('severity') == 'medium'])
    
    print(f"🔴 Critical: {critical}")
    print(f"🟠 High: {high}")
    print(f"🟡 Medium: {medium}")
    
    # Save aggregated findings
    import json
    output_file = os.path.join(output_dir, "elite_hunt_findings.json")
    with open(output_file, 'w') as f:
        json.dump({
            'total': len(all_findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'findings': all_findings
        }, f, indent=2)
    
    print(f"\n📄 Findings saved to: {output_file}")
    
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_elite_hunt.py <target_path> [output_dir]")
        sys.exit(1)
    
    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "."
    
    os.makedirs(output, exist_ok=True)
    run_elite_hunt(target, output)
