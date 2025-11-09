"""
Benchmark Comparison System
Compares Advanced Web3 Bug Hunter against Slither and Mythril
Tracks which tool finds what, and measures improvement
"""

import json
import subprocess
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import os


@dataclass
class BenchmarkResult:
    """Results from a single tool on a single contract"""
    tool_name: str
    contract_path: str
    execution_time: float
    vulnerabilities_found: List[str]
    vulnerability_details: List[Dict[str, Any]]
    exit_code: int
    error_message: Optional[str] = None
    

@dataclass
class ComparisonReport:
    """Comparison report across all tools"""
    contract_path: str
    timestamp: str
    results: Dict[str, BenchmarkResult]
    unique_to_our_tool: List[str]
    unique_to_slither: List[str]
    unique_to_mythril: List[str]
    common_findings: List[str]
    our_tool_advantage: int  # Number of unique findings
    

class BenchmarkSystem:
    """
    Comprehensive benchmarking system to prove our tool is better
    """
    
    def __init__(self, results_dir: str = "benchmark_results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        self.comparison_history: List[ComparisonReport] = []
        self._load_history()
        
    def _load_history(self):
        """Load historical benchmark results"""
        history_file = self.results_dir / "comparison_history.json"
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    self.comparison_history = [
                        ComparisonReport(**report) 
                        for report in data
                    ]
            except Exception as e:
                print(f"Warning: Could not load history: {e}")
                
    def _save_history(self):
        """Save benchmark history"""
        history_file = self.results_dir / "comparison_history.json"
        try:
            with open(history_file, 'w') as f:
                json.dump(
                    [asdict(r) for r in self.comparison_history],
                    f, 
                    indent=2
                )
        except Exception as e:
            print(f"Error saving history: {e}")
            
    def run_our_tool(self, contract_path: str) -> BenchmarkResult:
        """Run our Advanced Bug Hunter"""
        start_time = time.time()
        vulnerabilities = []
        details = []
        error = None
        exit_code = 0
        
        try:
            # Import our tool
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            
            from advanced.novel_vulnerability_patterns import NovelPatternDetector
            from advanced.behavioral_anomaly_detector import BehavioralAnomalyDetector
            
            # Read contract
            with open(contract_path, 'r') as f:
                contract_code = f.read()
                
            contract_name = Path(contract_path).stem
            
            # Run pattern detection
            pattern_detector = NovelPatternDetector()
            patterns = pattern_detector.detect_all_patterns(contract_code, contract_name)
            
            # Run anomaly detection
            anomaly_detector = BehavioralAnomalyDetector()
            anomalies = anomaly_detector.analyze_contract(contract_code, contract_name)
            
            # Collect findings
            for pattern in patterns:
                vulnerabilities.append(pattern.name)
                details.append({
                    'name': pattern.name,
                    'severity': pattern.severity,
                    'category': pattern.category.value,
                    'confidence': pattern.confidence
                })
                
            for anomaly in anomalies:
                vulnerabilities.append(anomaly.name)
                details.append({
                    'name': anomaly.name,
                    'severity': anomaly.severity,
                    'type': anomaly.anomaly_type.value,
                    'confidence': anomaly.confidence
                })
                
        except Exception as e:
            error = str(e)
            exit_code = 1
            
        execution_time = time.time() - start_time
        
        return BenchmarkResult(
            tool_name="AdvancedWeb3BugHunter",
            contract_path=contract_path,
            execution_time=execution_time,
            vulnerabilities_found=list(set(vulnerabilities)),
            vulnerability_details=details,
            exit_code=exit_code,
            error_message=error
        )
        
    def run_slither(self, contract_path: str) -> BenchmarkResult:
        """Run Slither static analyzer"""
        start_time = time.time()
        vulnerabilities = []
        details = []
        error = None
        exit_code = 0
        
        try:
            # Check if slither is installed
            result = subprocess.run(
                ['which', 'slither'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                error = "Slither not installed"
                exit_code = 127
            else:
                # Run slither
                result = subprocess.run(
                    ['slither', contract_path, '--json', '-'],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                exit_code = result.returncode
                
                if result.returncode == 0 or result.stdout:
                    try:
                        output = json.loads(result.stdout)
                        if 'results' in output and 'detectors' in output['results']:
                            for detector in output['results']['detectors']:
                                vuln_name = detector.get('check', 'unknown')
                                vulnerabilities.append(vuln_name)
                                details.append({
                                    'name': vuln_name,
                                    'severity': detector.get('impact', 'unknown'),
                                    'confidence': detector.get('confidence', 'unknown')
                                })
                    except json.JSONDecodeError:
                        error = "Failed to parse Slither output"
                else:
                    error = result.stderr
                    
        except subprocess.TimeoutExpired:
            error = "Slither execution timeout"
            exit_code = 124
        except Exception as e:
            error = str(e)
            exit_code = 1
            
        execution_time = time.time() - start_time
        
        return BenchmarkResult(
            tool_name="Slither",
            contract_path=contract_path,
            execution_time=execution_time,
            vulnerabilities_found=list(set(vulnerabilities)),
            vulnerability_details=details,
            exit_code=exit_code,
            error_message=error
        )
        
    def run_mythril(self, contract_path: str) -> BenchmarkResult:
        """Run Mythril symbolic analyzer"""
        start_time = time.time()
        vulnerabilities = []
        details = []
        error = None
        exit_code = 0
        
        try:
            # Check if mythril is installed
            result = subprocess.run(
                ['which', 'myth'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                error = "Mythril not installed"
                exit_code = 127
            else:
                # Run mythril
                result = subprocess.run(
                    ['myth', 'analyze', contract_path, '--solv', '0.8.0', '-o', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout
                )
                
                exit_code = result.returncode
                
                if result.stdout:
                    try:
                        output = json.loads(result.stdout)
                        if 'issues' in output:
                            for issue in output['issues']:
                                vuln_name = issue.get('title', 'unknown')
                                vulnerabilities.append(vuln_name)
                                details.append({
                                    'name': vuln_name,
                                    'severity': issue.get('severity', 'unknown'),
                                    'type': issue.get('swc-id', 'unknown')
                                })
                    except json.JSONDecodeError:
                        error = "Failed to parse Mythril output"
                else:
                    error = result.stderr if result.stderr else "No output"
                    
        except subprocess.TimeoutExpired:
            error = "Mythril execution timeout"
            exit_code = 124
        except Exception as e:
            error = str(e)
            exit_code = 1
            
        execution_time = time.time() - start_time
        
        return BenchmarkResult(
            tool_name="Mythril",
            contract_path=contract_path,
            execution_time=execution_time,
            vulnerabilities_found=list(set(vulnerabilities)),
            vulnerability_details=details,
            exit_code=exit_code,
            error_message=error
        )
        
    def compare_all_tools(self, contract_path: str) -> ComparisonReport:
        """
        Run all tools and generate comparison report
        This proves which tool is better
        """
        print(f"\n{'='*70}")
        print(f"BENCHMARKING: {contract_path}")
        print(f"{'='*70}")
        
        # Run all tools
        print("\n[1/3] Running Advanced Web3 Bug Hunter...")
        our_result = self.run_our_tool(contract_path)
        print(f"      Found {len(our_result.vulnerabilities_found)} vulnerabilities in {our_result.execution_time:.2f}s")
        
        print("\n[2/3] Running Slither...")
        slither_result = self.run_slither(contract_path)
        if slither_result.error_message:
            print(f"      Slither: {slither_result.error_message}")
        else:
            print(f"      Found {len(slither_result.vulnerabilities_found)} vulnerabilities in {slither_result.execution_time:.2f}s")
            
        print("\n[3/3] Running Mythril...")
        mythril_result = self.run_mythril(contract_path)
        if mythril_result.error_message:
            print(f"      Mythril: {mythril_result.error_message}")
        else:
            print(f"      Found {len(mythril_result.vulnerabilities_found)} vulnerabilities in {mythril_result.execution_time:.2f}s")
            
        # Analyze results
        our_findings = set(our_result.vulnerabilities_found)
        slither_findings = set(slither_result.vulnerabilities_found) if not slither_result.error_message else set()
        mythril_findings = set(mythril_result.vulnerabilities_found) if not mythril_result.error_message else set()
        
        # Find unique findings
        unique_to_our = list(our_findings - slither_findings - mythril_findings)
        unique_to_slither = list(slither_findings - our_findings - mythril_findings)
        unique_to_mythril = list(mythril_findings - our_findings - slither_findings)
        
        # Find common findings
        common = list(our_findings & slither_findings & mythril_findings)
        
        # Create comparison report
        report = ComparisonReport(
            contract_path=contract_path,
            timestamp=datetime.now().isoformat(),
            results={
                'AdvancedWeb3BugHunter': our_result,
                'Slither': slither_result,
                'Mythril': mythril_result
            },
            unique_to_our_tool=unique_to_our,
            unique_to_slither=unique_to_slither,
            unique_to_mythril=unique_to_mythril,
            common_findings=common,
            our_tool_advantage=len(unique_to_our)
        )
        
        # Save report
        self.comparison_history.append(report)
        self._save_history()
        
        # Print results
        self._print_comparison(report)
        
        return report
        
    def _print_comparison(self, report: ComparisonReport):
        """Print detailed comparison results"""
        print(f"\n{'='*70}")
        print("COMPARISON RESULTS")
        print(f"{'='*70}")
        
        # Summary
        our_count = len(report.results['AdvancedWeb3BugHunter'].vulnerabilities_found)
        slither_count = len(report.results['Slither'].vulnerabilities_found)
        mythril_count = len(report.results['Mythril'].vulnerabilities_found)
        
        print("\nVulnerabilities Found:")
        print(f"  Advanced Web3 Bug Hunter: {our_count}")
        print(f"  Slither:                  {slither_count}")
        print(f"  Mythril:                  {mythril_count}")
        
        print(f"\nCommon Findings: {len(report.common_findings)}")
        for finding in report.common_findings[:5]:
            print(f"  ✓ {finding}")
        if len(report.common_findings) > 5:
            print(f"  ... and {len(report.common_findings) - 5} more")
            
        print(f"\n🎯 UNIQUE TO OUR TOOL: {len(report.unique_to_our_tool)}")
        for finding in report.unique_to_our_tool[:10]:
            print(f"  ⭐ {finding}")
        if len(report.unique_to_our_tool) > 10:
            print(f"  ... and {len(report.unique_to_our_tool) - 10} more")
            
        print(f"\nUnique to Slither: {len(report.unique_to_slither)}")
        for finding in report.unique_to_slither[:5]:
            print(f"  • {finding}")
            
        print(f"\nUnique to Mythril: {len(report.unique_to_mythril)}")
        for finding in report.unique_to_mythril[:5]:
            print(f"  • {finding}")
            
        # Performance comparison
        our_time = report.results['AdvancedWeb3BugHunter'].execution_time
        slither_time = report.results['Slither'].execution_time
        mythril_time = report.results['Mythril'].execution_time
        
        print("\nExecution Time:")
        print(f"  Our Tool: {our_time:.2f}s")
        print(f"  Slither:  {slither_time:.2f}s")
        print(f"  Mythril:  {mythril_time:.2f}s")
        
        # Calculate advantage
        advantage = report.our_tool_advantage
        if advantage > 0:
            print(f"\n🏆 OUR TOOL FOUND {advantage} UNIQUE VULNERABILITIES!")
        elif advantage == 0 and our_count >= max(slither_count, mythril_count):
            print("\n✓ Our tool matched or exceeded other tools")
        else:
            print("\n⚠️ Other tools found some unique issues to investigate")
            
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary of all benchmarks"""
        if not self.comparison_history:
            return {'message': 'No benchmark data available'}
            
        total_comparisons = len(self.comparison_history)
        total_unique_findings = sum(r.our_tool_advantage for r in self.comparison_history)
        
        # Calculate win rate
        wins = sum(1 for r in self.comparison_history if r.our_tool_advantage > 0)
        win_rate = wins / total_comparisons if total_comparisons > 0 else 0
        
        # Average performance
        our_avg_time = sum(
            r.results['AdvancedWeb3BugHunter'].execution_time 
            for r in self.comparison_history
        ) / total_comparisons
        
        slither_avg_time = sum(
            r.results['Slither'].execution_time 
            for r in self.comparison_history
            if not r.results['Slither'].error_message
        ) / total_comparisons
        
        return {
            'total_benchmarks': total_comparisons,
            'total_unique_findings': total_unique_findings,
            'win_rate': win_rate,
            'average_execution_time': our_avg_time,
            'slither_avg_time': slither_avg_time,
            'most_recent_advantage': self.comparison_history[-1].our_tool_advantage if self.comparison_history else 0
        }


if __name__ == "__main__":
    # Demo the benchmark system
    print("="*70)
    print("BENCHMARK COMPARISON SYSTEM - Demo")
    print("="*70)
    
    benchmark = BenchmarkSystem("demo_benchmarks")
    
    # Run comparison on example contract
    example_contract = "examples/VulnerableVault.sol"
    if os.path.exists(example_contract):
        report = benchmark.compare_all_tools(example_contract)
        
        print("\n" + "="*70)
        print("SUMMARY REPORT")
        print("="*70)
        
        summary = benchmark.generate_summary_report()
        print(f"\nTotal benchmarks: {summary['total_benchmarks']}")
        print(f"Win rate: {summary['win_rate']:.1%}")
        print(f"Total unique findings: {summary['total_unique_findings']}")
    else:
        print(f"Example contract not found: {example_contract}")
        print("Please run from repository root directory")
