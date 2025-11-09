#!/usr/bin/env python3
"""
Auto-Learning Wrapper Script
Runs the full learning process: recent hacks + GitHub exploits
Usage: python learn.py [days]  # Default: 7 for hacks, 30 for GitHub
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from advanced.auto_learning import AutoLearner

def main(days_hacks=7, days_github=30):
    print("🚀 Starting Auto-Learning Process...")
    print(f"📅 Learning from hacks (last {days_hacks} days) + GitHub (last {days_github} days)")
    
    learner = AutoLearner()
    
    # Learn from recent hacks
    print("\n1/2: Learning from recent hacks...")
    hack_patterns = learner.learn_from_recent_hacks(days=days_hacks)
    
    # Learn from GitHub exploits
    print("\n2/2: Learning from GitHub exploit repos...")
    github_patterns = learner.learn_from_github_exploits(days=days_github)
    
    # Summary
    print("\n" + "="*50)
    print("📊 LEARNING SUMMARY")
    print("="*50)
    print(learner.get_learned_patterns_summary())
    print(f"\n✅ Total new patterns learned: {len(hack_patterns) + len(github_patterns)}")
    print("📁 Saved to: patterns/learned_patterns.json")
    print("🔄 Updated detectors: patterns/updated_detector.json")
    
    print("\n💡 Next: Run your analysis with updated patterns!")
    print("   python advanced_bug_hunter.py contract.sol --auto-learn")

if __name__ == "__main__":
    days_hacks = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    days_github = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    main(days_hacks, days_github)