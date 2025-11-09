#!/usr/bin/env python3
"""
Bug Bounty Optimized Configuration
Focuses on high-value vulnerability types for bug bounty hunting
"""

# Bug Bounty Focused Patterns
# These are the vulnerability types that pay the most in bug bounties

BUG_BOUNTY_PATTERNS = {
    # Economic Exploits (Highest Payout)
    "economic_exploits": [
        "first_depositor_inflation_attack",  # ERC-4626 inflation ($80M+ Rari)
        "flash_loan_attack",                 # Flash loan exploits ($34M Harvest)
        "sandwich_attack",                  # MEV extraction
        "oracle_manipulation",              # Price manipulation ($130M Cream)
        "liquidation_front_running",        # Liquidation attacks
        "donation_attack_vulnerability",    # Balance manipulation
        "just_in_time_liquidity_attack",    # JIT liquidity
        "twap_manipulation_short_window",   # TWAP manipulation
    ],
    
    # Access Control (High Payout)
    "access_control": [
        "unprotected_functions",            # Missing access control
        "missing_access_control",           # No access restrictions
        "delegatecall_to_user",            # Dangerous delegatecall
        "potential_backdoor",              # Admin backdoors
        "privilege_escalation",            # Role confusion
    ],
    
    # Reentrancy (High Payout)
    "reentrancy": [
        "cross_function_reentrancy",       # Cross-function reentrancy ($60M DAO)
        "read_only_reentrancy",           # Read-only reentrancy
        "callback_reentrancy_vulnerability", # Callback reentrancy
        "cross_contract_reentrancy",      # Cross-contract reentrancy ($25M Lendf.me)
    ],
    
    # Bridge Vulnerabilities (High Payout)
    "bridge_vulnerabilities": [
        "message_replay",                 # Cross-chain message replay
        "signature_malleability",        # Signature issues
        "finality_attacks",              # Premature finalization
        "state_desync",                  # State inconsistencies
    ],
    
    # Governance Attacks (High Payout)
    "governance_attacks": [
        "flash_loan_voting",             # Flash loan governance
        "proposal_griefing",             # Proposal blocking
        "vote_manipulation",             # Vote manipulation
        "governance_queue_manipulation", # Queue manipulation
    ],
    
    # Integration Issues (Medium-High Payout)
    "integration_issues": [
        "cross_contract_logic_flaw",     # Cross-contract issues
        "external_call_manipulation",   # External call issues
        "state_inconsistency",          # State management
        "callback_manipulation",        # Callback issues
    ]
}

# Severity Mapping for Bug Bounties
BUG_BOUNTY_SEVERITY_MAPPING = {
    "critical": {
        "description": "Immediate threat, can cause total loss",
        "bounty_range": "$10,000 - $100,000+",
        "examples": ["Admin backdoors", "Total fund drainage", "Governance takeover"]
    },
    "high": {
        "description": "Significant impact, can cause major losses", 
        "bounty_range": "$1,000 - $50,000",
        "examples": ["Flash loan attacks", "Oracle manipulation", "Reentrancy"]
    },
    "medium": {
        "description": "Moderate impact, can cause losses",
        "bounty_range": "$100 - $10,000", 
        "examples": ["MEV extraction", "Sandwich attacks", "Liquidation front-running"]
    },
    "low": {
        "description": "Minor impact, best practice violations",
        "bounty_range": "$0 - $1,000",
        "examples": ["Gas optimization", "Code quality", "Documentation"]
    }
}

# Platform-Specific Focus
PLATFORM_FOCUS = {
    "immunefi": {
        "primary_focus": ["economic_exploits", "access_control", "reentrancy"],
        "secondary_focus": ["governance_attacks", "integration_issues"],
        "high_value_protocols": ["Uniswap", "Aave", "Compound", "MakerDAO", "Curve"]
    },
    "hackenproof": {
        "primary_focus": ["bridge_vulnerabilities", "governance_attacks", "access_control"],
        "secondary_focus": ["economic_exploits", "reentrancy"],
        "high_value_protocols": ["Polygon", "Avalanche", "BSC", "Arbitrum", "Optimism"]
    },
    "hackerone": {
        "primary_focus": ["access_control", "reentrancy", "integration_issues"],
        "secondary_focus": ["economic_exploits", "governance_attacks"],
        "high_value_protocols": ["Ethereum", "Bitcoin", "Solana", "Cardano"]
    }
}

# Confidence Thresholds for Bug Bounties
CONFIDENCE_THRESHOLDS = {
    "immediate_submission": 0.9,    # Submit immediately
    "manual_review": 0.7,          # Review manually
    "investigate_further": 0.5,    # Investigate more
    "ignore": 0.3                  # Likely false positive
}

def get_bug_bounty_focus(platform="immunefi"):
    """Get vulnerability patterns to focus on for specific platform"""
    if platform not in PLATFORM_FOCUS:
        platform = "immunefi"  # Default
    
    focus = PLATFORM_FOCUS[platform]
    patterns = []
    
    # Add primary focus patterns
    for category in focus["primary_focus"]:
        patterns.extend(BUG_BOUNTY_PATTERNS[category])
    
    # Add secondary focus patterns
    for category in focus["secondary_focus"]:
        patterns.extend(BUG_BOUNTY_PATTERNS[category])
    
    return patterns

def get_confidence_guidance(confidence):
    """Get guidance based on confidence score"""
    if confidence >= CONFIDENCE_THRESHOLDS["immediate_submission"]:
        return "🚀 Submit immediately - High confidence finding"
    elif confidence >= CONFIDENCE_THRESHOLDS["manual_review"]:
        return "🔍 Manual review - Good confidence, verify details"
    elif confidence >= CONFIDENCE_THRESHOLDS["investigate_further"]:
        return "🔬 Investigate further - Medium confidence, dig deeper"
    else:
        return "❌ Ignore - Low confidence, likely false positive"

def get_bounty_estimate(severity, confidence):
    """Estimate potential bounty payout"""
    base_ranges = BUG_BOUNTY_SEVERITY_MAPPING[severity]["bounty_range"]
    
    # Adjust based on confidence
    if confidence >= 0.9:
        multiplier = 1.0  # Full range
    elif confidence >= 0.7:
        multiplier = 0.7  # 70% of range
    elif confidence >= 0.5:
        multiplier = 0.4  # 40% of range
    else:
        multiplier = 0.1  # 10% of range
    
    return f"Estimated bounty: {base_ranges} (confidence adjusted)"

def print_bug_bounty_summary():
    """Print bug bounty optimization summary"""
    print("🎯 Bug Bounty Optimization Summary")
    print("=" * 50)
    
    print("\n💰 High-Value Vulnerability Types:")
    for category, patterns in BUG_BOUNTY_PATTERNS.items():
        print(f"\n{category.replace('_', ' ').title()}:")
        for pattern in patterns[:3]:  # Show first 3
            print(f"  - {pattern}")
        if len(patterns) > 3:
            print(f"  ... and {len(patterns) - 3} more")
    
    print("\n🎯 Platform-Specific Focus:")
    for platform, focus in PLATFORM_FOCUS.items():
        print(f"\n{platform.upper()}:")
        print(f"  Primary: {', '.join(focus['primary_focus'])}")
        print(f"  Secondary: {', '.join(focus['secondary_focus'])}")
        print(f"  High-value protocols: {', '.join(focus['high_value_protocols'][:3])}")
    
    print("\n📊 Confidence Guidance:")
    for threshold, guidance in CONFIDENCE_THRESHOLDS.items():
        print(f"  {threshold}: {guidance}")

if __name__ == "__main__":
    print_bug_bounty_summary()
