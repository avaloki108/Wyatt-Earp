#!/bin/bash
# Bug Bounty Triage Script
# Quickly scan multiple targets to identify high-priority contracts

set -e

BOUNTY_DIR="$1"
if [ -z "$BOUNTY_DIR" ]; then
    echo "🎯 Bug Bounty Triage Script"
    echo "Usage: $0 <bounty_directory>"
    echo ""
    echo "Example:"
    echo "  $0 ~/bounties/immunefi/protocol/"
    echo "  $0 ~/bounties/hackenproof/high-tvl/"
    exit 1
fi

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "⚠️  Activating virtual environment..."
    source .venv/bin/activate
fi

# Check API key
if [ -z "$XAI_API_KEY" ]; then
    echo "❌ XAI_API_KEY not set. Please set your Grok API key:"
    echo "   export XAI_API_KEY=\"your-key\""
    exit 1
fi

echo "🎯 Bug Bounty Triage: $BOUNTY_DIR"
echo "=" * 60

# Create results directory
RESULTS_DIR="bounty_triage_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Find all Solidity contracts
echo "📄 Scanning for Solidity contracts..."
CONTRACTS=$(find "$BOUNTY_DIR" -name "*.sol" | head -20)  # Limit to first 20 for triage

if [ -z "$CONTRACTS" ]; then
    echo "❌ No Solidity contracts found in $BOUNTY_DIR"
    exit 1
fi

echo "📊 Found $(echo "$CONTRACTS" | wc -l) contracts"
echo ""

# Initialize counters
TOTAL_CONTRACTS=0
HIGH_PRIORITY=0
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0

# Process each contract
echo "$CONTRACTS" | while read contract; do
    TOTAL_CONTRACTS=$((TOTAL_CONTRACTS + 1))
    
    echo "📄 [$TOTAL_CONTRACTS] Analyzing: $(basename "$contract")"
    
    # Quick scan (no AI, no fuzzing for speed)
    ./hunt "$contract" --quick -o "$RESULTS_DIR/$(basename "$contract" .sol)_triage.json" 2>/dev/null || {
        echo "  ❌ Analysis failed"
        continue
    }
    
    # Extract findings
    REPORT_FILE="$RESULTS_DIR/$(basename "$contract" .sol)_triage.json"
    
    if [ -f "$REPORT_FILE" ]; then
        # Count findings by severity
        CRITICAL=$(jq '.analysis_results.novel_patterns.critical // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        HIGH=$(jq '.analysis_results.novel_patterns.high // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        MEDIUM=$(jq '.analysis_results.novel_patterns.medium // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        
        CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + CRITICAL))
        HIGH_FINDINGS=$((HIGH_FINDINGS + HIGH))
        
        # Determine priority
        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 2 ]; then
            HIGH_PRIORITY=$((HIGH_PRIORITY + 1))
            echo "  ⚠️  HIGH PRIORITY: Critical: $CRITICAL, High: $HIGH, Medium: $MEDIUM"
            echo "$contract" >> "$RESULTS_DIR/high_priority_contracts.txt"
        elif [ "$HIGH" -gt 0 ]; then
            echo "  🔍 MEDIUM PRIORITY: Critical: $CRITICAL, High: $HIGH, Medium: $MEDIUM"
        else
            echo "  ✅ Low priority: Critical: $CRITICAL, High: $HIGH, Medium: $MEDIUM"
        fi
    else
        echo "  ❌ Report not generated"
    fi
    
    echo ""
done

# Summary
echo "📊 TRIAGE SUMMARY"
echo "=" * 30
echo "Total contracts analyzed: $TOTAL_CONTRACTS"
echo "High priority contracts: $HIGH_PRIORITY"
echo "Total critical findings: $CRITICAL_FINDINGS"
echo "Total high findings: $HIGH_FINDINGS"
echo ""

if [ -f "$RESULTS_DIR/high_priority_contracts.txt" ]; then
    echo "🎯 HIGH PRIORITY CONTRACTS:"
    echo "=" * 30
    cat "$RESULTS_DIR/high_priority_contracts.txt"
    echo ""
    echo "💡 Next steps:"
    echo "  1. Run deep analysis on high priority contracts:"
    echo "     ./deep_analysis.sh $RESULTS_DIR/high_priority_contracts.txt"
    echo "  2. Focus on contracts with critical findings first"
    echo "  3. Generate PoCs for high-confidence findings"
else
    echo "✅ No high priority contracts found"
    echo "💡 Consider:"
    echo "  - Try different target directories"
    echo "  - Look for high TVL protocols"
    echo "  - Focus on admin/governance contracts"
fi

echo ""
echo "📁 Results saved to: $RESULTS_DIR/"
echo "📄 Individual reports: $RESULTS_DIR/*_triage.json"
echo "🎯 High priority list: $RESULTS_DIR/high_priority_contracts.txt"
