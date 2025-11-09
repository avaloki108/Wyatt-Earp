#!/bin/bash
# Deep Analysis Script for Bug Bounty Hunting
# Runs full multi-agent analysis on high-priority contracts

set -e

HIGH_PRIORITY_FILE="$1"
if [ -z "$HIGH_PRIORITY_FILE" ]; then
    echo "🔬 Deep Analysis Script"
    echo "Usage: $0 <high_priority_contracts_file>"
    echo ""
    echo "Example:"
    echo "  $0 bounty_triage_20241022_175500/high_priority_contracts.txt"
    echo ""
    echo "First run triage to identify high-priority contracts:"
    echo "  ./bug_bounty_triage.sh ~/bounties/protocol/"
    exit 1
fi

if [ ! -f "$HIGH_PRIORITY_FILE" ]; then
    echo "❌ High priority contracts file not found: $HIGH_PRIORITY_FILE"
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

echo "🔬 Deep Analysis of High Priority Contracts"
echo "=" * 60

# Create results directory
RESULTS_DIR="deep_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Count contracts
TOTAL_CONTRACTS=$(wc -l < "$HIGH_PRIORITY_FILE")
echo "📊 Analyzing $TOTAL_CONTRACTS high-priority contracts"
echo ""

# Initialize counters
ANALYZED=0
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
POCS_GENERATED=0

# Process each high-priority contract
while IFS= read -r contract; do
    ANALYZED=$((ANALYZED + 1))
    
    echo "🔬 [$ANALYZED/$TOTAL_CONTRACTS] Deep analysis: $(basename "$contract")"
    echo "-" * 50
    
    # Full analysis with AI (no fuzzing for speed)
    ./hunt "$contract" --no-fuzzing -o "$RESULTS_DIR/$(basename "$contract" .sol)_deep.json" 2>/dev/null || {
        echo "  ❌ Deep analysis failed"
        continue
    }
    
    REPORT_FILE="$RESULTS_DIR/$(basename "$contract" .sol)_deep.json"
    
    if [ -f "$REPORT_FILE" ]; then
        # Extract findings
        CRITICAL=$(jq '.analysis_results.novel_patterns.critical // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        HIGH=$(jq '.analysis_results.novel_patterns.high // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        MEDIUM=$(jq '.analysis_results.novel_patterns.medium // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        
        CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + CRITICAL))
        HIGH_FINDINGS=$((HIGH_FINDINGS + HIGH))
        
        echo "  📊 Findings: Critical: $CRITICAL, High: $HIGH, Medium: $MEDIUM"
        
        # Extract high-priority findings for submission
        jq '.analysis_results.novel_patterns.patterns[] | select(.severity | IN("critical", "high")) | {
            name: .name,
            severity: .severity,
            category: .category,
            description: .description,
            attack_vector: .attack_vector,
            exploit_scenario: .exploit_scenario,
            remediation: .remediation,
            confidence: .confidence,
            affected_functions: .affected_functions
        }' "$REPORT_FILE" > "$RESULTS_DIR/$(basename "$contract" .sol)_submission.json" 2>/dev/null || {
            echo "  ⚠️  No high-priority findings extracted"
        }
        
        # Check for PoCs
        POC_COUNT=$(jq '.poc_generation.pocs | length' "$REPORT_FILE" 2>/dev/null || echo "0")
        if [ "$POC_COUNT" -gt 0 ]; then
            POCS_GENERATED=$((POCS_GENERATED + POC_COUNT))
            echo "  🔬 Generated $POC_COUNT PoCs"
            
            # Extract PoCs
            jq '.poc_generation.pocs[]' "$REPORT_FILE" > "$RESULTS_DIR/$(basename "$contract" .sol)_pocs.json" 2>/dev/null || true
        fi
        
        # Show top findings
        echo "  🎯 Top findings:"
        jq -r '.analysis_results.novel_patterns.patterns[] | select(.severity | IN("critical", "high")) | "    - \(.severity | ascii_upcase): \(.name) (confidence: \(.confidence))"' "$REPORT_FILE" 2>/dev/null | head -3 || echo "    - No high-priority findings"
        
    else
        echo "  ❌ Report not generated"
    fi
    
    echo ""
done < "$HIGH_PRIORITY_FILE"

# Summary
echo "📊 DEEP ANALYSIS SUMMARY"
echo "=" * 40
echo "Contracts analyzed: $ANALYZED/$TOTAL_CONTRACTS"
echo "Total critical findings: $CRITICAL_FINDINGS"
echo "Total high findings: $HIGH_FINDINGS"
echo "PoCs generated: $POCS_GENERATED"
echo ""

# Generate consolidated report
echo "📄 Generating consolidated reports..."

# Combine all submission files
echo "{" > "$RESULTS_DIR/all_submissions.json"
echo "  \"submissions\": [" >> "$RESULTS_DIR/all_submissions.json"
FIRST=true
for submission_file in "$RESULTS_DIR"/*_submission.json; do
    if [ -f "$submission_file" ] && [ -s "$submission_file" ]; then
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "$RESULTS_DIR/all_submissions.json"
        fi
        
        CONTRACT_NAME=$(basename "$submission_file" _submission.json)
        echo "    {" >> "$RESULTS_DIR/all_submissions.json"
        echo "      \"contract\": \"$CONTRACT_NAME\"," >> "$RESULTS_DIR/all_submissions.json"
        echo "      \"findings\": " >> "$RESULTS_DIR/all_submissions.json"
        cat "$submission_file" >> "$RESULTS_DIR/all_submissions.json"
        echo "" >> "$RESULTS_DIR/all_submissions.json"
        echo "    }" >> "$RESULTS_DIR/all_submissions.json"
    fi
done
echo "  ]" >> "$RESULTS_DIR/all_submissions.json"
echo "}" >> "$RESULTS_DIR/all_submissions.json

# Generate summary report
cat > "$RESULTS_DIR/summary_report.md" << EOF
# Bug Bounty Deep Analysis Report

**Generated:** $(date)
**Contracts Analyzed:** $ANALYZED/$TOTAL_CONTRACTS
**Critical Findings:** $CRITICAL_FINDINGS
**High Findings:** $HIGH_FINDINGS
**PoCs Generated:** $POCS_GENERATED

## High-Priority Findings by Contract

EOF

for contract_file in "$RESULTS_DIR"/*_submission.json; do
    if [ -f "$contract_file" ] && [ -s "$contract_file" ]; then
        CONTRACT_NAME=$(basename "$contract_file" _submission.json)
        echo "### $CONTRACT_NAME" >> "$RESULTS_DIR/summary_report.md"
        echo "" >> "$RESULTS_DIR/summary_report.md"
        
        jq -r '.[] | "- **\(.severity | ascii_upcase)**: \(.name) (confidence: \(.confidence))"' "$contract_file" >> "$RESULTS_DIR/summary_report.md" 2>/dev/null || echo "- No high-priority findings" >> "$RESULTS_DIR/summary_report.md"
        echo "" >> "$RESULTS_DIR/summary_report.md"
    fi
done

echo "✅ Deep analysis complete!"
echo ""
echo "📁 Results saved to: $RESULTS_DIR/"
echo "📄 Individual reports: $RESULTS_DIR/*_deep.json"
echo "🎯 Submission files: $RESULTS_DIR/*_submission.json"
echo "🔬 PoC files: $RESULTS_DIR/*_pocs.json"
echo "📊 Consolidated report: $RESULTS_DIR/all_submissions.json"
echo "📋 Summary report: $RESULTS_DIR/summary_report.md"
echo ""
echo "💡 Next steps:"
echo "  1. Review high-priority findings in submission files"
echo "  2. Validate PoCs for critical findings"
echo "  3. Submit findings to bug bounty platform"
echo "  4. Focus on findings with confidence ≥ 0.8"
