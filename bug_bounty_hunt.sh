#!/bin/bash
# Complete Bug Bounty Hunting Workflow
# Optimized for HackenProof, Immunefi, and other platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Function to show usage
show_usage() {
    echo "🎯 Bug Bounty Hunting Workflow"
    echo "=" * 50
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  triage <directory>           - Quick triage of multiple targets"
    echo "  deep <contract_file>        - Deep analysis of single contract"
    echo "  hunt <directory>            - Complete hunt workflow"
    echo "  analyze <contract_file>     - Full analysis with PoCs"
    echo "  report <results_directory>  - Generate submission reports"
    echo ""
    echo "Examples:"
    echo "  $0 triage ~/bounties/immunefi/protocol/"
    echo "  $0 deep ~/bounties/protocol/Vault.sol"
    echo "  $0 hunt ~/bounties/hackenproof/high-tvl/"
    echo "  $0 analyze ~/bounties/protocol/Governance.sol"
    echo "  $0 report bounty_triage_20241022_175500/"
    echo ""
    echo "Environment Setup:"
    echo "  source .venv/bin/activate"
    echo "  export XAI_API_KEY=\"your-grok-key\""
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if virtual environment is activated
    if [[ "$VIRTUAL_ENV" == "" ]]; then
        print_warning "Virtual environment not activated. Activating..."
        source .venv/bin/activate
    fi
    
    # Check API key
    if [ -z "$XAI_API_KEY" ]; then
        print_error "XAI_API_KEY not set. Please set your Grok API key:"
        echo "  export XAI_API_KEY=\"your-key\""
        exit 1
    fi
    
    # Check if hunt script exists
    if [ ! -f "./hunt" ]; then
        print_error "Hunt script not found. Are you in the correct directory?"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to run triage
run_triage() {
    local target_dir="$1"
    
    if [ -z "$target_dir" ]; then
        print_error "Target directory required for triage"
        show_usage
        exit 1
    fi
    
    if [ ! -d "$target_dir" ]; then
        print_error "Target directory not found: $target_dir"
        exit 1
    fi
    
    print_header "🎯 Bug Bounty Triage: $target_dir"
    print_status "Running quick triage on all contracts..."
    
    ./bug_bounty_triage.sh "$target_dir"
    
    print_success "Triage complete! Check results for high-priority contracts"
}

# Function to run deep analysis
run_deep_analysis() {
    local contract_file="$1"
    
    if [ -z "$contract_file" ]; then
        print_error "Contract file required for deep analysis"
        show_usage
        exit 1
    fi
    
    if [ ! -f "$contract_file" ]; then
        print_error "Contract file not found: $contract_file"
        exit 1
    fi
    
    print_header "🔬 Deep Analysis: $contract_file"
    print_status "Running full multi-agent analysis..."
    
    # Full analysis with AI
    ./hunt "$contract_file" --no-fuzzing -o "$(basename "$contract_file" .sol)_deep.json"
    
    # Extract findings
    local report_file="$(basename "$contract_file" .sol)_deep.json"
    
    if [ -f "$report_file" ]; then
        print_success "Analysis complete: $report_file"
        
        # Show summary
        local critical=$(jq '.analysis_results.novel_patterns.critical // 0' "$report_file" 2>/dev/null || echo "0")
        local high=$(jq '.analysis_results.novel_patterns.high // 0' "$report_file" 2>/dev/null || echo "0")
        local medium=$(jq '.analysis_results.novel_patterns.medium // 0' "$report_file" 2>/dev/null || echo "0")
        
        print_status "Findings: Critical: $critical, High: $high, Medium: $medium"
        
        # Extract high-priority findings
        jq '.analysis_results.novel_patterns.patterns[] | select(.severity | IN("critical", "high")) | {
            name: .name,
            severity: .severity,
            description: .description,
            attack_vector: .attack_vector,
            exploit_scenario: .exploit_scenario,
            remediation: .remediation,
            confidence: .confidence
        }' "$report_file" > "$(basename "$contract_file" .sol)_submission.json" 2>/dev/null || {
            print_warning "No high-priority findings extracted"
        }
        
        # Check for PoCs
        local poc_count=$(jq '.poc_generation.pocs | length' "$report_file" 2>/dev/null || echo "0")
        if [ "$poc_count" -gt 0 ]; then
            print_success "Generated $poc_count PoCs"
            jq '.poc_generation.pocs[]' "$report_file" > "$(basename "$contract_file" .sol)_pocs.json" 2>/dev/null || true
        fi
        
        print_success "Submission files generated:"
        echo "  - $(basename "$contract_file" .sol)_submission.json"
        echo "  - $(basename "$contract_file" .sol)_pocs.json"
    else
        print_error "Analysis failed - no report generated"
    fi
}

# Function to run complete hunt workflow
run_hunt() {
    local target_dir="$1"
    
    if [ -z "$target_dir" ]; then
        print_error "Target directory required for hunt"
        show_usage
        exit 1
    fi
    
    if [ ! -d "$target_dir" ]; then
        print_error "Target directory not found: $target_dir"
        exit 1
    fi
    
    print_header "🎯 Complete Bug Bounty Hunt: $target_dir"
    
    # Step 1: Triage
    print_status "Step 1: Running triage..."
    ./bug_bounty_triage.sh "$target_dir"
    
    # Find triage results
    local triage_dir=$(ls -td bounty_triage_* 2>/dev/null | head -1)
    
    if [ -z "$triage_dir" ] || [ ! -f "$triage_dir/high_priority_contracts.txt" ]; then
        print_warning "No high-priority contracts found in triage"
        print_status "Running deep analysis on all contracts instead..."
        
        # Run deep analysis on all contracts
        find "$target_dir" -name "*.sol" | head -5 | while read contract; do
            print_status "Deep analysis: $contract"
            ./hunt "$contract" --no-fuzzing -o "$(basename "$contract" .sol)_hunt.json"
        done
        
        print_success "Hunt complete! Check individual reports"
        return
    fi
    
    # Step 2: Deep analysis on high-priority contracts
    print_status "Step 2: Running deep analysis on high-priority contracts..."
    ./deep_analysis.sh "$triage_dir/high_priority_contracts.txt"
    
    print_success "Hunt complete! Check results in:"
    echo "  - $triage_dir/ (triage results)"
    echo "  - deep_analysis_*/ (deep analysis results)"
}

# Function to run full analysis with PoCs
run_analyze() {
    local contract_file="$1"
    
    if [ -z "$contract_file" ]; then
        print_error "Contract file required for analysis"
        show_usage
        exit 1
    fi
    
    if [ ! -f "$contract_file" ]; then
        print_error "Contract file not found: $contract_file"
        exit 1
    fi
    
    print_header "🔬 Full Analysis with PoCs: $contract_file"
    print_status "Running comprehensive multi-agent analysis..."
    
    # Full analysis with all modules
    ./hunt "$contract_file" -o "$(basename "$contract_file" .sol)_full.json"
    
    local report_file="$(basename "$contract_file" .sol)_full.json"
    
    if [ -f "$report_file" ]; then
        print_success "Full analysis complete: $report_file"
        
        # Show detailed summary
        local critical=$(jq '.analysis_results.novel_patterns.critical // 0' "$report_file" 2>/dev/null || echo "0")
        local high=$(jq '.analysis_results.novel_patterns.high // 0' "$report_file" 2>/dev/null || echo "0")
        local medium=$(jq '.analysis_results.novel_patterns.medium // 0' "$report_file" 2>/dev/null || echo "0")
        local poc_count=$(jq '.poc_generation.pocs | length' "$report_file" 2>/dev/null || echo "0")
        
        print_status "Findings: Critical: $critical, High: $high, Medium: $medium"
        print_status "PoCs generated: $poc_count"
        
        # Extract all findings for submission
        jq '.analysis_results.novel_patterns.patterns[] | {
            name: .name,
            severity: .severity,
            category: .category,
            description: .description,
            attack_vector: .attack_vector,
            exploit_scenario: .exploit_scenario,
            remediation: .remediation,
            confidence: .confidence,
            affected_functions: .affected_functions
        }' "$report_file" > "$(basename "$contract_file" .sol)_all_findings.json" 2>/dev/null || {
            print_warning "No findings extracted"
        }
        
        # Extract PoCs
        if [ "$poc_count" -gt 0 ]; then
            jq '.poc_generation.pocs[]' "$report_file" > "$(basename "$contract_file" .sol)_all_pocs.json" 2>/dev/null || true
        fi
        
        print_success "Analysis files generated:"
        echo "  - $report_file (full report)"
        echo "  - $(basename "$contract_file" .sol)_all_findings.json (all findings)"
        echo "  - $(basename "$contract_file" .sol)_all_pocs.json (all PoCs)"
    else
        print_error "Analysis failed - no report generated"
    fi
}

# Function to generate submission reports
run_report() {
    local results_dir="$1"
    
    if [ -z "$results_dir" ]; then
        print_error "Results directory required for report generation"
        show_usage
        exit 1
    fi
    
    if [ ! -d "$results_dir" ]; then
        print_error "Results directory not found: $results_dir"
        exit 1
    fi
    
    print_header "📊 Generating Submission Reports: $results_dir"
    
    # Create submission directory
    local submission_dir="submission_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$submission_dir"
    
    # Find all submission files
    local submission_files=$(find "$results_dir" -name "*_submission.json" -o -name "*_all_findings.json" 2>/dev/null)
    
    if [ -z "$submission_files" ]; then
        print_warning "No submission files found in $results_dir"
        return
    fi
    
    print_status "Found $(echo "$submission_files" | wc -l) submission files"
    
    # Generate consolidated report
    echo "{" > "$submission_dir/consolidated_findings.json"
    echo "  \"submission_date\": \"$(date)\"," >> "$submission_dir/consolidated_findings.json"
    echo "  \"total_contracts\": $(echo "$submission_files" | wc -l)," >> "$submission_dir/consolidated_findings.json"
    echo "  \"findings\": [" >> "$submission_dir/consolidated_findings.json"
    
    local first=true
    echo "$submission_files" | while read file; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            local contract_name=$(basename "$file" | sed 's/_submission.json\|_all_findings.json//')
            
            if [ "$first" = true ]; then
                first=false
            else
                echo "," >> "$submission_dir/consolidated_findings.json"
            fi
            
            echo "    {" >> "$submission_dir/consolidated_findings.json"
            echo "      \"contract\": \"$contract_name\"," >> "$submission_dir/consolidated_findings.json"
            echo "      \"findings\": " >> "$submission_dir/consolidated_findings.json"
            cat "$file" >> "$submission_dir/consolidated_findings.json"
            echo "" >> "$submission_dir/consolidated_findings.json"
            echo "    }" >> "$submission_dir/consolidated_findings.json"
        fi
    done
    
    echo "  ]" >> "$submission_dir/consolidated_findings.json"
    echo "}" >> "$submission_dir/consolidated_findings.json"
    
    # Generate markdown report
    cat > "$submission_dir/submission_report.md" << EOF
# Bug Bounty Submission Report

**Generated:** $(date)
**Total Contracts:** $(echo "$submission_files" | wc -l)

## Summary

This report contains findings from the Advanced Web3 Bug Hunter multi-agent analysis system.

### High-Priority Findings by Contract

EOF
    
    echo "$submission_files" | while read file; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            local contract_name=$(basename "$file" | sed 's/_submission.json\|_all_findings.json//')
            echo "### $contract_name" >> "$submission_dir/submission_report.md"
            echo "" >> "$submission_dir/submission_report.md"
            
            jq -r '.[] | "- **\(.severity | ascii_upcase)**: \(.name) (confidence: \(.confidence))"' "$file" >> "$submission_dir/submission_report.md" 2>/dev/null || echo "- No findings" >> "$submission_dir/submission_report.md"
            echo "" >> "$submission_dir/submission_report.md"
        fi
    done
    
    print_success "Submission reports generated in: $submission_dir/"
    echo "  - consolidated_findings.json (JSON format)"
    echo "  - submission_report.md (Markdown format)"
}

# Main script logic
main() {
    local command="$1"
    
    if [ -z "$command" ]; then
        show_usage
        exit 1
    fi
    
    # Check prerequisites for all commands
    check_prerequisites
    
    case "$command" in
        "triage")
            run_triage "$2"
            ;;
        "deep")
            run_deep_analysis "$2"
            ;;
        "hunt")
            run_hunt "$2"
            ;;
        "analyze")
            run_analyze "$2"
            ;;
        "report")
            run_report "$2"
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
