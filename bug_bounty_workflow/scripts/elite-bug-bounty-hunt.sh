#!/bin/bash

# Elite Web3 Bug Bounty Hunting Script
# Based on the elite audit flow with specialized agents

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$WORKFLOW_DIR")"

# Ensure virtual environment is activated
if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    echo "❌ Virtual environment not found. Please run './setup.sh' first."
    exit 1
fi

# Activate virtual environment
source "$PROJECT_ROOT/.venv/bin/activate"

# Check for API key
if [ -z "$XAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo "⚠️  No AI API key found. AI analysis will be limited."
    echo "   Set XAI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY for full analysis."
fi

# --- Helper Functions ---
log_info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

log_success() {
    echo -e "\033[0;32m[SUCCESS]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

log_warning() {
    echo -e "\033[0;33m[WARNING]\033[0m $1"
}

# --- Commands ---

# Command: elite-audit <target_path> [output_dir]
# Performs a complete elite audit using the orchestrator
cmd_elite_audit() {
    local target_path="$1"
    local output_dir="$2"
    
    if [ -z "$target_path" ]; then
        log_error "Usage: $0 elite-audit <target_path> [output_dir]"
        return 1
    fi
    
    if [ ! -d "$target_path" ] && [ ! -f "$target_path" ]; then
        log_error "Target path does not exist: $target_path"
        return 1
    fi
    
    log_info "🚀 Starting Elite Web3 Bug Bounty Audit"
    log_info "📁 Target: $target_path"
    
    # Check for scope.txt file
    if [ -f "$target_path/scope.txt" ]; then
        log_info "📋 Found scope.txt - will analyze and follow scope"
    elif [ -f "$target_path/SCOPE.txt" ]; then
        log_info "📋 Found SCOPE.txt - will analyze and follow scope"
    elif [ -f "$target_path/scope.md" ]; then
        log_info "📋 Found scope.md - will analyze and follow scope"
    else
        log_warning "No scope.txt file found - proceeding with comprehensive analysis"
        log_info "💡 Tip: Create a scope.txt file to focus the hunt on specific contracts/functions"
    fi
    
    if [ -n "$output_dir" ]; then
        log_info "📁 Output: $output_dir"
    fi
    
    # Run the elite orchestrator
    python3 "$SCRIPT_DIR/elite-web3-orchestrator.py" "$target_path" "$output_dir"
    
    if [ $? -eq 0 ]; then
        log_success "Elite audit completed successfully!"
    else
        log_error "Elite audit failed!"
        return 1
    fi
}

# Command: quick-hunt <target_path>
# Performs a quick triage hunt for rapid assessment
cmd_quick_hunt() {
    local target_path="$1"
    
    if [ -z "$target_path" ]; then
        log_error "Usage: $0 quick-hunt <target_path>"
        return 1
    fi
    
    log_info "⚡ Starting Quick Hunt (Triage Mode)"
    log_info "📁 Target: $target_path"
    
    # Run quick triage with limited agents
    python3 "$SCRIPT_DIR/elite-web3-orchestrator.py" "$target_path" --quick
    
    if [ $? -eq 0 ]; then
        log_success "Quick hunt completed!"
    else
        log_error "Quick hunt failed!"
        return 1
    fi
}

# Command: deep-hunt <target_path>
# Performs a deep analysis with full agent coordination
cmd_deep_hunt() {
    local target_path="$1"
    
    if [ -z "$target_path" ]; then
        log_error "Usage: $0 deep-hunt <target_path>"
        return 1
    fi
    
    log_info "🔍 Starting Deep Hunt (Full Analysis)"
    log_info "📁 Target: $target_path"
    
    # Run deep analysis with all agents
    python3 "$SCRIPT_DIR/elite-web3-orchestrator.py" "$target_path" --deep
    
    if [ $? -eq 0 ]; then
        log_success "Deep hunt completed!"
    else
        log_error "Deep hunt failed!"
        return 1
    fi
}

# Command: agent-status
# Shows the status of all available agents
cmd_agent_status() {
    log_info "🤖 Elite Web3 Bug Bounty Agents"
    echo ""
    
    echo "📊 Reconnaissance Agents:"
    echo "  • recon-alpha: Architecture Intelligence Lead"
    echo "  • recon-beta: Static Analysis Lead"
    echo "  • recon-gamma: Access Control Intelligence Lead"
    echo "  • recon-delta: Integration Intelligence Lead"
    echo "  • recon-epsilon: Protocol Classification Lead"
    echo ""
    
    echo "🔨 Build Agents:"
    echo "  • build-alpha: Project Detection & Setup"
    echo "  • build-beta: Dependency Installation"
    echo "  • build-gamma: Test Execution & Validation"
    echo ""
    
    echo "🎯 Hunter Agents:"
    echo "  • hunter-alpha: Reentrancy Grandmaster"
    echo "  • hunter-beta: Access Control Grandmaster"
    echo "  • hunter-gamma: Mathematical Grandmaster"
    echo "  • hunter-delta: Oracle Grandmaster"
    echo "  • hunter-epsilon: Flash Loan & MEV Grandmaster"
    echo "  • hunter-zeta: Bridge & Cross-Chain Grandmaster"
    echo "  • hunter-eta: Governance Grandmaster"
    echo "  • hunter-theta: Signature Grandmaster"
    echo "  • hunter-iota: Edge Case Grandmaster"
    echo "  • hunter-kappa: Novel Attack Grandmaster"
    echo ""
    
    echo "✅ Validator Agents:"
    echo "  • validator-alpha: Vulnerability Validator"
    echo "  • validator-beta: Economic Validator"
    echo ""
    
    echo "🛡️ Skeptic Agents:"
    echo "  • skeptic-alpha: Logical Denier"
    echo "  • skeptic-beta: Economic Reality Check"
    echo "  • skeptic-gamma: Defense Analyst"
    echo ""
    
    echo "🧠 Mastermind:"
    echo "  • the-mastermind: Final Logic Synthesis & Arbiter"
    echo ""
    
    echo "💰 Financial Analysis:"
    echo "  • financial-flow-analyzer: Economic Flow Analysis"
    echo ""
}

# Command: analyze-scope <target_path>
# Analyzes scope.txt file and provides guidance
cmd_analyze_scope() {
    local target_path="$1"
    
    if [ -z "$target_path" ]; then
        log_error "Usage: $0 analyze-scope <target_path>"
        return 1
    fi
    
    if [ ! -d "$target_path" ] && [ ! -f "$target_path" ]; then
        log_error "Target path does not exist: $target_path"
        return 1
    fi
    
    log_info "📋 Analyzing scope for: $target_path"
    
    # Run scope analyzer
    python3 "$SCRIPT_DIR/scope_analyzer.py" "$target_path"
    
    if [ $? -eq 0 ]; then
        log_success "Scope analysis completed!"
    else
        log_error "Scope analysis failed!"
        return 1
    fi
}

# Command: help
# Shows help information
cmd_help() {
    echo "Elite Web3 Bug Bounty Hunting System"
    echo "====================================="
    echo ""
    echo "Commands:"
    echo "  elite-audit <target_path> [output_dir]  - Complete elite audit"
    echo "  quick-hunt <target_path>                - Quick triage hunt"
    echo "  deep-hunt <target_path>                  - Deep analysis hunt"
    echo "  analyze-scope <target_path>              - Analyze scope.txt file"
    echo "  agent-status                            - Show agent status"
    echo "  help                                    - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 elite-audit ~/bounties/protocol/"
    echo "  $0 quick-hunt ~/bounties/protocol/Vault.sol"
    echo "  $0 deep-hunt ~/bounties/protocol/"
    echo "  $0 analyze-scope ~/bounties/protocol/"
    echo "  $0 agent-status"
    echo ""
    echo "Scope File:"
    echo "  Create a scope.txt file in your target directory to focus the hunt"
    echo "  The tool will automatically detect and follow scope constraints"
    echo ""
    echo "Environment Setup:"
    echo "  source ../.venv/bin/activate"
    echo "  export XAI_API_KEY=\"your-grok-key\""
    echo ""
}

# --- Main Script Logic ---
COMMAND="$1"
shift # Remove the command from the arguments

case "$COMMAND" in
    elite-audit)
        cmd_elite_audit "$@"
        ;;
    quick-hunt)
        cmd_quick_hunt "$@"
        ;;
    deep-hunt)
        cmd_deep_hunt "$@"
        ;;
    analyze-scope)
        cmd_analyze_scope "$@"
        ;;
    agent-status)
        cmd_agent_status
        ;;
    help|--help|-h)
        cmd_help
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        echo ""
        cmd_help
        exit 1
        ;;
esac
