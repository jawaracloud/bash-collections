#!/bin/bash

# Don't exit on error for repository checks
set -o pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_input() {
    echo -e "${BLUE}[INPUT]${NC} $1"
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Sync ECR repositories between AWS accounts using skopeo.

OPTIONS:
    -sp, --src-profile PROFILE       Source AWS profile (optional, uses default if not specified)
    -dp, --dest-profile PROFILE      Destination AWS profile (required)
    -sr, --src-region REGION         Source AWS region (optional, default: ap-southeast-3)
    -dr, --dest-region REGION        Destination AWS region (optional, default: ap-southeast-3)
    -r, --repos "REPO1 REPO2 ..."    Space-separated list of repositories (optional, auto-detects if not provided)
    -a, --auto-detect                Automatically detect all repositories from source (default behavior)
    -h, --help                       Display this help message

EXAMPLES:
    # Auto-detect all repositories (recommended)
    $0 --dest-profile dxp-tma-prod

    # Auto-detect with different regions
    $0 --dest-profile prod --src-region us-east-1 --dest-region ap-southeast-1

    # With specific repositories only
    $0 --dest-profile prod --repos "tma/tma-ai tma/tma-api tma/tma-web"

    # Source has profile too
    $0 --src-profile dev --dest-profile prod

    # Interactive mode (will prompt for inputs)
    $0

EOF
    exit 1
}

# Function to get AWS account ID
get_account_id() {
    local profile=$1
    local account_id
    
    if [ -z "$profile" ]; then
        account_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
    else
        account_id=$(aws sts get-caller-identity --profile "$profile" --query Account --output text 2>/dev/null)
    fi
    
    if [ -z "$account_id" ]; then
        log_error "Failed to get account ID for profile: ${profile:-default}"
        return 1
    fi
    
    echo "$account_id"
}

# Function to check if repository exists in destination
check_repo_exists() {
    local repo_name=$1
    local region=$2
    local profile=$3
    
    if aws ecr describe-repositories \
        --repository-names "$repo_name" \
        --region "$region" \
        --profile "$profile" \
        &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to create repository in destination
create_repo() {
    local repo_name=$1
    local region=$2
    local profile=$3
    
    log_info "Creating repository: $repo_name in destination account"
    
    if aws ecr create-repository \
        --repository-name "$repo_name" \
        --region "$region" \
        --profile "$profile" \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256 &>/dev/null; then
        log_info "Successfully created repository: $repo_name"
        return 0
    else
        log_error "Failed to create repository: $repo_name"
        return 1
    fi
}

# Function to list all repositories in source account
list_source_repos() {
    local region=$1
    local profile=$2
    
    log_info "Discovering repositories in source account..."
    
    local repos
    if [ -z "$profile" ]; then
        repos=$(aws ecr describe-repositories \
            --region "$region" \
            --query 'repositories[].repositoryName' \
            --output text 2>/dev/null)
    else
        repos=$(aws ecr describe-repositories \
            --profile "$profile" \
            --region "$region" \
            --query 'repositories[].repositoryName' \
            --output text 2>/dev/null)
    fi
    
    if [ -z "$repos" ]; then
        log_error "Failed to list repositories or no repositories found in source account"
        return 1
    fi
    
    # Convert tab-separated output to array
    mapfile -t REPOS <<< "$(echo "$repos" | tr '\t' '\n')"
    
    log_info "Found ${#REPOS[@]} repositories in source account"
    return 0
}

# Function to get ECR login token
get_ecr_token() {
    local region=$1
    local profile=$2
    
    if [ -z "$profile" ]; then
        aws ecr get-login-password --region "$region" 2>/dev/null
    else
        aws ecr get-login-password --region "$region" --profile "$profile" 2>/dev/null
    fi
}

# Function to create all missing repositories
create_missing_repos() {
    log_info "=========================================="
    log_info "Checking and creating missing repositories in destination..."
    log_info "=========================================="
    
    local created_count=0
    local existing_count=0
    local failed_count=0
    
    for repo in "${REPOS[@]}"; do
        if check_repo_exists "$repo" "$DEST_REGION" "$DEST_PROFILE"; then
            log_info "Repository already exists: $repo"
            ((existing_count++))
        else
            log_warn "Repository missing: $repo"
            if create_repo "$repo" "$DEST_REGION" "$DEST_PROFILE"; then
                ((created_count++))
            else
                ((failed_count++))
            fi
        fi
    done
    
    echo ""
    log_info "Repository Creation Summary:"
    log_info "  Already existing: $existing_count"
    log_info "  Newly created: $created_count"
    log_info "  Failed to create: $failed_count"
    log_info "=========================================="
    echo ""
    
    if [ $failed_count -gt 0 ]; then
        log_error "Some repositories failed to create. Continuing with sync..."
    fi
}

# Function to sync repository
sync_repository() {
    local repo=$1
    local src_url="${SRC_ACCOUNT}.dkr.ecr.${SRC_REGION}.amazonaws.com/${repo}"
    local dest_url="${DEST_ACCOUNT}.dkr.ecr.${DEST_REGION}.amazonaws.com/${repo}"
    
    log_info "=========================================="
    log_info "Syncing repository: $repo"
    log_info "Source: $src_url"
    log_info "Destination: $dest_url"
    
    # Check if destination repository exists
    if ! check_repo_exists "$repo" "$DEST_REGION" "$DEST_PROFILE"; then
        log_warn "Repository does not exist in destination account"
        if create_repo "$repo" "$DEST_REGION" "$DEST_PROFILE"; then
            log_info "Repository created successfully, proceeding with sync"
        else
            log_error "Skipping sync for $repo due to repository creation failure"
            return 1
        fi
    else
        log_info "Repository exists in destination account"
    fi
    
    # Get login tokens
    log_info "Getting ECR login tokens..."
    SRC_TOKEN=$(get_ecr_token "$SRC_REGION" "$SRC_PROFILE")
    DEST_TOKEN=$(get_ecr_token "$DEST_REGION" "$DEST_PROFILE")
    
    if [ -z "$SRC_TOKEN" ] || [ -z "$DEST_TOKEN" ]; then
        log_error "Failed to get ECR login tokens"
        return 1
    fi
    
    # Sync all tags using skopeo
    log_info "Syncing all tags from source to destination..."
    skopeo sync \
        --src docker \
        --dest docker \
        --src-creds "AWS:${SRC_TOKEN}" \
        --dest-creds "AWS:${DEST_TOKEN}" \
        --all \
        "$src_url" \
        "${DEST_ACCOUNT}.dkr.ecr.${DEST_REGION}.amazonaws.com/${repo%/*}"
    
    if [ $? -eq 0 ]; then
        log_info "Successfully synced repository: $repo"
        return 0
    else
        log_error "Failed to sync repository: $repo"
        return 1
    fi
}

# Function to prompt for input
prompt_input() {
    local prompt_text=$1
    local default_value=$2
    local input_value
    
    if [ -n "$default_value" ]; then
        log_input "$prompt_text [default: $default_value]: "
    else
        log_input "$prompt_text: "
    fi
    
    read -r input_value
    
    if [ -z "$input_value" ] && [ -n "$default_value" ]; then
        echo "$default_value"
    else
        echo "$input_value"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -sp|--src-profile)
                SRC_PROFILE="$2"
                shift 2
                ;;
            -dp|--dest-profile)
                DEST_PROFILE="$2"
                shift 2
                ;;
            -sr|--src-region)
                SRC_REGION="$2"
                shift 2
                ;;
            -dr|--dest-region)
                DEST_REGION="$2"
                shift 2
                ;;
            -r|--repos)
                IFS=' ' read -ra REPOS <<< "$2"
                shift 2
                ;;
            -a|--auto-detect)
                AUTO_DETECT=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Interactive input collection
collect_inputs() {
    echo ""
    log_info "=========================================="
    log_info "ECR Cross-Account Sync Configuration"
    log_info "=========================================="
    echo ""
    
    # Source profile (optional)
    if [ -z "$SRC_PROFILE" ]; then
        SRC_PROFILE=$(prompt_input "Enter source AWS profile (press Enter for default profile)" "")
    fi
    
    # Destination profile (required)
    if [ -z "$DEST_PROFILE" ]; then
        DEST_PROFILE=$(prompt_input "Enter destination AWS profile (required)" "")
        if [ -z "$DEST_PROFILE" ]; then
            log_error "Destination profile is required!"
            exit 1
        fi
    fi
    
    # Source region
    if [ -z "$SRC_REGION" ]; then
        SRC_REGION=$(prompt_input "Enter source AWS region" "ap-southeast-3")
    fi
    
    # Destination region
    if [ -z "$DEST_REGION" ]; then
        DEST_REGION=$(prompt_input "Enter destination AWS region" "ap-southeast-3")
    fi
    
    # Repositories - auto-detect or manual input
    if [ ${#REPOS[@]} -eq 0 ]; then
        echo ""
        log_input "Do you want to auto-detect repositories from source? (Y/n): "
        read -r auto_detect
        
        if [[ -z "$auto_detect" || "$auto_detect" =~ ^[Yy]$ ]]; then
            AUTO_DETECT=true
        else
            log_info "Enter repository names (one per line, press Ctrl+D when done):"
            log_info "Example: tma/tma-ai"
            echo ""
            
            mapfile -t REPOS
            
            if [ ${#REPOS[@]} -eq 0 ]; then
                log_error "No repositories specified!"
                exit 1
            fi
        fi
    fi
}

# Main execution
main() {
    # Parse command line arguments
    parse_args "$@"
    
    # Collect any missing inputs interactively
    collect_inputs
    
    log_info "=========================================="
    log_info "Starting ECR sync process"
    log_info "=========================================="
    
    # Check if skopeo is installed
    if ! command -v skopeo &> /dev/null; then
        log_error "skopeo is not installed. Please install it first."
        log_info "Installation: sudo yum install -y skopeo (Amazon Linux/RHEL)"
        log_info "              sudo apt-get install -y skopeo (Debian/Ubuntu)"
        exit 1
    fi
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Get account IDs
    log_info "Detecting AWS account IDs..."
    SRC_ACCOUNT=$(get_account_id "$SRC_PROFILE")
    if [ -z "$SRC_ACCOUNT" ]; then
        log_error "Failed to detect source account ID"
        exit 1
    fi
    
    DEST_ACCOUNT=$(get_account_id "$DEST_PROFILE")
    if [ -z "$DEST_ACCOUNT" ]; then
        log_error "Failed to detect destination account ID"
        exit 1
    fi
    
    # Auto-detect repositories if needed
    if [ ${#REPOS[@]} -eq 0 ] || [ "$AUTO_DETECT" = true ]; then
        if ! list_source_repos "$SRC_REGION" "$SRC_PROFILE"; then
            log_error "Failed to auto-detect repositories"
            exit 1
        fi
        
        echo ""
        log_info "Detected repositories:"
        for repo in "${REPOS[@]}"; do
            echo "  - $repo"
        done
    fi
    
    echo ""
    log_info "Configuration Summary:"
    log_info "  Source Profile: ${SRC_PROFILE:-default}"
    log_info "  Source Account: $SRC_ACCOUNT"
    log_info "  Source Region: $SRC_REGION"
    log_info "  Destination Profile: $DEST_PROFILE"
    log_info "  Destination Account: $DEST_ACCOUNT"
    log_info "  Destination Region: $DEST_REGION"
    log_info "  Repositories: ${#REPOS[@]}"
    echo ""
    
    # Create all missing repositories first
    create_missing_repos
    
    # Sync each repository
    success_count=0
    fail_count=0
    
    for repo in "${REPOS[@]}"; do
        if sync_repository "$repo"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        echo ""
    done
    
    # Summary
    log_info "=========================================="
    log_info "Sync completed!"
    log_info "Successful: $success_count"
    log_info "Failed: $fail_count"
    log_info "=========================================="
    
    if [ $fail_count -gt 0 ]; then
        exit 1
    fi
}

# Run main function
main "$@"
