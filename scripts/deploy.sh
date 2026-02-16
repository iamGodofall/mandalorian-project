#!/bin/bash

# Mandalorian Project - Deployment Script
# This script handles the deployment of the Mandalorian secure boot system

set -e  # Exit on any error

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="${PROJECT_ROOT}/deploy"
BUILD_DIR="${PROJECT_ROOT}/build"
TARGET_PLATFORM="${TARGET_PLATFORM:-x86_64}"
DEPLOY_ENV="${DEPLOY_ENV:-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-deployment checks
pre_deployment_checks() {
    log_info "Running pre-deployment checks..."

    # Check if required tools are installed
    local required_tools=("cmake" "make" "gcc" "git")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool '$tool' is not installed"
            exit 1
        fi
    done

    # Check if build directory exists and is clean
    if [ ! -d "$BUILD_DIR" ]; then
        log_error "Build directory does not exist. Run build first."
        exit 1
    fi

    # Check for required build artifacts
    local required_files=(
        "${BUILD_DIR}/beskarcore/boot_rom"
        "${BUILD_DIR}/beskarcore/verified_boot"
        "${BUILD_DIR}/veridianos/runtime"
    )

    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "Required build artifact missing: $file"
            exit 1
        fi
    done

    log_success "Pre-deployment checks passed"
}

# Create deployment package
create_deployment_package() {
    log_info "Creating deployment package..."

    # Clean previous deployment
    rm -rf "$DEPLOY_DIR"
    mkdir -p "$DEPLOY_DIR"

    # Copy binaries
    mkdir -p "${DEPLOY_DIR}/bin"
    cp "${BUILD_DIR}/beskarcore/boot_rom" "${DEPLOY_DIR}/bin/"
    cp "${BUILD_DIR}/beskarcore/verified_boot" "${DEPLOY_DIR}/bin/"
    cp "${BUILD_DIR}/veridianos/runtime" "${DEPLOY_DIR}/bin/"

    # Copy configuration files
    mkdir -p "${DEPLOY_DIR}/config"
    cp "${PROJECT_ROOT}/toolchains/${TARGET_PLATFORM}.cmake" "${DEPLOY_DIR}/config/"
    cp "${PROJECT_ROOT}/requirements.txt" "${DEPLOY_DIR}/config/"

    # Copy documentation
    mkdir -p "${DEPLOY_DIR}/docs"
    cp "${PROJECT_ROOT}/README.md" "${DEPLOY_DIR}/docs/"
    cp "${PROJECT_ROOT}/docs/security/README.md" "${DEPLOY_DIR}/docs/"
    cp "${PROJECT_ROOT}/docs/troubleshooting/README.md" "${DEPLOY_DIR}/docs/"

    # Create deployment manifest
    cat > "${DEPLOY_DIR}/manifest.json" << EOF
{
    "project": "Mandalorian",
    "version": "$(git describe --tags --always 2>/dev/null || echo "dev")",
    "platform": "${TARGET_PLATFORM}",
    "environment": "${DEPLOY_ENV}",
    "build_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "commit": "$(git rev-parse HEAD 2>/dev/null || echo "unknown")",
    "components": {
        "beskarcore": {
            "boot_rom": "bin/boot_rom",
            "verified_boot": "bin/verified_boot"
        },
        "veridianos": {
            "runtime": "bin/runtime"
        }
    }
}
EOF

    log_success "Deployment package created at ${DEPLOY_DIR}"
}

# Validate deployment package
validate_deployment() {
    log_info "Validating deployment package..."

    # Check file integrity
    local files_to_check=(
        "${DEPLOY_DIR}/bin/boot_rom"
        "${DEPLOY_DIR}/bin/verified_boot"
        "${DEPLOY_DIR}/bin/runtime"
        "${DEPLOY_DIR}/manifest.json"
    )

    for file in "${files_to_check[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "Deployment validation failed: $file missing"
            exit 1
        fi

        # Check if file is executable (for binaries)
        if [[ "$file" == *"/bin/"* ]]; then
            if [ ! -x "$file" ]; then
                log_error "Deployment validation failed: $file is not executable"
                exit 1
            fi
        fi
    done

    # Validate manifest
    if ! python3 -m json.tool "${DEPLOY_DIR}/manifest.json" > /dev/null 2>&1; then
        log_error "Deployment validation failed: Invalid manifest JSON"
        exit 1
    fi

    log_success "Deployment package validation passed"
}

# Deploy to target environment
deploy_to_target() {
    log_info "Deploying to ${DEPLOY_ENV} environment..."

    case "${DEPLOY_ENV}" in
        "development")
            deploy_development
            ;;
        "staging")
            deploy_staging
            ;;
        "production")
            deploy_production
            ;;
        *)
            log_error "Unknown deployment environment: ${DEPLOY_ENV}"
            exit 1
            ;;
    esac
}

# Development deployment
deploy_development() {
    log_info "Performing development deployment..."

    # For development, just copy to a local directory
    local dev_dir="${HOME}/.mandalorian/dev"
    mkdir -p "$dev_dir"

    cp -r "${DEPLOY_DIR}"/* "$dev_dir/"

    log_success "Development deployment completed to ${dev_dir}"
}

# Staging deployment
deploy_staging() {
    log_info "Performing staging deployment..."

    # For staging, simulate deployment to a staging server
    # In a real scenario, this would use tools like Ansible, Puppet, etc.

    # Create staging directory
    local staging_dir="/opt/mandalorian/staging"
    sudo mkdir -p "$staging_dir"

    # Copy deployment package
    sudo cp -r "${DEPLOY_DIR}"/* "$staging_dir/"

    # Set appropriate permissions
    sudo chown -R root:root "$staging_dir"
    sudo chmod -R 755 "$staging_dir/bin"

    log_success "Staging deployment completed to ${staging_dir}"
}

# Production deployment
deploy_production() {
    log_warning "Production deployment requires manual approval"
    log_info "Please review the deployment package and confirm deployment"

    read -p "Do you want to proceed with production deployment? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Production deployment cancelled"
        exit 0
    fi

    log_info "Performing production deployment..."

    # For production, deploy to system directories
    local prod_dir="/opt/mandalorian"
    sudo mkdir -p "$prod_dir"

    # Backup existing installation
    if [ -d "$prod_dir/bin" ]; then
        local backup_dir="${prod_dir}/backup/$(date +%Y%m%d_%H%M%S)"
        sudo mkdir -p "$backup_dir"
        sudo cp -r "$prod_dir"/* "$backup_dir/" 2>/dev/null || true
        log_info "Backup created at ${backup_dir}"
    fi

    # Copy deployment package
    sudo cp -r "${DEPLOY_DIR}"/* "$prod_dir/"

    # Set appropriate permissions
    sudo chown -R root:root "$prod_dir"
    sudo chmod -R 755 "$prod_dir/bin"

    # Create systemd service files if deploying to Linux
    if command -v systemctl &> /dev/null; then
        create_systemd_services
    fi

    log_success "Production deployment completed to ${prod_dir}"
}

# Create systemd service files
create_systemd_services() {
    log_info "Creating systemd service files..."

    # Boot ROM service
    sudo tee /etc/systemd/system/mandalorian-boot-rom.service > /dev/null << EOF
[Unit]
Description=Mandalorian Boot ROM Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/mandalorian/bin/boot_rom
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Runtime service
    sudo tee /etc/systemd/system/mandalorian-runtime.service > /dev/null << EOF
[Unit]
Description=Mandalorian Runtime Service
After=mandalorian-boot-rom.service
Requires=mandalorian-boot-rom.service

[Service]
Type=simple
ExecStart=/opt/mandalorian/bin/runtime
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable services
    sudo systemctl daemon-reload
    sudo systemctl enable mandalorian-boot-rom.service
    sudo systemctl enable mandalorian-runtime.service

    log_success "Systemd services created and enabled"
}

# Post-deployment verification
post_deployment_verification() {
    log_info "Running post-deployment verification..."

    # Test basic functionality
    if [ -x "${DEPLOY_DIR}/bin/boot_rom" ]; then
        log_info "Testing boot ROM..."
        if timeout 10s "${DEPLOY_DIR}/bin/boot_rom" --version > /dev/null 2>&1; then
            log_success "Boot ROM test passed"
        else
            log_warning "Boot ROM test failed - may be expected for boot-time component"
        fi
    fi

    if [ -x "${DEPLOY_DIR}/bin/runtime" ]; then
        log_info "Testing runtime..."
        if timeout 10s "${DEPLOY_DIR}/bin/runtime" --version > /dev/null 2>&1; then
            log_success "Runtime test passed"
        else
            log_warning "Runtime test failed"
        fi
    fi

    log_success "Post-deployment verification completed"
}

# Rollback functionality
rollback_deployment() {
    log_warning "Rolling back deployment..."

    case "${DEPLOY_ENV}" in
        "staging")
            local staging_dir="/opt/mandalorian/staging"
            if [ -d "${staging_dir}/backup" ]; then
                sudo rm -rf "$staging_dir"
                sudo mv "${staging_dir}/backup"/* "$staging_dir/"
                log_success "Staging deployment rolled back"
            else
                log_error "No backup found for rollback"
            fi
            ;;
        "production")
            local prod_dir="/opt/mandalorian"
            local latest_backup=$(find "${prod_dir}/backup" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
            if [ -n "$latest_backup" ]; then
                sudo rm -rf "${prod_dir}/bin" "${prod_dir}/config"
                sudo cp -r "$latest_backup"/* "$prod_dir/"
                log_success "Production deployment rolled back to $latest_backup"
            else
                log_error "No backup found for rollback"
            fi
            ;;
        *)
            log_error "Rollback not supported for environment: ${DEPLOY_ENV}"
            ;;
    esac
}

# Main deployment function
main() {
    log_info "Starting Mandalorian deployment for ${TARGET_PLATFORM} on ${DEPLOY_ENV}"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Usage: $0 [--rollback] [--skip-validation]"
                exit 1
                ;;
        esac
    done

    if [ "$ROLLBACK" = true ]; then
        rollback_deployment
        exit 0
    fi

    pre_deployment_checks

    if [ "$SKIP_VALIDATION" != true ]; then
        create_deployment_package
        validate_deployment
    fi

    deploy_to_target
    post_deployment_verification

    log_success "Mandalorian deployment completed successfully!"
    log_info "Deployment location: $(get_deployment_path)"
}

# Get deployment path based on environment
get_deployment_path() {
    case "${DEPLOY_ENV}" in
        "development")
            echo "${HOME}/.mandalorian/dev"
            ;;
        "staging")
            echo "/opt/mandalorian/staging"
            ;;
        "production")
            echo "/opt/mandalorian"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
