#!/bin/bash

# Mandalorian Project - Maintenance Script
# This script handles backup, restore, and maintenance operations

set -e  # Exit on any error

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_NAME="$(basename "$0")"
BACKUP_DIR="/var/backups/mandalorian"
LOG_FILE="/var/log/mandalorian/maintenance.log"
CONFIG_DIR="/opt/mandalorian/config"
DATA_DIR="/var/lib/mandalorian"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
BACKUP_RETENTION_DAYS=30
COMPRESSION_LEVEL=6
BACKUP_SCHEDULE="daily"

# Logging functions
log_info() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Initialize maintenance system
init_maintenance() {
    log_info "Initializing maintenance system..."

    # Create necessary directories
    sudo mkdir -p "$BACKUP_DIR"
    sudo mkdir -p /var/log/mandalorian
    sudo mkdir -p "$DATA_DIR"

    # Set permissions
    sudo chown -R $USER:$USER "$BACKUP_DIR" 2>/dev/null || true
    sudo chown -R $USER:$USER /var/log/mandalorian 2>/dev/null || true

    # Initialize log file
    touch "$LOG_FILE"

    log_success "Maintenance system initialized"
}

# Create backup
create_backup() {
    local backup_type="${1:-full}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="mandalorian_${backup_type}_${timestamp}"
    local backup_path="${BACKUP_DIR}/${backup_name}.tar.gz"

    log_info "Creating $backup_type backup: $backup_name"

    # Stop services before backup (optional, uncomment if needed)
    # stop_services

    # Create backup archive
    case "$backup_type" in
        "full")
            # Full system backup
            sudo tar -czf "$backup_path" \
                --exclude="${BACKUP_DIR}" \
                --exclude="/var/log/mandalorian/maintenance.log" \
                /opt/mandalorian \
                /var/lib/mandalorian \
                /var/log/mandalorian \
                /etc/systemd/system/mandalorian-*.service \
                2>/dev/null || true
            ;;
        "config")
            # Configuration only backup
            sudo tar -czf "$backup_path" \
                /opt/mandalorian/config \
                /etc/systemd/system/mandalorian-*.service \
                2>/dev/null || true
            ;;
        "data")
            # Data only backup
            sudo tar -czf "$backup_path" \
                /var/lib/mandalorian \
                /var/log/mandalorian \
                2>/dev/null || true
            ;;
        *)
            log_error "Unknown backup type: $backup_type"
            exit 1
            ;;
    esac

    # Create backup manifest
    local manifest_file="${BACKUP_DIR}/${backup_name}.manifest"
    cat > "$manifest_file" << EOF
BACKUP_MANIFEST
Type: $backup_type
Created: $(date)
Host: $(hostname)
User: $(whoami)
Size: $(du -h "$backup_path" | cut -f1)
Checksum: $(sha256sum "$backup_path" | cut -d' ' -f1)
Contents:
$(tar -tzf "$backup_path" | head -20)
EOF

    # Start services after backup
    # start_services

    # Clean old backups
    cleanup_old_backups

    log_success "Backup created: $backup_path"
    echo "$backup_path"
}

# Restore from backup
restore_backup() {
    local backup_file="$1"

    if [ -z "$backup_file" ]; then
        log_error "Backup file not specified"
        exit 1
    fi

    if [ ! -f "$backup_file" ]; then
        log_error "Backup file does not exist: $backup_file"
        exit 1
    fi

    log_warning "Restoring from backup: $backup_file"
    log_warning "This will overwrite existing files. Continue? (yes/no)"
    read -r response
    if [[ ! "$response" =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Restore cancelled"
        exit 0
    fi

    # Stop services before restore
    stop_services

    # Create pre-restore backup
    local pre_restore_backup=$(create_backup "pre-restore")

    # Extract backup
    log_info "Extracting backup..."
    sudo tar -xzf "$backup_file" -C / || {
        log_error "Failed to extract backup"
        # Restore from pre-restore backup
        log_info "Attempting to restore from pre-restore backup..."
        restore_backup "$pre_restore_backup"
        exit 1
    }

    # Start services after restore
    start_services

    log_success "Restore completed from $backup_file"
}

# List available backups
list_backups() {
    log_info "Available backups:"

    if [ ! -d "$BACKUP_DIR" ]; then
        log_warning "Backup directory does not exist"
        return
    fi

    local count=0
    for backup_file in "${BACKUP_DIR}"/*.tar.gz; do
        if [ -f "$backup_file" ]; then
            local size=$(du -h "$backup_file" | cut -f1)
            local date=$(stat -c %y "$backup_file" 2>/dev/null || stat -f %Sm -t "%Y-%m-%d %H:%M" "$backup_file")
            echo "  $(basename "$backup_file") - ${size} - ${date}"
            ((count++))
        fi
    done

    if [ $count -eq 0 ]; then
        echo "  No backups found"
    else
        echo "  Total: $count backups"
    fi
}

# Clean up old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups (retention: ${BACKUP_RETENTION_DAYS} days)..."

    if [ ! -d "$BACKUP_DIR" ]; then
        return
    fi

    local deleted_count=0
    while IFS= read -r -d '' old_backup; do
        log_info "Removing old backup: $(basename "$old_backup")"
        rm -f "$old_backup"
        ((deleted_count++))
    done < <(find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$BACKUP_RETENTION_DAYS -print0 2>/dev/null)

    if [ $deleted_count -gt 0 ]; then
        log_success "Cleaned up $deleted_count old backups"
    else
        log_info "No old backups to clean up"
    fi
}

# Stop services
stop_services() {
    log_info "Stopping Mandalorian services..."

    if command -v systemctl &> /dev/null; then
        sudo systemctl stop mandalorian-runtime.service 2>/dev/null || true
        sudo systemctl stop mandalorian-boot-rom.service 2>/dev/null || true
    else
        # Fallback: kill processes
        pkill -f "runtime" || true
        pkill -f "boot_rom" || true
        sleep 2
    fi

    log_success "Services stopped"
}

# Start services
start_services() {
    log_info "Starting Mandalorian services..."

    if command -v systemctl &> /dev/null; then
        sudo systemctl start mandalorian-boot-rom.service 2>/dev/null || true
        sudo systemctl start mandalorian-runtime.service 2>/dev/null || true
    fi

    log_success "Services started"
}

# System health check
health_check() {
    log_info "Performing system health check..."

    local issues_found=0

    # Check disk space
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        log_error "Disk usage is critically high: ${disk_usage}%"
        ((issues_found++))
    elif [ "$disk_usage" -gt 80 ]; then
        log_warning "Disk usage is high: ${disk_usage}%"
    fi

    # Check memory
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$mem_usage" -gt 90 ]; then
        log_error "Memory usage is critically high: ${mem_usage}%"
        ((issues_found++))
    elif [ "$mem_usage" -gt 80 ]; then
        log_warning "Memory usage is high: ${mem_usage}%"
    fi

    # Check services
    if command -v systemctl &> /dev/null; then
        if ! systemctl is-active --quiet mandalorian-boot-rom.service 2>/dev/null; then
            log_error "Boot ROM service is not running"
            ((issues_found++))
        fi
        if ! systemctl is-active --quiet mandalorian-runtime.service 2>/dev/null; then
            log_error "Runtime service is not running"
            ((issues_found++))
        fi
    fi

    # Check file permissions
    if [ -d "/opt/mandalorian" ]; then
        local bad_perms=$(find /opt/mandalorian -type f ! -perm 644 2>/dev/null | wc -l)
        if [ "$bad_perms" -gt 0 ]; then
            log_warning "Found $bad_perms files with incorrect permissions in /opt/mandalorian"
        fi
    fi

    # Check log file sizes
    local log_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$log_size" -gt 104857600 ]; then  # 100MB
        log_warning "Maintenance log file is very large: $(($log_size / 1048576))MB"
    fi

    if [ $issues_found -eq 0 ]; then
        log_success "System health check passed"
    else
        log_error "Found $issues_found health issues"
    fi

    return $issues_found
}

# Update system
update_system() {
    log_info "Updating Mandalorian system..."

    # Create backup before update
    local pre_update_backup=$(create_backup "pre-update")

    # Update from repository
    if [ -d "$PROJECT_ROOT/.git" ]; then
        log_info "Pulling latest changes from repository..."
        cd "$PROJECT_ROOT"
        git pull origin main || {
            log_warning "Failed to pull from repository, continuing with local files"
        }
    fi

    # Rebuild system
    log_info "Rebuilding system..."
    cd "$PROJECT_ROOT"
    make clean
    make all

    # Deploy updated binaries
    if [ -f "build/beskarcore/boot_rom" ] && [ -f "build/veridianos/runtime" ]; then
        sudo cp build/beskarcore/boot_rom /opt/mandalorian/bin/
        sudo cp build/veridianos/runtime /opt/mandalorian/bin/
        sudo systemctl restart mandalorian-boot-rom.service 2>/dev/null || true
        sudo systemctl restart mandalorian-runtime.service 2>/dev/null || true
        log_success "System updated successfully"
    else
        log_error "Build failed, update aborted"
        # Restore from backup
        restore_backup "$pre_update_backup"
        exit 1
    fi
}

# Generate maintenance report
generate_report() {
    log_info "Generating maintenance report..."

    local report_file="/var/log/mandalorian/maintenance_report_$(date +%Y%m%d_%H%M%S).txt"

    cat > "$report_file" << EOF
Mandalorian Maintenance Report
Generated: $(date)
Host: $(hostname)

=== System Information ===
$(uname -a)
$(lsb_release -d 2>/dev/null || echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')")

=== Service Status ===
EOF

    if command -v systemctl &> /dev/null; then
        echo "Boot ROM: $(systemctl is-active mandalorian-boot-rom.service 2>/dev/null || echo 'unknown')" >> "$report_file"
        echo "Runtime: $(systemctl is-active mandalorian-runtime.service 2>/dev/null || echo 'unknown')" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

=== Resource Usage ===
$(df -h /)
$(free -h)

=== Backup Status ===
Backup Directory: $BACKUP_DIR
Backups Available: $(find "$BACKUP_DIR" -name "*.tar.gz" 2>/dev/null | wc -l)
Total Backup Size: $(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1 || echo "0")

Recent Backups:
$(find "$BACKUP_DIR" -name "*.tar.gz" -printf "%P %s bytes %TY-%Tm-%Td %TH:%TM\n" 2>/dev/null | sort -k3,4 | tail -5 || echo "None")

=== Log File Status ===
Maintenance Log: $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) bytes
$(find /var/log/mandalorian -name "*.log" -exec ls -lh {} \; 2>/dev/null || echo "No log files found")

=== Configuration ===
Config Directory: $CONFIG_DIR
$(find "$CONFIG_DIR" -type f -exec ls -lh {} \; 2>/dev/null || echo "No config files found")
EOF

    log_success "Maintenance report generated: $report_file"
    echo "$report_file"
}

# Setup automated maintenance
setup_automation() {
    log_info "Setting up automated maintenance..."

    # Create cron jobs for automated backups
    local cron_file="/etc/cron.d/mandalorian-maintenance"

    sudo tee "$cron_file" > /dev/null << EOF
# Mandalorian automated maintenance
# Daily backup at 2 AM
0 2 * * * root $PROJECT_ROOT/scripts/maintain.sh backup full

# Weekly cleanup on Sundays at 3 AM
0 3 * * 0 root $PROJECT_ROOT/scripts/maintain.sh cleanup

# Monthly health check on 1st at 4 AM
0 4 1 * * root $PROJECT_ROOT/scripts/maintain.sh health
EOF

    sudo chmod 644 "$cron_file"

    log_success "Automated maintenance configured"
}

# Main function
main() {
    # Parse command line arguments
    case "${1:-help}" in
        "backup")
            shift
            init_maintenance
            create_backup "$@"
            ;;
        "restore")
            shift
            init_maintenance
            restore_backup "$@"
            ;;
        "list")
            init_maintenance
            list_backups
            ;;
        "cleanup")
            init_maintenance
            cleanup_old_backups
            ;;
        "health")
            init_maintenance
            health_check
            ;;
        "update")
            init_maintenance
            update_system
            ;;
        "report")
            init_maintenance
            generate_report
            ;;
        "setup")
            init_maintenance
            setup_automation
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Show help
show_help() {
    cat << EOF
Mandalorian Maintenance Script

Usage: $SCRIPT_NAME COMMAND [OPTIONS]

Commands:
    backup [TYPE]       Create a backup (types: full, config, data)
    restore FILE        Restore from backup file
    list                List available backups
    cleanup             Clean up old backups
    health              Run system health check
    update              Update system from repository
    report              Generate maintenance report
    setup               Setup automated maintenance
    help                Show this help message

Examples:
    $SCRIPT_NAME backup full          # Create full system backup
    $SCRIPT_NAME backup config        # Backup only configuration
    $SCRIPT_NAME restore /path/to/backup.tar.gz  # Restore from backup
    $SCRIPT_NAME list                 # Show available backups
    $SCRIPT_NAME health               # Run health check
    $SCRIPT_NAME update               # Update system
    $SCRIPT_NAME report               # Generate report
    $SCRIPT_NAME setup                # Setup automation

Backup Types:
    full    - Complete system backup (default)
    config  - Configuration files only
    data    - Data and logs only

EOF
}

# Run main function with all arguments
main "$@"
