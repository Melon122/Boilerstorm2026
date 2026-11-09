#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the faillock configuration file path
faillock_config_file="/etc/security/faillock.conf"

# Backup the original faillock config file
cp "$faillock_config_file" "${faillock_config_file}.bak"

# Define the faillock configuration settings
faillock_settings=(
    'deny = 5'            # Lockout after 5 failed attempts
    'unlock_time = 900'    # Lockout duration in seconds (15 minutes)
    'fail_interval = 300'  # Reset fail counter after 300 seconds (5 minutes)
    'root_unlock_time = 900'  # Lockout root user for 15 minutes after failures
    'audit'                # Enable auditing of login failures
)

# Clear the current faillock file and apply the new settings
echo "# faillock configuration - Generated on $(date)" > "$faillock_config_file"

for setting in "${faillock_settings[@]}"; do
    echo "$setting" >> "$faillock_config_file"
done

# Apply changes
echo "faillock configuration updated successfully."
