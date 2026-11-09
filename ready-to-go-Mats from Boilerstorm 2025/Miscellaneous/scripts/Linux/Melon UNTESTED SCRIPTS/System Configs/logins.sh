#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the login.defs file path
login_defs_file="/etc/login.defs"

# Backup the original login.defs file
cp "$login_defs_file" "${login_defs_file}.bak"

# Define configurations to modify
login_defs_configurations=(
    'PASS_MAX_DAYS 90'
    'PASS_MIN_DAYS 7'
    'PASS_WARN_AGE 14'
    'LOGIN_RETRIES 3'
    'LOGIN_TIMEOUT 60'
    'UID_MIN 1000'
    'UID_MAX 60000'
    'GID_MIN 1000'
    'GID_MAX 60000'
    'UMASK 027'
    'USERGROUPS_ENAB no'
    'ENCRYPT_METHOD SHA512'
)

# Clear the current login.defs file
echo "# Login definitions configuration - Generated on $(date)" > "$login_defs_file"

# Write all configurations to login.defs
for config in "${login_defs_configurations[@]}"; do
    echo "$config" >> "$login_defs_file"
done

echo "login.defs configuration updated successfully."
