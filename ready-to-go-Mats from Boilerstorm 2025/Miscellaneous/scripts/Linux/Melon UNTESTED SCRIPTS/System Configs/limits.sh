#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the limits configuration file paths
limits_file="/etc/security/limits.conf"

# Backup the original limits.conf file
cp "$limits_file" "${limits_file}.bak"

# Define configurations to modify
limits_configurations=(
    '*               soft    core            0'
    '*               hard    core            0'
    '*               hard    nproc           10000'
    '*               soft    nproc           8192'
    '*               hard    nofile          65536'
    '*               soft    nofile          65536'
    '*               soft    memlock         64'
    '*               hard    memlock         64'
)

# Clear the current limits.conf file
echo "# System limits configuration - Generated on $(date)" > "$limits_file"

# Write all configurations to limits.conf
for config in "${limits_configurations[@]}"; do
    echo "$config" >> "$limits_file"
done

echo "limits.conf configuration updated successfully."
