#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the GRUB configuration file path
grub_config_file="/etc/default/grub"

# Backup the original GRUB config file
cp "$grub_config_file" "${grub_config_file}.bak"

# Define the GRUB configuration settings
grub_settings=(
    'GRUB_TIMEOUT=5'                      # Boot menu timeout (in seconds)
    'GRUB_DEFAULT=0'                       # Default boot entry
    'GRUB_DISABLE_RECOVERY=true'           # Disable recovery mode
    'GRUB_CMDLINE_LINUX="ipv6.disable=1"'  # Disable IPv6 for security
    'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash audit=1"'  # Enable auditing, quiet boot
    'GRUB_DISABLE_SUBMENU=y'               # Disable submenu in GRUB
)

# Clear the current grub file and apply the new settings
echo "# GRUB configuration - Generated on $(date)" > "$grub_config_file"

for setting in "${grub_settings[@]}"; do
    echo "$setting" >> "$grub_config_file"
done

# Update GRUB to apply the changes
update-grub

echo "GRUB configuration updated successfully."
