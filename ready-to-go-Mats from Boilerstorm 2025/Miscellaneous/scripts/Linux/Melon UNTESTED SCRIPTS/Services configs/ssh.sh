#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the SSH configuration file path
ssh_config_file="/etc/ssh/sshd_config"

# Backup the original SSH config file
cp "$ssh_config_file" "${ssh_config_file}.bak"

# Define an array of SSH configurations
ssh_configurations=(
    'PermitRootLogin no'
    'PasswordAuthentication no'
    'PubkeyAuthentication yes'
    'AllowTcpForwarding no'
    'X11Forwarding no'
    'UseDNS no'
    'ClientAliveInterval 300'
    'ClientAliveCountMax 0'
    'MaxAuthTries 3'
    'MaxSessions 2'
    'LogLevel VERBOSE'
    'LoginGraceTime 30s'
    'PermitEmptyPasswords no'
    'Banner /etc/issue.net'
    'AllowUsers admin'
    'Port 22'
)

# Write all configurations to the sshd_config file
echo "# SSH hardening configuration - Generated on $(date)" > "$ssh_config_file"
for config in "${ssh_configurations[@]}"; do
    echo "$config" >> "$ssh_config_file"
done

# Restart the SSH service
systemctl restart sshd || { echo "Failed to restart SSH service"; exit 1; }

echo "SSH hardening completed successfully."
