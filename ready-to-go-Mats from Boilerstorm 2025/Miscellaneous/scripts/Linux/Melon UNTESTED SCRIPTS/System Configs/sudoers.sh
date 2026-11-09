#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Backup the original sudoers file
sudoers_file="/etc/sudoers"
backup_file="${sudoers_file}.bak"
cp "$sudoers_file" "$backup_file"

echo "Backup of the original sudoers file created at ${backup_file}"

# Create a temporary file to store sudoers changes
temp_sudoers=$(mktemp)
cat "$sudoers_file" > "$temp_sudoers"

# Add security configurations to sudoers
echo "# Sudoers security configurations" >> "$temp_sudoers"
echo "Defaults logfile=\"/var/log/sudo.log\"" >> "$temp_sudoers"      # Log sudo commands
echo "Defaults passwd_timeout=1" >> "$temp_sudoers"                   # Require password after 1 minute of inactivity
echo "Defaults timestamp_timeout=0" >> "$temp_sudoers"                # Always prompt for password
echo "Defaults requiretty" >> "$temp_sudoers"                         # Prevents sudo execution without a terminal
echo "Defaults env_reset" >> "$temp_sudoers"                          # Clears environment variables for security
echo "Defaults insults" >> "$temp_sudoers"                            # Fun feature to return humorous responses to wrong passwords
echo "Defaults pwfeedback" >> "$temp_sudoers"                         # Shows password feedback when entering
echo "Defaults rootpw" >> "$temp_sudoers"                             # Require password for root when using sudo

# Secure sudo access for specific groups and users
echo "# Restrict root and admin privileges" >> "$temp_sudoers"
echo "root    ALL=(ALL:ALL) ALL" >> "$temp_sudoers"                   # Root must use sudo and provide password
echo "%admin  ALL=(ALL:ALL) ALL" >> "$temp_sudoers"
echo "%sudo   ALL=(ALL:ALL) ALL" >> "$temp_sudoers"

# Prevent direct root login over SSH (additionally in sshd_config later)
echo "# Disabling direct root login and requiring sudo usage" >> "$temp_sudoers"
echo "root    ALL=(ALL) ALL  NOPASSWD: /bin/su -" >> "$temp_sudoers"   # Limit su command access

# Apply the changes using visudo to check for syntax correctness
visudo -cf "$temp_sudoers"
if [[ $? -eq 0 ]]; then
    cp "$temp_sudoers" "$sudoers_file"
    echo "Sudoers configuration updated successfully."
else
    echo "Error: sudoers configuration contains syntax errors."
    echo "Reverting to the original sudoers file."
    cp "$backup_file" "$sudoers_file"
fi

# Clean up
rm "$temp_sudoers"
