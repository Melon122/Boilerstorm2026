#!/bin/bash

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the PAM configuration file paths
pam_common_auth="/etc/pam.d/common-auth"
pam_common_password="/etc/pam.d/common-password"

# Backup original files
cp "$pam_common_auth" "${pam_common_auth}.bak"
cp "$pam_common_password" "${pam_common_password}.bak"

# Update common-auth file
echo "# PAM common-auth configuration - Generated on $(date)" > "$pam_common_auth"
echo "auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit" >> "$pam_common_auth"
echo "auth required pam_faildelay.so delay=4000000" >> "$pam_common_auth"

# Update common-password file
echo "# PAM common-password configuration - Generated on $(date)" > "$pam_common_password"
echo "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" >> "$pam_common_password"
echo "password required pam_unix.so use_authtok sha512 shadow remember=5" >> "$pam_common_password"

echo "PAM common-auth and common-password configurations updated successfully."
