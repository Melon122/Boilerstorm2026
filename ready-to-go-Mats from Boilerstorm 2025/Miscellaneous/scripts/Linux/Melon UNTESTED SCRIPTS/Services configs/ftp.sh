#!/bin/bash

# FTP Configuration Script
# Ensure this script is run as root or with sudo privileges

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install vsftpd if not already installed
if ! command -v vsftpd &> /dev/null; then
    echo "Installing vsftpd..."
    apt update && apt install -y vsftpd
fi

# Backup the original vsftpd configuration
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Configure vsftpd for enhanced security
echo "Configuring vsftpd security settings..."

# Basic security configurations
cat <<EOF > /etc/vsftpd.conf
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=NO
chroot_local_user=YES
user_sub_token=\$USER
local_root=/home/\$USER/ftp
pasv_enable=YES
pasv_min_port=10000
pasv_max_port=10100
secure_chroot_dir=/var/run/vsftpd/empty
EOF

# Create necessary directories for FTP
mkdir -p /home/$USER/ftp
chown nobody:nogroup /home/$USER/ftp
chmod 755 /home/$USER/ftp

# Restart vsftpd service to apply changes
echo "Restarting vsftpd service..."
systemctl restart vsftpd || { echo "Failed to restart vsftpd service"; exit 1; }

# Enable vsftpd to start on boot
systemctl enable vsftpd

echo "FTP configuration completed successfully."
