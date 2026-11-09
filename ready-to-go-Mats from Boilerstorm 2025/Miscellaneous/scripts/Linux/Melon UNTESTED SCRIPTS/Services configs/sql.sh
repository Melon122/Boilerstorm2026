#!/bin/bash

# MySQL Secure Installation Script
# Ensure this script is run as root or with sudo privileges

# Check for root permissions
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# MySQL root password
read -sp "Enter MySQL root password: " root_password
echo

# Configure MySQL security settings
echo "Configuring MySQL security settings..."

# Disable remote root login
mysql -u root -p"$root_password" -e "UPDATE mysql.user SET Host='localhost' WHERE User='root';"
mysql -u root -p"$root_password" -e "FLUSH PRIVILEGES;"

# Remove anonymous users
mysql -u root -p"$root_password" -e "DROP USER IF EXISTS ''@'localhost';"
mysql -u root -p"$root_password" -e "DROP USER IF EXISTS ''@'%';"

# Disable the test database
mysql -u root -p"$root_password" -e "DROP DATABASE IF EXISTS test;"
mysql -u root -p"$root_password" -e "FLUSH PRIVILEGES;"

# Set a strong password policy
mysql -u root -p"$root_password" -e "SET GLOBAL validate_password.policy=STRONG;"
mysql -u root -p"$root_password" -e "SET GLOBAL validate_password.length=12;"
mysql -u root -p"$root_password" -e "SET GLOBAL validate_password.mixed_case_count=1;"
mysql -u root -p"$root_password" -e "SET GLOBAL validate_password.number_count=1;"
mysql -u root -p"$root_password" -e "SET GLOBAL validate_password.special_char_count=1;"

# Configure MySQL to listen only on localhost
my_cnf="/etc/mysql/my.cnf"
if grep -q "^bind-address" "$my_cnf"; then
    sed -i "s/^bind-address.*/bind-address = 127.0.0.1/" "$my_cnf"
else
    echo "bind-address = 127.0.0.1" >> "$my_cnf"
fi

# Restart MySQL service to apply changes
echo "Restarting MySQL service..."
systemctl restart mysql || { echo "Failed to restart MySQL service"; exit 1; }

echo "MySQL configuration completed successfully."
