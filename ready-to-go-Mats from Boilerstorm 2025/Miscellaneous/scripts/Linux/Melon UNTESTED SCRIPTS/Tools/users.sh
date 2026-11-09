#!bin/bash
# Define the filename
file="correctUsers.txt"

# Read file content and replace newlines with spaces
readmeContent=$(cat "$file" | tr '\n' ' ')

# Extract Authorized Administrators
result=$(echo "$readmeContent" | awk -F 'Authorized Administrators:' '{print $2}' | awk -F 'Authorized Users:' '{print $1}' | xargs)
echo "Authorized Administrators: $result"
# Turn to array
read -ra correctAdmins <<< "$result"

# Extract Authorized Users
result=$(echo "$readmeContent" | awk -F 'Authorized Users:' '{print $2}' | xargs) 
echo "Authorized Users: $result"
# Turn to array
read -ra correctUsers <<< "$result"

# Remove whitespace from each element in the correctAdmins array
for i in "${!correctAdmins[@]}"; do
    correctAdmins[i]=$(echo "${correctAdmins[i]}" | tr -d '[:space:]')
done

# Remove whitespace from each element in the correctUsers array
for i in "${!correctUsers[@]}"; do
    correctUsers[i]=$(echo "${correctUsers[i]}" | tr -d '[:space:]')
done

# Print trimmed arrays
echo "Trimmed Authorized Administrators: ${correctAdmins[@]}"
echo "Trimmed Authorized Users: ${correctUsers[@]}"

# Get a list of all local users
currentUsers=($(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd))

# Compare and add new users
for user in "${correctUsers[@]}"; do
    if [[ ! " ${currentUsers[@]} " =~ " $user " ]]; then
        adduser "$user" --disabled-password --gecos ""
        echo "Added user: $user"
    fi
done

# Get a list of all admins
currentAdmins=($(grep '^sudo:.*$' /etc/group | awk -F: '{print $4}' | tr ',' ' '))

# Compare and add new admins or convert existing users to admins
for admin in "${correctAdmins[@]}"; do    
    if [[ ! " ${currentAdmins[@]} " =~ " $admin " ]]; then
        if [[ " ${currentUsers[@]} " =~ " $admin " ]]; then
            usermod -aG sudo "$adminName"
            echo "Converted user to admin: $admin"
        else
            useradd -m -p CyberPatriot101#! "$admin"
            usermod -aG sudo "$admin"
            echo "Added admin: $admin"
        fi
    fi
done

# Compare and remove users
for user in "${currentUsers[@]}"; do
    if [[ ! " ${correctUsers[@]} " =~ " $user " ]] && [[ ! " ${correctAdmins[@]} " =~ " $user " ]]; then
        deluser --remove-home "$user" 2>/dev/null
        echo "Deleted user and their files: $user"
    fi
done

# Compare and remove admins or convert admins to users
for admin in "${currentAdmins[@]}"; do
    if [[ ! " ${correctAdmins[@]} " =~ " $admin " ]]; then
        if [[ " ${correctUsers[@]} " =~ " $admin " ]]; then
            deluser "$admin" sudo
            echo "Converted admin to user: $admin"
        else
            deluser --remove-home "$admin"
            echo "Removed admin: $admin"
        fi
    fi
done

# Change insecure admin passwords
for admin in "${correctAdmins[@]}"; do
    chage -m 15 -M 60 "$admin"    # Set min and max days for password change
    chage -I 5 "$admin"           # Set the account inactivity period
    chage -W 7 "$admin"           # Set password expiration warning days
    echo "$admin:CyberPatriot101#!" | sudo chpasswd
done

# Change insecure user passwords
for user in "${correctUsers[@]}"; do
    chage -m 15 -M 60 "$user"    # Set min and max days for password change
    chage -I 5 "$user"           # Set the account inactivity period
    chage -W 7 "$user"           # Set password expiration warning days
    echo "$user:CyberPatriot101#!" | sudo chpasswd
done

