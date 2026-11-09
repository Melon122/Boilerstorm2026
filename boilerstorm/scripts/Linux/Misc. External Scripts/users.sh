#!bin/bash

fixUsers() {
    #exit on error
    set -e

    # Ensure script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        return 1
    fi

    # Define constants
    readonly FILE="correctUsers.txt"
    readonly DEFAULT_PASSWORD="Cyber_Patriot101."
    readonly MIN_UID=1000
    
    # Input validation function
    validate_username() {
        local username="$1"
        # Linux-specific username requirements
        if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || \
           [[ "$username" =~ ^(root|daemon|bin|sys|daemon|system|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|_apt|admin)$ ]]; then
            echo "Invalid username format or reserved username: $username" >&2
            return 1
        fi
        return 0
    }

    # Check if the file exists and is readable
    if [[ ! -f "$FILE" ]] || [[ ! -r "$FILE" ]]; then
        echo "File $FILE not found or not readable!" >&2
        return 1
    fi

    # Secure file reading
    correctUsersContent=$(cat < "$FILE" | tr '\n' ' ')

    # Extracts authorized admins
    adminsLines=$(echo "$correctUsersContent" | awk -F 'Authorized Administrators:' '{print $2}' | awk -F 'Authorized Users:' '{print $1}' | xargs)
    echo "Authorized Administrators: $adminsLines"

    # User confirmation for admins
    read -p "Is this list correct? (y/n) " confirmAdmins
    if [[ "${confirmAdmins,,}" != "y" ]]; then
        echo "Please correct your $FILE file" >&2
        return 1
    fi

    # Makes array of adminsLines
    read -ra correctAdmins <<< "$adminsLines"

    # Extracts authorized users
    usersLines=$(echo "$correctUsersContent" | awk -F 'Authorized Users:' '{print $2}' | xargs)
    echo "Authorized Users: $usersLines"

    # User confirmation for users
    read -p "Is this list correct? (y/n) " confirmUsers
    if [[ "${confirmUsers,,}" != "y" ]]; then
        echo "Please correct your $FILE file" >&2
        return 1
    fi

    # Makes array of usersLines
    read -ra correctUsers <<< "$usersLines"

    # Remove whitespace
    for i in "${!correctAdmins[@]}"; do
        correctAdmins[i]=$(echo "${correctAdmins[i]}" | tr -d '[:space:]')
    done
    echo "Trimmed Authorized Administrators: ${correctAdmins[@]}"

    for i in "${!correctUsers[@]}"; do
        correctUsers[i]=$(echo "${correctUsers[i]}" | tr -d '[:space:]')
    done
    echo "Trimmed Authorized Users: ${correctUsers[@]}"

    # Validate usernames
    for admin in "${correctAdmins[@]}"; do
        if ! validate_username "$admin"; then
            echo "Invalid administrator username detected. Aborting." >&2
            return 1
        fi
    done

    for user in "${correctUsers[@]}"; do
        if ! validate_username "$user"; then
            echo "Invalid user username detected. Aborting." >&2
            return 1
        fi
    done

    # Get all users from the passwd file
    currentUsers=($(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd))



    # Add users that are not already on the system.
    for user in "${correctUsers[@]}"; do
        if [[ ! " ${currentUsers[*]} " =~ " ${user} " ]]; then
            if ! useradd \
                --create-home \
                --shell /bin/bash \
                --comment "Managed user" \
                --password "$(openssl passwd -6 "$DEFAULT_PASSWORD")" \
                "$user"; then
                echo "Failed to add user: $user" >&2
                continue
            fi
            echo "Added user: $user"
        fi
    done

    # Get an array of all admins
    currentAdmins=($(grep '^sudo:.*$' /etc/group | awk -F: '{print $4}' | tr ',' ' '))

    # Compare and add new admins or convert existing users to admins
    for admin in "${correctAdmins[@]}"; do
        if [[ ! " ${currentAdmins[*]} " =~ " ${admin} " ]]; then
            if [[ " ${currentUsers[*]} " =~ " ${admin} " ]]; then
                usermod -aG sudo "$admin"
                echo "Converted user to admin: $admin"
            else
                if ! useradd \
                    --create-home \
                    --shell /bin/bash \
                    --comment "Managed administrator" \
                    --password "$(openssl passwd -6 "$DEFAULT_PASSWORD")" \
                    "$admin"; then
                    echo "Failed to add admin: $admin" >&2
                    continue
                fi
                usermod -aG sudo "$admin"
                echo "Added admin: $admin"
            fi
        fi
    done

    # Compare and remove users
    for user in "${currentUsers[@]}"; do
        if [[ ! " ${correctUsers[*]} " =~ " ${user} " ]] && [[ ! " ${correctAdmins[*]} " =~ " ${user} " ]]; then
            if ! deluser --remove-home "$user" 2>/dev/null; then
                echo "Failed to remove user: $user" >&2
                continue
            fi
            echo "Deleted user and their files: $user"
        fi
    done

    # Compare and remove admins or convert admins to users
    for admin in "${currentAdmins[@]}"; do
        if [[ ! " ${correctAdmins[*]} " =~ " ${admin} " ]]; then
            if [[ " ${correctUsers[*]} " =~ " ${admin} " ]]; then
                deluser "$admin" sudo
                echo "Converted admin to user: $admin"
            else
                if ! deluser --remove-home "$admin" 2>/dev/null; then
                    echo "Failed to remove admin: $admin" >&2
                    continue
                fi
                echo "Removed admin: $admin"
            fi
        fi
    done

    # Set secure password policies
    for admin in "${correctAdmins[@]}"; do
        # Set password aging policies
        chage -m 15 -M 60 -I 5 -W 7 "$admin"

        # Set strong password with salt
        echo "$admin:$DEFAULT_PASSWORD" | chpasswd -e
    done

    for user in "${correctUsers[@]}"; do
        # Set password aging policies
        chage -m 15 -M 60 -I 5 -W 7 "$user"
        

        # Set strong password with salt
        echo "$user:$DEFAULT_PASSWORD" | chpasswd -e
    done

}

fixUsers