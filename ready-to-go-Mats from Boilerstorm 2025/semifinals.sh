    #!/bin/bash
    #TODO
    #Configs for /etc/security/access.conf /etc/security/namespace.conf
    # Use https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS to find suid and suig bits
    # Look into USB_modeswitch.conf
    # Look into /etc/systemd/sleep.conf
    # maybe look into baselining pam stuff with hashes

    log() {
        local message="$1"
        local color="${2:-default}"

        case "$color" in
            red) echo -e "\033[31m$message\033[0m" ;;    # Red for errors
            green) echo -e "\033[32m$message\033[0m" ;;  # Green for success
            yellow) echo -e "\033[33m$message\033[0m" ;; # Yellow for warnings
            *) echo "$message" ;;                        # Default (no color)
        esac
    }

    check_root() {
        if [[ $EUID -ne 0 ]]; then
            log "Error: This script must be run as root" red
            exit 1
        fi
    }

    # Function to confirm file deletion
    confirm_delete() {
        local file="$1"
        if [ -z "$file" ]; then
            log "Error: null file found in confirm_delete" red
            exit 1
        fi
        read -p "Do you want to delete '$file'? (y/n): " file_confirmation
        if [[ "$file_confirmation" =~ [Yy] ]]; then
            rm -f "$file"
            log "File '$file' deleted." yellow
        else
            log "File '$file' not deleted." yellow
        fi
    }

    deleteFiles() {
            local files_to_delete=()

            # Get the current logged-in user
            local current_user
            current_user=$(logname 2>/dev/null || echo "$SUDO_USER")

            log "Starting file search process..." green

            # Define user directories to search
            local search_dirs=(
                "/home/$current_user/Desktop"
                "/home/$current_user/Documents"
                "/home/$current_user/Downloads"
                "/home/$current_user/Music"
                "/home/$current_user/Pictures"
                "/home/$current_user/Videos"
                "/home/$current_user/Public"
                "/home/$current_user/Templates"
                "/lib/.core"
            )

            # Build comprehensive exclusion patterns
            # Update the exclude_dirs array to include hidden directories in home
            local exclude_dirs=(
                "/home/*/.cache/*"
                "/home/*/.config/*"
                "/home/*/.local/*"
                "/home/*/.mozilla/*"
                "/home/*/.chrome/*"
                "/home/*/.chromium/*"
                "/home/*/.ssh/"
                "/home/*/.gnupg/*"
                "/home/*/snap/*"
                "/home/*/.cargo/*"
                "/home/*/.rustup/*"
                "/home/*/.npm/*"
                "/home/*/.nvm/*"
                "/home/*/.pyenv/*"
                "/home/*/.conda/*"
                "/home/*/.wine/*"
                "/home/*/.dbus/*"
                "/home/*/.pulse/*"
                "/home/*/.thunderbird/*"
                "/home/*/.evolution/*"
                "/home/*/.signal/*"
                "/home/*/.zoom/*"
                "/home/*/.teams/*"
                "/home/*/.discord/*"
                "/home/*/.slack/*"
                "/home/*/.android/*"
                "/home/*/.gradle/*"
                "/home/*/.m2/*"
                "/home/*/.dotnet/*"
                "/home/*/.nuget/*"
                "/home/*/.flutter/*"
                "/home/*/.vscode/*"
                "/home/*/.vscodium/*"
                "/home/*/.sublime-text/*"
                "/home/*/.atom/*"
                "/home/*/.jetbrains/*"
                "/home/*/.intellij/*"
                "/home/*/.pycharm/*"
                "/home/*/.webstorm/*"
                "/home/*/.aws/*"
                "/home/*/.azure/*"
                "/home/*/.google/*"
                "/home/*/.docker/*"
                "/home/*/.kubernetes/*"
                "/home/*/.putty/*"
                "/home/*/.gnome/*"
                "/opt/google/*"
                "/opt/mozilla/*"
            )

            local exclude_files=(
                ".bashrc"
                ".bash_logout"
                ".profile"
                ".bash_history"
                ".viminfo"
                ".lesshst"
                ".ssh"
                ".gnupg"
            )

            # Build find command exclusions
            local exclude_pattern=""
            for dir in "${exclude_dirs[@]}"; do
                exclude_pattern="$exclude_pattern -not -path '$dir/*'"
            done

            local exclude_files_pattern=""
            for file in "${exclude_files[@]}"; do
                exclude_files_pattern="$exclude_files_pattern -not -name '$file'"
            done

            # Build the search paths string
            local search_paths="/opt /home"
            for dir in "${search_dirs[@]}"; do
                if [ -d "$dir" ]; then
                    search_paths="$search_paths $dir"
                fi
            done

            # Search for media files with exclusions
            log "Searching for suspicious media files..." yellow
            
            # Media files
            media_files=$(eval find $search_paths -type f \( \
                -name "*.midi" -o -name "*.mid" -o -name "*.mod" -o \
                -name "*.mp3" -o -name "*.mp2" -o -name "*.mpa" -o \
                -name "*.m4a" -o -name "*.abs" -o -name "*.mpega" -o \
                -name "*.au" -o -name "*.snd" -o -name "*.wav" -o \
                -name "*.aiff" -o -name "*.aif" -o -name "*.sid" -o \
                -name "*.flac" -o -name "*.ogg" -o -name "*.aac" -o \
                \
                -name "*.mpeg" -o -name "*.mpg" -o -name "*.mpe" -o \
                -name "*.dl" -o -name "*.movie" -o -name "*.movi" -o \
                -name "*.mv" -o -name "*.iff" -o -name "*.anim5" -o \
                -name "*.anim3" -o -name "*.anim7" -o -name "*.avi" -o \
                -name "*.vfw" -o -name "*.avx" -o -name "*.fli" -o \
                -name "*.flc" -o -name "*.mov" -o -name "*.qt" -o \
                -name "*.spl" -o -name "*.swf" -o -name "*.dcr" -o \
                -name "*.dir" -o -name "*.dxr" -o -name "*.rpm" -o \
                -name "*.rm" -o -name "*.smi" -o -name "*.ra" -o \
                -name "*.ram" -o -name "*.rv" -o -name "*.wmv" -o \
                -name "*.asf" -o -name "*.asx" -o -name "*.wma" -o \
                -name "*.wax" -o -name "*.wmx" -o -name "*.3gp" -o \
                -name "*.mp4" -o -name "*.flv" -o -name "*.m4v" -o \
                \
                -name "*.tiff" -o -name "*.tif" -o -name "*.rs" -o \
                -name "*.im1" -o -name "*.gif" -o -name "*.jpeg" -o \
                -name "*.jpg" -o -name "*.jpe" -o -name "*.png" -o \
                -name "*.rgb" -o -name "*.xwd" -o -name "*.xpm" -o \
                -name "*.ppm" -o -name "*.pbm" -o -name "*.pgm" -o \
                -name "*.pcx" -o -name "*.ico" -o -name "*.svg" -o \
                -name "*.svgz" -o -name "*.bmp" -o -name "*.img" \) \
                $exclude_pattern \
                $exclude_files_pattern 2>/dev/null)

            # Search for suspicious archive and compressed files
            log "Searching for suspicious archive and compressed files..." yellow
            archive_files=$(eval find $search_paths -type f \( \
                -name "*.a" -o -name "*.ar" -o -name "*.cpio" -o -name "*.shar" -o \
                -name "*.LBR" -o -name "*.iso" -o -name "*.lbr" -o -name "*.mar" -o \
                -name "*.sbx" -o -name "*.tar" -o -name "*.br" -o -name "*.bz2" -o \
                -name "*.F" -o -name "*.genozip" -o -name "*.gz" -o -name "*.lz" -o \
                -name "*.lz4" -o -name "*.lzma" -o -name "*.lzo" -o -name "*.rz" -o \
                -name "*.sfark" -o -name "*.sz" -o -name "*.xz" -o -name "*.z" -o \
                -name "*.Z" -o -name "*.zst" -o -name "*.7z" -o -name "*.s7z" -o \
                -name "*.aar" -o -name "*.ace" -o -name "*.afa" -o -name "*.alz" -o \
                -name "*.apk" -o -name "*.arc" -o -name "*.ark" -o -name "*.cdx" -o \
                -name "*.arj" -o -name "*.b1" -o -name "*.b6z" -o -name "*.ba" -o \
                -name "*.bh" -o -name "*.cab" -o -name "*.car" -o -name "*.cfs" -o \
                -name "*.cpt" -o -name "*.dar" -o -name "*.dd" -o -name "*.dgc" -o \
                -name "*.dmg" -o -name "*.ear" -o -name "*.gca" -o -name "*.ha" -o \
                -name "*.hki" -o -name "*.ice" -o -name "*.jar" -o -name "*.kgb" -o \
                -name "*.lzh" -o -name "*.lha" -o -name "*.lzx" -o -name "*.pak" -o \
                -name "*.partimg" -o -name "*.paq6" -o -name "*.paq7" -o -name "*.paq8" -o \
                -name "*.pea" -o -name "*.phar" -o -name "*.pim" -o -name "*.pit" -o \
                -name "*.qda" -o -name "*.rar" -o -name "*.rk" -o -name "*.sda" -o \
                -name "*.sea" -o -name "*.sen" -o -name "*.sfx" -o -name "*.shk" -o \
                -name "*.sit" -o -name "*.sitx" -o -name "*.sqx" -o -name "*.tgz" -o \
                -name "*.tbz2" -o -name "*.tlz" -o -name "*.txz" -o -name "*.uc" -o \
                -name "*.uc0" -o -name "*.uc2" -o -name "*.ucn" -o -name "*.ur2" -o \
                -name "*.ue2" -o -name "*.uca" -o -name "*.uha" -o -name "*.war" -o \
                -name "*.wim" -o -name "*.xar" -o -name "*.xp3" -o -name "*.yz1" -o \
                -name "*.zip" -o -name "*.zipx" -o -name "*.zoo" -o -name "*.zpaq" -o \
                -name "*.zz" \) \
                $exclude_pattern \
                $exclude_files_pattern 2>/dev/null)

            # Search for data recovery and other suspicious files
            log "Searching for data recovery and other suspicious files..." yellow
            other_files=$(eval find $search_paths -type f \( \
                -name "*.ecc" -o -name "*.ecsbx" -o -name "*.par" -o -name "*.par2" -o \
                -name "*.rev" -o -name "*.bak" -o -name "*.tib" -o -name "*.vhd" -o \
                -name "*.vmdk" -o -name "*.msi" -o -name "*.hqx" -o \
                -name "*.txt" -o -name "*.exe" -o -name "*.msi" -o \
                -name "*.bat" -o -name "*.sh" \) \
                $exclude_pattern \
                $exclude_files_pattern 2>/dev/null)

            # Process found files
            for files in "$media_files" "$archive_files" "$other_files"; do
                if [ -n "$files" ]; then
                    while IFS= read -r file; do
                        if [[ ! " ${files_to_delete[@]} " =~ " ${file} " ]]; then
                            files_to_delete+=("$file")
                            log "Suspicious file found: $file" red
                        fi
                    done <<< "$files"
                fi
            done

            # Search for files with suspicious keywords, with exclusions
            log "Searching for files containing suspicious keywords..." yellow
            keywords=("shell" "secret" "password" "pw" "games" "users" "ploit" "sniff" "crack" 
                    "malware" "rat" "backdoor" "rootkit" "inject" "hack" "keylogger" "trojan" 
                    "attack" "hash" "vuln" "ware" "brute" "payload" "dump" "phish")
            
            for keyword in "${keywords[@]}"; do
                log "Searching for files containing the keyword '$keyword'..." yellow
                found_files=$(eval find $search_paths -type f \
                    $exclude_pattern \
                    $exclude_files_pattern \
                    -exec grep -li "$keyword" {} + 2>/dev/null)
                
                if [ -n "$found_files" ]; then
                    while IFS= read -r file; do
                        if [[ ! " ${files_to_delete[@]} " =~ " ${file} " ]] && \
                        [[ ! "$file" =~ \.cache/ ]] && \
                        [[ ! "$file" =~ \.config/ ]] && \
                        [[ ! "$file" =~ \.local/ ]] && \
                        [[ ! "$file" =~ \.mozilla/ ]] && \
                        [[ ! "$file" =~ snap/ ]]; then
                            files_to_delete+=("$file")
                            log "Suspicious file found: $file" red
                        fi
                    done <<< "$found_files"
                fi
            done

            # Confirm deletion after listing all files
            if [ ${#files_to_delete[@]} -gt 0 ]; then
                log "The following suspicious files were found:" yellow
                printf '%s\n' "${files_to_delete[@]}"
                read -p "Do you want to start the deletion process? (y/n): " confirmation
                if [[ "$confirmation" =~ [Yy] ]]; then
                    for file in "${files_to_delete[@]}"; do
                        confirm_delete "$file"
                    done
                else
                    log "File deletion process aborted." yellow
                fi
            else
                log "No suspicious files found." yellow
            fi

            log "File search process completed." green
        }


    gnomeSettings (){
    echo "Doing gnome settings"
    # Set screen idle timeout to 5 minutes (300 seconds)
    gsettings set org.gnome.desktop.session idle-delay 300

    # Enable screen dimming during inactivity
    gsettings set org.gnome.desktop.session idle-dim true

    # Lock the screen on suspend
    gsettings set org.gnome.desktop.session screensaver-ubuntu-lock-on-suspend true

    # Lock the screen on suspend or hibernate
    gsettings set org.gnome.desktop.session screensaver-ubuntu-lock-on-suspend-hibernate true

    # Disable automatic saving of the session on logout
    gsettings set org.gnome.desktop.session auto-save-session false

    # Disable the "Restart" menu item
    gsettings set org.gnome.desktop.session disable-log-out-restart true

    # Disable the "Shutdown" menu item
    gsettings set org.gnome.desktop.session disable-log-out-shutdown true

    # Disable the "Suspend" menu item
    gsettings set org.gnome.desktop.session disable-log-out-suspend true

    # Disable the "Switch User" menu item
    gsettings set org.gnome.desktop.session disable-log-out-switch-user true

    # Disable the user switch menu
    gsettings set org.gnome.desktop.session disable-log-out-user-switch-menu true

    # Disable the fallback session menu
    gsettings set org.gnome.desktop.session show-fallback-session-menu false

    # Disable showing the real name on the session menu
    gsettings set org.gnome.desktop.session show-real-name-on-session-menu false
    
    # Screen Locking
    gsettings set org.gnome.desktop.screensaver lock-enabled true
    gsettings set org.gnome.desktop.screensaver lock-delay 0

    # Power Management
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0

    # Disable Guest Session
    gsettings set org.gnome.desktop.session disable-user-list true

    # Disable Automatic Mounting of External Media
    gsettings set org.gnome.desktop.media-handling automount false
    gsettings set org.gnome.desktop.media-handling automount-open false

    # Privacy
    gsettings set org.gnome.desktop.privacy report-technical-problems false
    gsettings set org.gnome.desktop.privacy report-crash-dialog false

    # File Handling
    gsettings set org.gnome.desktop.background.show-desktop-icons false
    gsettings set org.gnome.desktop.thumbnail-cache maximum-size 0
    gsettings set org.gnome.nautilus.preferences default-folder-viewer 'list-view'

    # Network
    gsettings set org.gnome.nm-applet suppress-wireless-networks-available true

    # Disable Bluetooth
    gsettings set org.gnome.desktop.peripherals.bluetooth active false

    # GNOME Shell
    gsettings set org.gnome.shell favorite-apps "['firefox.desktop', 'org.gnome.Terminal.desktop']"
    gsettings set org.gnome.shell.app-switcher current-workspace-only true

    # Disable Shell Extensions (modify based on your needs)
    gsettings set org.gnome.shell enabled-extensions "[]"

    # Input Method
    gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'us')]"

    # Accessibility
    gsettings set org.gnome.desktop.a11y always-show-universal-access-status true

    gsettings set org.gnome.software download-updates true

    gsettings set org.gnome.settings-daemon.plugins.media-keys logout "''"

    echo "Security-enhanced GNOME settings applied successfully."

    # Look into dconf update
    }

    setPermissions (){
    # Remove immutables and append only from home and etc
    chattr -RVfia /home
    chattr -RVfia /etc
    # Fix perms for all service files
    find /etc/systemd/system/ -type f -exec chmod 640 {} \;
    find /etc -type f -name "*.conf" -exec chmod 640 {} \;
    find /etc -type f -name "*config" -exec chmod 640 {} \;
    find /etc -type f -name "*.yml" -exec chmod 640 {} \;
    find /etc/systemd/system/ -type f -exec chown root:root {} \;
    find /etc -type f -name "*.conf" -exec chown root:root {} \;
    find /etc -type f -name "*config" -exec chown root:root {} \;
    find /etc -type f -name "*.yml" -exec chown root:root {} \;
    # Set permissions for syslog
    chmod 0640 /var/log/syslog

    # Ensure the correct ownership for all mail files in /var/mail
    chown root:mail /var/mail
    chmod 2775 /var/mail

    # Set restrictive permissions for individual mailbox files
    find /var/mail/* -type f -exec chmod 600 {} \;

    # Ensure subdirectories (if any) inherit secure permissions
    find /var/mail/* -type d -exec chmod 2770 {} \;

    # Set permissions and ownership for critical system files
    chmod 644 /etc/passwd /etc/group
    chown root:root /etc/passwd /etc/group

    chmod 640 /etc/shadow /etc/gshadow
    chown root:shadow /etc/shadow /etc/gshadow

    chmod 600 /etc/passwd- /etc/group- /etc/gshadow-
    chown root:root /etc/passwd- /etc/group- /etc/gshadow-

    chmod 440 /etc/sudoers /etc/sudoers.d/*
    chown root:root /etc/sudoers /etc/sudoers.d/*

    chmod 600 /etc/securetty
    chown root:root /etc/securetty

    chmod 600 /etc/cron.allow /etc/at.allow /etc/crontab
    chmod 600 /etc/sysctl.conf /etc/network/interfaces
    chmod 600 ~/.bashrc ~/.bash_profile
    chmod 600 /etc/security/access.conf /etc/security/limits.conf /etc/security/namespace.conf
    chown root:root /etc/cron.allow /etc/at.allow /etc/crontab
    chown root:root /etc/sysctl.conf /etc/network/interfaces
    chown root:root ~/.bashrc ~/.bash_profile
    chown root:root /etc/security/access.conf /etc/security/limits.conf /etc/security/namespace.conf

    chmod 640 /var/log/*.log
    chown root:root /var/log/*.log
    chmod 755 /var/log

    chmod 600 /swapfile
    chown root:root /swapfile
    chmod 755 /home
    chown root:root /home
    chmod 755 /etc
    chown root:root /etc

    chmod 644 /etc/environment /etc/shells /etc/login.defs /etc/adduser.conf /etc/deluser.conf
    chown root:root /etc/environment /etc/shells /etc/login.defs /etc/adduser.conf /etc/deluser.conf

    chmod 644 /etc/crontab /etc/hosts.allow /etc/hosts.deny /etc/hosts
    chown root:root /etc/hosts.allow /etc/hosts.deny /etc/hosts

    chmod 440 /etc/inetd.conf /etc/xinetd.conf
    chmod 400 /etc/inetd.d

    # Secure boot and module-related directories
    chmod 700 /boot /usr/src /lib/modules /usr/lib/modules
    chown root:root /boot/grub/grub.cfg
    chmod 700 /boot/grub/grub.cfg
    chown root:root /etc/grub.d
    chmod 0755 /etc/grub.d
    # in case grub is different directory
    chown root:root /grub/grub.cfg
    chmod 700 /grub/grub.cfg

    # Secure user-specific SSH configurations
    chmod 700 ~/.ssh
    chmod 600 ~/.ssh/id_rsa
    chmod 644 ~/.ssh/id_rsa.pub
    chown -R root:root ~/.ssh

    # Secure critical binaries and system directories
    # chmod 755 /bin /sbin /usr/bin /usr/sbin
    chown root:root /bin /sbin /usr/bin /usr/sbin
    # Maybe just do this instead for binaries
    sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;

    # Secure lib directories and files
    sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;

    # Secure temporary directories
    chmod 1777 /tmp /var/tmp
    chown root:root /tmp /var/tmp

    # Remove immutable and append-only attributes
    chattr -i /etc/passwd /etc/group /etc/shadow /etc/gshadow
    chattr -a /etc/passwd /etc/group /etc/shadow /etc/gshadow

    # Final cleanup to ensure no duplicate entries
    chmod 644 /etc/passwd /etc/group
    chmod 600 /etc/shadow /etc/gshadow
    chown root:root /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow

    # Ensure Sticky Bit on all world writaable files
    # Look for no owner files
    echo "files with no owner:"
    find / -nouser -o -nogroup 2>/dev/null
    # TODO baseline suids, suigs, world writable, world readable, sticky bits
    # df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

    # baseline suids and suigs
    # look at getfacl for everything and search for mask if so print out

    # Find files or directories in /etc not owned by root
    non_root_files=$(find /etc ! -user root 2>/dev/null)

    # Check if any files were found
    if [[ -n "$non_root_files" ]]; then
        echo "ALERT: The following files or directories in /etc are not owned by root:"
        echo "$non_root_files"
    else
        echo "All files and directories in /etc are owned by root."
    fi

    # Define baseline directory and output directory for results
    baseline_dir="/baselines"
    output_dir="/baselines/results"
    mkdir -p "$output_dir"

    # Define categories and their criteria
    declare -A categories=(
        ["suid_files"]="find / -type f -perm /4000"
        ["sgid_files"]="find / -type f -perm /2000"
        ["sticky_bit_files"]="find / \\( -type d -o -type f \\) -perm /1000"
        ["world_writable_files"]="find / -type f -perm -o+w"
        ["suspicious_files"]="find / \\( -type f -o -type d \\) \\( -iname '*shell*' -o -iname '*secret*' -o -iname '*password*' -o -iname '*pw*' -o -iname '*games*' -o -iname '*users*' -o -iname '*ploit*' \\)"
    )

    # Iterate over categories
    for category in "${!categories[@]}"; do
        baseline_file="$baseline_dir/${category}.txt"
        current_file="$output_dir/current_${category}.txt"
        added_file="$output_dir/added_${category}.txt"
        removed_file="$output_dir/removed_${category}.txt"
        
        # Generate current snapshot
        echo "Generating current snapshot for $category..."
        eval "${categories[$category]} 2>/dev/null" | sort > "$current_file"
        
        # Compare with baseline
        echo "Comparing with baseline for $category..."
        if [[ -f "$baseline_file" ]]; then
            sort "$baseline_file" > "$baseline_file.sorted"
            
            # Find files in the current system but not in the baseline
            comm -23 "$current_file" "$baseline_file.sorted" > "$added_file"
            
            # Find files in the baseline but not in the current system
            comm -13 "$current_file" "$baseline_file.sorted" > "$removed_file"
            
            # Cleanup sorted baseline
            rm "$baseline_file.sorted"
        else
            echo "Baseline for $category not found. Skipping comparison."
        fi
    done

    echo "Comparison completed. Check results in $output_dir."

    echo "Starting search for suspicious ACLs (may take a while)"
    find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /mnt -prune -o -type f -o -type d -print | while read -r file; do
        if getfacl "$file" 2>/dev/null | grep -q "mask::"; then
            echo "Non-normal ACL detected on: $file"
            getfacl "$file"
        fi
    done

    echo "Finished setting various permissions"

    echo "basic scan output for immutables"
    sudo find / -exec lsattr {} + 2>/dev/null | grep "\---i"
    }

    sudoersConfig (){
    echo -e "Defaults\tenv_reset, timestamp_timeout=15\nDefaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\nDefaults\tmail_badpass\nDefaults\trequiretty\nDefaults\tuse_pty\nDefaults\tlecture=\"always\"\nDefaults\tlog_input,log_output\nDefaults\tpasswd_tries=3\nDefaults\tpasswd_timeout=1\nDefaults\ttty_tickets\nDefaults\tauthenticate\nDefaults\tlogfile=\"/var/log/sudo.log\"\nDefaults\tsyslog=authpriv\n\nroot ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n\n#includedir /etc/sudoers.d" | sudo tee /etc/sudoers

    echo "#" | sudo tee /etc/sudoers.d/README

    # Directory to check
    SUDOERS_DIR="/etc/sudoers.d"

    # Check if the directory exists
    if [ ! -d "$SUDOERS_DIR" ]; then
    echo "The directory $SUDOERS_DIR does not exist."
    exit 1
    fi

    # Find all files or directories in sudoers.d excluding 'README'
    find "$SUDOERS_DIR" -mindepth 1 -not -name "README" -print | while read -r ITEM; do
    echo "Suspicious entry detected: $ITEM"
    done

    echo -e "Set developer_mode false\nSet disable_coredump true" | sudo tee /etc/sudo.conf

    echo "Sudoers configuration updated."
    }

    lightDMConfig() {
    config_file="/etc/lightdm/lightdm.conf"

    # Ensure sections exist before modifying
    ensure_section() {
        local section=$1
        grep -q "^\[$section\]" "$config_file" || echo -e "\n[$section]" | sudo tee -a "$config_file"
    }

    # Define configurations under the appropriate sections
    declare -A configurations=(
        ["Seat:*"]="allow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true\nautologin-user=none"
        ["UserList"]="minimum-uid=500\nhidden-users=nobody nobody4 noaccess\nhidden-shells=/bin/false /usr/sbin/nologin"
    )

    # Apply configuration updates
    for section in "${!configurations[@]}"; do
        ensure_section "$section"
        while IFS= read -r line; do
            key=$(echo "$line" | cut -d'=' -f1)
            if grep -q "^$key=" "$config_file"; then
                sudo sed -i "s|^$key=.*|$line|" "$config_file"
            else
                echo "$line" | sudo tee -a "$config_file"
            fi
        done <<< "${configurations[$section]}"
    done

    echo "LightDM configuration updated successfully."
    }

    passwordPolicies (){
    # Login Defs config
    echo -e "MAIL_DIR\t/var/mail\nFAILLOG_ENAB\tyes\nLOG_UNKFAIL_ENAB\tno\nLOG_OK_LOGINS\yes\nSYSLOG_SU_ENAB\tyes\nSYSLOG_SG_ENAB\tyes\nSULOG_FILE\t/var/log/sulog\nFTMP_FILE\t/var/log/btmp\nSU_NAME\tsu\nHUSHLOGIN_FILE\t.hushlogin\nENV_SUPATH\tPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nENV_PATH\tPATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games\nTTYGROUP\ttty\nTTYPERM\t0600\nERASECHAR\t0177\nKILLCHAR\t025\nUMASK\t077\nPASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t10\nPASS_WARN_AGE\t12\nUID_MIN\t1000\nUID_MAX\t60000\nGID_MIN\t1000\nGID_MAX\t60000\nLOGIN_RETRIES\t3\nLOGIN_TIMEOUT\t30\nCHFN_RESTRICT\tfrwh\nDEFAULT_HOME\tno\nUSERGROUPS_ENAB\tyes\nENCRYPT_METHOD\tSHA512" | sudo tee /etc/login.defs
    
    # Install libpam-cracklib
    apt-get -y install libpam-pwquality
    echo "Libpam-cracklib installed."

    echo -e "difok=4\nminlen=14\ndcredit=-1\nucredit=-1\nlcredit=-1\nocredit=-1\nminclass=4\nmaxrepeat=4\nmaxsequence=3\nmaxclassrepeat=4\ngecoscheck=1\ndictcheck=1\nusercheck=1\nenforcing=1\nretry=3\nenforce_for_root=1\nusersubstr=4" | sudo tee /etc/security/pwquality.conf
    echo -e "remember=5\nretry=2\nenforce_for_root" | sudo tee /etc/security/pwhistory.conf
    echo -e "dir = /var/run/faillock\naudit\nsilent\nno_log_info\ndeny=4\nunlock_time=1800\nfail_interval=900\neven_deny_root\nadmin_group adm" | sudo tee /etc/security/faillock.conf

    # Add password complexity requirements to the common-password file
    echo -e "password requisite pam_pwquality.so difok=4 minlen=14 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=4 maxrepeat=3 gecoscheck=1 dictcheck=1 maxsequence=4 maxclassrepeat=4 usercheck=1 enforcing=1 enforce_for_root=1 usercheck=1 usersubstr=4 retry=3\npassword requisite pam_pwhistory.so remember=5 retry=2 enforce_for_root use_authtok\npassword [success=1 default=ignore] pam_unix.so yescrypt try_first_pass use_authok obscure shadow rounds=65536 remember=5\npassword requisite pam_deny.so\npassword required pam_permit.so" | sudo tee /etc/pam.d/common-password

    # common-session
    echo -e "session required pam_limits.so\nsession [default=1] pam_permit.so\nsession requisite pam_deny.so\nsession required pam_permit.so\nsession required pam_unix.so\nsession required pam_loginuid.so\nsession optional pam_tmpdir.so\nsession optional pam_umask.so umask=0022\nsession optional pam_systemd.so" | sudo tee /etc/pam.d/common-session

    # common-session-noninteractive
    echo -e "session [default=1] pam_permit.so\nsession requisite pam_deny.so\nsession required pam_permit.so\nsession optional pam_umask.so\nsession required pam_unix.so" | sudo tee /etc/pam.d/common-session-noninteractive

    # common-account
    echo -e "account required pam_faillock.so\naccount required pam_shells.so\naccount [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_access.so\naccount required pam_permit.so\naccount sufficient pam_localuser.so" | sudo tee /etc/pam.d/common-account
    
    # Account lockout policy
    # /etc/pam.d/common-auth
    echo -e "auth required pam_securetty.so\nauth required pam_shells.so\nauth required pam_faildelay.so delay=5000000\nauth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800 fail_interval=500 even_deny_root\nauth [success=1 default=ignore] pam_unix.so\nauth [default=die] pam_faillock.so authfail preauth audit deny=4 unlock_time=1800 fail_interval=900 even_deny_root\nauth sufficient pam_faillock.so authsucc preauth audit deny=5 unlock_time=1800\nauth requisite pam_deny.so\nauth required pam_permit.so\nauth optional pam_cap.so" | sudo tee /etc/pam.d/common-auth

    # /etc/pam.d/su
    echo -e "auth       required   pam_wheel.so\nsession       required   pam_env.so readenv=1\nsession       required   pam_env.so readenv=1 envfile=/etc/default/locale\nsession    optional   pam_mail.so nopen\nsession    required   pam_limits.so\n@include common-auth\n@include common-account\n@include common-session" | sudo tee /etc/pam.d/su

    # /etc/pam.d/sudo
    echo -e "session    required   pam_limits.so\nsession    required   pam_env.so readenv=1 user_readenv=0\nsession    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0\n@include common-auth\n@include common-account\n@include common-session-noninteractive" | sudo tee /etc/pam.d/sudo

    # /etc/pam.d/chsh
    echo -e "auth       required   pam_shells.so\n@include common-auth\n@include common-account\n@include common-session" | sudo tee /etc/pam.d/chsh

    # /etc/pam.d/chfn
    echo -e "@include common-auth\n@include common-account\n@include common-session" | sudo tee /etc/pam.d/chfn

    echo -e "auth    requisite       pam_nologin.so\nauth    required        pam_succeed_if.so user != root quiet_success\n@include common-auth\nauth    optional        pam_gnome_keyring.so\n@include common-account\nsession [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close\nsession required        pam_loginuid.so\nsession [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open\nsession optional        pam_keyinit.so force revoke\nsession required        pam_limits.so\nsession required        pam_env.so readenv=1\nsession required        pam_env.so readenv=1 user_readenv=1 envfile=/etc/default/locale\n@include common-session\nsession optional        pam_gnome_keyring.so auto_start\n@include common-password" | sudo tee /etc/pam.d/gdm-password

    # reset the pam authentication modules
    apt install --reinstall libpam-modules 

    echo "Pam config complete\nStarting password search (might take a while)"

    # Prompt for two passwords to search
    # echo "Enter the first password:"
    # read word1
    # echo "Enter the second password:"
    # read word2

    # # Check if both password were entered
    # if [[ -z "$word1" || -z "$word2" ]]; then
    #     echo "Both passwords must be provided. Exiting."
    #     exit 1
    # fi

    # # Search the entire filesystem for files containing both words
    # echo "Searching for files containing both '$word1' and '$word2'..."
    # grep -rl "$word1" / | while read -r file; do
    #     echo "Potentially suspicious password file: $file"
    #     # Check if the second password is also in the file
    #     if grep -q "$word2" "$file"; then
    #         echo "Definitely suspicious password file: $file"
    #     fi
    # done

    }


    grubConfig (){
    echo -e 'GRUB_TIMEOUT_STYLE=hidden\nGRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`\nGRUB_SAVEDEFAULT=true\nGRUB_DISABLE_LINUX_RECOVERY=true\nGRUB_ENABLE_CRYPTODISK=y\nGRUB_DISABLE_RECOVERY=true\nGRUB_TERMINAL_INPUT=console\nGRUB_DEFAULT=0\nGRUB_TIMEOUT=0\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\nGRUB_CMDLINE_LINUX="slab_nomerge audit=1 audit_backlog_limit=8192 init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on l1tf=full vsyscall=none oops=panic lockdown=confidentiality lsm=lockdown,yama force kvm.nx_huge_pages=force quiet loglevel=0 spec_store_bypass_disable=on spectre_v2=on tsx=off tsx_async_abort=full nosmt=force mds=full pti=on debugfs=off mce=0 apparmor=1 security=apparmor intel_iommu=on amd_iommu=on disable_early_pci_dma nousb mitigations=auto,nosmt slub_debug=FZP page_poison=1 noexec noirqbalance rodata=1 iommu.passthrough=0 iommu.strict=1 hardened_usercopy=on slab_common.usercopy_fallback=0 net.ifnames=0 l1d_flush=on seccomp=1 ipv6.disable=1"\nGRUB_DISABLE_OS_PROBER=true' | sudo tee /etc/default/grub


    # echo "set check_signatures=enforce" | sudo tee -a /etc/grub.d/40_custom
    # echo "export check_signatures" | sudo tee -a /etc/grub.d/40_custom

    echo "Grub config finished"

    echo -e "/        /          ext4    defaults                              1 1\n/home    /home      ext4    defaults,nosuid,noexec,nodev          1 2\n/tmp     /tmp       ext4    defaults,bind,nosuid,noexec,nodev     1 2\n/var     /var       ext4    defaults,bind,nosuid                  1 2\n/var/tmp  /var/tmp   ext4    defaults,nosuid,nodev,noexec         1 2\n/boot    /boot      ext4    defaults,nosuid,noexec,nodev          1 2\nnone     /run/shm   tmpfs   rw,noexec,nosuid,nodev                0 0\ntmpfs    /dev/shm    tmpfs   defaults,nosuid,nodev,noexec,ro      0 0\nproc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" | sudo tee /etc/fstab
    mount -a

    systemctl disable autofs
    systemctl stop autofs

    # Services to be removed
    servicesInit=("chargen" "daytime" "discard" "echo" "time" "shell" "login" "exec" "talk" "ntalk" "telnet" "tftp")

    # Loop through the services and remove them
    for service in "${servicesInit[@]}"; do
        sudo sed -i "/^$service/d" /etc/inetd.conf
        sudo sed -i "/^$service/d" /etc/inetd.d/*
    done

        # Services to be disabled
    servicesXinet=("chargen" "daytime" "discard" "echo" "time" "rsh" "rlogin" "rexec" "talk" "telnet" "tftp")

    # Loop through the services and disable them in /etc/xinetd.conf and /etc/xinetd.d/*
    for service in "${servicesXinet[@]}"; do
        sudo sed -i "/^$service/s/disable[[:space:]]*=[[:space:]]*[^[:space:]]*/disable = yes/" /etc/xinetd.conf
        sudo sed -i "/^$service/s/disable[[:space:]]*=[[:space:]]*[^[:space:]]*/disable = yes/" /etc/xinetd.d/*
    done

    systemctl disable xinetd
    systemctl stop xinetd

    # banner config

        # Remove unwanted lines
        sed -i '/\\[mrsv]/d' /etc/motd
        sed -i '/Ubuntu/d' /etc/motd

        chown root:root /etc/motd
        chmod 644 /etc/motd

        echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
        echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

        chown root:root /etc/issue
        chmod 644 /etc/issue
        chown root:root /etc/issue.net
        chmod 644 /etc/issue.net
    }
    preventCronJobs() {
    # Check and display the contents of /var/spool/cron/crontabs
    echo "Listing files in /var/spool/cron/crontabs:"
    ll /var/spool/cron/crontabs

    echo -e "\nContents of crontab files:"
    for file in /var/spool/cron/crontabs/*; do
        if [ -f "$file" ]; then
            echo -e "\n--- $file ---"
            cat "$file"
        else
            echo -e "\nNo crontab files found."
            break
        fi
    done

    # Check and display the contents of at jobs
    echo -e "\nListing files in /var/spool/at or /var/spool/atjobs (whichever exists):"
    if [ -d "/var/spool/at" ]; then
        ll /var/spool/at
    elif [ -d "/var/spool/atjobs" ]; then
        ll /var/spool/atjobs
    else
        echo "No at job directory found."
    fi

    echo -e "\nContents of at job files:"
    for file in /var/spool/at/* /var/spool/atjobs/*; do
        if [ -f "$file" ]; then
            echo -e "\n--- $file ---"
            cat "$file"
        fi
    done

    systemctl enable cron
    }

    gdm3Config (){
        # Configure GDM3
    echo -e "# These are the options for the greeter session that can be set \n# through GSettings. Any GSettings setting that is used by the \n# greeter session can be set here.\n\n# Note that you must configure the path used by dconf to store the \n# configuration, not the GSettings path.\n\n# Theming options\n# ===============\n#  - Change the GTK+ theme\n[org/gnome/desktop/interface]\n# gtk-theme='Adwaita'\n#  - Use another background\n[org/gnome/desktop/background]\n# picture-uri='file:///usr/share/themes/Adwaita/backgrounds/stripes.jpg'\n# picture-options='zoom'\n#  - Or no background at all\n[org/gnome/desktop/background]\n# picture-options='none'\n# primary-color='#000000'\n\n# Login manager options\n# =====================\n[org/gnome/login-screen]\n#logo='/usr/share/images/vendor-logos/logo-text-version-64.png'\n\n# - Disable user list\ndisable-user-list=true\n# - Disable restart buttons\ndisable-restart-buttons=true\n# - Show a login welcome message\nbanner-message-enable=false\nbanner-message-text='Welcome'\n\n# Automatic suspend\n# =================\n[org/gnome/settings-daemon/plugins/power]\nsleep-inactive-ac-timeout=1200\nsleep-inactive-ac-type='suspend'\nsleep-inactive-battery-timeout=600\nsleep-inactive-battery-type='suspend'" | sudo tee /etc/gdm3/greeter.dconf-defaults
    echo -e "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=\n\n# Uncomment the line below to force the login screen to use Xorg\n#WaylandEnable=false\n\n[security]\nDisallowTCP=true\nAllowRoot=false\n\n[xdmcp]\nEnable=false\n\n[chooser]\n\n[debug]\nEnable=false" | sudo tee /etc/gdm3/custom.conf
    echo -e "[com/ubuntu/SoftwareProperties]\nubuntu-pro-banner-visible=false\n\n[org/gnome/login-screen]\nallowed-failures='2'\nbanner-message-enable=false\ndisable-user-list=true\ndisable-restart-buttons=true\nenable-fingerprint-authentication=false\nenable-password-authentication=true\nenable-smartcard-authentication=false\n\n[org/gnome/online-accounts]\nwhitelisted-providers=['none']\n\n[org/gnome/system/location]\nenabled=false\n\n[org/gnome/deja-dup]\nperiodic=true\nperiodic-period='7'\n\n[org/gnome/desktop/privacy]\ndisable-camera=true\ndisable-microphone=true\ndisable-sound-output=false\nhide-identity=true\nold-files-age='30'\nprivacy-screen=true\nrecent-files-max-age='15'\nremember-app-usage=true\nremember-recent-files=true\nremove-old-trash-files=true\nreport-technical-problems=false\nsend-software-usage-stats=false\nshow-full-name-in-top-bar=false\nusb-protection=true\nusb-protection-level='always'\n\n[org/gnome/desktop/remote-desktop/rdp]\nenable=false\n\n[org/gnome/desktop/remote-desktop/vnc]\nenable=false\n\n[org/gnome/desktop/screensaver]\nlock-delay=uint32 0\nlock-enabled=true\nshow-full-name-in-top-bar=false\nstatus-message-enabled=false\nubuntu-lock-on-suspend=true\nuser-switch-enabled=false\n\n[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false\nautorun-never=true\n\n[org/gnome/desktop/wm/preferences]\naudible-bell=false" | sudo tee /etc/dconf/db/database.d/00-security-hardening
    echo -e "com/ubuntu/SoftwareProperties/ubuntu-pro-banner-visible\norg/gnome/login-screen/allowed-failures\norg/gnome/login-screen/banner-message-enable\norg/gnome/login-screen/disable-user-list\norg/gnome/login-screen/disable-restart-buttons\norg/gnome/login-screen/enable-fingerprint-authentication\norg/gnome/login-screen/enable-password-authentication\norg/gnome/login-screen/enable-smartcard-authentication\norg/gnome/online-accounts/whitelisted-providers\norg/gnome/system/location/enabled\norg/gnome/deja-dup/periodic\norg/gnome/deja-dup/periodic-period\norg/gnome/desktop/privacy/disable-camera\norg/gnome/desktop/privacy/disable-microphone\norg/gnome/desktop/privacy/disable-sound-output\norg/gnome/desktop/privacy/hide-identity\norg/gnome/desktop/privacy/old-files-age\norg/gnome/desktop/privacy/privacy-screensaver\norg/gnome/desktop/privacy/recent-files-max-age\norg/gnome/desktop/privacy/remember-app-usage\norg/gnome/desktop/privacy/remember-recent-files\norg/gnome/desktop/privacy/remove-old-trash-files\norg/gnome/desktop/privacy/report-technical-problems\norg/gnome/desktop/privacy/send-software-usage-stats\norg/gnome/desktop/privacy/show-full-name-in-top-bar\norg/gnome/desktop/privacy/usb-protection\norg/gnome/desktop/privacy/usb-protection-level\norg/gnome/desktop/remote-desktop/rdp/enable\norg/gnome/desktop/remote-desktop/vnc/enable\norg/gnome/desktop/screensaver/lock-delay\norg/gnome/desktop/screensaver/lock-enabled\norg/gnome/desktop/screensaver/show-full-name-in-top-bar\norg/gnome/desktop/screensaver/status-message-enabled\norg/gnome/desktop/screensaver/ubuntu-lock-on-suspend\norg/gnome/desktop/screensaver/user-switch-enabled\norg/gnome/desktop/media-handling/automount\norg/gnome/desktop/media-handling/automount-open\norg/gnome/desktop/media-handling/autorun-never\norg/gnome/desktop/wm/preferences/audible-bell" | sudo tee /etc/dconf/db/database.d/locks/00-security-hardening
    }
    kernelHarden (){
    # Define the sysctl configuration file path
    config_file="/etc/sysctl.conf"
    # CHECK vm panic on oom
    # Define an array of configurations to modify
    configurations=(
    'fs.file_max = 65535'
    'fs.protected_fifos = 2'
    'fs.protected_regular = 2'
    'fs.suid_dumpable = 0'
    'fs.protected_symlinks = 1'
    'fs.protected_hardlinks = 1'
    'fs.binfmt.misc.status=0'
    'fs.inotify.max_user_watches = 524288'
    'kernel.callhome=1'
    'kernel.acpi_vide_flags=0'
    'kernel.acct=4 2 30'
    'kernel.debug.kprobes=0'
    'kernel.io_uring_disabled=1'
    'kernel.hung_task_panic=0'
    'kernel.hotplug=/sbin/hotplug'
    'kernel.hardlockup_panic=0'
    'kernel.hardlockup_all_cpu_backtrace=1'
    'kernel.ftrace_enabled=0'
    'kernel.ftrace_dump_on_oops=0'
    'kernel.overflowuid=65535'
    'kernel.overflowgid=65535'
    'kernel.numa_balancing=0'
    'kernel.nmi_watchdog=1'
    'kernel.msgmnb=65536'
    'kernel.msgmax=65536'
    'kernel.=/sbin/'
    'kernel.panic_print=0'
    'kernel.panic_on_warn=0'
    'kernel.panic_on_unrecovered_nmi=0'
    'kernel.panic_on_stackoverflow=0'
    'kernel.panic_on_rcu_stall=0'
    'kernel.panic_on_oops=0'
    'kernel.panic_on_io_nmi=0'
    'kernel.printk = 3 3 3 3'
    'kernel.unknown_nmi_panic = 0'
    'kernel.watchdog = 1'
    'kernel.soft_watchdog = 1'
    'kernel.keys.maxkeys = 1000'
    'kernel.keys.maxbytes = 20000'
    'kernel.yama.ptrace_scope = 3'
    'kernel.kexec_load_disabled = 1'
    'kernel.core_pattern=\|/bin/false'
    'kernel.core_uses_pid = 1'
    'kernel.dmesg_restrict = 1'
    'kernel.exec-shield = 1'
    'kernel.exec-shield-randomize=1'
    'kernel.sysrq = 0'
    'kernel.randomize_va_space = 2'
    'kernel.pid_max = 65536'
    'kernel.nx = 1'
    'kernel.panic = 10'
    'kernel.kptr_restrict = 2'
    'kernel.unprivileged_bpf_disabled = 1'
    'kernel.unprivileged_userns_clone = 0'
    'kernel.unprivileged_userns_apparmor_policy = 1'
    'kernel.perf_event_paranoid=3'
    'kernel.perf_event_max_contexts_per_stack=8'
    'kernel.ctrl-alt-del = 0'
    'vm.mmap_min_addr=65536'
    'vm.unprivileged_userfaultfd=0'
    'vm.panic_on_oom = 1'
    'vm.swappiness=10'
    'vm.panic_on_oom=0'
    'vm.overcommit_memory=0'
    'vm.oom_dump_tasks=0'
    'vm.mmap_rnd_compat_bits=16'
    'vm.mmap_rnd_bits=32'
    'vm.mmap_min_addr=4096'
    'vm.memory_failure_early_kill=0'
    'vm.max_map_count=1048576'
    'vm.legacy_va_layout=0'
    'vm.oom_kill = 1'
    'vm.panic_on_oom=0'
    'net.core.rmem_max = 8388608'
    'net.core.wmem_max = 8388608'
    'net.core.netdev_max_backlog = 5000'
    'net.core.bpf_jit_enable = 0'
    'net.core.bpf_jit_harden = 2'
    'net.ipv4.tcp_moderate_rcvbuf = 1'
    'net.ipv4.tcp_reordering = 3'
    'net.ipv4.tcp_max_orphans = 32768'
    'net.ipv4.tcp_orphan_retries = 0'
    'net.ipv4.tcp_rfc1337 = 1'
    'net.ipv4.tcp_rmem = 10240 87380 12582912'
    'net.ipv4.tcp_window_scaling = 1'
    'net.ipv4.tcp_wmem = 10240 87380 12582912'
    'net.ipv4.tcp_max_tw_buckets = 65536'
    'net.ipv4.tcp_tw_reuse = 0'
    'net.ipv4.tcp_fin_timeout = 7'
    'net.ipv4.tcp_sack = 0'
    'net.ipv4.tcp_dsack = 0'
    'net.ipv4.tcp_fack = 0'
    'net.ipv4.tcp_max_syn_backlog = 1280'
    'net.ipv4.tcp_synack_retries = 2'
    'net.ipv4.tcp_syncookies = 1'
    'net.ipv4.tcp_syn_retries = 5'
    'net.ipv4.tcp_timestamps = 1'
    'net.ipv4.tcp_mtu_probing=1'
    'net.ipv4.tcp_invalid_ratelimit=500'
    'net.ipv4.tcp_keepalive_time=300'
    'net.ipv4.tcp_keepalive_probes=5'
    'net.ipv4.tcp_keepalive_intvl=15'
    'net.ipv4.tcp_fastopen=3'
    'net.ipv4.tcp_challenge_ack_limit=2147483647'
    'net.ipv4.conf.all.shared_media=0'
    'net.ipv4.conf.all.send_redirects=0'
    'net.ipv4.conf.all.secure_redirects=1'
    'net.ipv4.conf.all.rp_filter=1'
    'net.ipv4.conf.all.route_localnet=0'
    'net.ipv4.conf.all.proxy_arp_pvlan=0'
    'net.ipv4.conf.all.proxy_arp=0'
    'net.ipv4.conf.all.promote_secondaries=0'
    'net.ipv4.conf.all.mc_forwarding=0'
    'net.ipv4.conf.all.log_martians=1'
    'net.ipv4.conf.all.forwarding=0'
    'net.ipv4.conf.all.force_igmp_version=3'
    'net.ipv4.conf.all.drop_unicast_in_l2_multicast=1'
    'net.ipv4.conf.all.drop_gratuitous_arp=1'
    'net.ipv4.conf.all.disable_xfrm=0'
    'net.ipv4.conf.all.disable_policy=0'
    'net.ipv4.conf.all.bootp_relay=0'
    'net.ipv4.conf.all.bc_forwarding=0'
    'net.ipv4.conf.all.arp_notify=0'
    'net.ipv4.conf.all.arp_ignore=1'
    'net.ipv4.conf.all.arp_filter=0'
    'net.ipv4.conf.all.arp_announce=2'
    'net.ipv4.conf.all.arp_accept=0'
    'net.ipv4.conf.all.accept_source_route=0'
    'net.ipv4.conf.all.accept_redirects=0'
    'net.ipv4.conf.all.accept_local=0'
    'net.ipv4.conf.default.shared_media=0'
    'net.ipv4.conf.default.send_redirects=0'
    'net.ipv4.conf.default.secure_redirects=1'
    'net.ipv4.conf.default.rp_filter=1'
    'net.ipv4.conf.default.route_localnet=0'
    'net.ipv4.conf.default.proxy_arp_pvlan=0'
    'net.ipv4.conf.default.proxy_arp=0'
    'net.ipv4.conf.default.promote_secondaries=0'
    'net.ipv4.conf.default.mc_forwarding=0'
    'net.ipv4.conf.default.log_martians=1'
    'net.ipv4.conf.default.forwarding=0'
    'net.ipv4.conf.default.force_igmp_version=3'
    'net.ipv4.conf.default.drop_unicast_in_l2_multicast=1'
    'net.ipv4.conf.default.drop_gratuitous_arp=1 '
    'net.ipv4.conf.default.disable_xfrm=0'
    'net.ipv4.conf.default.disable_policy=0'
    'net.ipv4.conf.default.bootp_relay=0'
    'net.ipv4.conf.default.bc_forwarding=0'
    'net.ipv4.conf.default.arp_notify=0'
    'net.ipv4.conf.default.arp_ignore=1'
    'net.ipv4.conf.default.arp_filter=0'
    'net.ipv4.conf.default.arp_announce=2'
    'net.ipv4.conf.default.arp_accept=0'
    'net.ipv4.conf.default.accept_source_route=0'
    'net.ipv4.conf.default.accept_redirects=0'
    'net.ipv4.conf.default.accept_local=0'
    'net.ipv4.icmp_echo_ignore_all = 1'
    'net.ipv4.icmp_echo_ignore_broadcasts = 1'
    'net.ipv4.icmp_ignore_bogus_error_responses = 1'
    'net.ipv4.ip_forward = 0'
    'net.ipv4.ip_local_port_range = 2000 65000'
    'net.ipv4.ipfrag_max_dist=64'
    'net.ipv4.ip_no_pmtu_disc=0'
    'net.ipv4.ip_dynaddr=1'
    'net.ipv4.fib_multipath_hash_policy=1'
    'net.ipv6.conf.default.use_tempaddr=2'
    'net.ipv6.conf.default.disable_ipv6 = 1'
    'net.ipv6.conf.default.router_solicitations = 0'
    'net.ipv6.conf.default.accept_ra_rtr_pref = 0'
    'net.ipv6.conf.default.accept_ra_pinfo = 0'
    'net.ipv6.conf.default.accept_ra_defrtr = 0'
    'net.ipv6.conf.default.accept_ra = 0'
    'net.ipv6.conf.default.autoconf = 0'
    'net.ipv6.conf.default.dad_transmits = 0'
    'net.ipv6.conf.default.max_addresses = 1'
    'net.ipv6.conf.default.forwarding=0'
    'net.ipv6.conf.default.accept_source_route=0'
    'net.ipv6.conf.default.accept_redirects=0'
    'net.ipv6.conf.all.use_tempaddr=2'
    'net.ipv6.conf.all.max_addresses=1'
    'net.ipv6.conf.all.forwarding=0'
    'net.ipv6.conf.all.disable_ipv6=1'
    'net.ipv6.conf.all.dad_transmits=0'
    'net.ipv6.conf.all.autoconf=0'
    'net.ipv6.conf.all.accept_source_route=0'
    'net.ipv6.conf.all.accept_redirects=0'
    'net.ipv6.conf.all.accept_ra_rtr_pref=0'
    'net.ipv6.conf.all.accept_ra_pinfo=0'
    'net.ipv6.conf.all.accept_ra_defrtr=0'
    'net.ipv6.conf.all.accept_ra=0'
    'abi.vsyscall32=0'
    'crypto.fips_enabled=1'
    'dev.tty.ldisc_autoload=0'
    'dev.tty.legacy_tiocsti=0'
    'user.max_user_namespaces=0'
    )

    # Iterate through each configuration and modify the file
    for config in "${configurations[@]}"; do
    regex="^([^=[:space:]]+)"
    [[ $config =~ $regex ]]
    captured="${BASH_REMATCH[1]}"
    if grep -q "$captured" config_file; then
        sed -i "/$captured/c${config}" "$config_file"
    else
        echo "${config}" | sudo tee -a "$config_file"
    fi
    done

    # Change file to ufw
    config_file="/etc/ufw/sysctl.conf"
    # Iterate through each configuration and modify the file
    for config in "${configurations[@]}"; do
    regex="^([^=[:space:]]+)"
    [[ $config =~ $regex ]]
    captured="${BASH_REMATCH[1]}"
    if grep -q "$captured" config_file; then
        sed -i "/$captured/c${config}" "$config_file"
    else
        echo "${config}" | sudo tee -a "$config_file"
    fi
    done
    # Turns on lockdown
    echo "none integrity [confidentiality]" | sudo tee /sys/kernel/security/lockdown

    echo "Kernel has been hardened"
    sysctl -p
    echo "#" > /etc/init/control-alt-delete.conf
    systemctl disable ctrl-alt-del.target
    systemctl mask ctrl-alt-del.target
    echo "Ctrl Alt Del disabled"
    }

    networkConfig (){
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4\noptions dnssec\noptions edns0\noptions timeout:5\noptions attempts:3\noptions rotate" | sudo tee /etc/resolv.conf

    echo "127.0.0.1	localhost" > /etc/hosts
    echo "127.0.1.1	ubuntu"  >> /etc/hosts
    echo "::1     ip6-localhost ip6-loopback" >> /etc/hosts
    echo "fe00::0 ip6-localnet" >> /etc/hosts
    echo "ff00::0 ip6-mcastprefix" >> /etc/hosts
    echo "ff02::1 ip6-allnodes" >> /etc/hosts
    echo "ff02::2 ip6-allrouters" >> /etc/hosts
    echo "ALL: ALL" > /etc/hosts.deny

    # Think deprecated
    # echo -e "order bind,host\nmulti off\nnospoof on" > /etc/host.conf
    echo "IP spoofing prevention configuration completed."
    }

    systemdConfig (){
        # Logind Configuration
        echo -e '[Login]\nUserTasksMax=33%\nKillUserProcesses=yes\nKillOnlyUser=\nKillExcludeUsers=root\nSystemCallFilter=@cpu-emulation @debug\nIdleAction=lock\nIdleActionSec=5min\nRuntimeDirectoryPreserve=no\nRemoveIPC=yes\nAllowNAutoVTs=0' | sudo tee /etc/systemd/logind.conf

        # System Configuration
        echo -e "[Manager]\nLogLevel=debug\nLogTarget=journal-or-kmsg\nLogColor=yes\nLogLocation=yes\nLogTime=yes\nShowStatus=error\nDumpCore=no\nShowStatus=yes\nCrashChangeVT=yes\nCrashShell=no\nCrashReboot=no\nCtrlAltDelBurstAction=none\nCPUAffinity=1 2\nNUMAPolicy=local\nSystemCallArchitectures=native\nDumpCore=no\nCrashShell=no\nDefaultLimitCORE=0\nDefaultLimitNOFILE=1024" | sudo tee /etc/systemd/system.conf

        # OOM configuration
        echo -e '[OOM]\nSwapUsedLimit=10%\nDefaultMemoryPressureLimit=10%\nDefaultMemoryPressureDurationSec=30' | sudo tee /etc/systemd/oomd.conf

        # Resolved config 
        echo -e '[Resolve]\nDomains=~.\nDNS=1.1.1.1 1.0.0.1\nDNSOverTLS=yes\nFallbackDNS=8.8.8.8 8.8.4.4\nDNSSEC=yes\nLLMNR=no\nMulticastDNS=no\nCache=yes\nCacheMinSec=0\nCacheMaxSec=86400\nDNSStubListener=no' | sudo tee /etc/systemd/resolved.conf

        # Journald config
        echo -e "[Journal]\nForwardToSyslog=yes\nCompress=yes\nStorage=persistent\nAudit=yes\nSeal=yes\nSplitMode=uid" | sudo tee /etc/systemd/journald.conf

        # User config
        echo -e "[Manager]\nLogLevel=debug" | sudo tee /etc/systemd/user.conf

        # Pstore config
        echo -e "[PStore]\nUnlink=1" | sudo tee /etc/systemd/pstore.conf

        # CoreDumo config 
        echo -e "[Coredump]\nStorage=none\nProcessSizeMax=0" | sudo tee /etc/systemd/coredump.conf

        # logind hidepid
        echo -e "[Service]\nSupplementaryGroups=proc" > /etc/systemd/system/systemd-logind.service.d/hidepid.conf

        # limits config
        echo -e "*\tsoft\tcore\t0\n*\thard\tcore\t0\n\n*\tsoft\tdata\tunlimited\n*\thard\tdata\tunlimited\n\n*\tsoft\tfsize\t3000000\n*\thard\tfsize\t4000000\n\n*\tsoft\tmemlock\t256000\n*\thard\tmemlock\t512000\n\n*\tsoft\trss\t809600\n*\thard\trss\t1619200\n\n*\tsoft\tstack\t8192\n*\thard\tstack\t40960\n\n*\tsoft\tcpu\t1800\n*\thard\tcpu\t3600\n\n*\tsoft\tnproc\t1024\n*\thard\tnproc\t2048\n\n*\tsoft\tas\t256000\n*\thard\tas\t512000\n\n0:1000 hard maxlogins 0\n1000: hard maxlogins 1\n\n*\tsoft\tmaxsyslogins\t5\n*\thard\tmaxsyslogins\t10\n\n*\tsoft\tpriority\t0\n*\thard\tpriority\t0\n\n*\tsoft\tlocks\t256\n*\thard\tlocks\t512\n\n*\tsoft\tsigpending\t8192\n*\thard\tsigpending\t8192\n\n*\tsoft\tmsgqueue\t819200\n*\thard\tmsgqueue\t819200\n\n*\tsoft\tnice\t0\n*\thard\tnice\t0\n\n*\tsoft\trtprio\t0\n*\thard\trtprio\t0\n\n*\thard\tinotify\t1024\n*\tsoft\tinotify\t512\n\n*\tsoft\tnofile\t512\n*\thard\tnofile\t1024" | sudo tee /etc/security/limits.conf
    }

    securityTools (){
    # Install security tools
    apt purge ufw
    apt install -y clamav chkrootkit rkhunter apparmor debian-goodies rfkill ufw
    # UFW configuration
    ufw reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow http
    ufw allow https
    ufw logging on
    ufw logging full
    ufw enable
    ufw status
    systemctl enable ufw

    echo -e "IPV6=no\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\nDEFAULT_APPLICATION_POLICY=\"SKIP\"\nMANAGE_BUILTINS=no\nIPT_SYSCTL=/etc/sysctl.conf\nIPT_MODULES=\"\"" | sudo tee /etc/default/ufw

    ufw status verbose

    echo "Firewall enabled."
    rfkill block all
    echo "Installed security tools"
    # Enable rsyslog
    systemctl enable rsyslog
    systemctl start rsyslog
    # Sets secure permissions on all log files
    find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-wx,o-rwx "{}" +
    # Update ClamAV definitions
    freshclam
    # Run chkrootkit
    chkrootkit -q 
    # Update and run rkhunter
    # rkhunter --update
    # rkhunter --propupd
    # rkhunter -c --enable all --disable none
    
    # clamscan -ir 
    
    aa-enforce /etc/apparmor.d/*
    systemctl enable apparmor
    systemctl start apparmor
    systemctl start journald
    systemctl enable journald
    

    checkrestart
    which-pkg-broke

    systemctl enable apt-daily-upgrade.timer
    systemctl start apt-daily-upgrade.timer

    systemctl enable apt-daily.timer
    systemctl start apt-daily.timer

    systemctl enable update-notifier-motd.timer
    systemctl start update-notifier-motd.timer

    systemctl enable update-notifier-download.timer
    systemctl start update-notifier-download.timer

    # echo "Set MONITOR_ALL yes/nSet LOGFILE syslog" > /etc/samhain/samhainrc

    echo "Ran security tools"

    # Configure Auditd
    apt-get install -y auditd git

    # Enable Auditd
    auditctl -e 1

    # Configure /etc/audit/auditd.conf
    # Define the auditd configuration file path
    config_file="/etc/audit/auditd.conf"

    # Define an array of configurations to modify
    configurations=(
    'write_logs = yes'
    'log_file = /var/log/audit/audit.log'
    'max_log_file = 100000000000'
    'log_file_mode = 0640'
    'space_left = 100'
    'space_left_action = email'
    'action_mail_acct = root'
    'admin_space_left_action = halt'
    'max_log_file_action = keep_logs'
    'local_events = yes'
    )

    # Iterate through each configuration and modify the file
    for config in "${configurations[@]}"; do
    regex="^([^=[:space:]]+)"
    [[ $config =~ $regex ]]
    captured="${BASH_REMATCH[1]}"
    if grep -q "$captured" config_file; then
        sed -i "/$captured/c${config}" "$config_file"
    else
        echo "${config}" | sudo tee -a "$config_file"
    fi
    done

    # Restart Auditd
    systemctl enable auditd

    # Install Lynis
    cd /usr/local
    git clone https://github.com/CISOfy/lynis
    chown -R 0:0 /usr/local/lynis

    # Audit the system with Lynis
    cd /usr/local/lynis
    git pull
    ./lynis audit system

    echo "Scanning completed."

    # Look through /var/log/lynis-report.dat for warnings and suggestions
    grep -E 'warning|suggestion' /var/log/lynis-report.dat | sed -e 's/warning\[\]\=//g' | sed -e 's/suggestion\[\]\=//g'
    }


    malwareHunt (){
    # Root directory to start searching from
    SEARCH_DIR="/"

    # Directories to skip (system-critical directories that should not be altered)
    EXCLUDE_DIRS=(
        "/proc"
        "/dev"
        "/run"
        "/mnt"
        "/media"
        "/sys/module"
        "/boot"
        "/var/lib"
    )

    # Log file for tracking deletions
    LOG_FILE="/var/log/malware_hunt.log"

    # Function to safely remove suspicious files or directories with confirmation
    remove_suspicious_files() {
        local dir=$1

        for exclude in "${EXCLUDE_DIRS[@]}"; do
            if [[ "$dir" == "$exclude"* ]]; then
                return 0  # Skip this directory
            fi
        done

        echo "Scanning directory: $dir"

        # Patterns to detect suspicious files or directories
        declare -A patterns=(
            ["."]="Suspicious hidden directory"
            [".."]="Directory traversal pattern"
            ["./*"]="Suspicious prefix"
            ["*[^[:print:]]*"]="Non-printable characters"
        )

        for pattern in "${!patterns[@]}"; do
            find "$dir" -mindepth 1 -name "$pattern" 2>/dev/null | while read -r file; do
                echo "[!] ${patterns[$pattern]} found: $file"
                read -p "Do you want to delete it? (y/n): " answer
                if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
                    rm -rf "$file"
                    echo "Deleted: $file" | tee -a "$LOG_FILE"
                else
                    echo "Skipped: $file"
                fi
            done
        done
    }

    # Scan the system for suspicious files
    remove_suspicious_files "$SEARCH_DIR"

    # Additional checks
    echo "[+] Searching for potentially suspicious files and patterns..."

    # Detect "hehe" pattern in filenames
    find / -iname "*hehe*" 2>/dev/null

    # Check for hidden processes
    unhide-posix proc

    # Scan for suspicious network activity (e.g., netcat)
    sudo lsof -i -n | grep -E 'nc|netcat'

    # Check for OpenSSL abuse
    echo "Potentially suspicious OpenSSL processes:"
    ps aux | grep openssl | grep -v grep

    # Function to search for personally identifiable information (PII)
    search_for_pii() {
        local dir=$1
        echo "[+] Searching $dir for PII..."

        grep -arE "(\([0-9]{3}\) |[0-9]{3}-)[0-9]{3}-[0-9]{4}" "$dir" 2>/dev/null
        grep -arE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(com|org|net|edu|gov)' "$dir" 2>/dev/null
        grep -arE '[0-9]{3}-[0-9]{2}-[0-9]{4}' "$dir" 2>/dev/null
    }

    # Search common directories for PII
    search_for_pii "/home"
    search_for_pii "/var/www"

    # Check FTP configurations for potential PII exposure
    check_ftp_configs() {
        local config_file=$1
        local pattern=$2

        if [ -f "$config_file" ]; then
            echo "[+] Found $config_file. Checking for exposed directories..."
            local paths=$(grep -E "^$pattern" "$config_file" | awk '{print $2}')
            
            for path in $paths; do
                if [ -d "$path" ]; then
                    echo "[+] Checking $path for PII..."
                    search_for_pii "$path"
                fi
            done
        fi
    }

    check_ftp_configs "/etc/vsftpd.conf" "anon_root"
    check_ftp_configs "/etc/vsftpd.conf" "local_root"
    check_ftp_configs "/etc/proftpd/proftpd.conf" "DefaultRoot"

    # Check Samba shares for PII
    if [ -f /etc/samba/smb.conf ]; then
        echo "[+] Samba config found. Checking for shared paths..."
        shares=$(grep -E '^\s*path\s*=' /etc/samba/smb.conf | awk -F= '{print $2}' | sed 's/"//g' | xargs)
        
        for share in $shares; do
            if [ -d "$share" ]; then
                read -p "Check $share for PII? (y/n): " skip
                if [[ "$skip" != "y" ]]; then
                    search_for_pii "$share"
                fi
            fi
        done
    fi

    # Capabilities check for privilege escalation
    echo "[+] Checking for files with unusual capabilities..."
    for dir in "/usr/bin" "/usr/sbin"; do
        find "$dir" -type f -exec getcap {} + 2>/dev/null | grep -v "no capabilities set"
    done

    # Pause for manual review
    echo -n "Press any key to continue..."
    read -n 1 -s

    # Network review
    echo "Network connections overview:"
    lsof -i -n -P | grep -v "LISTEN"

    echo "[+] Malware detection script completed."
    }

    packagesAndServices (){
    sudo apt-mark unhold $(apt-mark showhold)
    sudo apt-get purge -y 0ad 0ad-data 0ad-data-common 2048-qt 3dchess 4digits 7kaa 7kaa-data a7xpg a7xpg-data aajm abe abe-data ace-of-penguins acm adanaxisgpl adanaxisgpl-data adonthell adonthell-data airstrike airstrike-common aisleriot alex4 alex4-data alien-arena alien-arena-data alien-arena-server alienblaster alienblaster-data allure amoebax amoebax-data amphetamine amphetamine-data an anagramarama anagramarama-data angband angband-audio angband-data angrydd animals antigravitaattori ardentryst armagetronad armagetronad-common armagetronad-dedicated asc asc-data asc-music asciijump assaultcube assaultcube-data astromenace astromenace-data-src asylum asylum-data atanks atanks-data atom4 atomix atomix-data attal attal-themes-medieval auralquiz balder2d balder2d-data ballerburg ballz ballz-data ballz-dbg bambam barrage bastet bb bear-factory beneath-a-steel-sky berusky berusky-data berusky2 berusky2-data between billard-gl billard-gl-data biloba biloba-data biniax2 biniax2-data black-box blobandconquer blobandconquer-data blobby blobby-data blobby-server bloboats blobwars blobwars-data blockattack blockout2 blocks-of-the-undead blocks-of-the-undead-data bombardier bomber bomberclone bomberclone-data boswars boswars-data bouncy bovo brainparty brainparty-data briquolo briquolo-data brutalchess bsdgames bsdgames-nonfree btanks btanks-data bubbros bucklespring bucklespring-data bugsquish bumprace bumprace-data burgerspace bve-route-cross-city-south bve-train-br-class-323 bve-train-br-class-323-3dcab bygfoot bygfoot-data bzflag bzflag-client bzflag-data bzflag-server cappuccino caveexpress caveexpress-data cavepacker cavepacker-data cavezofphear ceferino ceferino-data cgoban chessx childsplay childsplay-alphabet-sounds-bg childsplay-alphabet-sounds-ca childsplay-alphabet-sounds-de childsplay-alphabet-sounds-el childsplay-alphabet-sounds-en-gb childsplay-alphabet-sounds-es childsplay-alphabet-sounds-fr childsplay-alphabet-sounds-it childsplay-alphabet-sounds-nb childsplay-alphabet-sounds-nl childsplay-alphabet-sounds-pt childsplay-alphabet-sounds-ro childsplay-alphabet-sounds-ru childsplay-alphabet-sounds-sl childsplay-alphabet-sounds-sv chipw chocolate-common chocolate-doom chromium-bsu chromium-bsu-data circuslinux circuslinux-data colobot colobot-common colobot-common-sounds colobot-common-textures colorcode colossal-cave-adventure connectagram connectagram-data cookietool corsix-th corsix-th-data cowsay cowsay-off crack-attack crafty crafty-bitmaps crafty-books-medium crafty-books-medtosmall crafty-books-small crawl crawl-common crawl-tiles crawl-tiles-data crimson criticalmass criticalmass-data crossfire-client crossfire-client-images crossfire-client-sounds crossfire-common crossfire-maps crossfire-maps crossfire-maps-small crossfire-server crrcsim crrcsim-data csmash csmash-data csmash-demosong cube2 cube2-data cube2-server cultivation curseofwar cutemaze cuyo cuyo-data cyphesis-cpp cyphesis-cpp-clients cyphesis-cpp-mason cytadela cytadela-data d1x-rebirth d2x-rebirth dangen darkplaces darkplaces-server ddnet ddnet-data ddnet-server ddnet-tools dds deal dealer defendguin defendguin-data desmume deutex dhewm3 dhewm3-d3xp dhewm3-doom3 dizzy dodgindiamond2 dolphin-emu dolphin-emu-data doom-wad-shareware doomsday doomsday-common doomsday-data doomsday-server dopewars dopewars-data dossizola dossizola-data drascula drascula-french drascula-german drascula-italian drascula-music drascula-spanish dreamchess dreamchess-data dustracing2d dustracing2d-data dvorak7min dwarf-fortress dwarf-fortress-data eboard eboard-extras-pack1 edgar edgar-data efp einstein el-ixir ember ember-media empire empire-hub empire-lafe endless-sky endless-sky-data endless-sky-high-dpi enemylines3 enemylines7 enigma enigma-data epiphany epiphany-data etoys etqw etqw-server etw etw-data excellent-bifurcation extremetuxracer extremetuxracer-data exult exult-studio ezquake fairymax fb-music-high ffrenzy fgo fgrun fheroes2-pkg filler fillets-ng fillets-ng-data fillets-ng-data-cs fillets-ng-data-nl filters five-or-more fizmo-common fizmo-console fizmo-ncursesw fizmo-sdl2 flare flare-data flare-engine flare-game flight-of-the-amazon-queen flightgear flightgear-data-ai flightgear-data-all flightgear-data-base flightgear-data-models flightgear-phi flobopuyo fltk1.1-games fltk1.3-games foobillardplus foobillardplus-data fortunate.app fortune-anarchism fortune-mod fortune-zh fortunes fortunes-bg fortunes-bofh-excuses fortunes-br fortunes-cs fortunes-de fortunes-debian-hints fortunes-eo fortunes-eo-ascii fortunes-eo-iso3 fortunes-es fortunes-es-off fortunes-fr fortunes-ga fortunes-it fortunes-it-off fortunes-mario fortunes-min fortunes-off fortunes-pl fortunes-ru fortunes-spam fortunes-zh four-in-a-row freealchemist freecell-solver-bin freeciv freeciv-client-extras freeciv-client-gtk freeciv-client-gtk3 freeciv-client-qt freeciv-client-sdl freeciv-data freeciv-server freeciv-sound-standard freecol freedink freedink-data freedink-dfarc freedink-dfarc-dbg freedink-engine freedink-engine-dbg freedm freedoom freedroid freedroid-data freedroidrpg freedroidrpg-data freegish freegish-data freeorion freeorion-data freespace2 freespace2-launcher-wxlauncher freesweep freetennis freetennis-common freevial fretsonfire fretsonfire-game fretsonfire-songs-muldjord fretsonfire-songs-sectoid frogatto frogatto-data frotz frozen-bubble frozen-bubble-data fruit funguloids funguloids-data funnyboat gamazons game-data-packager game-data-packager-runtime gameclock gamine gamine-data garden-of-coloured-lights garden-of-coloured-lights-data gargoyle-free gav gav-themes gbrainy gcompris gearhead gearhead-data gearhead-sdl gearhead2 gearhead2-data gearhead2-sdl geekcode geki2 geki3 gemdropx gemrb gemrb-baldurs-gate gemrb-baldurs-gate-2 gemrb-baldurs-gate-2-data gemrb-baldurs-gate-data gemrb-data gemrb-icewind-dale gemrb-icewind-dale-2 gemrb-icewind-dale-2-data gemrb-icewind-dale-data gemrb-planescape-torment gemrb-planescape-torment-data geneatd gfceu gfpoken gl-117 gl-117-data glaurung glhack glob2 glob2-data glpeces glpeces-data gltron gmchess gmult gnome-2048 gnome-breakout gnome-cards-data gnome-chess gnome-games-app gnome-klotski gnome-mahjongg gnome-mastermind gnome-mines gnome-nibbles gnome-robots gnome-sudoku gnome-tetravex gnubg gnubg-data gnubik gnuboy-sdl gnuboy-x gnuchess gnuchess-book gnudoq gnugo gnujump gnujump-data gnuminishogi gnurobbo gnurobbo-data gnushogi golly gomoku.app gplanarity gpsshogi gpsshogi-data granatier granule gravitation gravitywars greed grhino grhino-data gridlock.app groundhog gsalliere gtans gtkballs gtkboard gtkpool gunroar gunroar-data gweled hachu hannah hannah-data hearse hedgewars hedgewars-data heroes heroes-data heroes-sound-effects heroes-sound-tracks hex-a-hop hex-a-hop-data hexalate hexxagon higan hitori hoichess holdingnuts holdingnuts-server holotz-castle holotz-castle-data holotz-castle-editor hyperrogue hyperrogue-music iagno icebreaker ii-esu infon-server infon-viewer instead instead-data ioquake3 ioquake3-server jag jag-data jester jigzo jigzo-data jmdlx jumpnbump jumpnbump-levels jzip kajongg kanagram kanatest kapman katomic kawari8 kball kball-data kblackbox kblocks kbounce kbreakout kcheckers kdegames-card-data kdegames-card-data-kf5 kdegames-mahjongg-data-kf5 kdiamond ketm ketm-data kfourinline kgoldrunner khangman kigo kiki-the-nano-bot kiki-the-nano-bot-data kildclient killbots kiriki kjumpingcube klickety klines kmahjongg kmines knavalbattle knetwalk knights kobodeluxe kobodeluxe-data kolf kollision komi konquest koules kpat krank kraptor kraptor-data kreversi kshisen ksirk ksnakeduel kspaceduel ksquares ksudoku ktuberling kubrick laby lambdahack late late-data lbreakout2 lbreakout2-data lgc-pg lgeneral lgeneral-data libatlas-cpp-0.6-tools libgemrb libmgba libretro-beetle-pce-fast libretro-beetle-psx libretro-beetle-vb libretro-beetle-wswan libretro-bsnes-mercury-accuracy libretro-bsnes-mercury-balanced libretro-bsnes-mercury-performance libretro-desmume libretro-gambatte libretro-genesisplusgx libretro-mgba libretro-mupen64plus libretro-nestopia libretro-snes9x lierolibre lierolibre-data lightsoff lightyears lincity lincity-ng lincity-ng-data liquidwar liquidwar-data liquidwar-server littlewizard littlewizard-data lmarbles lmemory lolcat londonlaw lordsawar lordsawar-data love lskat ltris lugaru lugaru-data luola luola-data luola-levels luola-nostalgy lure-of-the-temptress macopix-gtk2 madbomber madbomber-data maelstrom magicmaze magicor magicor-data magictouch mah-jong mame mame-data mame-extra manaplus manaplus-data mancala marsshooter marsshooter-data matanza mazeofgalious mazeofgalious-data mednafen mednaffe megaglest megaglest-data meritous meritous-data mgba-common mgba-qt mgba-sdl mgt miceamaze micropolis micropolis-data minetest minetest-data minetest-mod-advspawning minetest-mod-animalmaterials minetest-mod-animals minetest-mod-character-creator minetest-mod-craftguide minetest-mod-homedecor minetest-mod-maidroid minetest-mod-mesecons minetest-mod-mobf minetest-mod-mobf-core minetest-mod-mobf-trap minetest-mod-moreblocks minetest-mod-moreores minetest-mod-nether minetest-mod-pipeworks minetest-mod-player-3d-armor minetest-mod-quartz minetest-mod-torches minetest-mod-unifieddyes minetest-mod-worldedit minetest-server mirrormagic mirrormagic-data mokomaze monopd monsterz monsterz-data moon-buggy moon-lander moon-lander-data moria morris mousetrap mrboom mrrescue mttroff mu-cade mu-cade-data mudlet multitet mupen64plus-audio-all mupen64plus-audio-sdl mupen64plus-data mupen64plus-input-all mupen64plus-input-sdl mupen64plus-qt mupen64plus-rsp-all mupen64plus-rsp-hle mupen64plus-rsp-z64 mupen64plus-ui-console mupen64plus-video-all mupen64plus-video-arachnoid mupen64plus-video-glide64 mupen64plus-video-glide64mk2 mupen64plus-video-rice mupen64plus-video-z64 nestopia nethack-common nethack-console nethack-el nethack-lisp nethack-x11 netmaze netpanzer netpanzer-data netris nettoe neverball neverball-common neverball-data neverputt neverputt-data nexuiz nexuiz-data nexuiz-music nexuiz-server nexuiz-textures nikwi nikwi-data ninix-aya ninvaders njam njam-data noiz2sa noiz2sa-data nsnake nudoku numptyphysics ogamesim ogamesim-www omega-rpg oneisenough oneko onscripter open-adventure open-invaders open-invaders-data openarena openarena-081-maps openarena-081-misc openarena-081-players openarena-081-players-mature openarena-081-textures openarena-085-data openarena-088-data openarena-data openarena-oacmp1 openarena-server openbve-data opencity opencity-data openclonk openclonk-data openlugaru openlugaru-data openmw openmw-cs openmw-data openmw-launcher openpref openssn openssn-data openttd openttd-data openttd-opengfx openttd-openmsx openttd-opensfx opentyrian openyahtzee orbital-eunuchs-sniper orbital-eunuchs-sniper-data osmose-emulator out-of-order overgod overgod-data pachi pachi-data pacman pacman4console palapeli palapeli-data pangzero parsec47 parsec47-data passage pathogen pathological pax-britannica pax-britannica-data pcsx2 pcsxr peg-e peg-solitaire pegsolitaire penguin-command pente pentobi performous performous-tools pescetti petris pgn-extract phalanx phlipple phlipple-data pianobooster picmi pinball pinball-data pinball-dev pingus pingus-data pink-pony pink-pony-data pioneers pioneers-console pioneers-console-data pioneers-data pioneers-metaserver pipenightdreams pipenightdreams-data pipewalker piu-piu pixbros pixfrogger planarity planetblupi planetblupi-common planetblupi-music-midi planetblupi-music-ogg plee-the-bear plee-the-bear-data pokemmo-installer pokerth pokerth-data pokerth-server polygen polygen-data polyglot pong2 powder powermanga powermanga-data pq prboom-plus prboom-plus-game-server primrose projectl purity purity-ng purity-off pybik pybik-bin pybridge pybridge-common pybridge-server pykaraoke pykaraoke-bin pynagram pyracerz pyscrabble pyscrabble-common pyscrabble-server pysiogame pysolfc pysolfc-cardsets pysycache pysycache-buttons-beerabbit pysycache-buttons-crapaud pysycache-buttons-ice pysycache-buttons-wolf pysycache-click-dinosaurs pysycache-click-sea pysycache-dblclick-appleandpear pysycache-dblclick-butterfly pysycache-i18n pysycache-images pysycache-move-animals pysycache-move-food pysycache-move-plants pysycache-move-sky pysycache-move-sports pysycache-puzzle-cartoons pysycache-puzzle-photos pysycache-sounds python-pykaraoke python-renpy qgo qonk qstat qtads quadrapassel quake quake-server quake2 quake2-server quake3 quake3-data quake3-server quake4 quake4-server quakespasm quarry qxw rafkill rafkill-data raincat raincat-data randtype rbdoom3bfg redeclipse redeclipse-common redeclipse-data redeclipse-server reminiscence renpy renpy-demo renpy-thequestion residualvm residualvm-data ri-li ri-li-data ricochet rlvm robocode robotfindskitten rockdodger rocksndiamonds rolldice rott rrootage rrootage-data rtcw rtcw-common rtcw-server runescape salliere sandboxgamemaker sauerbraten sauerbraten-server scid scid-data scid-rating-data scid-spell-data scorched3d scorched3d-data scottfree scummvm scummvm-data scummvm-tools sdl-ball sdl-ball-data seahorse-adventures searchandrescue searchandrescue-common searchandrescue-data sgt-launcher sgt-puzzles shogivar shogivar-data simutrans simutrans-data simutrans-makeobj simutrans-pak128.britain simutrans-pak64 singularity singularity-music sjaakii sjeng sl slashem slashem-common slashem-gtk slashem-sdl slashem-x11 slimevolley slimevolley-data slingshot sludge-engine sm snake4 snowballz solarwolf sopwith spacearyarya spacezero speedpad spellcast sponc spout spring spring-common spring-javaai spring-maps-kernelpanic spring-mods-kernelpanic springlobby starfighter starfighter-data starvoyager starvoyager-data stax steam steam-devices steam-installer steamcmd stockfish stormbaancoureur stormbaancoureur-data sudoku supertransball2 supertransball2-data supertux supertux-data supertuxkart supertuxkart-data swell-foop tagua tagua-data tali tanglet tanglet-data tatan tdfsb tecnoballz tecnoballz-data teeworlds teeworlds-data teeworlds-server tenace tenmado tennix tetrinet-client tetrinet-server tetrinetx tetzle tf tf5 tictactoe-ng tint tintin++ tinymux titanion titanion-data toga2 tomatoes tomatoes-data tome toppler torcs torcs-data torus-trooper torus-trooper-data tourney-manager trackballs trackballs-data transcend treil trigger-rally trigger-rally-data triplane triplea trophy trophy-data trophy-dbg tumiki-fighters tumiki-fighters-data tuxfootball tuxmath tuxmath-data tuxpuck tuxtype tuxtype-data tworld tworld-data typespeed uci2wb ufoai ufoai-common ufoai-data ufoai-maps ufoai-misc ufoai-music ufoai-server ufoai-sound ufoai-textures uhexen2 uhexen2-common uligo unknown-horizons uqm uqm-content uqm-music uqm-russian uqm-voice val-and-rick val-and-rick-data vbaexpress vcmi vectoroids viruskiller visualboyadvance vodovod vor warmux warmux-data warmux-servers warzone2100 warzone2100-data warzone2100-music werewolf wesnoth wesnoth-1.12 wesnoth-1.12-aoi wesnoth-1.12-core wesnoth-1.12-data wesnoth-1.12-did wesnoth-1.12-dm wesnoth-1.12-dw wesnoth-1.12-ei wesnoth-1.12-httt wesnoth-1.12-l wesnoth-1.12-low wesnoth-1.12-music wesnoth-1.12-nr wesnoth-1.12-server wesnoth-1.12-sof wesnoth-1.12-sotbe wesnoth-1.12-thot wesnoth-1.12-tools wesnoth-1.12-trow wesnoth-1.12-tsg wesnoth-1.12-ttb wesnoth-1.12-utbs wesnoth-core wesnoth-music wfut whichwayisup widelands widelands-data wing wing-data wizznic wizznic-data wmpuzzle wolf4sdl wordplay wordwarvi wordwarvi-sound xabacus xabacus xball xbill xblast-tnt xblast-tnt-images xblast-tnt-levels xblast-tnt-models xblast-tnt-musics xblast-tnt-sounds xboard xbomb xbubble xbubble-data xchain xcowsay xdemineur xdesktopwaves xevil xfireworks xfishtank xflip xfrisk xgalaga xgalaga++ xgammon xinv3d xjig xjokes xjump xletters xmabacus xmahjongg xmille xmoto xmoto-data xmountains xmpuzzles xonix xpat2 xpenguins xphoon xpilot-extra xpilot-ng xpilot-ng-client-sdl xpilot-ng-client-x11 xpilot-ng-common xpilot-ng-server xpilot-ng-utils xpuzzles xqf xracer xracer-tools xscavenger xscorch xscreensaver-screensaver-dizzy xshisen xshogi xskat xsok xsol xsoldier xstarfish xsystem35 xteddy xtron xvier xwelltris xye xye-data xzip yahtzeesharp yamagi-quake2 yamagi-quake2-core zangband zangband-data zatacka zaz zaz-data zec zivot zoom-player gameconqueror
    sudo apt-get purge -y acfax aldo ampr-ripd antennavis aprsdigi aprx ax25-apps ax25-tools ax25-xtools ax25mail-utils axmail baycomepp baycomusb chirp comptext comptty cqrlog cubicsdr cutesdr cw cwcp cwdaemon d-rats dablin direwolf ebook2cw ebook2cwgui fbb fccexam flamp fldigi flmsg flrig flwrap freedv glfer gnss-sdr gnuais gnuaisgui gpredict gqrx-sdr grig gsmc hamexam hamfax icom inspectrum klog libecholib1.3 libfap6 libhamlib-utils limesuite linpac linpsk lysdr morse morse-x morse2ascii multimon nec2c owx p10cfgd predict predict-gsat psk31lx pydxcluster pyqso qrq qsstv qtel qtel-icons quisk remotetrx soapyosmo-common0.6 soapyremote-server soapysdr-module-airspy soapysdr-module-all soapysdr-module-audio soapysdr-module-bladerf soapysdr-module-hackrf soapysdr-module-lms7 soapysdr-module-mirisdr soapysdr-module-osmosdr soapysdr-module-redpitaya soapysdr-module-remote soapysdr-module-rfspace soapysdr-module-rtlsdr soapysdr-module-uhd soapysdr-tools soapysdr0.6-module-airspy soapysdr0.6-module-all soapysdr0.6-module-audio soapysdr0.6-module-bladerf soapysdr0.6-module-hackrf soapysdr0.6-module-lms7 soapysdr0.6-module-mirisdr soapysdr0.6-module-osmosdr soapysdr0.6-module-redpitaya soapysdr0.6-module-remote soapysdr0.6-module-rfspace soapysdr0.6-module-rtlsdr soapysdr0.6-module-uhd soundmodem splat svxlink-calibration-tools svxlink-gpio svxlink-server svxreflector tk2 tk5 tlf trustedqsl tucnak twclock twpsk uhd-soapysdr uronode wsjtx wwl xastir xcwcp xdemorse xdx xlog xlog-data xnec2c xnecview yagiuda z8530-utils2  
    sudo apt-get purge -y akqml bino browser-plugin-gnash browser-plugin-vlc cclive crtmpserver crtmpserver-apps crtmpserver-dev crtmpserver-libs deepin-movie dtv-scan-tables dumphd dvblast dvbstreamer dvdrip-utils ffmpeg flowblade flvmeta freetuxtv frei0r-plugins get-flash-videos gmlive gnash-common-opengl gnash-ext-fileio gnash-ext-lirc gnash-ext-mysql gnash-opengl gnome-dvb-client gnome-dvb-daemon gnome-mpv gnome-twitch gnome-twitch-player-backend-gstreamer-cairo gnome-twitch-player-backend-gstreamer-clutter gnome-twitch-player-backend-gstreamer-opengl gnome-twitch-player-backend-mpv-opengl grilo-plugins-dvb-daemon growisofs gst123 gstreamer1.0-crystalhd h264enc hdmi2usb-fx2-firmware i965-va-driver i965-va-driver-shaders imagination imagination-common kazam klash-opengl kodi kodi-bin kodi-data kodi-eventclients-common kodi-eventclients-kodi-send kodi-eventclients-ps3 kodi-eventclients-wiiremote kodi-pvr-hts kodi-repository-kodi kylin-video libaacs0 libde265-examples libdvbcsa1 libffmpegthumbnailer4v5 libheif-examples libqtav1 libqtavwidgets1 libtotem0 libvlc-bin libxine2-xvdr lives-plugins livestreamer m2vrequantiser mediathekview mencoder minitube mjpegtools-gtk mplayer mplayer-gui mpv multicat nageru nomnom nordlicht obs-plugins obs-studio oggvideotools ogmrip-dirac ogmrip-oggz ogmrip-plugins openalpr openalpr-daemon openshot openshot-qt photofilmstrip qml-module-qtav qstopmotion qtav-players ser-player shotdetect simplescreenrecorder smplayer-l10n smtube sreview-common sreview-detect sreview-encoder sreview-master sreview-web streamlink subliminal-nautilus swfdec-gnome swfdec-mozilla tablet-encode transcode transmageddon tsdecrypt tvnamer va-driver-all vdpau-driver-all vdr-plugin-dvbhddevice vdr-plugin-dvbsddevice vdr-plugin-epgsync vdr-plugin-osdteletext vdr-plugin-satip vdr-plugin-skinenigmang vdr-plugin-softhddevice vdr-plugin-svdrpext vdr-plugin-svdrpext vdr-plugin-svdrposd vdr-plugin-vnsiserver vlc-bin vlc-plugin-access-extra vlc-plugin-base vlc-plugin-fluidsynth vlc-plugin-notify vlc-plugin-qt vlc-plugin-samba vlc-plugin-skins2 vlc-plugin-svg vlc-plugin-video-output vlc-plugin-video-splitter vlc-plugin-visualization vlc-plugin-vlsub vlc-plugin-zvbi voctomix voctomix-core voctomix-gui voctomix-outcasts vokoscreen webcamoid webcamoid-data webcamoid-plugins winff-data winff-gtk2 winff-qt x265 xbmc-pvr-argustv xbmc-pvr-dvbviewer xbmc-pvr-iptvsimple xbmc-pvr-mediaportal-tvserver xbmc-pvr-mythtv-cmyth xbmc-pvr-nextpvr xbmc-pvr-njoy xbmc-pvr-tvheadend-hts xbmc-pvr-vdr-vnsi xbmc-pvr-vuplus xbmc-pvr-wmc xvidenc totem*
    
    # Stop and disable services
    systemctl stop avahi-daemon
    systemctl disable avahi-daemon
    systemctl stop 'cups*'
    systemctl disable 'cups*'
    systemctl stop slapd
    systemctl disable slapd
    systemctl stop rpcbind
    systemctl disable rpcbind
    systemctl stop named
    systemctl disable named
    systemctl stop httpd
    systemctl disable httpd
    systemctl stop dovecot
    systemctl disable dovecot
    systemctl stop squid
    systemctl disable squid
    systemctl stop rsyncd
    systemctl disable rsyncd
    systemctl stop rsync
    systemctl disable rsync
    systemctl stop ypserv
    systemctl disable ypserv
    systemctl stop 'irc*'
    systemctl disable 'irc*'
    systemctl list-units --type=service 
    echo "Look for anything suspicious above"
    ll /var/lib/snapd/snaps/
    echo "Look for anything suspicious above"

        # Configuration
        CRITICAL_PACKAGES=(
            "perl" "curl" "python3" "systemd" "apt" "dpkg" "bash" "coreutils"
            "grep" "sed" "gawk" "util-linux" "mount" "login" "passwd" "adduser"
        )

        # Set up logging directory
        SCRIPT_DIR="/var/log/security-cleanup"
        LOG_FILE="$SCRIPT_DIR/security-cleanup.log"

        # Create logging directory with proper permissions
        setup_logging() {
            mkdir -p "$SCRIPT_DIR"
            touch "$LOG_FILE"
            chmod 750 "$SCRIPT_DIR"
            chmod 640 "$LOG_FILE"
        }

        printTime() {
            echo "[$(date +%T)] $1" | tee -a "$LOG_FILE"
        }

        fix_dpkg() {
            log "Fixing potential dpkg interruptions..." yellow
            dpkg --configure -a
            apt-get update -qq
            apt-get install -f -y -qq
        }

        is_critical_package() {
            local package="$1"
            for critical in "${CRITICAL_PACKAGES[@]}"; do
                if [[ "$package" == "$critical" ]]; then
                    return 0
                fi
            done
            return 1
        }

        is_package_installed() {
            local package="$1"
            dpkg -l "$package" 2>/dev/null | grep -q "^ii.*$package "
            return $?
        }

        remove_package_suite() {
            local title="$1"
            shift
            local packages=("$@")
            local removal_failed=0
            
            # Ask user for confirmation
            read -p "Are you sure you want to remove $title? (y/n): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log "Aborted. No packages were removed." yellow
                return 0
            fi

            log "Removing $title..." yellow
            for pkg in "${packages[@]}"; do
                if is_package_installed "$pkg"; then
                    if DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$pkg"; then
                        log "Removed $pkg" green
                    else
                        log "Failed to remove $pkg" red
                        removal_failed=1
                    fi
                fi
            done

            if [ $removal_failed -eq 1 ]; then
                log "Some packages in $title failed to remove. Running dpkg fix..." yellow
                fix_dpkg
            else
                log "$title has been removed." green
            fi
        }

        check_hacking_tools() {
            log "Checking for remaining hacking tools..." yellow
            dpkg -l | egrep "crack|hack" >> "$LOG_FILE" 2>&1 || true
            log "Hacking tools check completed and logged to $LOG_FILE" green
        }

        remove_security_tools() {
            # Create groups of related packages
            local netcat_packages=(
                "netcat" "netcat-openbsd" "netcat-traditional" "ncat"
                "pnetcat" "socat" "sock" "socket" "sbd" "cryptcat" "nc"
            )
            
            local cracking_tools=(
                "john" "john-data" "hydra" "hydra-gtk" "aircrack-ng"
                "fcrackzip" "lcrack" "ophcrack" "ophcrack-cli" "pdfcrack"
                "pyrit" "rarcrack" "sipcrack" "irpas" "hashcat" "sqlmap"
                "wifite" "yersinia" "pixiewps" "bbqsql" "reaver"
                "slowhttptest" "ssldump" "sslstrip" "thc-ipv6" "cupp3"
                "truecrack" "medusa" "nikto" "sucrack" 
            )

            local zeitgeist_packages=(
                "zeitgeist-core" "zeitgeist-datahub" "python-zeitgeist"
                "rhythmbox-plugin-zeitgeist" "zeitgeist"
            )

            local additional_packages=(
                "filebeat"
                "logstash"
                "samba"
                "ssh"
                "dovecot"
                "postfix"
                "endless-sky"
                "apache2"
                "wireshark"
                "nmap"
                "zmap"
                "kismet"
                "networkminer"
                "ettercap"
                "4g8"
                "acccheck"
                "airgraph-ng"
                "bittornado"
                "bluemon"
                "btscanner"
                "brutespray"
                "hunt"
                "nast"
                "python-scapy"
                "sipgrep"
                "tcpick"
                "tcpreplay"
                "tcpslice"
                "tcptrace"
                "tcptraceroute"
                "tcpxtract"
                "mdk3"
                "darkstat"
                "flowscan"
                "ntopng"
                "ostinato"
                "softflowd"
                "tshark"
                "rfdump"
                "heartbleeder"
                "cmospwd"
                "irc"
                "hexchat"
                "irssi"
                "weechat"
                "xchat"
                "konversation"
                "eggdrop"
                "bitchx"
                "pirc"
                "vuze"
                "frostwire"
                "freeciv"
                "minetest"
                "tightvncserver"
                "x11vnc"
                "nfs"
                "xinetd"
                "smb"
                "postgresql"
                "sftpd"
                "vsftpd"
                "ftp"
                "mysql"
                "php"
                "snmp"
                "pop3"
                "icmp"
                "sendmail"
                "bind9"
                "nginx"
                "telnet"
                "rlogind"
                "rshd"
                "rcmd"
                "rexecd"
                "rbootd"
                "rquotad"
                "rstatd"
                "rusersd"
                "rwalld"
                "rexd"
                "fingerd"
                "tftpd"
                "logkeys"
                "dns"
                "xserver-xorg"
                "ypbind"
                "talk"
                "openldap-clients"
                "tcpdump"
                "snort"
                "fwsnort"
                "nessus"
                "traceroute"
                "httrack"
                "openvas"
                "torrent"
                "sniff"
                "bluetooth"
                "remmina"
                "linuxdcpp"
                "bro"
                "jellyfin"
                "anydesk"
                "teamviewer"
                "burpsuite"
                "deluge"
                "chromium"
                "powershell"
                "dsniff"
                "qbittorrent"
                "metasploit-framework"
                "teamspeak"
            )

            # Create backup
            local backup_file="/root/package-list-backup-$(date +%Y%m%d-%H%M%S).txt"
            log "Creating backup of current package list to $backup_file..." green
            dpkg --get-selections > "$backup_file"
            
            # Fix any existing dpkg issues before starting
            fix_dpkg
            
            # Remove package suites
            remove_package_suite "Netcat and related packages" "${netcat_packages[@]}"
            remove_package_suite "Cracking tools" "${cracking_tools[@]}"
            remove_package_suite "Zeitgeist packages" "${zeitgeist_packages[@]}"
            remove_package_suite "Additional security tools" "${additional_packages[@]}"
            
            # Remove nc binary if it exists
            if [ -f /usr/bin/nc ]; then
                rm -f /usr/bin/nc
                log "Removed nc binary" green
            fi
            
            # Final dpkg fix
            fix_dpkg
            
            # Check for remaining hacking tools
            # check_hacking_tools
        }

        cleanup() {
            # Compress log file if it exists
            if [ -f "$LOG_FILE" ]; then
                gzip -f "$LOG_FILE"
                log "Log file has been compressed to ${LOG_FILE}.gz" green
            fi
        }

        main() {
            check_root
            setup_logging
            
            # Initialize log file
            echo "=== Security Cleanup Script Log $(date) ===" > "$LOG_FILE"
            
            # Trap for cleanup on script exit
            trap cleanup EXIT
            
            remove_security_tools
            
            log "Package cleanup completed." green
            log "Log file has been saved to: $LOG_FILE" green
            log "If you experience any issues, you can reinstall packages using the backup created at the start." yellow
        }
        main
    }

    userAudit() {
    # Validate username function
    validate_username() {
        local username="$1"
        # Linux-specific username requirements
        if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] ||
        [[ "$username" =~ ^(root|daemon|bin|sys|system|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|_apt|admin)$ ]]; then
            log "Invalid username format or reserved username: $username" red
            return 1
        fi
        return 0
    }

    # Define special accounts and their specific shells
    declare -A SPECIAL_ACCOUNTS=(
        ["root"]="/bin/bash"
        ["bin"]="/usr/sbin/nologin"
        ["daemon"]="/bin/false"
        ["sync"]="/bin/sync"
        ["shutdown"]="/sbin/shutdown"
        ["halt"]="/sbin/halt"
        ["ftp"]="/usr/sbin/nologin"
        ["nobody"]="/usr/sbin/nologin"
        ["sshd"]="/usr/sbin/nologin"
    )

    # Secure hashing algorithms
    SECURE_HASHES=("6" "y") # SHA-512 ($6$) and yescrypt ($y$)

    check_root

    local FILE="correct.txt"
    local DEFAULT_PASSWORD="CyberPatriot101#!"

    # Read file content and replace newlines with spaces
    local readmeContent=$(cat "$FILE" | tr '\n' ' ')

    # Extract Authorized Administrators
    local result=$(echo "$readmeContent" | awk -F 'Authorized Administrators:' '{print $2}' | awk -F 'Authorized Users:' '{print $1}' | xargs)
    log "Authorized Administrators: $result" yellow

    # Turn to array
    read -ra correctAdmins <<< "$result"

    # Extract Authorized Users
    result=$(echo "$readmeContent" | awk -F 'Authorized Users:' '{print $2}' | xargs) 
    log "Authorized Users: $result" yellow

    # Turn to array
    read -ra correctUsers <<< "$result"

    # Validate usernames
    for admin in "${correctAdmins[@]}"; do
        if ! validate_username "$admin"; then
            log "Invalid administrator username detected. Aborting." red
            return 1
        fi
    done

    for user in "${correctUsers[@]}"; do
        if ! validate_username "$user"; then
            log "Invalid user username detected. Aborting." red
            return 1
        fi
    done

    # Remove whitespace from each element in the arrays
    for i in "${!correctAdmins[@]}"; do
        correctAdmins[i]=$(echo "${correctAdmins[i]}" | tr -d '[:space:]')
    done

    for i in "${!correctUsers[@]}"; do
        correctUsers[i]=$(echo "${correctUsers[i]}" | tr -d '[:space:]')
    done

    # Get a list of all local users
    local currentUsers=($(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd))

    # Get a list of all admins
    local currentAdmins=($(grep '^sudo:.*$' /etc/group | awk -F: '{print $4}' | tr ',' ' '))

    # Combine valid users
    local validUsers=("${correctUsers[@]}" "${correctAdmins[@]}")

    # Add new users
    for user in "${correctUsers[@]}"; do
        if [[ ! " ${currentUsers[@]} " =~ " $user " ]]; then
            useradd "$user" --disabled-password --gecos ""
            log "Added user: $user" yellow
        fi
    done

    # Add new admins or convert existing users to admins
    for admin in "${correctAdmins[@]}"; do    
        if [[ ! " ${currentAdmins[@]} " =~ " $admin " ]]; then
            if [[ " ${currentUsers[@]} " =~ " $admin " ]]; then
                usermod -aG sudo "$admin"
                log "Converted user to admin: $admin" yellow
            else
                useradd -m -p "$(openssl passwd -6 "$DEFAULT_PASSWORD")" "$admin"
                usermod -aG sudo "$admin"
                log "Added admin: $admin" yellow
            fi
        fi
    done

    # Remove unauthorized users
    for user in "${currentUsers[@]}"; do
        if [[ ! " ${validUsers[@]} " =~ " $user " ]]; then
            deluser --remove-home "$user" 2>/dev/null
            log "Deleted user and their files: $user" yellow
        fi
    done

    # Remove unauthorized admins
    for admin in "${currentAdmins[@]}"; do
        if [[ ! " ${correctAdmins[@]} " =~ " $admin " ]]; then
            if [[ " ${correctUsers[@]} " =~ " $admin " ]]; then
                deluser "$admin" sudo
                log "Converted admin to user: $admin" yellow
            else
                deluser --remove-home "$admin"
                log "Removed admin: $admin" yellow
            fi
        fi
    done

    # Password and account management for admins
    for admin in "${correctAdmins[@]}"; do
        # Set min and max days for password change
        chage -m 15 -M 60 "$admin"
        # Set the account inactivity period
        chage -I 5 "$admin"
        # Set password expiration warning days
        chage -W 7 "$admin"
        
        # Set password
        echo "$admin:$DEFAULT_PASSWORD" | sudo chpasswd
        
        # Ensure account is unlocked
        if passwd -S "$admin" | grep -q "L"; then
            passwd -u "$admin"
        fi 

        # Ensure bash shell
        chsh -s /bin/bash "$admin"
    done

    # Password and account management for users
    for user in "${correctUsers[@]}"; do 
        # Set min and max days for password change
        chage -m 15 -M 60 "$user"
        # Set the account inactivity period
        chage -I 5 "$user"
        # Set password expiration warning days
        chage -W 7 "$user"
        
        # Set password
        echo "$user:$DEFAULT_PASSWORD" | sudo chpasswd
        
        # Ensure account is unlocked
        if passwd -S "$user" | grep -q "L"; then
            passwd -u "$user"
        fi   

        # Ensure bash shell
        chsh -s /bin/bash "$user"
    done

    # Additional security checks

    # Check for missing groups
    local missing_groups=()
    for gid in $(awk -F: '{print $4}' /etc/passwd | sort -u); do
        if ! grep -q -P "^[^:]*:[^:]*:$gid:" /etc/group; then
            missing_groups+=("$gid")
        fi
    done

    if [ ${#missing_groups[@]} -gt 0 ]; then
        for group in "${missing_groups[@]}"; do
            log "Group $group is referenced in /etc/passwd but does not exist in /etc/group." red
        done
    fi

    # Check for duplicate UIDs, GIDs, and usernames
    awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read -r uid; do
        users=$(awk -F: -v uid="$uid" '($3 == uid) {print $1}' /etc/passwd | xargs)
        log "Duplicate UID ($uid): $users" red
    done

    awk -F: '{print $3}' /etc/group | sort | uniq -d | while read -r gid; do
        groups=$(awk -F: -v gid="$gid" '($3 == gid) {print $1}' /etc/group | xargs)
        log "Duplicate GID ($gid): $groups" red
    done

    cut -d":" -f1 /etc/passwd | sort | uniq -d | while read -r username; do
        uids=$(awk -F: -v name="$username" '($1 == name) { print $3 }' /etc/passwd | xargs)
        log "Duplicate Username ($username): UIDs $uids" red
    done

    # Shadow group check
    if grep -q "^shadow:" /etc/group; then
        local shadow_users=$(grep "^shadow:" /etc/group | cut -d: -f4)
        if [ -n "$shadow_users" ]; then
            log "Warning: The 'shadow' group is not empty. Users: $shadow_users" red
        fi
    else
        log "Error: The 'shadow' group does not exist." red
    fi

    # Hash algorithm security check
    log "Checking /etc/shadow for secure hashing algorithms..." yellow
    for username in "${validUsers[@]}"; do
        local userLine=$(grep "^$username:" /etc/shadow)
        
        if [[ -z $userLine ]]; then
            log "User '$username' not found in /etc/shadow." yellow
            continue
        fi

        IFS=: read -r _ password _ <<< "$userLine"

        if [[ -z $password || $password == "!" || $password == "*" ]]; then
            log "User '$username' has no password or the account is locked." yellow
            continue
        fi

        local hash_algo=$(echo "$password" | awk -F'$' '{print $2}')
        
        if [[ -n $hash_algo && ! " ${SECURE_HASHES[*]} " =~ " $hash_algo " ]]; then
            log "Insecure hashing algorithm found for user '$username': \$${hash_algo}\$" red
        fi
    done

    # Home directory management
    for user in "${validUsers[@]}"; do
        local home_dir="/home/$user"
        if [ ! -d "$home_dir" ]; then
            mkdir -m 700 "$home_dir"
            chown "$user:$user" "$home_dir"
            log "Created home directory for $user" green
        else
            chmod 700 "$home_dir"
            chown "$user:$user" "$home_dir"
        fi
    done

    # Lock and set shells for special and non-special accounts
    local all_users=$(getent passwd | awk -F: '{print $1}')
    for user in $all_users; do
        if [[ -n "${SPECIAL_ACCOUNTS[$user]}" ]]; then
            passwd -l "$user"
            local current_shell=$(getent passwd "$user" | cut -d: -f7)
            if [[ "$current_shell" != "${SPECIAL_ACCOUNTS[$user]}" ]]; then
                chsh -s "${SPECIAL_ACCOUNTS[$user]}" "$user"
                log "Shell for special account '$user' changed from '$current_shell' to '${SPECIAL_ACCOUNTS[$user]}'." yellow
            fi
        else
            if [[ ! " ${validUsers[@]} " =~ " $user " ]]; then
                passwd -l "$user"
                local current_shell=$(getent passwd "$user" | cut -d: -f7)
                if [[ "$current_shell" != "/bin/false" && "$current_shell" != "/usr/sbin/nologin" ]]; then
                    chsh -s "/bin/false" "$user"
                    log "Shell for user '$user' changed to /bin/false." yellow
                fi
            fi
        fi
    done

    log "User audit and management complete." green
}

    upgradeAndUpdate() {
    # unhold packages
    apt-mark unhold $(apt-mark showhold)

    # Update package lists
    apt-get update 

    # Upgrade installed packages
    apt-get upgrade 

    # Perform a distribution upgrade
    # apt-get dist-upgrade -qq -y

    # Install unattended-upgrades if not already installed
    apt-get install -y unattended-upgrades
    dpkg-reconfigure unattended-upgrades 

    echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"7\";" > /etc/apt/apt.conf.d/10periodic

    echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/20auto-upgrades

    # Edit /etc/apt/apt.conf.d/50auto-upgrades using sed
    # sed -i '1s//Unattended-Upgrade::Allowed-Origins {\n"\${distro_id} stable";\n"\${distro_id} \${distro_codename}-security";\n"\${distro_id} \${distro_codename}-updates";\n};\n\n/' /etc/apt/apt.conf.d/50auto-upgrades

    # echo 'APT::Periodic::Update-Package-Lists "1"; APT::Periodic::Download-Upgradeable-Packages "1"; APT::Periodic::AutocleanInterval "7"; APT::Periodic::Unattended-Upgrade "1"; APT::Periodic::Verbose "3"; APT::Periodic::RandomSleep "1800"; APT::Periodic::Unattended-Upgrade::Automatic-Reboot "0"; APT::Sandbox::Seccomp "true"; APT::Sandbox::ResetEnvironment "true"; APT::Get::AllowUnauthenticated "false"; Acquire::ForceHash "sha256"; Acquire::AllowInsecureRepositories "0"; Acquire::AllowDowngradeToInsecureRepositories "0"; Acquire::AllowWeakRepositories "0"; Unattended-Upgrade::Remove-Unused-Dependencies "true"; Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"; Unattended-Upgrade::Allowed-Origins { "${distro_id} stable"; "${distro_id} ${distro_codename}-security"; "${distro_id} ${distro_codename}-updates"; }; Unattended-Upgrade::Automatic-Reboot "false"; APT::Periodic::AutocleanInterval "1";' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades 

    echo "Automatic updates have been enabled."
    echo "Unattended upgrades configuration completed."

    apt list --installed | grep upgradable
    }

    # Function to display the menu
    display_menu() {
    echo "----------------------------------------------------------"
    echo "| 0. Quit                   | 1. Upgrade and Update      |"
    echo "| 2. Delete Files           | 3. Set Permissions         |"
    echo "| 4. Baseline Extensions    | 5. User Auditing           |"
    echo "| 6. Password Policies      | 7. Packages & Services     |"
    echo "| 8. Harden Kernel          | 9. Sudoers Config          |"
    echo "| 10. Prevent Cron Jobs     | 11. LightDM Config         |"
    echo "| 12. GDM3 Config           | 13. GNOME Settings         |"
    echo "| 14. GRUB Config           | 15. Network Config         |"
    echo "| 16. Systemd Config        | 17. Security Tools         |"
    echo "| 18. Malware Hunt          | 19. Quit                   |"
    echo "----------------------------------------------------------"
    echo "\nFunctions in Progress: 4. Baseline Extensions, 14. Grub Config, 18. Malware Hunt"
    }


    execute_method() {
    case $1 in
        0) echo "Exiting script. Goodbye!"; exit ;;
        1) upgradeAndUpdate ;;
        2) deleteFiles ;;
        3) setPermissions ;;
        4) baselineExt ;;
        5) userAudit ;; 
        6) passwordPolicies;;
        7) packagesAndServices ;;
        8) kernelHarden ;;
        9) sudoersConfig ;;
        10) preventCronJobs ;;
        11) lightDMConfig ;;
        12) gdm3Config ;;
        13) gnomeSettings ;; 
        14) grubConfig ;;
        15) networkConfig ;;
        16) systemdConfig ;;
        17) securityTools ;;
        18) malwareHunt ;;
        19) echo "Exiting script. Goodbye!"; exit ;;
        *) echo "Invalid choice. Please enter a valid number." ;;
    esac
    }

    # Main script
    while true; do
    display_menu
    read -p "Enter the number of the method (or 0 to quit): " choice

    if [[ $choice == 0 ]]; then
        echo "Exiting script. Goodbye!"
        exit
    elif [[ $choice =~ ^[1-9][0-9]*$ && $choice -le 44 ]]; then
        execute_method "$choice"
    else
        echo "Invalid input. Please enter a valid number."
    fi
    done



