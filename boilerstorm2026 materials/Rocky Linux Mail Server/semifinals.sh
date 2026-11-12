#!/usr/bin/env bash
# ==============================================================================
# Rocky Linux CCDC Mail Server Security Baseline & Auditing Script
# Target OS: Rocky Linux 8 / 9 (RHEL-compatible)
# System Role: Mail Server (Postfix / Dovecot / Sendmail / Exim / Webmail)
# Design: Audit-First, Conservative Hardening, Idempotent, Mail-Safe
# ==============================================================================

set -o pipefail

# ==============================================================================
# 1. INITIALIZATION, CONFIGURATION & BASELINE VARIABLES
# ==============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly LOG_DIR="/var/log/ccdc_hardening"
readonly LOG_FILE="${LOG_DIR}/baseline_${TIMESTAMP}.log"
readonly BACKUP_ROOT="/var/backups/ccdc_hardening/${TIMESTAMP}"
readonly USER_ROSTER_FILE="${SCRIPT_DIR}/users.txt"
readonly SYSCTL_DROPIN="/etc/sysctl.d/99-ccdc-mail-baseline.conf"
readonly SUDOERS_DROPIN="/etc/sudoers.d/99-ccdc-baseline"

# Global Execution Mode:1 = Dry-Run (No changes applied), 0 = Live Mode
DRY_RUN=1

# Protected Mail & Infrastructure Services (Never auto-disable or purge)
readonly PROTECTED_SERVICES=(
    "sshd" "firewalld" "NetworkManager" "systemd-journald" "rsyslog" "crond"
    "postfix" "dovecot" "sendmail" "exim" "cyrus-imapd" "opendkim" "opendmarc"
    "spamassassin" "spamd" "clamd@scan" "clamav-milter" "amavisd" "sqlgrey"
    "postgrey" "httpd" "nginx" "php-fpm" "mariadb" "mysqld" "postgresql"
    "named" "unbound" "slapd" "sssd" "chronyd" "auditd" "polkit"
)

# Protected System & Mail Accounts (Never lock, delete, or alter shell)
readonly PROTECTED_ACCOUNTS=(
    "root" "bin" "daemon" "adm" "lp" "sync" "shutdown" "halt" "mail" "operator"
    "games" "ftp" "nobody" "dbus" "systemd-coredump" "systemd-resolve" "tss"
    "polkitd" "unbound" "sssd" "sshd" "chrony" "postfix" "dovecot" "dovenull"
    "opendkim" "opendmarc" "spamd" "amavis" "clamupdate" "virusgroup" "vmail"
    "apache" "nginx" "mysql" "postgres" "named" "ldap" "rpc" "rpcuser" "cockpit-ws"
)

# Common Mail Ports (TCP)
readonly MAIL_PORTS_TCP=(25 465 587 110 143 993 995)

# Detected Active Mail Components
ACTIVE_MAIL_SERVICES=()
ACTIVE_MAIL_PORTS=()
IPV6_REQUIRED=0

# ==============================================================================
# 2. LOGGING AND REPORTING
# ==============================================================================
init_logging() {
    if [[ $EUID -eq 0 ]]; then
        mkdir -p "$LOG_DIR"
        chmod 700 "$LOG_DIR"
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    else
        LOG_FILE="/tmp/ccdc_baseline_${TIMESTAMP}.log"
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
}

log_msg() {
    local level="$1"
    local msg="$2"
    local color_reset="\033[0m"
    local color=""

    case "$level" in
        INFO)    color="\033[36m" ;; # Cyan
        OK)      color="\033[32m" ;; # Green
        WARN)    color="\033[33m" ;; # Yellow
        ALERT)   color="\033[31m" ;; # Red
        ACTION)  color="\033[35m" ;; # Magenta
        DRYRUN)  color="\033[34m" ;; # Blue
        *)       color="" ;;
    esac

    local formatted="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg"
    echo -e "${color}${formatted}${color_reset}"
    echo "$formatted" >> "$LOG_FILE" 2>/dev/null
}

print_header() {
    echo ""
    echo "=============================================================================="
    echo " $1"
    echo "=============================================================================="
    echo "=== $1 ===" >> "$LOG_FILE" 2>/dev/null
}

# ==============================================================================
# 3. ROOT PRIVILEGE & OS VERIFICATION
# ==============================================================================
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_msg "ALERT" "This operation requires root privileges. Please run as root or via sudo."
        return 1
    fi
    return 0
}

verify_rocky_linux() {
    print_header "OS & ENVIRONMENT VERIFICATION"
    if [[ ! -f /etc/os-release ]]; then
        log_msg "ALERT" "/etc/os-release not found. Cannot verify operating system."
        return 1
    fi

    # shellcheck source=/dev/null
    source /etc/os-release
    log_msg "INFO" "Detected OS: ${PRETTY_NAME:-Unknown} (ID: ${ID:-Unknown}, Version: ${VERSION_ID:-Unknown})"

    if [[ "$ID" != "rocky" && "$ID" != "rhel" && "$ID" != "almalinux" && "$ID" != "centos" ]]; then
        log_msg "ALERT" "OS '$ID' is not Rocky Linux / RHEL family! Aborting to prevent system damage."
        exit 1
    fi

    log_msg "OK" "RHEL/Rocky Linux compatibility verified."
    return 0
}

# ==============================================================================
# 4. BACKUP AND ROLLBACK SUPPORT
# ==============================================================================
backup_file() {
    local target="$1"
    if [[ ! -e "$target" ]]; then
        return 0
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Would back up '$target' to '${BACKUP_ROOT}${target}'"
        return 0
    fi

    require_root || return 1
    local dest_dir
    dest_dir="${BACKUP_ROOT}$(dirname "$target")"
    mkdir -p "$dest_dir"
    chmod 700 "$BACKUP_ROOT"

    if cp -a "$target" "${BACKUP_ROOT}${target}"; then
        log_msg "INFO" "Backed up '$target' -> '${BACKUP_ROOT}${target}'"
        return 0
    else
        log_msg "ALERT" "Failed to back up '$target'!"
        return 1
    fi
}

show_rollback_instructions() {
    print_header "BACKUP & ROLLBACK INSTRUCTIONS"
    log_msg "INFO" "All modified configuration files are backed up with preserved permissions and SELinux contexts under:"
    log_msg "INFO" "  ${BACKUP_ROOT}"
    echo ""
    echo "To roll back a specific file (example: /etc/ssh/sshd_config):"
    echo "  cp -a ${BACKUP_ROOT}/etc/ssh/sshd_config /etc/ssh/sshd_config"
    echo "  restorecon -v /etc/ssh/sshd_config"
    echo "  systemctl reload sshd"
    echo ""
    echo "To list all backups taken in this session:"
    echo "  find ${BACKUP_ROOT} -type f 2>/dev/null"
}

# Helper for executing or simulating hardening commands
run_cmd() {
    local desc="$1"
    shift
    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "$desc -> Command: $*"
        return 0
    else
        log_msg "ACTION" "$desc"
        if "$@"; then
            return 0
        else
            local rc=$?
            log_msg "ALERT" "Command failed (exit $rc): $*"
            return $rc
        fi
    fi
}

# ==============================================================================
# 5. MAIL-SERVER STACK DETECTION & CHECKS (PRIORITY MODULE)
# ==============================================================================
detect_mail_stack() {
    ACTIVE_MAIL_SERVICES=()
    ACTIVE_MAIL_PORTS=()
    IPV6_REQUIRED=0

    local mail_candidates=(
        "postfix" "dovecot" "sendmail" "exim" "cyrus-imapd"
        "opendkim" "opendmarc" "spamassassin" "spamd" "clamd@scan"
        "amavisd" "httpd" "nginx" "mariadb" "postgresql" "named" "slapd"
    )

    for svc in "${mail_candidates[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            ACTIVE_MAIL_SERVICES+=("$svc")
        fi
    done

    # Check listening mail ports
    for port in "${MAIL_PORTS_TCP[@]}"; do
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
            ACTIVE_MAIL_PORTS+=("$port")
        fi
    done

    # Check if Postfix or Dovecot or system is actively binding IPv6 on mail ports or configured for IPv6
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "\[::\]:(25|465|587|110|143|993|995)$"; then
        IPV6_REQUIRED=1
    fi
    if [[ -f /etc/postfix/main.cf ]] && grep -Eq "^[[:space:]]*inet_protocols[[:space:]]*=[[:space:]]*(all|.*ipv6)" /etc/postfix/main.cf; then
        IPV6_REQUIRED=1
    fi
    if [[ -f /etc/dovecot/dovecot.conf ]] && grep -Eq "^[[:space:]]*listen[[:space:]]*=.*::" /etc/dovecot/dovecot.conf; then
        IPV6_REQUIRED=1
    fi
}

audit_mail_stack() {
    print_header "MAIL SERVER STACK & OPERATIONAL AUDIT (READ-ONLY)"
    detect_mail_stack

    if [[ ${#ACTIVE_MAIL_SERVICES[@]} -gt 0 ]]; then
        log_msg "OK" "Detected active/enabled mail & supporting services: ${ACTIVE_MAIL_SERVICES[*]}"
    else
        log_msg "WARN" "No standard mail services detected as active/enabled via systemd!"
    fi

    if [[ ${#ACTIVE_MAIL_PORTS[@]} -gt 0 ]]; then
        log_msg "OK" "Detected listening mail TCP ports: ${ACTIVE_MAIL_PORTS[*]}"
    else
        log_msg "WARN" "No standard mail TCP ports (25, 465, 587, 110, 143, 993, 995) are currently listening!"
    fi

    if [[ $IPV6_REQUIRED -eq 1 ]]; then
        log_msg "INFO" "IPv6 is actively used or configured by the mail stack. IPv6 MUST NOT be disabled."
    else
        log_msg "INFO" "No explicit IPv6 bindings detected on mail ports (still preserving IPv6 loopback for stability)."
    fi

    # Postfix checks
    if command -v postconf >/dev/null 2>&1 && [[ -d /etc/postfix ]]; then
        log_msg "INFO" "--- Postfix Configuration Audit ---"
        local myhostname mydomain mynetworks inet_interfaces smtpd_banner relay_restrictions
        myhostname="$(postconf -h myhostname 2>/dev/null)"
        mydomain="$(postconf -h mydomain 2>/dev/null)"
        mynetworks="$(postconf -h mynetworks 2>/dev/null)"
        inet_interfaces="$(postconf -h inet_interfaces 2>/dev/null)"
        smtpd_banner="$(postconf -h smtpd_banner 2>/dev/null)"
        relay_restrictions="$(postconf -h smtpd_relay_restrictions 2>/dev/null)"

        log_msg "INFO" "Postfix myhostname: $myhostname | mydomain: $mydomain"
        log_msg "INFO" "Postfix inet_interfaces: $inet_interfaces"
        log_msg "INFO" "Postfix mynetworks: $mynetworks"
        log_msg "INFO" "Postfix smtpd_banner: $smtpd_banner"
        log_msg "INFO" "Postfix smtpd_relay_restrictions: $relay_restrictions"

        # Open relay check on mynetworks
        if echo "$mynetworks" | grep -Eq "(0\.0\.0\.0/0|::/0)"; then
            log_msg "ALERT" "Postfix mynetworks contains 0.0.0.0/0 or ::/0 (OPEN RELAY RISK)!"
        fi
        if ! echo "$relay_restrictions" | grep -Eq "(reject_unauth_destination|defer_unauth_destination)"; then
            log_msg "ALERT" "Postfix smtpd_relay_restrictions may lack reject_unauth_destination!"
        fi

        # Check Postfix TLS settings
        local tls_level tls_cert tls_key
        tls_level="$(postconf -h smtpd_tls_security_level 2>/dev/null)"
        tls_cert="$(postconf -h smtpd_tls_cert_file 2>/dev/null)"
        tls_key="$(postconf -h smtpd_tls_key_file 2>/dev/null)"
        log_msg "INFO" "Postfix TLS level: ${tls_level:-none} | Cert: ${tls_cert:-unset} | Key: ${tls_key:-unset}"
        if [[ -n "$tls_key" && -f "$tls_key" ]]; then
            local key_perms
            key_perms="$(stat -c "%a %U:%G" "$tls_key" 2>/dev/null)"
            log_msg "INFO" "Postfix TLS private key permissions: $tls_key ($key_perms)"
        fi

        # Check mail queue count (non-destructive)
        if command -v mailq >/dev/null 2>&1; then
            local queue_summary
            queue_summary="$(mailq 2>/dev/null | tail -n 1)"
            log_msg "INFO" "Postfix Mail Queue Summary: ${queue_summary:-Empty}"
        fi
    fi

    # Dovecot checks
    if command -v doveconf >/dev/null 2>&1 && [[ -d /etc/dovecot ]]; then
        log_msg "INFO" "--- Dovecot Configuration Audit ---"
        local disable_plaintext auth_mechs mail_loc ssl_status
        disable_plaintext="$(doveconf -h disable_plaintext_auth 2>/dev/null)"
        auth_mechs="$(doveconf -h auth_mechanisms 2>/dev/null)"
        mail_loc="$(doveconf -h mail_location 2>/dev/null)"
        ssl_status="$(doveconf -h ssl 2>/dev/null)"
        log_msg "INFO" "Dovecot ssl: $ssl_status | disable_plaintext_auth: $disable_plaintext"
        log_msg "INFO" "Dovecot auth_mechanisms: $auth_mechs | mail_location: $mail_loc"

        if [[ "$ssl_status" == "no" ]]; then
            log_msg "WARN" "Dovecot SSL is set to 'no'. Verify if SSL/TLS is scored or required."
        fi
    fi

    # Mail storage directories check (Read-only inspection)
    for mdir in /var/spool/mail /var/mail /var/spool/postfix /var/vmail /home; do
        if [[ -e "$mdir" ]]; then
            local mstat
            mstat="$(stat -c "%a %U:%G %C" "$mdir" 2>/dev/null)"
            log_msg "INFO" "Storage Path $mdir -> Mode/Owner/SELinux: $mstat"
        fi
    done

    # DNS Resolution check (essential for MX/A record lookups)
    log_msg "INFO" "--- Mail DNS & Hostname Verification ---"
    log_msg "INFO" "System Hostname: $(hostname -f 2>/dev/null || hostname)"
    if [[ -f /etc/resolv.conf ]]; then
        local nameservers
        nameservers="$(grep -E '^[[:space:]]*nameserver' /etc/resolv.conf | awk '{print $2}' | xargs)"
        log_msg "INFO" "Configured Nameservers (/etc/resolv.conf): ${nameservers:-NONE!}"
        if [[ -z "$nameservers" ]]; then
            log_msg "ALERT" "No nameservers configured in /etc/resolv.conf! Mail delivery will fail."
        fi
    fi
}

# ==============================================================================
# 6. MODULE A: USER AND ACCOUNT MANAGEMENT
# ==============================================================================
is_protected_account() {
    local acct="$1"
    for p in "${PROTECTED_ACCOUNTS[@]}"; do
        [[ "$acct" == "$p" ]] && return 0
    done
    return 1
}

validate_username_syntax() {
    local username="$1"
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{0,31}[$]?$ ]]; then
        return 1
    fi
    return 0
}

audit_users_and_accounts() {
    print_header "MODULE A: USER AND ACCOUNT AUDIT (READ-ONLY)"

    # 1. Check UID 0 accounts
    local uid0_users
    uid0_users="$(awk -F: '$3 == 0 {print $1}' /etc/passwd | xargs)"
    if [[ "$uid0_users" == "root" ]]; then
        log_msg "OK" "Only 'root' has UID 0."
    else
        log_msg "ALERT" "Multiple accounts with UID 0 detected: $uid0_users"
    fi

    # 2. Check human/standard accounts (UID >= 1000, excluding nobody/nfsnobody)
    log_msg "INFO" "Standard user accounts (UID >= 1000):"
    awk -F: '$3 >= 1000 && $1 !~ /^(nobody|nfsnobody)$/ {printf "  - %-20s UID: %-6s GID: %-6s Home: %-20s Shell: %s\n", $1, $3, $4, $6, $7}' /etc/passwd | tee -a "$LOG_FILE"

    # 3. Check system accounts (UID < 1000) with interactive login shells
    log_msg "INFO" "Checking system accounts (UID < 1000) with interactive login shells:"
    while IFS=: read -r uname _ uid _ _ _ shell; do
        if [[ "$uid" -lt 1000 && "$uname" != "root" && "$uname" != "sync" && "$uname" != "shutdown" && "$uname" != "halt" ]]; then
            if [[ "$shell" != "/sbin/nologin" && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
                log_msg "ALERT" "System account '$uname' (UID $uid) has an interactive shell: $shell"
            fi
        fi
    done < /etc/passwd

    # 4. Check wheel group members (Rocky Linux administrative group)
    local wheel_members
    wheel_members="$(getent group wheel | awk -F: '{print $4}')"
    log_msg "INFO" "Members of administrative 'wheel' group: ${wheel_members:-<none>}"

    # 5. Check for accounts with empty passwords in /etc/shadow
    if [[ $EUID -eq 0 ]]; then
        local empty_pw
        empty_pw="$(awk -F: '($2 == "") {print $1}' /etc/shadow | xargs)"
        if [[ -n "$empty_pw" ]]; then
            log_msg "ALERT" "Accounts with EMPTY passwords in /etc/shadow: $empty_pw"
        else
            log_msg "OK" "No accounts have empty password fields in /etc/shadow."
        fi
    fi

    # 6. Check duplicate UIDs, GIDs, and Usernames
    local dup_uids dup_gids dup_names
    dup_uids="$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | xargs)"
    dup_gids="$(awk -F: '{print $3}' /etc/group | sort | uniq -d | xargs)"
    dup_names="$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d | xargs)"
    [[ -n "$dup_uids" ]] && log_msg "ALERT" "Duplicate UIDs detected: $dup_uids" || log_msg "OK" "No duplicate UIDs."
    [[ -n "$dup_gids" ]] && log_msg "ALERT" "Duplicate GIDs detected: $dup_gids" || log_msg "OK" "No duplicate GIDs."
    [[ -n "$dup_names" ]] && log_msg "ALERT" "Duplicate Usernames detected: $dup_names" || log_msg "OK" "No duplicate Usernames."
}

manage_user_accounts() {
    print_header "MODULE A: USER ACCOUNT RECONCILIATION (ROSTER-BASED)"
    require_root || return 1

    log_msg "INFO" "Looking for external user roster file at: $USER_ROSTER_FILE"
    log_msg "INFO" "Expected format per line: username:role  (where role is 'admin' or 'user'; lines starting with # are ignored)"

    if [[ ! -f "$USER_ROSTER_FILE" ]]; then
        log_msg "WARN" "Roster file '$USER_ROSTER_FILE' not found."
        log_msg "INFO" "To use this module, create '$USER_ROSTER_FILE' with entries like:"
        log_msg "INFO" "  alice:admin"
        log_msg "INFO" "  bob:user"
        return 1
    fi

    local -A roster_role=()
    local line uname role

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip comments and whitespace
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        [[ -z "$line" ]] && continue

        IFS=: read -r uname role <<< "$line"
        uname="$(echo "$uname" | xargs)"
        role="$(echo "$role" | tr '[:upper:]' '[:lower:]' | xargs)"

        if ! validate_username_syntax "$uname"; then
            log_msg "ALERT" "Invalid username syntax in roster: '$uname'. Aborting reconciliation for safety."
            return 1
        fi
        if [[ "$role" != "admin" && "$role" != "user" ]]; then
            log_msg "ALERT" "Invalid role '$role' for user '$uname' (must be 'admin' or 'user'). Aborting."
            return 1
        fi
        roster_role["$uname"]="$role"
    done < "$USER_ROSTER_FILE"

    if [[ ${#roster_role[@]} -eq 0 ]]; then
        log_msg "WARN" "Roster file is empty. Nothing to reconcile."
        return 1
    fi

    log_msg "INFO" "Loaded ${#roster_role[@]} valid users from roster."

    # 1. Verify existence & privilege level for roster users
    for uname in "${!roster_role[@]}"; do
        role="${roster_role[$uname]}"
        if ! id "$uname" >/dev/null 2>&1; then
            log_msg "WARN" "Roster user '$uname' ($role) does NOT exist on system."
            read -r -p "Create missing user '$uname'? (y/N): " confirm_create
            if [[ "$confirm_create" =~ ^[Yy]$ ]]; then
                run_cmd "Creating user '$uname'" useradd -m -s /bin/bash "$uname"
            fi
        fi

        if id "$uname" >/dev/null 2>&1; then
            local in_wheel=0
            id -nG "$uname" | grep -qw "wheel" && in_wheel=1

            if [[ "$role" == "admin" && $in_wheel -eq 0 ]]; then
                run_cmd "Granting wheel (admin) privileges to '$uname'" usermod -aG wheel "$uname"
            elif [[ "$role" == "user" && $in_wheel -eq 1 ]]; then
                if [[ "$uname" == "root" ]]; then
                    log_msg "WARN" "Skipping privilege removal on root."
                else
                    run_cmd "Removing wheel (admin) privileges from standard user '$uname'" gpasswd -d "$uname" wheel
                fi
            else
                log_msg "OK" "User '$uname' privilege state matches roster ($role)."
            fi
        fi
    done

    # 2. Identify unauthorized human users (UID >= 1000) not in roster
    log_msg "INFO" "Checking for existing UID >= 1000 accounts not listed in '$USER_ROSTER_FILE'..."
    while IFS=: read -r sys_user _ sys_uid _ _ _ _; do
        [[ "$sys_uid" -lt 1000 ]] && continue
        [[ "$sys_user" == "nobody" || "$sys_user" == "nfsnobody" ]] && continue
        if is_protected_account "$sys_user"; then
            log_msg "INFO" "Skipping protected service/mail account '$sys_user' (UID $sys_uid)."
            continue
        fi

        if [[ -z "${roster_role[$sys_user]+_}" ]]; then
            log_msg "ALERT" "Unauthorized account detected (not in roster): '$sys_user' (UID $sys_uid)"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_msg "DRYRUN" "Would prompt to lock or delete unauthorized account '$sys_user' (never deletes mailboxes automatically)."
            else
                echo "Select action for unauthorized user '$sys_user':"
                echo "  [1] Do nothing (skip)"
                echo "  [2] Lock password & remove from wheel (Safe - preserves mail & files)"
                echo "  [3] Delete user account ONLY (Keep home & mail spool - requires confirmation)"
                read -r -p "Choice [1-3, default 1]: " u_action
                case "$u_action" in
                    2)
                        run_cmd "Locking account '$sys_user'" usermod -L "$sys_user"
                        gpasswd -d "$sys_user" wheel 2>/dev/null || true
                        ;;
                    3)
                        read -r -p "TYPE 'DELETE $sys_user' to confirm account deletion (files/mail retained): " confirm_del
                        if [[ "$confirm_del" == "DELETE $sys_user" ]]; then
                            backup_file /etc/passwd
                            backup_file /etc/shadow
                            backup_file /etc/group
                            run_cmd "Deleting user account '$sys_user' (retaining home/mail)" userdel "$sys_user"
                        else
                            log_msg "INFO" "Deletion of '$sys_user' cancelled."
                        fi
                        ;;
                    *)
                        log_msg "INFO" "Skipped '$sys_user'."
                        ;;
                esac
            fi
        fi
    done < /etc/passwd
}

# ==============================================================================
# 7. MODULE B: PASSWORD MANAGEMENT
# ==============================================================================
manage_user_passwords() {
    print_header "MODULE B: SECURE PASSWORD & AGING MANAGEMENT"
    require_root || return 1

    if [[ ! -f "$USER_ROSTER_FILE" ]]; then
        log_msg "WARN" "Roster file '$USER_ROSTER_FILE' not found. Cannot batch-process roster users."
        return 1
    fi

    echo "Select password input mode:"
    echo "  [1] Read per-user credentials from a root-only (0600) file (Format: username:password)"
    echo "  [2] Prompt interactively via hidden input (applied to all roster users)"
    echo "  [3] Apply password aging policies ONLY (do not change passwords)"
    echo "  [4] Apply hardcoded DEFAULT_COMP_PASSWORD to all roster users (Rapid Comp Mode)"
    echo "  [0] Cancel"
    read -r -p "Choice [0-4]: " pw_mode

    case "$pw_mode" in
        1)
            read -r -p "Enter full path to 0600 credential file: " cred_file
            if [[ ! -f "$cred_file" ]]; then
                log_msg "ALERT" "Credential file '$cred_file' does not exist."
                return 1
            fi
            local f_perm
            f_perm="$(stat -c "%a" "$cred_file" 2>/dev/null)"
            if [[ "$f_perm" != "600" && "$f_perm" != "400" ]]; then
                log_msg "ALERT" "Credential file '$cred_file' permissions ($f_perm) are too permissive! Must be 600 or 400."
                return 1
            fi
            if [[ $DRY_RUN -eq 1 ]]; then
                log_msg "DRYRUN" "Would update passwords using 'chpasswd -c SHA512 < $cred_file'."
            else
                backup_file /etc/shadow
                if chpasswd -c SHA512 < "$cred_file"; then
                    log_msg "OK" "Passwords updated securely from '$cred_file'."
                else
                    log_msg "ALERT" "chpasswd reported an error processing '$cred_file'."
                fi
            fi
            ;;
        2)
            local new_pass1 new_pass2
            read -r -s -p "Enter new shared password for all roster users (hidden): " new_pass1
            echo ""
            read -r -s -p "Confirm new shared password (hidden): " new_pass2
            echo ""
            if [[ -z "$new_pass1" || "$new_pass1" != "$new_pass2" ]]; then
                log_msg "ALERT" "Passwords do not match or are empty. Aborting."
                unset new_pass1 new_pass2
                return 1
            fi

            backup_file /etc/shadow
            while IFS= read -r line || [[ -n "$line" ]]; do
                line="${line%%#*}"
                line="$(echo "$line" | xargs)"
                [[ -z "$line" ]] && continue
                IFS=: read -r uname _ <<< "$line"
                uname="$(echo "$uname" | xargs)"
                if id "$uname" >/dev/null 2>&1 && ! is_protected_account "$uname"; then
                    if [[ $DRY_RUN -eq 1 ]]; then
                        log_msg "DRYRUN" "Would update password for '$uname' via stdin pipe to chpasswd."
                    else
                        printf '%s:%s\n' "$uname" "$new_pass1" | chpasswd -c SHA512
                        log_msg "OK" "Updated password for '$uname'."
                    fi
                fi
            done < "$USER_ROSTER_FILE"
            unset new_pass1 new_pass2
            ;;
        3)
            log_msg "INFO" "Proceeding to password aging configuration only."
            ;;
        4)
            if [[ -z "${DEFAULT_COMP_PASSWORD:-}" ]]; then
                log_msg "ALERT" "DEFAULT_COMP_PASSWORD is empty or unset!"
                return 1
            fi
            backup_file /etc/shadow
            while IFS= read -r line || [[ -n "$line" ]]; do
                line="${line%%#*}"
                line="$(echo "$line" | xargs)"
                [[ -z "$line" ]] && continue
                IFS=: read -r uname _ <<< "$line"
                uname="$(echo "$uname" | xargs)"
                if id "$uname" >/dev/null 2>&1 && ! is_protected_account "$uname"; then
                    if [[ $DRY_RUN -eq 1 ]]; then
                        log_msg "DRYRUN" "Would set DEFAULT_COMP_PASSWORD for '$uname' and unlock account."
                    else
                        # Builtin printf pipes directly to chpasswd stdin (never visible in ps aux)
                        printf '%s:%s\n' "$uname" "$DEFAULT_COMP_PASSWORD" | chpasswd -c SHA512
                        # Also clear any pam_faillock or passwd lockouts for this user!
                        passwd -u "$uname" >/dev/null 2>&1 || true
                        faillock --user "$uname" --reset >/dev/null 2>&1 || true
                        log_msg "OK" "Reset password and cleared lockouts for '$uname'."
                    fi
                fi
            done < "$USER_ROSTER_FILE"
            ;;
        *)
            log_msg "INFO" "Cancelled."
            return 0
            ;;
    esac

    # Apply conservative account aging to human users in roster
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        [[ -z "$line" ]] && continue
        IFS=: read -r uname _ <<< "$line"
        uname="$(echo "$uname" | xargs)"
        if id "$uname" >/dev/null 2>&1 && ! is_protected_account "$uname"; then
            run_cmd "Setting password aging (min 1 day, max 90 days, warn 7 days) for '$uname'" chage -m 1 -M 90 -W 7 "$uname"
        fi
    done < "$USER_ROSTER_FILE"
}

# ==============================================================================
# 8. MODULE C: PASSWORD AND AUTHENTICATION POLICIES (PAM / AUTHSELECT)
# ==============================================================================
audit_auth_policies() {
    print_header "MODULE C: PASSWORD & AUTHENTICATION POLICY AUDIT (READ-ONLY)"

    # 1. Check authselect status
    if command -v authselect >/dev/null 2>&1; then
        log_msg "INFO" "Checking Rocky Linux authselect profile:"
        authselect current 2>&1 | sed 's/^/  /' | tee -a "$LOG_FILE"
        if authselect check >/dev/null 2>&1; then
            log_msg "OK" "authselect configuration integrity check passed."
        else
            log_msg "WARN" "authselect reports manual modifications or non-authselect PAM files!"
        fi
    else
        log_msg "WARN" "authselect command not found."
    fi

    # 2. Audit /etc/security/pwquality.conf
    if [[ -f /etc/security/pwquality.conf ]]; then
        log_msg "INFO" "Active settings in /etc/security/pwquality.conf:"
        grep -Ev '^[[:space:]]*(#|$)' /etc/security/pwquality.conf | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # 3. Audit /etc/security/faillock.conf
    if [[ -f /etc/security/faillock.conf ]]; then
        log_msg "INFO" "Active settings in /etc/security/faillock.conf:"
        grep -Ev '^[[:space:]]*(#|$)' /etc/security/faillock.conf | sed 's/^/  /' | tee -a "$LOG_FILE"
        if grep -Eq '^[[:space:]]*even_deny_root' /etc/security/faillock.conf; then
            log_msg "ALERT" "'even_deny_root' is enabled in /etc/security/faillock.conf! Red Team can brute-force root and lock out administrators."
        fi
    fi

    # 4. Audit /etc/login.defs
    if [[ -f /etc/login.defs ]]; then
        log_msg "INFO" "Key settings in /etc/login.defs:"
        grep -E '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD|UMASK|MAIL_DIR)' /etc/login.defs | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # 5. Check PAM files for rogue modules (pam_permit.so in auth, backdoors)
    log_msg "INFO" "Auditing /etc/pam.d/ for suspicious 'pam_permit.so' in auth stacks or unexpected changes:"
    grep -rn "pam_permit.so" /etc/pam.d/ 2>/dev/null | grep -E "auth[[:space:]]+" && \
        log_msg "ALERT" "Review pam_permit.so usage in auth stacks above!" || \
        log_msg "OK" "No suspicious auth pam_permit.so entries detected."

    if command -v rpm >/dev/null 2>&1; then
        local pam_verify
        pam_verify="$(rpm -Vf /etc/pam.d/system-auth 2>/dev/null)"
        [[ -n "$pam_verify" ]] && log_msg "INFO" "RPM verify on pam package: $pam_verify"
    fi
}

harden_auth_policies() {
    print_header "MODULE C: HARDEN PASSWORD & AUTHENTICATION POLICIES"
    require_root || return 1

    # 1. Harden /etc/security/pwquality.conf via drop-in or direct safe update
    if [[ -f /etc/security/pwquality.conf ]]; then
        backup_file /etc/security/pwquality.conf
        local pwq_conf="/etc/security/pwquality.conf.d/99-ccdc-baseline.conf"
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would write password complexity rules to $pwq_conf (minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1)"
        else
            mkdir -p /etc/security/pwquality.conf.d
            cat << 'EOF' > "$pwq_conf"
# CCDC Rocky Linux Password Quality Baseline
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
dictcheck = 1
enforcing = 1
retry = 3
EOF
            chmod 644 "$pwq_conf"
            log_msg "OK" "Configured password complexity in $pwq_conf."
        fi
    fi

    # 2. Harden /etc/security/pwhistory.conf (Rocky 9 / modern PAM)
    if [[ -f /etc/security/pwhistory.conf ]]; then
        backup_file /etc/security/pwhistory.conf
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would configure remember = 5 in /etc/security/pwhistory.conf"
        else
            sed -i 's/^[#[:space:]]*remember[[:space:]]*=.*/remember = 5/' /etc/security/pwhistory.conf
            grep -Eq '^remember[[:space:]]*=' /etc/security/pwhistory.conf || echo "remember = 5" >> /etc/security/pwhistory.conf
            log_msg "OK" "Configured password history (remember = 5) in /etc/security/pwhistory.conf."
        fi
    fi

    # 3. Configure /etc/security/faillock.conf CONSERVATIVELY (Do NOT enable even_deny_root; moderate unlock time to prevent scoring DoS)
    if [[ -f /etc/security/faillock.conf ]]; then
        backup_file /etc/security/faillock.conf
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would configure conservative faillock settings in /etc/security/faillock.conf (deny=5, unlock_time=300, even_deny_root disabled)"
        else
            # Comment out even_deny_root if present so Red Team cannot lock out root
            sed -i 's/^[[:space:]]*even_deny_root/# even_deny_root/' /etc/security/faillock.conf
            grep -Eq '^deny[[:space:]]*=' /etc/security/faillock.conf && \
                sed -i 's/^deny[[:space:]]*=.*/deny = 5/' /etc/security/faillock.conf || \
                echo "deny = 5" >> /etc/security/faillock.conf
            grep -Eq '^unlock_time[[:space:]]*=' /etc/security/faillock.conf && \
                sed -i 's/^unlock_time[[:space:]]*=.*/unlock_time = 300/' /etc/security/faillock.conf || \
                echo "unlock_time = 300" >> /etc/security/faillock.conf
            log_msg "OK" "Configured /etc/security/faillock.conf (deny=5, unlock_time=300s, root lockout disabled)."
        fi
    fi

    # 4. Safely update /etc/login.defs IN-PLACE (Preserve Rocky Linux MAIL_DIR /var/spool/mail)
    if [[ -f /etc/login.defs ]]; then
        backup_file /etc/login.defs
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would update PASS_MAX_DAYS (90), PASS_MIN_DAYS (1), PASS_WARN_AGE (7), and ENCRYPT_METHOD (SHA512) in /etc/login.defs"
        else
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
            sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
            sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
            sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD\tSHA512/' /etc/login.defs
            log_msg "OK" "Updated password aging defaults in /etc/login.defs while preserving Rocky Linux mail paths."
        fi
    fi

    # 5. Enable authselect features safely if authselect is currently managing PAM
    if command -v authselect >/dev/null 2>&1 && authselect check >/dev/null 2>&1; then
        if authselect current >/dev/null 2>&1; then
            run_cmd "Enabling authselect with-faillock feature" authselect enable-feature with-faillock
            run_cmd "Applying authselect changes" authselect apply-changes
        fi
    else
        log_msg "WARN" "Skipping automatic authselect modification because custom PAM configuration is active."
    fi
}

# ==============================================================================
# 9. MODULE D & E: NETWORK CONFIGURATION & SYSCTL KERNEL HARDENING
# ==============================================================================
audit_network_and_sysctl() {
    print_header "MODULE D & E: NETWORK & SYSCTL AUDIT (READ-ONLY)"
    detect_mail_stack

    log_msg "INFO" "--- Active Network Interfaces & Addresses ---"
    ip -brief addr show | sed 's/^/  /' | tee -a "$LOG_FILE"

    log_msg "INFO" "--- Routing Table ---"
    ip route show | sed 's/^/  /' | tee -a "$LOG_FILE"

    log_msg "INFO" "--- Key Kernel & Network Sysctl Values ---"
    local keys=(
        "net.ipv4.ip_forward"
        "net.ipv4.conf.all.accept_Source_route"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.all.rp_filter"
        "net.ipv4.tcp_syncookies"
        "net.ipv4.icmp_echo_ignore_all"
        "net.ipv4.icmp_echo_ignore_broadcasts"
        "net.ipv6.conf.all.disable_ipv6"
        "net.ipv6.conf.all.accept_redirects"
        "net.ipv6.conf.all.forwarding"
        "kernel.randomize_va_space"
        "kernel.kptr_restrict"
        "kernel.dmesg_restrict"
        "kernel.unprivileged_bpf_disabled"
        "kernel.sysrq"
        "fs.suid_dumpable"
        "fs.protected_hardlinks"
        "fs.protected_symlinks"
        "crypto.fips_enabled"
    )

    for k in "${keys[@]}"; do
        local val
        val="$(sysctl -n "$k" 2>/dev/null || echo "N/A")"
        printf "  %-45s = %s\n" "$k" "$val" | tee -a "$LOG_FILE"
    done

    # Check for conflicting sysctl files
    log_msg "INFO" "--- Existing Sysctl Configuration Files ---"
    ls -la /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
}

harden_sysctl() {
    print_header "MODULE D & E: SYSCTL & KERNEL HARDENING"
    require_root || return 1
    detect_mail_stack

    backup_file "$SYSCTL_DROPIN"

    # Determine safe IPv6 sysctl posture
    local disable_ipv6_val=0
    if [[ $IPV6_REQUIRED -eq 1 ]]; then
        log_msg "INFO" "Mail server or system requires IPv6. Keeping IPv6 enabled and hardening IPv6 stack."
        disable_ipv6_val=0
    else
        log_msg "INFO" "Keeping IPv6 enabled on loopback/interfaces by default to prevent Postfix/Dovecot socket bind failures, while hardening IPv6 redirects/RA."
        disable_ipv6_val=0
    fi

    local tmp_sysctl="/tmp/ccdc_sysctl_${TIMESTAMP}.conf"
    cat << EOF > "$tmp_sysctl"
# ==============================================================================
# CCDC Rocky Linux Mail Server Sysctl Hardening Baseline
# Generated: ${TIMESTAMP}
# ==============================================================================

# --- Kernel Security & Memory Protection ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 2
kernel.yama.ptrace_scope = 1

# --- Filesystem & Core Dump Restrictions ---
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
dev.tty.ldisc_autoload = 0

# --- IPv4 Network Stack Hardening ---
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- ICMP Behavior (Preserve Ping for CCDC Scoring Checks!) ---
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- IPv6 Network Stack Hardening (Mail-Safe) ---
net.ipv6.conf.all.disable_ipv6 = ${disable_ipv6_val}
net.ipv6.conf.default.disable_ipv6 = ${disable_ipv6_val}
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

    # Filter out any sysctl keys not supported by the running kernel to guarantee clean validation
    local validated_tmp="/tmp/ccdc_sysctl_valid_${TIMESTAMP}.conf"
    : > "$validated_tmp"
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
            echo "$line" >> "$validated_tmp"
            continue
        fi
        local key="${line%%=*}"
        key="$(echo "$key" | xargs)"
        local proc_path="/proc/sys/${key//./\/}"
        if [[ -e "$proc_path" ]]; then
            echo "$line" >> "$validated_tmp"
        else
            log_msg "WARN" "Skipping unsupported kernel sysctl key on this kernel: $key"
        fi
    done < "$tmp_sysctl"
    rm -f "$tmp_sysctl"

    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Validated sysctl configuration. Would install to '$SYSCTL_DROPIN' and run 'sysctl --system'."
        rm -f "$validated_tmp"
    else
        mv "$validated_tmp" "$SYSCTL_DROPIN"
        chmod 644 "$SYSCTL_DROPIN"
        chown root:root "$SYSCTL_DROPIN"
        restorecon "$SYSCTL_DROPIN" 2>/dev/null || true
        if sysctl -p "$SYSCTL_DROPIN" >/dev/null; then
            log_msg "OK" "Applied sysctl baseline from '$SYSCTL_DROPIN'."
        else
            log_msg "WARN" "Some sysctl keys returned warnings when applying '$SYSCTL_DROPIN'."
        fi
    fi
}

# ==============================================================================
# 10. MODULE F: SSH AND SSHD
# ==============================================================================
audit_sshd() {
    print_header "MODULE F: SSH & SSHD CONFIGURATION AUDIT (READ-ONLY)"

    if systemctl is-active --quiet sshd 2>/dev/null; then
        log_msg "OK" "sshd service is active and running."
    else
        log_msg "WARN" "sshd service is NOT running!"
    fi

    if command -v sshd >/dev/null 2>&1; then
        log_msg "INFO" "Effective sshd configuration (via sshd -T):"
        sshd -T 2>/dev/null | grep -E "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax|allowusers|allowgroups|denyusers|denygroups|usepam|x11forwarding|authorizedkeysfile)" | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # Check /etc/ssh/sshd_config.d/ drop-ins (Rocky Linux 9 uses drop-ins extensively!)
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        log_msg "INFO" "Inspecting /etc/ssh/sshd_config.d/ drop-in files:"
        ls -la /etc/ssh/sshd_config.d/ | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # Audit authorized_keys across users for Red Team persistence
    log_msg "INFO" "Auditing SSH authorized_keys files across all accounts:"
    while IFS=: read -r uname _ _ _ _ homedir _; do
        if [[ -d "$homedir/.ssh" ]]; then
            for kf in "$homedir/.ssh/authorized_keys" "$homedir/.ssh/authorized_keys2"; do
                if [[ -f "$kf" && -s "$kf" ]]; then
                    local count
                    count="$(grep -Ev '^[[:space:]]*(#|$)' "$kf" | wc -l)"
                    log_msg "WARN" "User '$uname' has $count key(s) in $kf"
                fi
            done
        fi
    done < /etc/passwd
}

harden_sshd() {
    print_header "MODULE F: HARDEN SSHD CONFIGURATION"
    require_root || return 1

    local sshd_main="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_main" ]]; then
        log_msg "ALERT" "$sshd_main not found!"
        return 1
    fi

    backup_file "$sshd_main"

    # Never disable PasswordAuthentication automatically in CCDC unless verified, as scoring engines often use SSH password auth
    local tmp_sshd="/tmp/sshd_config.${TIMESTAMP}"
    cp -a "$sshd_main" "$tmp_sshd"

    declare -A ssh_settings=(
        ["PermitRootLogin"]="no"
        ["PubkeyAuthentication"]="yes"
        ["PasswordAuthentication"]="yes"
        ["PermitEmptyPasswords"]="no"
        ["MaxAuthTries"]="4"
        ["LoginGraceTime"]="60"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["X11Forwarding"]="no"
        ["UsePAM"]="yes"
    )

    for key in "${!ssh_settings[@]}"; do
        local val="${ssh_settings[$key]}"
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$tmp_sshd"; then
            sed -i -E "s/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/${key} ${val}/" "$tmp_sshd"
        else
            echo "${key} ${val}" >> "$tmp_sshd"
        fi
    done

    # Validate candidate config with sshd -t BEFORE touching live file
    if ! sshd -t -f "$tmp_sshd" 2>/dev/null; then
        log_msg "ALERT" "Candidate sshd_config failed 'sshd -t' validation! Aborting SSHD changes."
        rm -f "$tmp_sshd"
        return 1
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Candidate sshd_config passed 'sshd -t' validation. Would update $sshd_main and reload sshd."
        rm -f "$tmp_sshd"
    else
        mv "$tmp_sshd" "$sshd_main"
        chown root:root "$sshd_main"
        chmod 600 "$sshd_main"
        restorecon "$sshd_main" 2>/dev/null || true
        run_cmd "Reloading sshd service safely" systemctl reload sshd
        log_msg "OK" "SSHD hardened and reloaded (PasswordAuthentication preserved for CCDC scoring)."
    fi
}

# ==============================================================================
# 11. MODULE G: FTP AUDIT
# ==============================================================================
audit_ftp() {
    print_header "MODULE G: FTP SERVICES & CONFIGURATION AUDIT (READ-ONLY)"

    local ftp_pkgs=("vsftpd" "proftpd" "pure-ftpd" "tftp-server")
    local found_ftp=0

    for pkg in "${ftp_pkgs[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            found_ftp=1
            log_msg "WARN" "FTP package installed: $pkg"
            local st
            st="$(systemctl is-active "$pkg" 2>/dev/null || echo "inactive")"
            log_msg "INFO" "Service '$pkg' status: $st"
        fi
    done

    if [[ $found_ftp -eq 0 ]]; then
        log_msg "OK" "No FTP server packages (vsftpd, proftpd, pure-ftpd, tftp-server) are installed."
    fi

    # Check Rocky Linux vsftpd path (/etc/vsftpd/vsftpd.conf) and fallback (/etc/vsftpd.conf)
    for vconf in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        if [[ -f "$vconf" ]]; then
            log_msg "INFO" "Inspecting $vconf:"
            grep -Ev '^[[:space:]]*(#|$)' "$vconf" | sed 's/^/  /' | tee -a "$LOG_FILE"
            if grep -Eq '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES' "$vconf"; then
                log_msg "ALERT" "Anonymous FTP login is ENABLED in $vconf!"
            fi
            if grep -Eq '^[[:space:]]*write_enable[[:space:]]*=[[:space:]]*YES' "$vconf"; then
                log_msg "WARN" "FTP write_enable=YES in $vconf."
            fi
        fi
    done
}

# ==============================================================================
# 12. MODULE H: CORE SYSTEM AND /etc SECURITY
# ==============================================================================
audit_and_harden_etc_permissions() {
    local mode="${1:-audit}" # 'audit' or 'harden'
    print_header "MODULE H: CORE SYSTEM & /etc SECURITY (${mode^^})"

    # Expected file permissions on Rocky Linux: path|octal_mode|owner:group
    # NOTE: Rocky Linux /etc/shadow and /etc/gshadow MUST be 0000 root:root
    local baseline_specs=(
        "/etc|755|root:root"
        "/etc/passwd|644|root:root"
        "/etc/group|644|root:root"
        "/etc/shadow|0|root:root"
        "/etc/gshadow|0|root:root"
        "/etc/passwd-|644|root:root"
        "/etc/group-|644|root:root"
        "/etc/shadow-|0|root:root"
        "/etc/gshadow-|0|root:root"
        "/etc/sudoers|440|root:root"
        "/etc/sudoers.d|750|root:root"
        "/etc/security|755|root:root"
        "/etc/ssh|755|root:root"
        "/etc/ssh/sshd_config|600|root:root"
        "/etc/pam.d|755|root:root"
        "/etc/sysctl.conf|644|root:root"
        "/etc/sysctl.d|755|root:root"
        "/etc/systemd|755|root:root"
        "/etc/crontab|600|root:root"
        "/etc/cron.d|700|root:root"
        "/etc/cron.daily|700|root:root"
        "/etc/cron.hourly|700|root:root"
        "/etc/cron.weekly|700|root:root"
        "/etc/cron.monthly|700|root:root"
        "/tmp|1777|root:root"
        "/var/tmp|1777|root:root"
    )

    for spec in "${baseline_specs[@]}"; do
        IFS='|' read -r fpath exp_perm exp_own <<< "$spec"
        [[ ! -e "$fpath" ]] && continue

        local cur_perm cur_own
        cur_perm="$(stat -c "%a" "$fpath" 2>/dev/null)"
        cur_own="$(stat -c "%U:%G" "$fpath" 2>/dev/null)"

        if [[ "$cur_perm" != "$exp_perm" || "$cur_own" != "$exp_own" ]]; then
            log_msg "WARN" "$fpath -> Current: $cur_perm ($cur_own) | Expected: $exp_perm ($exp_own)"
            if [[ "$mode" == "harden" ]]; then
                require_root || return 1
                # Remove immutable attribute if set on critical auth files before fixing perms
                chattr -ia "$fpath" 2>/dev/null || true
                run_cmd "Setting ownership $exp_own on $fpath" chown "$exp_own" "$fpath"
                run_cmd "Setting permissions 0$exp_perm on $fpath" chmod "0$exp_perm" "$fpath"
                restorecon "$fpath" 2>/dev/null || true
            fi
        else
            log_msg "OK" "$fpath matches baseline ($cur_perm $cur_own)."
        fi
    done

    # Check for world-writable files inside /etc
    log_msg "INFO" "Checking for world-writable files or directories in /etc:"
    local ww_etc
    ww_etc="$(find /etc -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null)"
    if [[ -n "$ww_etc" ]]; then
        log_msg "ALERT" "World-writable items found in /etc:"
        echo "$ww_etc" | sed 's/^/  /' | tee -a "$LOG_FILE"
    else
        log_msg "OK" "No world-writable files or directories in /etc."
    fi

    # Check SUID/SGID binaries in standard binary paths (Fast, bounded search)
    log_msg "INFO" "Auditing SUID/SGID binaries in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local:"
    find /bin /sbin /usr/bin /usr/sbin /usr/local -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} + 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    # Check immutable files in /etc
    if command -v lsattr >/dev/null 2>&1; then
        log_msg "INFO" "Checking for immutable (+i) or append-only (+a) files in /etc:"
        lsattr -R /etc 2>/dev/null | grep -E '^[a-zA-Z-]{4}[ia]' | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi
}

audit_and_harden_sudoers() {
    local mode="${1:-audit}"
    print_header "SUDOERS CONFIGURATION (${mode^^})"

    if [[ -d /etc/sudoers.d ]]; then
        log_msg "INFO" "Inspecting /etc/sudoers and /etc/sudoers.d/ for NOPASSWD or suspicious rules:"
        grep -rnE '^[^#].*(ALL|NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    if [[ "$mode" == "harden" ]]; then
        require_root || return 1
        backup_file "$SUDOERS_DROPIN"
        local tmp_sudo="/tmp/ccdc_sudoers_${TIMESTAMP}"
        cat << 'EOF' > "$tmp_sudo"
# CCDC Rocky Linux Safe Sudoers Baseline Drop-in
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults passwd_tries=3
Defaults timestamp_timeout=15
%wheel ALL=(ALL) ALL
EOF
        chmod 440 "$tmp_sudo"
        if visudo -cf "$tmp_sudo" >/dev/null 2>&1; then
            if [[ $DRY_RUN -eq 1 ]]; then
                log_msg "DRYRUN" "Validated sudoers drop-in via 'visudo -cf'. Would install to $SUDOERS_DROPIN."
                rm -f "$tmp_sudo"
            else
                mv "$tmp_sudo" "$SUDOERS_DROPIN"
                chown root:root "$SUDOERS_DROPIN"
                chmod 440 "$SUDOERS_DROPIN"
                restorecon "$SUDOERS_DROPIN" 2>/dev/null || true
                log_msg "OK" "Installed validated sudoers baseline at $SUDOERS_DROPIN."
            fi
        else
            log_msg "ALERT" "visudo validation failed on $tmp_sudo! Aborting."
            rm -f "$tmp_sudo"
            return 1
        fi
    fi
}

# ==============================================================================
# 13. MODULE I & U: REPOSITORY, PACKAGE MANAGEMENT & AUTOMATIC UPDATES
# ==============================================================================
audit_packages_and_repos() {
    print_header "MODULE I & U: DNF REPOSITORIES, PACKAGES & AUTO-UPDATES AUDIT (READ-ONLY)"

    log_msg "INFO" "Inspecting /etc/yum.repos.d/ repository files and GPG checks:"
    for repo in /etc/yum.repos.d/*.repo; do
        [[ ! -f "$repo" ]] && continue
        log_msg "INFO" "Repo file: $repo"
        if grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' "$repo"; then
            log_msg "ALERT" "gpgcheck=0 found in $repo!"
        fi
    done

    # Check for suspicious offensive/backdoor packages installed via RPM
    local suspect_pkgs=(
        "nmap-ncat" "nc" "socat" "hydra" "john" "hashcat" "wireshark" "tcpdump"
        "nikto" "sqlmap" "aircrack-ng" "ettercap" "metasploit" "telnet-server"
        "rsh-server" "tftp-server" "xinetd" "tigervnc-server"
    )
    log_msg "INFO" "Checking for potentially unwanted or dual-use packages:"
    for pkg in "${suspect_pkgs[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            log_msg "WARN" "Installed package requires review: $pkg"
        fi
    done

    # Check dnf-automatic status (Module U)
    log_msg "INFO" "--- Automatic Updates Status (dnf-automatic) ---"
    if rpm -q dnf-automatic >/dev/null 2>&1; then
        log_msg "INFO" "dnf-automatic is installed."
        systemctl list-timers 'dnf-automatic*' --no-pager 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    else
        log_msg "INFO" "dnf-automatic is not installed (manual update control active)."
    fi
}

update_all_applications() {
    print_header "MODULE I: DNF PACKAGE UPDATE (MAINTENANCE)"
    require_root || return 1

    log_msg "INFO" "Checking available DNF updates (read-only preview)..."
    dnf check-update
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        log_msg "OK" "All installed packages are up to date."
        return 0
    elif [[ $rc -ne 100 ]]; then
        log_msg "ALERT" "dnf check-update failed with exit code $rc. Check network/DNS or repo config."
        return 1
    fi

    log_msg "WARN" "Updates are available (exit code 100)."
    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Dry-Run enabled. Would prompt before running 'dnf upgrade --nobest --setopt=install_weak_deps=False' without rebooting."
        return 0
    fi

    read -r -p "Proceed with applying DNF package updates now? (Never auto-reboots) (y/N): " confirm_upd
    if [[ "$confirm_upd" =~ ^[Yy]$ ]]; then
        if dnf upgrade -y --nobest; then
            log_msg "OK" "DNF package updates completed successfully. System was NOT rebooted."
        else
            log_msg "ALERT" "DNF package upgrade encountered errors! Review $LOG_FILE."
            return 1
        fi
    else
        log_msg "INFO" "Package update skipped by administrator."
    fi
}

# ==============================================================================
# 14. MODULE J: LIGHTWEIGHT MALWARE AND ROOTKIT AUDITING
# ==============================================================================
audit_malware_lightweight() {
    print_header "MODULE J: LIGHTWEIGHT MALWARE & INTEGRITY AUDIT (READ-ONLY)"

    # 1. Check /dev/shm, /tmp, /var/tmp for executable files or scripts
    log_msg "INFO" "Scanning /dev/shm, /tmp, and /var/tmp for executable files or hidden items:"
    find /dev/shm /tmp /var/tmp -xdev \( -type f -perm /111 -o -name ".*" \) 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    # 2. Check /etc/ld.so.preload (classic userland rootkit hook)
    if [[ -f /etc/ld.so.preload && -s /etc/ld.so.preload ]]; then
        log_msg "ALERT" "/etc/ld.so.preload exists and is non-empty! Contents:"
        cat /etc/ld.so.preload | sed 's/^/  /' | tee -a "$LOG_FILE"
    else
        log_msg "OK" "/etc/ld.so.preload is absent or empty."
    fi

    # 3. Check binary file capabilities (getcap) in system binary directories
    if command -v getcap >/dev/null 2>&1; then
        log_msg "INFO" "Checking file capabilities in /usr/bin, /usr/sbin, /usr/local, /home, /tmp:"
        getcap -r /usr/bin /usr/sbin /usr/local /home /tmp 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # 4. Targeted RPM integrity check on critical authentication & network packages (Fast, takes ~2 seconds)
    log_msg "INFO" "Running targeted RPM integrity check (rpm -V) on core security packages:"
    local core_rpms=("openssh-server" "openssh-clients" "pam" "sudo" "shadow-utils" "systemd" "util-linux" "coreutils" "iproute" "procps-ng" "postfix" "dovecot")
    for pkg in "${core_rpms[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            local v_out
            v_out="$(rpm -V "$pkg" 2>/dev/null | grep -Ev ' c ')" # Ignore normal config file edits (' c ')
            if [[ -n "$v_out" ]]; then
                log_msg "ALERT" "Binary/File integrity anomaly in package '$pkg':"
                echo "$v_out" | sed 's/^/  /' | tee -a "$LOG_FILE"
            fi
        fi
    done

    # 5. Check optional installed scanners (Do not run heavy scans automatically)
    for tool in rkhunter chkrootkit clamscan aide; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_msg "INFO" "Optional security tool '$tool' is INSTALLED."
        else
            log_msg "INFO" "Optional security tool '$tool' is NOT installed."
        fi
    done
}

# ==============================================================================
# 15. MODULE K: POLKIT AUDIT
# ==============================================================================
audit_polkit() {
    print_header "MODULE K: POLKIT AUTHORIZATION RULES AUDIT (READ-ONLY)"

    local polkit_dirs=("/etc/polkit-1/rules.d" "/etc/polkit-1/localauthority" "/usr/share/polkit-1/rules.d")
    for pdir in "${polkit_dirs[@]}"; do
        if [[ -d "$pdir" ]]; then
            log_msg "INFO" "Listing Polkit directory: $pdir"
            ls -la "$pdir" 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

            # Check for world/group writable rules
            local writable_rules
            writable_rules="$(find "$pdir" -type f -perm /022 2>/dev/null)"
            if [[ -n "$writable_rules" ]]; then
                log_msg "ALERT" "Group/World-writable Polkit files found in $pdir: $writable_rules"
            fi

            # Search for unconditional YES returns in custom /etc rules
            if [[ "$pdir" == /etc/* ]]; then
                grep -rnE "polkit\.Result\.YES|NOPASSWD" "$pdir" 2>/dev/null | sed 's/^/  [RULE MATCH] /' | tee -a "$LOG_FILE"
            fi
        fi
    done
}

# ==============================================================================
# 16. MODULE L: CRON AND SCHEDULED TASKS AUDIT
# ==============================================================================
audit_scheduled_tasks() {
    print_header "MODULE L: CRON, AT & SYSTEMD TIMERS AUDIT (READ-ONLY)"

    # 1. System crontabs
    local cron_paths=("/etc/crontab" "/etc/anacrontab" "/etc/cron.d" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/var/spool/cron")
    for cp in "${cron_paths[@]}"; do
        if [[ -f "$cp" ]]; then
            log_msg "INFO" "Contents of $cp:"
            grep -Ev '^[[:space:]]*(#|$)' "$cp" | sed 's/^/  /' | tee -a "$LOG_FILE"
        elif [[ -d "$cp" ]]; then
            log_msg "INFO" "Files in $cp:"
            ls -la "$cp" 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
            for f in "$cp"/*; do
                [[ -f "$f" ]] || continue
                log_msg "INFO" "--- Task File: $f ---"
                grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null | head -n 30 | sed 's/^/    /' | tee -a "$LOG_FILE"
            done
        fi
    done

    # 2. Check at jobs (/var/spool/at on Rocky Linux)
    if [[ -d /var/spool/at ]]; then
        log_msg "INFO" "Checking /var/spool/at jobs:"
        find /var/spool/at -maxdepth 1 -type f ! -name ".SEQ" -ls 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # 3. Systemd Timers
    log_msg "INFO" "Active & Enabled Systemd Timers:"
    systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
}

# ==============================================================================
# 17. MODULE M: DISPLAY MANAGER AND GSETTINGS (GDM / GNOME)
# ==============================================================================
audit_display_manager() {
    print_header "MODULE M: DISPLAY MANAGER & GNOME AUDIT (READ-ONLY)"

    if ! rpm -q gdm >/dev/null 2>&1 && [[ ! -d /etc/gdm ]]; then
        log_msg "OK" "No graphical Display Manager (GDM) is installed (Headless Mail Server)."
        return 0
    fi

    log_msg "WARN" "GDM graphical display manager is installed on this mail server!"
    log_msg "INFO" "Current default systemd target: $(systemctl get-default 2>/dev/null)"

    if [[ -f /etc/gdm/custom.conf ]]; then
        log_msg "INFO" "Contents of /etc/gdm/custom.conf:"
        grep -Ev '^[[:space:]]*(#|$)' /etc/gdm/custom.conf | sed 's/^/  /' | tee -a "$LOG_FILE"
        if grep -Eqi '^[[:space:]]*AutomaticLoginEnable[[:space:]]*=[[:space:]]*(true|1)' /etc/gdm/custom.conf; then
            log_msg "ALERT" "GDM AutomaticLoginEnable is enabled in /etc/gdm/custom.conf!"
        fi
    fi

    if [[ -d /etc/dconf/db ]]; then
        log_msg "INFO" "Inspecting /etc/dconf/db locks & policies:"
        find /etc/dconf/db -type f -ls 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi
}

# ==============================================================================
# 18. MODULE N: GRUB AND BOOTLOADER AUDIT
# ==============================================================================
audit_grub_and_banners() {
    local mode="${1:-audit}"
    print_header "MODULE N: GRUB BOOTLOADER & BANNERS (${mode^^})"

    # 1. Check /etc/default/grub
    if [[ -f /etc/default/grub ]]; then
        log_msg "INFO" "Contents of /etc/default/grub:"
        cat /etc/default/grub | sed 's/^/  /' | tee -a "$LOG_FILE"
        if grep -Eq "selinux=0|enforcing=0" /etc/default/grub; then
            log_msg "ALERT" "SELinux is disabled or set to permissive on kernel command line in /etc/default/grub!"
        fi
    fi

    # 2. Check live kernel command line
    log_msg "INFO" "Live /proc/cmdline: $(cat /proc/cmdline 2>/dev/null)"

    # 3. Check GRUB2 configuration file permissions (Rocky BIOS & EFI paths)
    local grub_files=("/boot/grub2/grub.cfg" "/boot/grub2/user.cfg" "/boot/efi/EFI/rocky/grub.cfg" "/boot/efi/EFI/rocky/user.cfg")
    for gf in "${grub_files[@]}"; do
        if [[ -f "$gf" ]]; then
            local g_stat
            g_stat="$(stat -c "%a %U:%G" "$gf" 2>/dev/null)"
            log_msg "INFO" "Bootloader file $gf -> Permissions: $g_stat"
            if [[ "$mode" == "harden" ]]; then
                require_root || return 1
                run_cmd "Securing permissions (0600 root:root) on $gf" chmod 600 "$gf"
                run_cmd "Setting owner root:root on $gf" chown root:root "$gf"
            fi
        fi
    done

    # 4. Legal Banners (/etc/issue, /etc/issue.net)
    if [[ "$mode" == "harden" ]]; then
        require_root || return 1
        for bfile in /etc/issue /etc/issue.net; do
            backup_file "$bfile"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_msg "DRYRUN" "Would set warning banner in $bfile (0644 root:root)"
            else
                echo "Authorized uses only. All activity may be monitored and reported." > "$bfile"
                chown root:root "$bfile"
                chmod 644 "$bfile"
                log_msg "OK" "Updated login warning banner in $bfile."
            fi
        done
    fi
}

# ==============================================================================
# 19. MODULE O, P & R: SERVICES, PORTS, AND SYSTEMD AUDIT
# ==============================================================================
audit_services_and_systemd() {
    print_header "MODULE O & R: SYSTEMD SERVICES & UNIT FILES AUDIT (READ-ONLY)"
    detect_mail_stack

    log_msg "INFO" "--- Active Running Services ---"
    systemctl list-units --type=service --state=running --no-pager 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    log_msg "INFO" "--- Failed Services ---"
    systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    # Check for custom or overridden systemd unit files in /etc/systemd/system and /run/systemd/system
    log_msg "INFO" "--- Custom Unit Files & Drop-in Overrides in /etc/systemd/system ---"
    find /etc/systemd/system -maxdepth 2 \( -type f -o -type d \) ! -name "*.wants" 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    # Check for world-writable systemd service unit files
    log_msg "INFO" "--- Checking for World-Writable Systemd Unit Files ---"
    local ww_units
    ww_units="$(find /etc/systemd/system /usr/lib/systemd/system -type f -perm -0002 2>/dev/null)"
    if [[ -n "$ww_units" ]]; then
        log_msg "ALERT" "World-writable systemd unit files found: $ww_units"
    else
        log_msg "OK" "No world-writable systemd unit files detected."
    fi
}

audit_listening_ports() {
    print_header "MODULE P: LISTENING NETWORK SOCKETS AUDIT (READ-ONLY)"

    log_msg "INFO" "--- Listening TCP Sockets (ss -tlnp) ---"
    ss -tlnp 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    log_msg "INFO" "--- Listening UDP Sockets (ss -ulnp) ---"
    ss -ulnp 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
}

# ==============================================================================
# 20. MODULE Q: FIREWALL (FIREWALLD)
# ==============================================================================
audit_firewall() {
    print_header "MODULE Q: FIREWALLD & NFTABLES AUDIT (READ-ONLY)"
    detect_mail_stack

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        log_msg "OK" "firewalld service is active."
        log_msg "INFO" "Default Zone: $(firewall-cmd --get-default-zone 2>/dev/null)"
        log_msg "INFO" "Active Zones & Interfaces:"
        firewall-cmd --get-active-zones 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
        log_msg "INFO" "Runtime Configuration (--list-all):"
        firewall-cmd --list-all 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
        log_msg "INFO" "Permanent Configuration (--list-all --permanent):"
        firewall-cmd --list-all --permanent 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    else
        log_msg "WARN" "firewalld is NOT active! Checking raw nftables/iptables ruleset:"
        nft list ruleset 2>/dev/null | head -n 40 | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi
}

harden_firewall() {
    print_header "MODULE Q: CONFIGURE FIREWALLD (MAIL-SERVER SAFE)"
    require_root || return 1
    detect_mail_stack

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log_msg "ALERT" "firewall-cmd is not installed. Cannot configure firewalld."
        return 1
    fi

    # Start and enable firewalld if not running
    if ! systemctl is-active --quiet firewalld 2>/dev/null; then
        run_cmd "Enabling and starting firewalld" systemctl enable --now firewalld
    fi

    # 1. Always permit SSH so remote administration and SSH scoring never drop
    run_cmd "Permitting SSH service in firewalld (runtime)" firewall-cmd --add-service=ssh
    run_cmd "Permitting SSH service in firewalld (permanent)" firewall-cmd --permanent --add-service=ssh

    # 2. Permit ONLY the mail ports that are actively listening on this server
    if [[ ${#ACTIVE_MAIL_PORTS[@]} -gt 0 ]]; then
        for mport in "${ACTIVE_MAIL_PORTS[@]}"; do
            run_cmd "Permitting active mail TCP port ${mport}/tcp (runtime)" firewall-cmd --add-port="${mport}/tcp"
            run_cmd "Permitting active mail TCP port ${mport}/tcp (permanent)" firewall-cmd --permanent --add-port="${mport}/tcp"
        done
    else
        log_msg "WARN" "No active listening mail ports were detected via ss! Review firewall rules manually if mail services are currently stopped."
    fi

    # 3. If webmail (httpd/nginx) is active, preserve HTTP/HTTPS
    if systemctl is-active --quiet httpd 2>/dev/null || systemctl is-active --quiet nginx 2>/dev/null; then
        log_msg "INFO" "Active web server detected (likely Webmail). Preserving HTTP/HTTPS in firewalld."
        run_cmd "Permitting HTTP/HTTPS (runtime)" firewall-cmd --add-service=http --add-service=https
        run_cmd "Permitting HTTP/HTTPS (permanent)" firewall-cmd --permanent --add-service=http --add-service=https
    fi

    log_msg "OK" "Firewalld updated safely without disrupting SSH or active mail ports."
}

# ==============================================================================
# 21. MODULE S: LOGGING AUDIT AND BASELINE
# ==============================================================================
audit_and_harden_logging() {
    local mode="${1:-audit}"
    print_header "MODULE S: SYSTEM & MAIL LOGGING (${mode^^})"

    for lsvc in systemd-journald rsyslog auditd; do
        local st
        st="$(systemctl is-active "$lsvc" 2>/dev/null || echo "inactive")"
        log_msg "INFO" "Logging service '$lsvc' status: $st"
    done

    # Check Rocky Linux log files (/var/log/maillog, /var/log/secure, /var/log/messages)
    local rocky_logs=("/var/log/maillog" "/var/log/secure" "/var/log/messages" "/var/log/cron" "/var/log/audit/audit.log")
    for lf in "${rocky_logs[@]}"; do
        if [[ -f "$lf" ]]; then
            local lstat
            lstat="$(stat -c "%a %U:%G %s bytes" "$lf" 2>/dev/null)"
            log_msg "OK" "Log file present: $lf ($lstat)"
            if [[ "$mode" == "harden" ]]; then
                require_root || return 1
                run_cmd "Restricting permissions (0600) on $lf" chmod 600 "$lf"
            fi
        else
            log_msg "WARN" "Expected Rocky Linux log file missing: $lf"
        fi
    done

    # Ensure persistent systemd journal directory exists if hardening
    if [[ "$mode" == "harden" ]]; then
        require_root || return 1
        if [[ ! -d /var/log/journal ]]; then
            run_cmd "Creating persistent journal directory /var/log/journal" mkdir -p /var/log/journal
            run_cmd "Applying systemd-tmpfiles to /var/log/journal" systemd-tmpfiles --create --prefix /var/log/journal
            run_cmd "Restarting systemd-journald" systemctl restart systemd-journald
        fi
        if systemctl list-unit-files rsyslog.service >/dev/null 2>&1; then
            run_cmd "Ensuring rsyslog is enabled and running" systemctl enable --now rsyslog
        fi
    fi
}

# ==============================================================================
# 22. MODULE T: SELINUX (AND OPTIONAL APPARMOR CHECK)
# ==============================================================================
audit_selinux() {
    print_header "MODULE T: SELINUX MANDATORY ACCESS CONTROL AUDIT (READ-ONLY)"

    if command -v getenforce >/dev/null 2>&1; then
        local enf
        enf="$(getenforce 2>/dev/null)"
        if [[ "$enf" == "Enforcing" ]]; then
            log_msg "OK" "SELinux current mode: $enf"
        else
            log_msg "WARN" "SELinux current mode is '$enf' (Not Enforcing!)."
        fi
    else
        log_msg "ALERT" "getenforce not found! SELinux tools may be missing."
    fi

    if command -v sestatus >/dev/null 2>&1; then
        log_msg "INFO" "sestatus output:"
        sestatus 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # Check SELinux file contexts on critical mail and auth paths (Read-only restorecon -nv)
    if command -v restorecon >/dev/null 2>&1; then
        log_msg "INFO" "Checking for SELinux file context mismatches on critical paths (restorecon -nv):"
        local check_paths=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/ssh" "/etc/postfix" "/etc/dovecot" "/var/spool/mail" "/var/spool/postfix")
        for cp in "${check_paths[@]}"; do
            [[ -e "$cp" ]] || continue
            local mis
            mis="$(restorecon -Rnv "$cp" 2>/dev/null | head -n 20)"
            if [[ -n "$mis" ]]; then
                log_msg "WARN" "SELinux context mismatch detected under $cp:"
                echo "$mis" | sed 's/^/  /' | tee -a "$LOG_FILE"
            fi
        done
    fi

    # Check recent SELinux AVC denials (last 15 minutes)
    if command -v ausearch >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
        log_msg "INFO" "Checking recent SELinux AVC denials (ausearch -m avc -ts recent):"
        ausearch -m avc -ts recent 2>/dev/null | tail -n 20 | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # Only check AppArmor if explicitly installed
    if command -v aa-status >/dev/null 2>&1; then
        log_msg "WARN" "AppArmor tools detected on Rocky Linux:"
        aa-status 2>/dev/null | head -n 10 | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi
}

# ==============================================================================
# 23. FULL READ-ONLY BASELINE AUDIT & CONSERVATIVE HARDENING SUITES
# ==============================================================================
run_full_audit() {
    print_header "STARTING FULL READ-ONLY SECURITY & MAIL BASELINE AUDIT"
    verify_rocky_linux
    audit_mail_stack
    audit_users_and_accounts
    audit_auth_policies
    audit_sshd
    audit_network_and_sysctl
    audit_ftp
    audit_and_harden_etc_permissions "audit"
    audit_and_harden_sudoers "audit"
    audit_packages_and_repos
    audit_polkit
    audit_scheduled_tasks
    audit_display_manager
    audit_grub_and_banners "audit"
    audit_services_and_systemd
    audit_listening_ports
    audit_firewall
    audit_selinux
    audit_and_harden_logging "audit"
    audit_malware_lightweight
    print_header "FULL AUDIT COMPLETE — LOG SAVED TO: $LOG_FILE"
}

run_conservative_hardening() {
    print_header "STARTING CONSERVATIVE HARDENING SUITE (DRY_RUN=${DRY_RUN})"
    require_root || return 1
    verify_rocky_linux
    detect_mail_stack

    audit_and_harden_etc_permissions "harden"
    audit_and_harden_sudoers "harden"
    harden_auth_policies
    harden_sshd
    harden_sysctl
    harden_firewall
    audit_grub_and_banners "harden"
    audit_and_harden_logging "harden"

    print_header "CONSERVATIVE HARDENING COMPLETE (DRY_RUN=${DRY_RUN})"
    show_rollback_instructions
}

# ==============================================================================
# 24. MAIN MENU AND EXECUTION FLOW
# ==============================================================================
toggle_dry_run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        DRY_RUN=0
        log_msg "WARN" "LIVE MODE ENABLED (DRY_RUN=0). Hardening actions WILL modify the system (with backups)."
    else
        DRY_RUN=1
        log_msg "INFO" "DRY-RUN MODE ENABLED (DRY_RUN=1). No system files will be modified."
    fi
}

display_menu() {
    local mode_str="DRY-RUN (Safe Preview - No Changes)"
    [[ $DRY_RUN -eq 0 ]] && mode_str="LIVE MODE (Applies Changes with Backups)"

    echo ""
    echo "=============================================================================="
    echo " ROCKY LINUX CCDC MAIL SERVER SECURITY BASELINE"
    echo " Execution Mode : $mode_str"
    echo " Log File       : $LOG_FILE"
    echo " Backup Path    : $BACKUP_ROOT"
    echo "=============================================================================="
    echo " [AUDIT - READ-ONLY MODULES]"
    echo "   1) Run FULL Read-Only System & Mail Audit (Recommended First Step)"
    echo "   2) Audit Mail Stack (Postfix/Dovecot/Queues/TLS/DNS/Storage)"
    echo "   3) Audit Users, UID 0, Wheel Group & System Shells"
    echo "   4) Audit PAM, authselect, pwquality & faillock"
    echo "   5) Audit SSHD, network/sysctl, Listening Ports & Firewalld"
    echo "   6) Audit /etc Permissions, Sudoers, Polkit, Cron & Systemd"
    echo "   7) Audit SELinux, Logging & Lightweight Malware/RPM Integrity"
    echo ""
    echo " [HARDEN - CONSERVATIVE CONFIGURATION MODULES]"
    echo "   8) Toggle DRY-RUN / LIVE Mode (Currently: $([[ $DRY_RUN -eq 1 ]] && echo "DRY-RUN" || echo "LIVE"))"
    echo "   9) Run ALL Conservative Hardening Modules (Mail-Safe)"
    echo "  10) Harden Core /etc Permissions & Sudoers"
    echo "  11) Harden Password & Auth Policies (pwquality/faillock/login.defs)"
    echo "  12) Harden SSHD Configuration (Validated via sshd -t)"
    echo "  13) Harden Kernel & Network Sysctl (/etc/sysctl.d/)"
    echo "  14) Harden Firewalld (Preserves SSH & Detected Mail Ports)"
    echo "  15) Harden Logging & Login Banners"
    echo ""
    echo " [MAINTENANCE & ACCOUNT OPERATIONS (INTERACTIVE CONFIRMATION)]"
    echo "  16) Reconcile Users & Privileges from Roster ($USER_ROSTER_FILE)"
    echo "  17) Manage User Passwords & Aging Policies"
    echo "  18) Check & Apply DNF Package Updates (dnf upgrade)"
    echo "  19) Show Backup & Rollback Instructions"
    echo "   0) Exit"
    echo "=============================================================================="
}

main() {
    init_logging

    # Support CLI flags for non-interactive audit
    if [[ "${1:-}" == "--audit" ]]; then
        run_full_audit
        exit 0
    elif [[ "${1:-}" == "--live" ]]; then
        DRY_RUN=0
    fi

    while true; do
        display_menu
        read -r -p "Select an option [0-19]: " choice
        case "$choice" in
            1)  run_full_audit ;;
            2)  audit_mail_stack ;;
            3)  audit_users_and_accounts ;;
            4)  audit_auth_policies ;;
            5)  audit_sshd; audit_network_and_sysctl; audit_listening_ports; audit_firewall ;;
            6)  audit_and_harden_etc_permissions "audit"; audit_and_harden_sudoers "audit"; audit_polkit; audit_scheduled_tasks; audit_services_and_systemd ;;
            7)  audit_selinux; audit_and_harden_logging "audit"; audit_malware_lightweight ;;
            8)  toggle_dry_run ;;
            9)  run_conservative_hardening ;;
            10) audit_and_harden_etc_permissions "harden"; audit_and_harden_sudoers "harden" ;;
            11) harden_auth_policies ;;
            12) harden_sshd ;;
            13) harden_sysctl ;;
            14) harden_firewall ;;
            15) audit_grub_and_banners "harden"; audit_and_harden_logging "harden" ;;
            16) manage_user_accounts ;;
            17) manage_user_passwords ;;
            18) update_all_applications ;;
            19) show_rollback_instructions ;;
            0)  log_msg "INFO" "Exiting script."; exit 0 ;;
            *)  log_msg "WARN" "Invalid selection: $choice" ;;
        esac
    done
}

main "$@"