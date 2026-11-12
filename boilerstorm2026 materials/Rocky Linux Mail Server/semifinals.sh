#!/usr/bin/env bash
# ==============================================================================
# Rocky Linux CCDC Mail Server Security Baseline & Auditing Script
# Target OS: Rocky Linux 8 / 9 (RHEL-compatible)
# System Role: Mail Server (Postfix / Dovecot / Sendmail / Exim / Webmail)
# Design: Audit-First, Conservative Hardening, Idempotent, Mail-Safe
# ==============================================================================

set -o pipefail

# Self-check for CRLF line endings
if grep -q $'\r' "$0" 2>/dev/null; then
    echo "[ALERT] CRLF line endings detected in $0! Run: sed -i 's/\r$//' \"$0\"" >&2
    exit 1
fi

# ==============================================================================
# 1. INITIALIZATION, CONFIGURATION & BASELINE VARIABLES
# ==============================================================================
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly TIMESTAMP
readonly LOG_DIR="/var/log/ccdc_hardening"
LOG_FILE="${LOG_DIR}/baseline_${TIMESTAMP}.log"
readonly BACKUP_ROOT="/var/backups/ccdc_hardening/${TIMESTAMP}"
readonly SECURE_TMP_DIR="/run/ccdc_hardening"
readonly USER_ROSTER_FILE="${SCRIPT_DIR}/users.txt"
readonly SYSCTL_DROPIN="/etc/sysctl.d/99-ccdc-mail-baseline.conf"
readonly SUDOERS_DROPIN="/etc/sudoers.d/99-ccdc-baseline"
readonly SSHD_DROPIN="/etc/ssh/sshd_config.d/00-ccdc.conf"
readonly PWQUALITY_DROPIN="/etc/security/pwquality.conf.d/99-ccdc-baseline.conf"

# Optional hardcoded competition fallback password (leave empty to prompt interactively in Mode 4)
readonly DEFAULT_COMP_PASSWORD=""

# Identify invoking administrative user to prevent self-lockout
INVOKING_USER="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"
readonly INVOKING_USER

# Global Execution Mode: 1 = Dry-Run (No changes applied), 0 = Live Mode
DRY_RUN=1

# Protected Mail & Infrastructure Services (Never auto-disable or purge)
readonly PROTECTED_SERVICES=(
    "sshd" "firewalld" "NetworkManager" "systemd-journald" "rsyslog" "crond"
    "postfix" "dovecot" "sendmail" "exim" "cyrus-imapd" "opendkim" "opendmarc"
    "spamassassin" "spamd" "clamd@scan" "clamav-milter" "amavisd" "sqlgrey"
    "postgrey" "httpd" "nginx" "php-fpm" "mariadb" "mysqld" "postgresql"
    "named" "unbound" "slapd" "sssd" "chronyd" "auditd" "polkit"
)

# Protected System, Cloud & Mail Accounts (Never lock, delete, or alter shell)
readonly PROTECTED_ACCOUNTS=(
    "root" "bin" "daemon" "adm" "lp" "sync" "shutdown" "halt" "mail" "operator"
    "games" "ftp" "nobody" "nfsnobody" "dbus" "systemd-coredump" "systemd-resolve"
    "tss" "polkitd" "unbound" "sssd" "sshd" "chrony" "postfix" "dovecot" "dovenull"
    "opendkim" "opendmarc" "spamd" "amavis" "clamupdate" "virusgroup" "vmail"
    "apache" "nginx" "mysql" "postgres" "named" "ldap" "rpc" "rpcuser" "cockpit-ws"
    "rocky" "cloud-user"
)

# Common Mail Ports (TCP)
readonly MAIL_PORTS_TCP=(25 465 587 110 143 993 995)

# Detected Active Mail Components
ACTIVE_MAIL_SERVICES=()
ACTIVE_MAIL_PORTS=()
ACTIVE_SSH_PORTS=()
IPV6_REQUIRED=0

# ==============================================================================
# 2. LOGGING, WHITESPACE HELPERS & SECURE TEMP FILES
# ==============================================================================
trim_str() {
    local var="$*"
    var="${var//$'\r'/}"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

init_logging() {
    if [[ $EUID -eq 0 ]]; then
        mkdir -p "$LOG_DIR"
        chmod 700 "$LOG_DIR"
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
        mkdir -p "$SECURE_TMP_DIR"
        chmod 700 "$SECURE_TMP_DIR"
        chown root:root "$SECURE_TMP_DIR"
    else
        LOG_FILE="/tmp/ccdc_baseline_${TIMESTAMP}_$$.log"
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
    readonly LOG_FILE
}

make_secure_tmp() {
    local prefix="${1:-ccdc}"
    mkdir -p "$SECURE_TMP_DIR"
    chmod 700 "$SECURE_TMP_DIR"
    chown root:root "$SECURE_TMP_DIR"
    mktemp "${SECURE_TMP_DIR}/${prefix}.XXXXXXXXXX"
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

    local formatted
    formatted="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg"
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

confirm_live_action() {
    local prompt_msg="$1"
    if [[ $DRY_RUN -eq 1 ]]; then
        return 0
    fi
    read -r -p "[CONFIRM LIVE CHANGE] ${prompt_msg} (y/N): " resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
        return 0
    fi
    log_msg "INFO" "Action skipped by administrator."
    return 1
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
    log_msg "INFO" "Invoking Admin User: ${INVOKING_USER}"

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
        log_msg "DRYRUN" "Would back up '$target' under '${BACKUP_ROOT}${target}'"
        return 0
    fi

    require_root || return 1
    local dest_dir dest_file
    dest_dir="${BACKUP_ROOT}$(dirname "$target")"
    dest_file="${BACKUP_ROOT}${target}"
    mkdir -p "$dest_dir"
    chmod 700 "$BACKUP_ROOT"

    # Never overwrite the initial baseline backup if a module is run multiple times
    if [[ -e "$dest_file" ]]; then
        dest_file="${dest_file}.$(date +%H%M%S)"
    fi

    if cp -a "$target" "$dest_file"; then
        log_msg "INFO" "Backed up '$target' -> '$dest_file'"
        return 0
    else
        log_msg "ALERT" "Failed to back up '$target'!"
        return 1
    fi
}

show_rollback_instructions() {
    print_header "BACKUP & ROLLBACK INSTRUCTIONS"
    log_msg "INFO" "Original configuration files and pre-change state are stored under:"
    log_msg "INFO" "  ${BACKUP_ROOT}"
    cat << EOF

1. Roll back a modified configuration file (e.g., sshd, sudoers, login.defs, faillock.conf):
   cp -a ${BACKUP_ROOT}/etc/ssh/sshd_config /etc/ssh/sshd_config
   rm -f ${SSHD_DROPIN}
   restorecon -Rv /etc/ssh
   systemctl reload sshd

2. Roll back Sysctl runtime & persistent changes:
   rm -f ${SYSCTL_DROPIN}
   sysctl -p ${BACKUP_ROOT}/sysctl_runtime_before.conf
   sysctl --system

3. Roll back authselect PAM profile changes:
   authselect backup-list
   authselect backup-restore <BACKUP_NAME>

4. Roll back Firewalld to permanent state (if runtime rules caused an issue):
   firewall-cmd --reload

5. Roll back DNF package updates:
   dnf history list
   dnf history undo last

To list all files backed up in this session:
   find ${BACKUP_ROOT} -type f 2>/dev/null
EOF
}

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
    ACTIVE_SSH_PORTS=()
    IPV6_REQUIRED=0

    local svc
    for svc in "${PROTECTED_SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            ACTIVE_MAIL_SERVICES+=("$svc")
        fi
    done

    # Check listening mail ports
    local port
    for port in "${MAIL_PORTS_TCP[@]}"; do
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
            ACTIVE_MAIL_PORTS+=("$port")
        fi
    done

    # Detect actual SSH port(s) from sshd -T and ss -tlnp
    if command -v sshd >/dev/null 2>&1; then
        while IFS= read -r p; do
            [[ -n "$p" && "$p" =~ ^[0-9]+$ ]] && ACTIVE_SSH_PORTS+=("$p")
        done < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
    fi
    if [[ ${#ACTIVE_SSH_PORTS[@]} -eq 0 ]]; then
        ACTIVE_SSH_PORTS=(22)
    fi

    # Check if mail stack or host actively uses IPv6 or SLAAC
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "\[::\]:(25|465|587|110|143|993|995)$"; then
        IPV6_REQUIRED=1
    fi
    if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
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
        log_msg "OK" "Detected active/enabled protected & mail services: ${ACTIVE_MAIL_SERVICES[*]}"
    else
        log_msg "WARN" "No protected/mail services detected as active/enabled via systemd!"
    fi

    if [[ ${#ACTIVE_MAIL_PORTS[@]} -gt 0 ]]; then
        log_msg "OK" "Detected listening mail TCP ports: ${ACTIVE_MAIL_PORTS[*]}"
    else
        log_msg "WARN" "No standard mail TCP ports (25, 465, 587, 110, 143, 993, 995) are currently listening!"
    fi

    if [[ $IPV6_REQUIRED -eq 1 ]]; then
        log_msg "INFO" "IPv6 global addresses or mail bindings detected. IPv6 and RA will be preserved."
    else
        log_msg "INFO" "No explicit global IPv6 mail bindings detected (preserving IPv6 loopback for stability)."
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

        if echo "$mynetworks" | grep -Eq "(0\.0\.0\.0/0|::/0)"; then
            log_msg "ALERT" "Postfix mynetworks contains 0.0.0.0/0 or ::/0 (OPEN RELAY RISK)!"
        fi
        if ! echo "$relay_restrictions" | grep -Eq "(reject_unauth_destination|defer_unauth_destination)"; then
            log_msg "ALERT" "Postfix smtpd_relay_restrictions may lack reject_unauth_destination!"
        fi

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
    local mdir
    for mdir in /var/spool/mail /var/mail /var/spool/postfix /var/vmail /home; do
        if [[ -e "$mdir" ]]; then
            local mstat
            mstat="$(stat -c "%a %U:%G %C" "$mdir" 2>/dev/null)"
            log_msg "INFO" "Storage Path $mdir -> Mode/Owner/SELinux: $mstat"
        fi
    done

    # DNS Resolution check
    log_msg "INFO" "--- Mail DNS & Hostname Verification ---"
    log_msg "INFO" "System Hostname: $(hostname -f 2>/dev/null || hostname)"
    if [[ -f /etc/resolv.conf ]]; then
        local nameservers
        nameservers="$(awk '/^[[:space:]]*nameserver/ {print $2}' /etc/resolv.conf | paste -sd ' ' -)"
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
    [[ "$acct" == "$INVOKING_USER" ]] && return 0
    local p
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

    local uid0_users
    uid0_users="$(awk -F: '$3 == 0 {print $1}' /etc/passwd | paste -sd ' ' -)"
    if [[ "$uid0_users" == "root" ]]; then
        log_msg "OK" "Only 'root' has UID 0."
    else
        log_msg "ALERT" "Multiple accounts with UID 0 detected: $uid0_users"
    fi

    log_msg "INFO" "Standard user accounts (UID >= 1000):"
    awk -F: '$3 >= 1000 && $1 !~ /^(nobody|nfsnobody)$/ {printf "  - %-20s UID: %-6s GID: %-6s Home: %-20s Shell: %s\n", $1, $3, $4, $6, $7}' /etc/passwd | tee -a "$LOG_FILE"

    log_msg "INFO" "Checking system accounts (UID < 1000) with interactive login shells:"
    local uname uid shell
    while IFS=: read -r uname _ uid _ _ _ shell; do
        if [[ "$uid" -lt 1000 && "$uname" != "root" && "$uname" != "sync" && "$uname" != "shutdown" && "$uname" != "halt" ]]; then
            if [[ "$shell" != "/sbin/nologin" && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
                log_msg "ALERT" "System account '$uname' (UID $uid) has an interactive shell: $shell"
            fi
        fi
    done < /etc/passwd

    local wheel_members
    wheel_members="$(getent group wheel | awk -F: '{print $4}')"
    log_msg "INFO" "Members of administrative 'wheel' group: ${wheel_members:-<none>}"

    if [[ $EUID -eq 0 ]]; then
        local empty_pw
        empty_pw="$(awk -F: '($2 == "") {print $1}' /etc/shadow | paste -sd ' ' -)"
        if [[ -n "$empty_pw" ]]; then
            log_msg "ALERT" "Accounts with EMPTY passwords in /etc/shadow: $empty_pw"
        else
            log_msg "OK" "No accounts have empty password fields in /etc/shadow."
        fi
    fi

    local dup_uids dup_gids dup_names
    dup_uids="$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | paste -sd ' ' -)"
    dup_gids="$(awk -F: '{print $3}' /etc/group | sort | uniq -d | paste -sd ' ' -)"
    dup_names="$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d | paste -sd ' ' -)"
    [[ -n "$dup_uids" ]] && log_msg "ALERT" "Duplicate UIDs detected: $dup_uids" || log_msg "OK" "No duplicate UIDs."
    [[ -n "$dup_gids" ]] && log_msg "ALERT" "Duplicate GIDs detected: $dup_gids" || log_msg "OK" "No duplicate GIDs."
    [[ -n "$dup_names" ]] && log_msg "ALERT" "Duplicate Usernames detected: $dup_names" || log_msg "OK" "No duplicate Usernames."
}

load_roster_into_map() {
    # Expects associative array name `roster_role` in caller scope
    if [[ ! -f "$USER_ROSTER_FILE" ]]; then
        log_msg "WARN" "Roster file '$USER_ROSTER_FILE' not found."
        log_msg "INFO" "Expected format per line: username:role (where role is 'admin' or 'user')"
        return 1
    fi

    local line uname role
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line//$'\r'/}"
        line="${line%%#*}"
        line="$(trim_str "$line")"
        [[ -z "$line" ]] && continue

        IFS=: read -r uname role <<< "$line"
        uname="$(trim_str "$uname")"
        role="$(trim_str "${role,,}")"

        if ! validate_username_syntax "$uname"; then
            log_msg "ALERT" "Invalid username syntax in roster: '$uname'. Aborting."
            return 1
        fi
        if [[ "$role" != "admin" && "$role" != "user" ]]; then
            log_msg "ALERT" "Invalid role '$role' for user '$uname' (must be 'admin' or 'user'). Aborting."
            return 1
        fi
        roster_role["$uname"]="$role"
    done < "$USER_ROSTER_FILE"

    if [[ ${#roster_role[@]} -eq 0 ]]; then
        log_msg "WARN" "Roster file is empty."
        return 1
    fi
    return 0
}

manage_user_accounts() {
    print_header "MODULE A: USER ACCOUNT RECONCILIATION (ROSTER-BASED)"
    require_root || return 1

    local -A roster_role=()
    load_roster_into_map || return 1
    log_msg "INFO" "Loaded ${#roster_role[@]} valid users from '$USER_ROSTER_FILE'."

    # 1. Verify existence & privilege level for roster users
    local uname role
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
                if [[ "$uname" == "root" || "$uname" == "$INVOKING_USER" ]]; then
                    log_msg "WARN" "Refusing to strip wheel privileges from root or invoking user '$uname'."
                else
                    # Check that at least one other wheel member exists before removing
                    local wheel_count
                    wheel_count="$(getent group wheel | awk -F: '{print $4}' | tr ',' '\n' | grep -cvE "^(${uname}|)$")"
                    if [[ "$wheel_count" -lt 1 ]]; then
                        log_msg "ALERT" "Refusing to remove '$uname' from wheel: they are the last remaining wheel admin!"
                    else
                        run_cmd "Removing wheel (admin) privileges from standard user '$uname'" gpasswd -d "$uname" wheel
                    fi
                fi
            else
                log_msg "OK" "User '$uname' privilege state matches roster ($role)."
            fi
        fi
    done

    # 2. Identify unauthorized human users (UID >= 1000) not in roster
    log_msg "INFO" "Checking for existing UID >= 1000 accounts not listed in '$USER_ROSTER_FILE'..."
    local sys_user sys_uid
    while IFS=: read -r sys_user _ sys_uid _ _ _ _; do
        [[ "$sys_uid" -lt 1000 ]] && continue
        if is_protected_account "$sys_user"; then
            log_msg "INFO" "Skipping protected/invoking account '$sys_user' (UID $sys_uid)."
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

    cat << 'EOF'
------------------------------------------------------------------------------
SECURITY IMPLICATION WARNING: SHARED PASSWORDS & ACCOUNT AGING
------------------------------------------------------------------------------
1. Shared Passwords: Using one password across accounts enables lateral
   movement if any single account is compromised via cleartext IMAP/POP3/SMTP.
2. Password Aging on Mail Servers: Applying 'chage -M 90' to mail users whose
   passwords were set >90 days ago immediately expires their account, causing
   Dovecot/Postfix PAM authentication to fail. Aging is therefore restricted
   to 'admin' accounts only, with a last-change preview.
------------------------------------------------------------------------------
EOF

    local -A roster_role=()
    load_roster_into_map || return 1

    echo "Select password operation mode:"
    echo "  [1] Read per-user credentials from a root-owned (0600) file (Format: username:password)"
    echo "  [2] Prompt interactively via hidden input (applied to roster users)"
    echo "  [3] Apply password aging policies to ADMIN roster accounts ONLY (no password change)"
    echo "  [4] Rapid Comp Mode: Apply shared fallback password to roster users & clear faillock"
    echo "  [0] Cancel"
    read -r -p "Choice [0-4]: " pw_mode

    local uname role
    case "$pw_mode" in
        1)
            read -r -p "Enter full path to root-owned 0600 credential file: " cred_file
            if [[ ! -f "$cred_file" || -L "$cred_file" ]]; then
                log_msg "ALERT" "Credential file '$cred_file' does not exist or is a symlink."
                return 1
            fi
            local f_perm f_owner
            f_perm="$(stat -c "%a" "$cred_file" 2>/dev/null)"
            f_owner="$(stat -c "%u:%g" "$cred_file" 2>/dev/null)"
            if [[ "$f_owner" != "0:0" ]] || [[ "$f_perm" != "600" && "$f_perm" != "400" ]]; then
                log_msg "ALERT" "Credential file '$cred_file' must be owned by root:root (0:0) with mode 600 or 400 (Current: $f_owner $f_perm)."
                return 1
            fi

            backup_file /etc/shadow
            local c_line c_user c_pass
            while IFS= read -r c_line || [[ -n "$c_line" ]]; do
                c_line="${c_line//$'\r'/}"
                [[ -z "$c_line" || "$c_line" =~ ^[[:space:]]*# ]] && continue
                c_user="${c_line%%:*}"
                c_pass="${c_line#*:}"
                c_user="$(trim_str "$c_user")"
                if [[ -z "$c_user" || -z "$c_pass" ]]; then
                    continue
                fi
                if is_protected_account "$c_user" && [[ "$c_user" != "$INVOKING_USER" ]]; then
                    log_msg "WARN" "Skipping protected system/service account '$c_user' in credential file."
                    continue
                fi
                local uid_check
                uid_check="$(id -u "$c_user" 2>/dev/null || echo "")"
                if [[ -z "$uid_check" || "$uid_check" -lt 1000 ]]; then
                    log_msg "WARN" "Skipping non-existent or UID < 1000 account '$c_user'."
                    continue
                fi
                if [[ $DRY_RUN -eq 1 ]]; then
                    log_msg "DRYRUN" "Would update password for '$c_user' from credential file."
                else
                    printf '%s:%s\n' "$c_user" "$c_pass" | chpasswd -c SHA512
                    log_msg "OK" "Updated password for '$c_user'."
                fi
            done < "$cred_file"
            unset c_pass
            ;;
        2)
            local new_pass1 new_pass2
            read -r -s -p "Enter new password for roster users (hidden): " new_pass1
            echo ""
            read -r -s -p "Confirm new password (hidden): " new_pass2
            echo ""
            if [[ -z "$new_pass1" || "$new_pass1" != "$new_pass2" ]]; then
                log_msg "ALERT" "Passwords do not match or are empty. Aborting."
                unset new_pass1 new_pass2
                return 1
            fi

            confirm_live_action "Apply new password to all non-protected users in '$USER_ROSTER_FILE'?" || { unset new_pass1 new_pass2; return 0; }
            backup_file /etc/shadow
            for uname in "${!roster_role[@]}"; do
                if id "$uname" >/dev/null 2>&1 && ! is_protected_account "$uname"; then
                    if [[ $DRY_RUN -eq 1 ]]; then
                        log_msg "DRYRUN" "Would update password for '$uname' via stdin pipe to chpasswd."
                    else
                        printf '%s:%s\n' "$uname" "$new_pass1" | chpasswd -c SHA512
                        log_msg "OK" "Updated password for '$uname'."
                    fi
                fi
            done
            unset new_pass1 new_pass2
            ;;
        3)
            log_msg "INFO" "Proceeding to admin-only password aging configuration."
            ;;
        4)
            local comp_pw="$DEFAULT_COMP_PASSWORD"
            if [[ -z "$comp_pw" ]]; then
                read -r -s -p "DEFAULT_COMP_PASSWORD is unset. Enter fallback shared password (hidden): " comp_pw
                echo ""
                if [[ -z "$comp_pw" ]]; then
                    log_msg "ALERT" "Empty password entered. Aborting."
                    return 1
                fi
            fi

            confirm_live_action "Apply shared competition password and reset faillock for all roster users?" || { unset comp_pw; return 0; }
            backup_file /etc/shadow
            for uname in "${!roster_role[@]}"; do
                if id "$uname" >/dev/null 2>&1 && ! is_protected_account "$uname"; then
                    if [[ $DRY_RUN -eq 1 ]]; then
                        log_msg "DRYRUN" "Would set fallback password and reset faillock tally for '$uname' (without unlocking intentionally locked accounts)."
                    else
                        printf '%s:%s\n' "$uname" "$comp_pw" | chpasswd -c SHA512
                        # Clear pam_faillock tallies, but do NOT run 'passwd -u' blindly
                        faillock --user "$uname" --reset >/dev/null 2>&1 || true
                        log_msg "OK" "Updated password and cleared faillock tally for '$uname'."
                    fi
                fi
            done
            unset comp_pw
            ;;
        *)
            log_msg "INFO" "Cancelled."
            return 0
            ;;
    esac

    # Apply conservative account aging ONLY to 'admin' accounts in roster to avoid breaking mail SASL/PAM users
    log_msg "INFO" "Checking password aging for 'admin' accounts in roster (mail/standard users are skipped to prevent PAM expiry lockouts):"
    for uname in "${!roster_role[@]}"; do
        role="${roster_role[$uname]}"
        [[ "$role" != "admin" ]] && continue
        if id "$uname" >/dev/null 2>&1 && ! is_protected_account "$uname"; then
            local last_chg
            last_chg="$(chage -l "$uname" 2>/dev/null | awk -F': ' '/Last password change/ {print $2}')"
            log_msg "INFO" "Admin '$uname' Last password change: ${last_chg:-Unknown}"
            run_cmd "Setting password aging (min 1d, max 90d, warn 7d) for admin '$uname'" chage -m 1 -M 90 -W 7 "$uname"
        fi
    done
}

# ==============================================================================
# 8. MODULE C: PASSWORD AND AUTHENTICATION POLICIES (PAM / AUTHSELECT)
# ==============================================================================
audit_auth_policies() {
    print_header "MODULE C: PASSWORD & AUTHENTICATION POLICY AUDIT (READ-ONLY)"

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

    if [[ -f /etc/security/pwquality.conf ]]; then
        log_msg "INFO" "Active settings in /etc/security/pwquality.conf & drop-ins:"
        grep -rnEv '^[[:space:]]*(#|$)' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    if [[ -f /etc/security/faillock.conf ]]; then
        log_msg "INFO" "Active settings in /etc/security/faillock.conf:"
        grep -Ev '^[[:space:]]*(#|$)' /etc/security/faillock.conf | sed 's/^/  /' | tee -a "$LOG_FILE"
        if grep -Eq '^[[:space:]]*even_deny_root' /etc/security/faillock.conf; then
            log_msg "ALERT" "'even_deny_root' is enabled in /etc/security/faillock.conf! Red Team can brute-force root and lock out administrators."
        fi
    fi

    if [[ -f /etc/login.defs ]]; then
        log_msg "INFO" "Key settings in /etc/login.defs:"
        grep -E '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD|UMASK|MAIL_DIR)' /etc/login.defs | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # Audit /etc/security/{access,limits,namespace}.conf
    local sec_f
    for sec_f in /etc/security/access.conf /etc/security/limits.conf /etc/security/namespace.conf; do
        if [[ -f "$sec_f" ]]; then
            log_msg "INFO" "Non-comment entries in $sec_f:"
            grep -Ev '^[[:space:]]*(#|$)' "$sec_f" | sed 's/^/  /' | tee -a "$LOG_FILE"
        fi
    done

    log_msg "INFO" "Auditing /etc/pam.d/ for suspicious 'pam_permit.so' in auth stacks:"
    grep -rn "pam_permit.so" /etc/pam.d/ 2>/dev/null | grep -E "auth[[:space:]]+" && \
        log_msg "ALERT" "Review pam_permit.so usage in auth stacks above!" || \
        log_msg "OK" "No suspicious auth pam_permit.so entries detected."

    if command -v rpm >/dev/null 2>&1; then
        local pam_verify
        pam_verify="$(rpm -Vf /etc/pam.d/system-auth 2>/dev/null)"
        [[ -n "$pam_verify" ]] && log_msg "INFO" "RPM verify on pam package: $pam_verify"
    fi
}

set_or_append_kv() {
    local file="$1"
    local key="$2"
    local sep="$3"
    local val="$4"
    if grep -Eq "^[#[:space:]]*${key}[[:space:]]*${sep}" "$file" 2>/dev/null; then
        sed -i -E "0,/^[#[:space:]]*${key}[[:space:]]*${sep}.*/s//${key}${sep}${val}/" "$file"
    else
        printf '%s%s%s\n' "$key" "$sep" "$val" >> "$file"
    fi
}

harden_auth_policies() {
    print_header "MODULE C: HARDEN PASSWORD & AUTHENTICATION POLICIES"
    require_root || return 1
    confirm_live_action "Apply PAM / pwquality / faillock / login.defs authentication policies?" || return 0

    log_msg "WARN" "NOTE ON FAILLOCK IN CCDC: Enabling faillock (deny=5, unlock_time=300) protects against brute-force, but allows Red Team to intentionally trigger 5 failed logins against scored user accounts. Use 'faillock --reset' if a scored user is locked out."

    # 1. Harden /etc/security/pwquality.conf via drop-in
    if [[ -f /etc/security/pwquality.conf ]]; then
        backup_file /etc/security/pwquality.conf
        backup_file "$PWQUALITY_DROPIN"
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would write password complexity rules to $PWQUALITY_DROPIN (minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1)"
        else
            mkdir -p /etc/security/pwquality.conf.d
            cat << 'EOF' > "$PWQUALITY_DROPIN"
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
            chmod 644 "$PWQUALITY_DROPIN"
            restorecon "$PWQUALITY_DROPIN" 2>/dev/null || true
            log_msg "OK" "Configured password complexity in $PWQUALITY_DROPIN."
        fi
    fi

    # 2. Harden /etc/security/pwhistory.conf (Rocky 9 / modern PAM)
    if [[ -f /etc/security/pwhistory.conf ]]; then
        backup_file /etc/security/pwhistory.conf
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would configure remember = 5 in /etc/security/pwhistory.conf"
        else
            set_or_append_kv /etc/security/pwhistory.conf "remember" " = " "5"
            log_msg "OK" "Configured password history (remember = 5) in /etc/security/pwhistory.conf."
        fi
    else
        log_msg "WARN" "/etc/security/pwhistory.conf not present on this Rocky version; pwhistory relies on authselect PAM stack."
    fi

    # 3. Configure /etc/security/faillock.conf CONSERVATIVELY (even_deny_root disabled)
    if [[ -f /etc/security/faillock.conf ]]; then
        backup_file /etc/security/faillock.conf
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would configure conservative faillock settings in /etc/security/faillock.conf (deny=5, unlock_time=300, even_deny_root disabled)"
        else
            sed -i 's/^[[:space:]]*even_deny_root/# even_deny_root/' /etc/security/faillock.conf
            set_or_append_kv /etc/security/faillock.conf "deny" " = " "5"
            set_or_append_kv /etc/security/faillock.conf "unlock_time" " = " "300"
            log_msg "OK" "Configured /etc/security/faillock.conf (deny=5, unlock_time=300s, root lockout disabled)."
        fi
    fi

    # 4. Safely update or append keys in /etc/login.defs (Preserve Rocky Linux MAIL_DIR /var/spool/mail)
    if [[ -f /etc/login.defs ]]; then
        backup_file /etc/login.defs
        if [[ $DRY_RUN -eq 1 ]]; then
            log_msg "DRYRUN" "Would update or append PASS_MAX_DAYS (90), PASS_MIN_DAYS (1), PASS_WARN_AGE (7), and ENCRYPT_METHOD (SHA512) in /etc/login.defs"
        else
            set_or_append_kv /etc/login.defs "PASS_MAX_DAYS" $'\t' "90"
            set_or_append_kv /etc/login.defs "PASS_MIN_DAYS" $'\t' "1"
            set_or_append_kv /etc/login.defs "PASS_WARN_AGE" $'\t' "7"
            set_or_append_kv /etc/login.defs "ENCRYPT_METHOD" $'\t' "SHA512"
            log_msg "OK" "Updated password aging defaults in /etc/login.defs while preserving Rocky Linux mail paths."
        fi
    fi

    # 5. Enable authselect features (with-faillock and with-pwhistory) with authselect backup
    if command -v authselect >/dev/null 2>&1 && authselect check >/dev/null 2>&1; then
        if authselect current >/dev/null 2>&1; then
            run_cmd "Enabling authselect with-faillock feature (with backup)" authselect enable-feature with-faillock --backup="ccdc_${TIMESTAMP}"
            if authselect list-features "$(authselect current -r 2>/dev/null | awk '{print $1}')" 2>/dev/null | grep -qx "with-pwhistory"; then
                run_cmd "Enabling authselect with-pwhistory feature" authselect enable-feature with-pwhistory
            else
                log_msg "WARN" "Current authselect profile does not advertise 'with-pwhistory'."
            fi
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
        "net.ipv4.conf.all.accept_source_route"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.all.rp_filter"
        "net.ipv4.tcp_syncookies"
        "net.ipv4.icmp_echo_ignore_all"
        "net.ipv4.icmp_echo_ignore_broadcasts"
        "net.ipv6.conf.all.disable_ipv6"
        "net.ipv6.conf.all.accept_redirects"
        "net.ipv6.conf.all.accept_ra"
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

    local k val
    for k in "${keys[@]}"; do
        val="$(sysctl -n "$k" 2>/dev/null || echo "N/A")"
        printf "  %-45s = %s\n" "$k" "$val" | tee -a "$LOG_FILE"
    done

    log_msg "INFO" "--- Existing Sysctl Configuration Files ---"
    ls -la /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
}

harden_sysctl() {
    print_header "MODULE D & E: SYSCTL & KERNEL HARDENING"
    require_root || return 1
    detect_mail_stack

    backup_file "$SYSCTL_DROPIN"

    # Check if containers/NAT/routing require ip_forward=1
    local ip_fwd_val=0
    if ip link show 2>/dev/null | grep -Eq "docker0|podman|virbr|cni" || \
       nft list ruleset 2>/dev/null | grep -qi "masquerade"; then
        log_msg "WARN" "Container bridge or NAT masquerading detected! Preserving net.ipv4.ip_forward = 1."
        ip_fwd_val=1
    fi

    local tmp_sysctl
    tmp_sysctl="$(make_secure_tmp "sysctl")"
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

# --- IPv4 Network Stack Hardening (rp_filter=2 loose mode for asymmetric routing safety) ---
net.ipv4.ip_forward = ${ip_fwd_val}
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
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

# --- IPv6 Network Stack Hardening (Mail-Safe & SLAAC-Safe) ---
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

    # Only disable IPv6 Router Advertisements if IPv6 is NOT actively used on global interfaces
    if [[ $IPV6_REQUIRED -eq 0 ]]; then
        cat << 'EOF' >> "$tmp_sysctl"
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
    else
        log_msg "INFO" "IPv6 active: omitting accept_ra=0 so SLAAC default routes are not dropped."
    fi

    # Validate keys against /proc/sys/ and record current runtime values for rollback
    local validated_tmp
    validated_tmp="$(make_secure_tmp "sysctl_valid")"
    local runtime_save="${BACKUP_ROOT}/sysctl_runtime_before.conf"
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p "$BACKUP_ROOT"
        chmod 700 "$BACKUP_ROOT"
    fi

    local line key proc_path cur_val
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
            echo "$line" >> "$validated_tmp"
            continue
        fi
        key="$(trim_str "${line%%=*}")"
        proc_path="/proc/sys/${key//./\/}"
        if [[ -e "$proc_path" ]]; then
            echo "$line" >> "$validated_tmp"
            if [[ $DRY_RUN -eq 0 && ! -f "${runtime_save}.done" ]]; then
                cur_val="$(sysctl -n "$key" 2>/dev/null || true)"
                [[ -n "$cur_val" ]] && printf '%s = %s\n' "$key" "$cur_val" >> "$runtime_save"
            fi
        else
            log_msg "WARN" "Skipping unsupported kernel sysctl key on this kernel: $key"
        fi
    done < "$tmp_sysctl"
    rm -f "$tmp_sysctl"
    [[ $DRY_RUN -eq 0 && -f "$runtime_save" ]] && touch "${runtime_save}.done"

    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Validated sysctl configuration. Would install to '$SYSCTL_DROPIN' and apply via 'sysctl -p'."
        rm -f "$validated_tmp"
    else
        mv "$validated_tmp" "$SYSCTL_DROPIN"
        chmod 644 "$SYSCTL_DROPIN"
        chown root:root "$SYSCTL_DROPIN"
        restorecon "$SYSCTL_DROPIN" 2>/dev/null || true
        if sysctl -p "$SYSCTL_DROPIN" >/dev/null; then
            log_msg "OK" "Applied sysctl baseline from '$SYSCTL_DROPIN' (Previous runtime values saved to $runtime_save)."
        else
            log_msg "WARN" "Some sysctl keys returned warnings when applying '$SYSCTL_DROPIN'."
        fi
    fi
}

# ==============================================================================
# 10. MODULE F: SSH AND SSHD
# ==============================================================================
verify_nonroot_admin_access() {
    # Check that at least one non-root user in 'wheel' has an active password hash or non-empty authorized_keys
    local wheel_users
    wheel_users="$(getent group wheel | awk -F: '{print $4}' | tr ',' ' ')"
    local u shadow_hash homedir
    for u in $wheel_users; do
        [[ "$u" == "root" ]] && continue
        id "$u" >/dev/null 2>&1 || continue
        shadow_hash="$(awk -F: -v usr="$u" '$1 == usr {print $2}' /etc/shadow 2>/dev/null)"
        if [[ -n "$shadow_hash" && "$shadow_hash" != "!"* && "$shadow_hash" != "*" && "$shadow_hash" != "!!" ]]; then
            return 0
        fi
        homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
        if [[ -s "${homedir}/.ssh/authorized_keys" ]]; then
            return 0
        fi
    done
    return 1
}

audit_sshd() {
    print_header "MODULE F: SSH & SSHD CONFIGURATION AUDIT (READ-ONLY)"

    if systemctl is-active --quiet sshd 2>/dev/null; then
        log_msg "OK" "sshd service is active and running."
    else
        log_msg "WARN" "sshd service is NOT running!"
    fi

    if command -v sshd >/dev/null 2>&1; then
        log_msg "INFO" "Effective sshd configuration (via sshd -T):"
        sshd -T 2>/dev/null | grep -E "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax|allowusers|allowgroups|denyusers|denygroups|usepam|x11forwarding|banner|authorizedkeysfile)" | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        log_msg "INFO" "Inspecting /etc/ssh/sshd_config.d/ drop-in files:"
        ls -la /etc/ssh/sshd_config.d/ | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    log_msg "INFO" "Auditing SSH authorized_keys files across all accounts:"
    local uname homedir kf count
    while IFS=: read -r uname _ _ _ _ homedir _; do
        if [[ -d "$homedir/.ssh" ]]; then
            for kf in "$homedir/.ssh/authorized_keys" "$homedir/.ssh/authorized_keys2"; do
                if [[ -f "$kf" && -s "$kf" ]]; then
                    count="$(grep -cEv '^[[:space:]]*(#|$)' "$kf")"
                    log_msg "WARN" "User '$uname' has $count key(s) in $kf"
                fi
            done
        fi
    done < /etc/passwd
}

harden_sshd() {
    print_header "MODULE F: HARDEN SSHD CONFIGURATION (DROP-IN & LOCKOUT-SAFE)"
    require_root || return 1

    local sshd_main="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_main" ]]; then
        log_msg "ALERT" "$sshd_main not found!"
        return 1
    fi

    # Lockout Guard: Never disable PermitRootLogin unless a verified non-root wheel admin exists
    local permit_root="no"
    if ! verify_nonroot_admin_access; then
        log_msg "ALERT" "LOCKOUT GUARD: No non-root user in 'wheel' has a valid password hash or SSH key! Refusing to set PermitRootLogin=no."
        permit_root="yes"
    elif [[ -z "${SUDO_USER:-}" && "$INVOKING_USER" == "root" ]]; then
        log_msg "WARN" "You are logged in directly as 'root' (no SUDO_USER). Setting PermitRootLogin=no will require logging in as a wheel user on new SSH sessions."
    fi

    confirm_live_action "Apply SSHD hardening drop-in ($SSHD_DROPIN) with PermitRootLogin=${permit_root}?" || return 0

    backup_file "$sshd_main"
    backup_file "$SSHD_DROPIN"

    local tmp_dropin
    tmp_dropin="$(make_secure_tmp "sshd_dropin")"
    cat << EOF > "$tmp_dropin"
# CCDC Rocky Linux SSHD Hardening Drop-In (00-ccdc.conf takes first-match precedence)
PermitRootLogin ${permit_root}
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
UsePAM yes
Banner /etc/issue.net
EOF

    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Would write SSHD drop-in to $SSHD_DROPIN, ensure top-level Include in $sshd_main, validate with 'sshd -t', and verify effective settings with 'sshd -T'."
        rm -f "$tmp_dropin"
        return 0
    fi

    mkdir -p /etc/ssh/sshd_config.d
    chmod 700 /etc/ssh/sshd_config.d
    mv "$tmp_dropin" "$SSHD_DROPIN"
    chown root:root "$SSHD_DROPIN"
    chmod 600 "$SSHD_DROPIN"
    restorecon "$SSHD_DROPIN" 2>/dev/null || true

    # Ensure /etc/ssh/sshd_config includes /etc/ssh/sshd_config.d/*.conf BEFORE any Match blocks (for Rocky 8 compatibility)
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$sshd_main"; then
        local tmp_main
        tmp_main="$(make_secure_tmp "sshd_main")"
        printf 'Include /etc/ssh/sshd_config.d/*.conf\n' > "$tmp_main"
        cat "$sshd_main" >> "$tmp_main"
        mv "$tmp_main" "$sshd_main"
        chown root:root "$sshd_main"
        chmod 600 "$sshd_main"
        restorecon "$sshd_main" 2>/dev/null || true
    fi

    if ! sshd -t 2>/dev/null; then
        log_msg "ALERT" "'sshd -t' validation failed! Rolling back $SSHD_DROPIN."
        rm -f "$SSHD_DROPIN"
        return 1
    fi

    run_cmd "Reloading sshd service safely" systemctl reload sshd

    # Post-verification via sshd -T to confirm first-match precedence took effect
    local eff_root eff_x11
    eff_root="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" {print $2}')"
    eff_x11="$(sshd -T 2>/dev/null | awk '$1 == "x11forwarding" {print $2}')"
    if [[ "$eff_root" == "$permit_root" && "$eff_x11" == "no" ]]; then
        log_msg "OK" "Verified via 'sshd -T': permitrootlogin=$eff_root, x11forwarding=$eff_x11, PasswordAuthentication preserved."
    else
        log_msg "WARN" "sshd -T reports permitrootlogin=$eff_root, x11forwarding=$eff_x11. An earlier line in $sshd_main may precede the Include directive!"
    fi
}

# ==============================================================================
# 11. MODULE G: FTP AUDIT
# ==============================================================================
audit_ftp() {
    print_header "MODULE G: FTP SERVICES & CONFIGURATION AUDIT (READ-ONLY)"

    local ftp_pkgs=("vsftpd" "proftpd" "pure-ftpd" "tftp-server")
    local found_ftp=0
    local pkg
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

    local vconf
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
    local mode="${1:-audit}"
    print_header "MODULE H: CORE SYSTEM & /etc SECURITY (${mode^^})"

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

    local spec fpath exp_perm exp_own cur_perm cur_own cur_attr
    for spec in "${baseline_specs[@]}"; do
        IFS='|' read -r fpath exp_perm exp_own <<< "$spec"
        [[ ! -e "$fpath" ]] && continue

        cur_perm="$(stat -c "%a" "$fpath" 2>/dev/null)"
        cur_own="$(stat -c "%U:%G" "$fpath" 2>/dev/null)"

        if [[ "$cur_perm" != "$exp_perm" || "$cur_own" != "$exp_own" ]]; then
            log_msg "WARN" "$fpath -> Current: $cur_perm ($cur_own) | Expected: $exp_perm ($exp_own)"
            if [[ "$mode" == "harden" ]]; then
                require_root || return 1
                if [[ $DRY_RUN -eq 0 ]]; then
                    cur_attr="$(lsattr -d "$fpath" 2>/dev/null | awk '{print $1}')"
                    if [[ "$cur_attr" =~ [ia] ]]; then
                        log_msg "WARN" "Stripping immutable/append-only attribute ($cur_attr) from $fpath"
                        chattr -ia "$fpath" 2>/dev/null || true
                    fi
                fi
                run_cmd "Setting ownership $exp_own on $fpath" chown "$exp_own" "$fpath"
                run_cmd "Setting permissions 0$exp_perm on $fpath" chmod "0$exp_perm" "$fpath"
                if [[ $DRY_RUN -eq 0 ]]; then
                    restorecon "$fpath" 2>/dev/null || true
                fi
            fi
        else
            log_msg "OK" "$fpath matches baseline ($cur_perm $cur_own)."
        fi
    done

    log_msg "INFO" "Checking for world-writable files or directories in /etc:"
    local ww_etc
    ww_etc="$(find /etc -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null)"
    if [[ -n "$ww_etc" ]]; then
        log_msg "ALERT" "World-writable items found in /etc:"
        echo "$ww_etc" | sed 's/^/  /' | tee -a "$LOG_FILE"
    else
        log_msg "OK" "No world-writable files or directories in /etc."
    fi

    log_msg "INFO" "Checking for world-writable directories missing the sticky bit (+t):"
    local no_sticky
    no_sticky="$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null)"
    if [[ -n "$no_sticky" ]]; then
        log_msg "ALERT" "World-writable directories missing sticky bit (+t):"
        echo "$no_sticky" | sed 's/^/  /' | tee -a "$LOG_FILE"
    else
        log_msg "OK" "All world-writable directories have the sticky bit set."
    fi

    log_msg "INFO" "Auditing SUID/SGID binaries across /bin, /sbin, /usr, /opt, /var, /home:"
    find /bin /sbin /usr/bin /usr/sbin /usr/local /usr/libexec /usr/lib /opt /var /home -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} + 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    if command -v lsattr >/dev/null 2>&1; then
        log_msg "INFO" "Checking for immutable (+i) or append-only (+a) files in /etc:"
        lsattr -R /etc 2>/dev/null | grep -E '^[^[:space:]]*[ia][^[:space:]]*[[:space:]]' | sed 's/^/  /' | tee -a "$LOG_FILE"
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
        local tmp_sudo
        tmp_sudo="$(make_secure_tmp "sudoers")"
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
    local repo
    for repo in /etc/yum.repos.d/*.repo; do
        [[ ! -f "$repo" ]] && continue
        log_msg "INFO" "Repo file: $repo"
        if grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' "$repo"; then
            log_msg "ALERT" "gpgcheck=0 found in $repo!"
        fi
    done

    local suspect_pkgs=(
        "nmap-ncat" "nc" "socat" "hydra" "john" "hashcat" "wireshark" "tcpdump"
        "nikto" "sqlmap" "aircrack-ng" "ettercap" "metasploit" "telnet-server"
        "rsh-server" "tftp-server" "xinetd" "tigervnc-server"
    )
    log_msg "INFO" "Checking for potentially unwanted or dual-use packages/capabilities (rpm -q --whatprovides):"
    local pkg prov
    for pkg in "${suspect_pkgs[@]}"; do
        if prov="$(rpm -q --whatprovides "$pkg" 2>/dev/null)"; then
            log_msg "WARN" "Installed package capability '$pkg' provided by: $prov"
        fi
    done

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

    log_msg "WARN" "OPERATIONAL NOTE: Run package updates outside scoring check windows, as updating postfix, dovecot, or openssl briefly restarts mail daemons."
    log_msg "INFO" "Checking available DNF updates (read-only preview)..."
    dnf check-update | tee -a "$LOG_FILE"
    local rc="${PIPESTATUS[0]}"

    if [[ $rc -eq 0 ]]; then
        log_msg "OK" "All installed packages are up to date."
        return 0
    elif [[ $rc -ne 100 ]]; then
        log_msg "ALERT" "dnf check-update failed with exit code $rc. Check network/DNS or repo config."
        return 1
    fi

    log_msg "WARN" "Updates are available (exit code 100)."
    if [[ $DRY_RUN -eq 1 ]]; then
        log_msg "DRYRUN" "Dry-Run enabled. Would prompt before running 'dnf upgrade -y --nobest --setopt=install_weak_deps=False' without rebooting."
        return 0
    fi

    read -r -p "Proceed with applying DNF package updates now? (Never auto-reboots) (y/N): " confirm_upd
    if [[ "$confirm_upd" =~ ^[Yy]$ ]]; then
        if dnf upgrade -y --nobest --setopt=install_weak_deps=False 2>&1 | tee -a "$LOG_FILE"; then
            log_msg "OK" "DNF package updates completed. System was NOT rebooted."
            log_msg "INFO" "To roll back this transaction if needed: 'dnf history list' and 'dnf history undo last'."
            if command -v needs-restarting >/dev/null 2>&1; then
                needs-restarting -r 2>&1 | sed 's/^/  /' | tee -a "$LOG_FILE"
            fi
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

    log_msg "INFO" "Scanning /dev/shm, /tmp, and /var/tmp for executable files or hidden items:"
    find /dev/shm /tmp /var/tmp -xdev \( -type f -perm /111 -o -name ".*" ! -name "." ! -name ".." \) 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

    if [[ -f /etc/ld.so.preload && -s /etc/ld.so.preload ]]; then
        log_msg "ALERT" "/etc/ld.so.preload exists and is non-empty! Contents:"
        sed 's/^/  /' /etc/ld.so.preload | tee -a "$LOG_FILE"
    else
        log_msg "OK" "/etc/ld.so.preload is absent or empty."
    fi

    if command -v getcap >/dev/null 2>&1; then
        log_msg "INFO" "Checking file capabilities in /usr/bin, /usr/sbin, /usr/local, /usr/libexec, /opt, /home, /tmp:"
        getcap -r /usr/bin /usr/sbin /usr/local /usr/libexec /opt /home /tmp 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    log_msg "INFO" "Running targeted RPM integrity check (rpm -V) on core security & mail packages:"
    local core_rpms=("openssh-server" "openssh-clients" "pam" "sudo" "shadow-utils" "systemd" "util-linux" "coreutils" "iproute" "procps-ng" "postfix" "dovecot")
    local pkg v_out
    for pkg in "${core_rpms[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            v_out="$(rpm -V "$pkg" 2>/dev/null | grep -Ev ' c ')"
            if [[ -n "$v_out" ]]; then
                log_msg "ALERT" "Binary/File integrity anomaly in package '$pkg':"
                echo "$v_out" | sed 's/^/  /' | tee -a "$LOG_FILE"
            fi
        fi
    done

    local tool
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
    local pdir writable_rules
    for pdir in "${polkit_dirs[@]}"; do
        if [[ -d "$pdir" ]]; then
            log_msg "INFO" "Listing Polkit directory: $pdir"
            ls -la "$pdir" 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

            writable_rules="$(find "$pdir" -type f -perm /022 2>/dev/null)"
            if [[ -n "$writable_rules" ]]; then
                log_msg "ALERT" "Group/World-writable Polkit files found in $pdir: $writable_rules"
            fi

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

    local cron_paths=("/etc/crontab" "/etc/anacrontab" "/etc/cron.d" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/var/spool/cron")
    local cp f
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

    if [[ -d /var/spool/at ]]; then
        log_msg "INFO" "Checking /var/spool/at jobs:"
        find /var/spool/at -maxdepth 1 -type f ! -name ".SEQ" -ls 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

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

    if [[ -f /etc/default/grub ]]; then
        log_msg "INFO" "Contents of /etc/default/grub:"
        sed 's/^/  /' /etc/default/grub | tee -a "$LOG_FILE"
        if grep -Eq "selinux=0|enforcing=0" /etc/default/grub; then
            log_msg "ALERT" "SELinux is disabled or set to permissive on kernel command line in /etc/default/grub!"
        fi
    fi

    log_msg "INFO" "Live /proc/cmdline: $(cat /proc/cmdline 2>/dev/null)"

    # Check if GRUB password protection is configured
    if grep -rq "password_pbkdf2" /boot/grub2/ /boot/efi/EFI/rocky/ /etc/grub.d/ 2>/dev/null; then
        log_msg "OK" "GRUB bootloader password_pbkdf2 entry detected."
    else
        log_msg "WARN" "No GRUB bootloader password (password_pbkdf2) detected."
    fi

    if [[ "$mode" == "harden" ]]; then
        require_root || return 1
        confirm_live_action "Secure GRUB config permissions and write /etc/issue(.net) warning banners?" || return 0
    fi

    local grub_files=("/boot/grub2/grub.cfg" "/boot/grub2/user.cfg" "/boot/efi/EFI/rocky/grub.cfg" "/boot/efi/EFI/rocky/user.cfg")
    local gf g_stat fstype
    for gf in "${grub_files[@]}"; do
        if [[ -f "$gf" ]]; then
            g_stat="$(stat -c "%a %U:%G" "$gf" 2>/dev/null)"
            fstype="$(df -T "$gf" 2>/dev/null | awk 'NR==2 {print $2}')"
            log_msg "INFO" "Bootloader file $gf (fs: ${fstype:-unknown}) -> Permissions: $g_stat"
            if [[ "$mode" == "harden" ]]; then
                if [[ "$fstype" == "vfat" || "$fstype" == "msdos" ]]; then
                    log_msg "INFO" "Skipping chmod/chown on $gf because it resides on a vfat EFI partition (permissions controlled by /etc/fstab umask)."
                else
                    run_cmd "Securing permissions (0600 root:root) on $gf" chmod 600 "$gf"
                    run_cmd "Setting owner root:root on $gf" chown root:root "$gf"
                fi
            fi
        fi
    done

    if [[ "$mode" == "harden" ]]; then
        local bfile
        for bfile in /etc/issue /etc/issue.net; do
            backup_file "$bfile"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_msg "DRYRUN" "Would set warning banner in $bfile (0644 root:root)"
            else
                echo "Authorized uses only. All activity may be monitored and reported." > "$bfile"
                chown root:root "$bfile"
                chmod 644 "$bfile"
                restorecon "$bfile" 2>/dev/null || true
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

    log_msg "INFO" "--- Custom Unit Files & Drop-in Overrides in /etc/systemd/system ---"
    find /etc/systemd/system -maxdepth 2 \( -type f -o -type d \) ! -name "*.wants" 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"

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
# 20. MODULE Q: FIREWALL (FIREWALLD - RUNTIME-FIRST & ACTIVE-ZONE AWARE)
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
    print_header "MODULE Q: CONFIGURE FIREWALLD (RUNTIME-FIRST, MAIL & ZONE SAFE)"
    require_root || return 1
    detect_mail_stack

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log_msg "ALERT" "firewall-cmd is not installed. Cannot configure firewalld."
        return 1
    fi

    # Build list of ports and services to allow before enabling or modifying firewalld
    local planned_services=("ssh")
    local planned_ports=()

    local sp
    for sp in "${ACTIVE_SSH_PORTS[@]}"; do
        planned_ports+=("${sp}/tcp")
    done
    local mp
    for mp in "${ACTIVE_MAIL_PORTS[@]}"; do
        planned_ports+=("${mp}/tcp")
    done
    if systemctl is-active --quiet httpd 2>/dev/null || systemctl is-active --quiet nginx 2>/dev/null; then
        planned_services+=("http" "https")
    fi
    if systemctl is-active --quiet named 2>/dev/null || systemctl is-active --quiet unbound 2>/dev/null; then
        planned_services+=("dns")
    fi

    log_msg "INFO" "Planned Firewalld Allowed Services : ${planned_services[*]}"
    log_msg "INFO" "Planned Firewalld Allowed Ports    : ${planned_ports[*]:-<none detected>}"
    if [[ ${#ACTIVE_MAIL_PORTS[@]} -eq 0 ]]; then
        log_msg "WARN" "No active listening mail ports were detected via 'ss -tln'! If Postfix/Dovecot are currently stopped, start them first or add their ports manually."
    fi

    confirm_live_action "Apply these rules to RUNTIME firewalld across active zones?" || return 0

    if ! systemctl is-active --quiet firewalld 2>/dev/null; then
        run_cmd "Starting firewalld service (runtime)" systemctl start firewalld
    fi

    # Determine active zones (fallback to default zone if no interfaces are bound to a zone yet)
    local target_zones=()
    while IFS= read -r z; do
        [[ -n "$z" ]] && target_zones+=("$z")
    done < <(firewall-cmd --get-active-zones 2>/dev/null | grep -Ev '^[[:space:]]')

    if [[ ${#target_zones[@]} -eq 0 ]]; then
        local def_z
        def_z="$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")"
        target_zones=("$def_z")
    fi

    local zone svc prt
    for zone in "${target_zones[@]}"; do
        log_msg "INFO" "Applying runtime rules to zone: $zone"
        for svc in "${planned_services[@]}"; do
            run_cmd "Zone '$zone' (runtime): permitting service '$svc'" firewall-cmd --zone="$zone" --add-service="$svc"
        done
        for prt in "${planned_ports[@]}"; do
            run_cmd "Zone '$zone' (runtime): permitting port '$prt'" firewall-cmd --zone="$zone" --add-port="$prt"
        done
    done

    if [[ $DRY_RUN -eq 0 ]]; then
        log_msg "OK" "Runtime firewalld rules applied. Verify that SSH and mail scoring checks still succeed!"
        read -r -p "Save current runtime firewalld rules to PERMANENT configuration and enable firewalld on boot? (y/N): " save_perm
        if [[ "$save_perm" =~ ^[Yy]$ ]]; then
            run_cmd "Saving runtime rules to permanent config" firewall-cmd --runtime-to-permanent
            run_cmd "Enabling firewalld on boot" systemctl enable firewalld
            log_msg "OK" "Firewalld configuration saved permanently."
        else
            log_msg "INFO" "Kept changes in runtime only (run 'firewall-cmd --reload' to revert to previous permanent rules)."
        fi
    fi
}

# ==============================================================================
# 21. MODULE S: LOGGING AUDIT AND BASELINE
# ==============================================================================
audit_and_harden_logging() {
    local mode="${1:-audit}"
    print_header "MODULE S: SYSTEM & MAIL LOGGING (${mode^^})"

    local lsvc st
    for lsvc in systemd-journald rsyslog auditd; do
        st="$(systemctl is-active "$lsvc" 2>/dev/null || echo "inactive")"
        log_msg "INFO" "Logging service '$lsvc' status: $st"
    done

    # Audit rsyslog.conf, rsyslog.d, and journald.conf
    if [[ -f /etc/rsyslog.conf ]]; then
        log_msg "INFO" "Checking /etc/rsyslog.conf & /etc/rsyslog.d/ for mail rules and remote forwarding (@/@@):"
        grep -rnE '^[^#]*(mail\.|@)' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi
    if [[ -f /etc/systemd/journald.conf ]]; then
        log_msg "INFO" "Active settings in /etc/systemd/journald.conf:"
        grep -Ev '^[[:space:]]*(#|$)' /etc/systemd/journald.conf | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    local rocky_logs=("/var/log/maillog" "/var/log/secure" "/var/log/messages" "/var/log/cron" "/var/log/audit/audit.log")
    local lf lstat
    for lf in "${rocky_logs[@]}"; do
        if [[ -f "$lf" ]]; then
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
            log_msg "OK" "SELinux runtime mode: $enf"
        else
            log_msg "WARN" "SELinux runtime mode is '$enf' (Not Enforcing!)."
        fi
    else
        log_msg "ALERT" "getenforce not found! SELinux tools may be missing."
    fi

    # Check persistent /etc/selinux/config
    if [[ -f /etc/selinux/config ]]; then
        local cfg_mode
        cfg_mode="$(awk -F= '/^[[:space:]]*SELINUX=/ {print $2}' /etc/selinux/config | tr -d '[:space:]')"
        log_msg "INFO" "Persistent /etc/selinux/config SELINUX=${cfg_mode:-unknown}"
        if [[ "$cfg_mode" != "enforcing" ]]; then
            log_msg "ALERT" "/etc/selinux/config is set to '${cfg_mode}' instead of 'enforcing'!"
        fi
    fi

    if command -v sestatus >/dev/null 2>&1; then
        log_msg "INFO" "sestatus output:"
        sestatus 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    # Check relevant mail SELinux booleans
    if command -v getsebool >/dev/null 2>&1; then
        log_msg "INFO" "Mail-related SELinux booleans:"
        getsebool -a 2>/dev/null | grep -E "postfix|dovecot|mail|httpd_can_sendmail|nis_enabled" | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

    if command -v restorecon >/dev/null 2>&1; then
        log_msg "INFO" "Checking for SELinux file context mismatches on critical paths (restorecon -Rnv):"
        local check_paths=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/ssh" "/etc/postfix" "/etc/dovecot" "/var/spool/mail" "/var/spool/postfix")
        local cp mis
        for cp in "${check_paths[@]}"; do
            [[ -e "$cp" ]] || continue
            mis="$(restorecon -Rnv "$cp" 2>/dev/null | head -n 20)"
            if [[ -n "$mis" ]]; then
                log_msg "WARN" "SELinux context mismatch detected under $cp:"
                echo "$mis" | sed 's/^/  /' | tee -a "$LOG_FILE"
            fi
        done
    fi

    # Check recent SELinux AVC denials (ausearch -ts recent covers the last 10 minutes)
    if command -v ausearch >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
        log_msg "INFO" "Checking recent SELinux AVC denials (last 10 minutes via ausearch -m avc -ts recent):"
        ausearch -m avc -ts recent 2>/dev/null | tail -n 20 | sed 's/^/  /' | tee -a "$LOG_FILE"
    fi

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
    confirm_live_action "Run the Conservative Hardening Suite across /etc, Sudoers, PAM, SSHD, Sysctl, Firewalld, GRUB, and Logging?" || return 0
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
        read -r -p "Switch to LIVE MODE (DRY_RUN=0)? Hardening modules will modify system files (with backups). (y/N): " confirm_live
        if [[ "$confirm_live" =~ ^[Yy]$ ]]; then
            DRY_RUN=0
            log_msg "WARN" "LIVE MODE ENABLED (DRY_RUN=0). Hardening actions WILL modify the system (with backups)."
        else
            log_msg "INFO" "Remaining in DRY-RUN mode."
        fi
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
    echo " Invoking Admin : $INVOKING_USER"
    echo " Log File       : $LOG_FILE"
    echo " Backup Path    : $BACKUP_ROOT"
    echo "=============================================================================="
    echo " [AUDIT - READ-ONLY MODULES]"
    echo "   1) Run FULL Read-Only System & Mail Audit (Recommended First Step)"
    echo "   2) Audit Mail Stack (Postfix/Dovecot/Queues/TLS/DNS/Storage)"
    echo "   3) Audit Users, UID 0, Wheel Group & System Shells"
    echo "   4) Audit PAM, authselect, pwquality, faillock & /etc/security"
    echo "   5) Audit SSHD, Network/Sysctl, Listening Ports & Firewalld"
    echo "   6) Audit /etc Permissions, Sudoers, Polkit, Cron & Systemd"
    echo "   7) Audit SELinux, Logging & Lightweight Malware/RPM Integrity"
    echo ""
    echo " [HARDEN - CONSERVATIVE CONFIGURATION MODULES]"
    echo "   8) Toggle DRY-RUN / LIVE Mode (Currently: $([[ $DRY_RUN -eq 1 ]] && echo "DRY-RUN" || echo "LIVE"))"
    echo "   9) Run ALL Conservative Hardening Modules (Mail-Safe)"
    echo "  10) Harden Core /etc Permissions & Sudoers"
    echo "  11) Harden Password & Auth Policies (pwquality/pwhistory/faillock/login.defs)"
    echo "  12) Harden SSHD Configuration (Drop-in, Lockout Guard & sshd -T Check)"
    echo "  13) Harden Kernel & Network Sysctl (/etc/sysctl.d/)"
    echo "  14) Harden Firewalld (Runtime-First, Active Zones & Detected Mail Ports)"
    echo "  15) Harden Logging, GRUB Permissions & Login Banners"
    echo ""
    echo " [MAINTENANCE & ACCOUNT OPERATIONS (INTERACTIVE CONFIRMATION)]"
    echo "  16) Reconcile Users & Privileges from Roster ($USER_ROSTER_FILE)"
    echo "  17) Manage User Passwords & Admin-Only Aging Policies"
    echo "  18) Check & Apply DNF Package Updates (dnf upgrade)"
    echo "  19) Show Backup & Rollback Instructions"
    echo "   0) Exit"
    echo "=============================================================================="
}

main() {
    init_logging

    if [[ "${1:-}" == "--audit" ]]; then
        run_full_audit
        exit 0
    elif [[ "${1:-}" == "--live" ]]; then
        DRY_RUN=0
    fi

    local choice
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