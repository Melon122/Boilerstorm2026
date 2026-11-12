# Rocky Linux CCDC Mail Server Baseline (`rocky_mail_baseline.sh`)

A lightweight, audit-first security baselining and hardening script built for **Rocky Linux 8/9** operating as a **Mail Server** (`Postfix`, `Dovecot`, `Sendmail`, `Exim`, `Webmail`) in a live CCDC environment.

---

## Quick Start

```bash
chmod 700 rocky_mail_baseline.sh

# 1. Run a non-interactive, read-only full system & mail audit first:
sudo ./rocky_mail_baseline.sh --audit

# 2. Launch the interactive menu (Starts in safe DRY-RUN mode by default):
sudo ./rocky_mail_baseline.sh

# 3. Launch the interactive menu directly in LIVE mode:
sudo ./rocky_mail_baseline.sh --live

```

### Required Roster File (`users.txt`)

Before running User or Password Management (**Options 16 & 17**), create `users.txt` in the same directory as the script:

```text
# Format: username:role (admin = wheel group, user = standard user)
alice:admin
bob:user
charlie:user

```

---

## Live CCDC Execution Playbook (Order of Operations)

### Phase 1: Situational Awareness (Minutes 0–5) — *Read-Only (`DRY_RUN=1`)*

1. **Run Option `1` (`run_full_audit`)**: Captures a full baseline snapshot in `/var/log/ccdc_hardening/baseline_<TIMESTAMP>.log`.
2. **Verify Mail Stack**: Check the output of `audit_mail_stack` to confirm active mail services (`postfix`, `dovecot`, `httpd`, etc.) and listening TCP ports (`25, 110, 143, 465, 587, 993, 995`).

### Phase 2: Access Control & Eviction (Minutes 5–15) — *Switch to `LIVE MODE*`

1. Populate `users.txt` from your team packet and file any required Password Change Requests (PCRs) with the scoring engine.


2. **Run Option `8` (`toggle_dry_run`)**: Switch from `DRY-RUN` to `LIVE MODE`.
3. **Run Option `16` (`manage_user_accounts`)**: Reconciles `wheel` group membership and prompts to lock unauthorized human accounts (`UID >= 1000`) without deleting mail spools.
4. **Run Option `17` (`manage_user_passwords`)**: Rotates passwords via `chpasswd -c SHA512` (hidden from `ps aux`) and clears `faillock` lockouts.
5. Manually remove unauthorized keys from `~/.ssh/authorized_keys` flagged in Phase 1, then **run Option `12` (`harden_sshd`)**.
6. **Test Login**: Open a **second SSH session** to verify login before closing your active root shell.

### Phase 3: Perimeter & System Hardening (Minutes 15–25) — *`LIVE MODE`*

> **Important:** Ensure `postfix`/`dovecot` are running (`systemctl status postfix dovecot`) before running the firewall module so active mail ports are automatically detected and permitted.

1. **Run Option `14` (`harden_firewall`)**: Enables `firewalld` and permits `ssh`, active listening mail ports, and `http`/`https` (if webmail is active).
2. **Run Option `10` (`audit_and_harden_etc_permissions` & `sudoers`)**: Locks `/etc/shadow` to `0000 root:root`, fixes `/etc/cron*` permissions, and deploys `/etc/sudoers.d/99-ccdc-baseline` (validated via `visudo -cf`).
3. **Run Option `11` (`harden_auth_policies`)**: Configures `pwquality`, `pwhistory`, `/etc/login.defs`, and `faillock` (with `even_deny_root` disabled to prevent root lockout DoS).
4. **Run Option `13` (`harden_sysctl`)**: Applies kernel and network hardening in `/etc/sysctl.d/99-ccdc-mail-baseline.conf` while keeping ICMP ping and IPv6 enabled for mail/scoring stability.


5. **Run Option `15` (`audit_grub_and_banners` & `logging`)**: Secures `/boot/grub2/grub.cfg` (`0600`), sets legal banners, and enforces persistent `journald`/`rsyslog` logging.
* *(Shortcut: **Option `9**` executes Options `10` through `15` in a single pass.)*



### Phase 4: Threat Hunting & Remediation (Minutes 25–45)

Review findings from **Options `2`, `6`, and `7**` to manually remediate persistence:

* **Mail Open Relay / Backdoors**: Check `mynetworks` (`0.0.0.0/0`) in `/etc/postfix/main.cf` and inspect `/etc/aliases` for malicious pipe (`|`) commands.
* **Scheduled Tasks**: Remove rogue jobs flagged in `/var/spool/cron`, `/etc/cron*`, and `systemctl list-timers`.
* **Trojanized Binaries**: Inspect any package binaries flagged by `rpm -V` in `audit_malware_lightweight`.

### Phase 5: Maintenance & Re-Auditing (Mid-Competition)

* **Run Option `18` (`update_all_applications`)**: Previews and runs `dnf upgrade -y --nobest` between scoring checks (never auto-reboots).
* **Re-run Option `1**` every 30–60 minutes to detect new Red Team modifications.

---

## Module & Function Reference

### 1. Audit Modules (Strictly Read-Only)

| Menu | Function(s) | What It Checks |
| :--- | :--- | :--- |
| **1** | `run_full_audit` | Executes all read-only audit modules below and writes a full report to `/var/log/ccdc_hardening/`. |
| **2** | `audit_mail_stack` | Detects active mail services/ports, checks Postfix (`postconf`) for open relays and TLS keys, checks Dovecot (`doveconf`) auth settings, inspects mail spool permissions, and verifies DNS nameservers. |
| **3** | `audit_users_and_accounts` | Flags non-root `UID 0` accounts, lists human users (`UID >= 1000`), alerts on system accounts (`UID < 1000`) with interactive login shells, lists `wheel` members, and checks `/etc/shadow` for empty passwords. |
| **4** | `audit_auth_policies` | Checks `authselect` profile integrity, `/etc/security/pwquality.conf`, `/etc/security/faillock.conf` (`even_deny_root` risk), `/etc/login.defs`, and scans `/etc/pam.d/` for rogue `pam_permit.so` backdoors. |
| **5** | `audit_sshd`, `audit_network_and_sysctl`, `audit_listening_ports`, `audit_firewall` | Dumps effective `sshd -T` config, lists `/etc/ssh/sshd_config.d/` drop-ins, counts `~/.ssh/authorized_keys` per user, logs IPs/routes/sysctls, lists listening sockets (`ss -tlnp`/`-ulnp`), and dumps `firewalld`/`nftables` rules. |
| **6** | `audit_and_harden_etc_permissions`, `audit_and_harden_sudoers`, `audit_polkit`, `audit_scheduled_tasks`, `audit_services_and_systemd` | Checks `/etc` permissions, world-writable files, SUID/SGID binaries, and immutable (`+i`) files; greps `sudoers` for `NOPASSWD`; audits Polkit rules; dumps all cron/at jobs and systemd timers; checks systemd unit overrides. |
| **7** | `audit_selinux`, `audit_and_harden_logging`, `audit_malware_lightweight` | Checks `getenforce`/`sestatus`, runs dry-run `restorecon -Rnv` on mail/auth paths, checks recent `AVC` denials, verifies `/var/log/maillog` and `secure`, scans `/dev/shm` & `/tmp` for executables, checks `/etc/ld.so.preload`, runs `getcap`, and runs `rpm -V` on core packages. |

---

### 2. Hardening & Maintenance Modules (Backed Up & Idempotent)

| Menu | Function(s) | What It Modifies (When `DRY_RUN=0`) |
| :--- | :--- | :--- |
| **8** | `toggle_dry_run` | Switches between `DRY-RUN` (preview only) and `LIVE MODE` (applies changes with automatic backups). |
| **9** | `run_conservative_hardening` | Runs Options `10`, `11`, `12`, `13`, `14`, and `15` sequentially. |
| **10** | `audit_and_harden_etc_permissions`, `audit_and_harden_sudoers` | Removes rogue `chattr +i/+a` flags, sets strict permissions on core `/etc` files (`/etc/shadow` `0000`) without touching `/etc/postfix` or `/etc/dovecot`, and installs `/etc/sudoers.d/99-ccdc-baseline` after `visudo -cf` validation. |
| **11** | `harden_auth_policies` | Writes complexity rules to `/etc/security/pwquality.conf.d/99-ccdc-baseline.conf`, sets `remember = 5` in `pwhistory.conf`, sets conservative `faillock.conf` (`deny=5, unlock_time=300`, no root lockout), and updates `/etc/login.defs` aging while preserving `MAIL_DIR /var/spool/mail`. |
| **12** | `harden_sshd` | Sets `PermitRootLogin no`, `PermitEmptyPasswords no`, `MaxAuthTries 4`, and keeps `PasswordAuthentication yes` (for scoring checks). Validates with `sshd -t -f` before replacing `/etc/ssh/sshd_config` and reloading `sshd`. |
| **13** | `harden_sysctl` | Validates supported keys against `/proc/sys/` and writes `/etc/sysctl.d/99-ccdc-mail-baseline.conf` (SYN cookies, `rp_filter`, ASLR, `suid_dumpable=0`, `kptr_restrict=2`, ICMP echo preserved, IPv6 preserved). |
| **14** | `harden_firewall` | Enables `firewalld` and permits `ssh`, all actively listening mail TCP ports (`25, 465, 587, 110, 143, 993, 995`), and `http`/`https` (if `httpd`/`nginx` is active) in runtime and permanent configs. |
| **15** | `audit_grub_and_banners`, `audit_and_harden_logging` | Sets `0600 root:root` on `/boot/grub2/grub.cfg`, sets warning banners in `/etc/issue` and `/etc/issue.net`, sets `0600` on `/var/log/{maillog,secure,messages}`, creates `/var/log/journal`, and enables `rsyslog`. |
| **16** | `manage_user_accounts` | Reconciles users against `users.txt`. Protects all system/mail service accounts (`postfix`, `dovecot`, `vmail`, etc.). Prompts before locking or removing unlisted human accounts. |
| **17** | `manage_user_passwords` | Updates passwords for `users.txt` accounts via `0600` file, interactive hidden prompt, or `DEFAULT_COMP_PASSWORD`, resets `faillock` counters, and sets `chage` aging (`-m 1 -M 90 -W 7`). |
| **18** | `update_all_applications` | Runs `dnf check-update` and prompts before executing `dnf upgrade -y --nobest` (no auto-reboot). |
| **19** | `show_rollback_instructions` | Prints exact `cp -a` and `restorecon` commands to restore any file from `/var/backups/ccdc_hardening/<TIMESTAMP>/`. |

---

## Backup & Rollback

Every file modified in `LIVE MODE` is automatically backed up with permissions and SELinux contexts preserved under:

```text
/var/backups/ccdc_hardening/<TIMESTAMP>/

```

To roll back a configuration file and restore its SELinux context:

```bash
sudo cp -a /var/backups/ccdc_hardening/<TIMESTAMP>/etc/ssh/sshd_config /etc/ssh/sshd_config
sudo restorecon -v /etc/ssh/sshd_config
sudo systemctl reload sshd

```