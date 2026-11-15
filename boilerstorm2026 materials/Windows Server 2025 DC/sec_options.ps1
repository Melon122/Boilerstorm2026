# Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3

# Ensure 'Accounts: Guest account status' is set to 'Disabled'
Get-LocalUser -Name "Guest" | Disable-LocalUser

# Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Configure 'Accounts: Rename administrator account'
Rename-LocalUser -Name "Administrator" -NewName "NewAdminName"

# Configure 'Accounts: Rename guest account'
Rename-LocalUser -Name "Guest" -NewName "NewGuestName"
# Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
Write-Host "Setting 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' to 'Enabled'"
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

# Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
Write-Host "Setting 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled'"
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(gc C:\Windows\Temp\secpol.cfg).replace("CrashOnAuditFail = 1", "CrashOnAuditFail = 0") | Out-File C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
Remove-Item C:\Windows\Temp\secpol.cfg

# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$registryName = "DisablePrinterDriverInstallation"

# Check if the registry path exists, if not, create it
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

# Set the registry value to 1 (Enabled)
Set-ItemProperty -Path $registryPath -Name $registryName -Value 1

# Output the result
Write-Output "The setting 'Devices: Prevent users from installing printer drivers' has been set to 'Enabled'."

# Disable 'Interactive logon: Do not require CTRL+ALT+DEL'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0

# Enable 'Interactive logon: Don't display last signed-in'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1

# Set 'Interactive logon: Machine account lockout threshold' to 10
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Value 10

# Set 'Interactive logon: Machine inactivity limit' to 900 seconds (15 minutes)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900

# Configure 'Interactive logon: Message text for users attempting to log on'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Your custom message text here."

# Configure 'Interactive logon: Message title for users attempting to log on'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "Your custom message title here."

# Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 14 days
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordExpiryWarning" -Value 14

# Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "SCRemoveOption" -Value 1

# Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1

# Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0
# Set 'Microsoft network server: Amount of idle time required before suspending session' to '15 or fewer minute(s)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoDisconnect" -Value 15

# Enable 'Microsoft network server: Digitally sign communications (always)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Enable 'Microsoft network server: Digitally sign communications (if client agrees)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1

# Enable 'Microsoft network server: Disconnect clients when logon hours expire'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableForcedLogoff" -Value 1

# Set 'Microsoft network server: Server SPN target name validation level' to 'Accept if provided by client' or higher
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SmbServerNameHardeningLevel" -Value 1

Write-Output "Microsoft network server settings have been configured."
# 2.3.10.1 Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# 2.3.10.2 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1

# 2.3.10.3 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# 2.3.10.4 Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1

# 2.3.10.5 Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# 2.3.10.6 Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value ""

# 2.3.10.7 Ensure 'Network access: Remotely accessible registry paths' is configured
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value ""

# 2.3.10.8 Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value ""

# 2.3.10.9 Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# 2.3.10.10 Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value 1

# 2.3.10.11 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value ""

# 2.3.10.12 Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest" -Value 0

# 2.3.11 Network Security Settings

# 2.3.11.1 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "UseComputerID" -Value 1

# 2.3.11.2 Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowNullSessionFallback" -Value 0

# 2.3.11.3 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
$Pku2uRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u'
New-Item -Path $Pku2uRegPath -Force | Out-Null
Set-ItemProperty -Path $Pku2uRegPath -Name 'AllowOnlineID' -Value 0 -Type DWORD

# 2.3.11.4 Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483648

# 2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1

# 2.3.11.6 Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
# Define the registry path and value name
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$valueName = "EnableForcedLogoff"

# Check if the registry key exists
if (-not (Test-Path $regPath)) {
    # Create the registry key if it doesn't exist
    New-Item -Path $regPath -Force
}

# Set the registry value to 1 (Enabled)
Set-ItemProperty -Path $regPath -Name $valueName -Value 1

Write-Host "'Network security: Force logoff when logon hours expire' has been set to 'Enabled'."


# 2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# 2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 1

# 2.3.11.9 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1

# 2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1

# 2.3.11.11 Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditIncomingNTLM" -Value 1

# 2.3.11.12 Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditOutgoingNTLM" -Value 1
# Get the current setting
$currentSetting = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection"

# Desired setting
$desiredSetting = 2

# If the current setting is not the desired setting, update it
if ($currentSetting.ForceKeyProtection -ne $desiredSetting) {
    Write-Output "Updating system cryptography setting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection" -Value $desiredSetting
    Write-Output "System cryptography setting updated to 'User is prompted when the key is first used'."
} else {
    Write-Output "System cryptography setting is already set to the desired value."
}

# Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
$caseInsensitivity = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
Set-ItemProperty -Path $caseInsensitivity -Name "ObCaseInsensitive" -Value 1

# Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
$defaultPermissions = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
Set-ItemProperty -Path $defaultPermissions -Name "ProtectionMode" -Value 1

Write-Output "System objects settings have been configured successfully."
# Enable Admin Approval Mode for the Built-in Administrator account
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1

# Prompt for consent on the secure desktop for administrators in Admin Approval Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# Automatically deny elevation requests for standard users
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0

# Detect application installations and prompt for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1

# Only elevate UIAccess applications that are installed in secure locations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1

# Run all administrators in Admin Approval Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Switch to the secure desktop when prompting for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

# Virtualize file and registry write failures to per-user locations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1

Write-Output "User Account Control settings have been configured successfully."
