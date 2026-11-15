# CyberPatriot Windows Security Hardening Script
# This script configures comprehensive Windows security settings through registry modifications

# Function to create registry key if it doesn't exist and set property
function Set-RegistryProperty {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Host "Created new registry key: $Path"
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -Force
        Write-Host "Successfully set $Name to $Value in $Path"
    }
    catch {
        Write-Error "Failed to set registry value: $Path\$Name`nError: $_"
    }
}

# Account Policies
Write-Host "`nConfiguring Account Policies..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Security Options
Write-Host "`nConfiguring Security Options..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1

# Audit Policies
Write-Host "`nConfiguring Audit Policies..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# Network Security
Write-Host "`nConfiguring Network Security..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 1

# Remote Desktop Security
Write-Host "`nConfiguring Remote Desktop Security..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3

# Original Notification Settings
Write-Host "`nConfiguring Notification settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1

# Original Help Experience Settings
Write-Host "`nConfiguring Help Experience settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -Value 1

# Original Attachment Manager Settings
Write-Host "`nConfiguring Attachment Manager settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Attachments" -Name "SaveZoneInformation" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Attachments" -Name "ScanWithAntiVirus" -Value 1

# Original Cloud Content Settings
Write-Host "`nConfiguring Cloud Content settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollection" -Value 1

# Additional Privacy Settings
Write-Host "`nConfiguring Privacy settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Value 2
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Value 2

# SMB Security
Write-Host "`nConfiguring SMB Security..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200

# Original Data Collection Settings
Write-Host "`nConfiguring Data Collection settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotUseDiagnosticDataForTailoredExperiences" -Value 1

# Original Network Sharing Settings
Write-Host "`nConfiguring Network Sharing settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" -Name "NoSharing" -Value 1

# Original Windows Installer Settings
Write-Host "`nConfiguring Windows Installer settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0

# Original Media Player Settings
Write-Host "`nConfiguring Media Player settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\MediaPlayer" -Name "PreventCodecDownload" -Value 1

# Internet Explorer Security
Write-Host "`nConfiguring Internet Explorer Security..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Security" -Name "DisableSecuritySettingsCheck" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DEPOff" -Value 0

# Windows Defender Settings
Write-Host "`nConfiguring Windows Defender settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0

Write-Host "`nConfiguration complete!" -ForegroundColor Green
Write-Host "`nNote: Some settings may require a system restart to take effect." -ForegroundColor Yellow
