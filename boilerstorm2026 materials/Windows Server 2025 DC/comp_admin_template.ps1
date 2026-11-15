$ErrorActionPreference = 'Stop'

function Test-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    return Test-Path -Path $Path
}

function Create-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    if (-not (Test-RegistryPath -Path $Path)) {
        try {
            New-Item -Path $Path -Force | Out-Null
            Write-Host "Created registry path: $Path" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create registry path: $Path`nError: $_"
            return $false
        }
    }
    return $true
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        $Value,
        [string]$Type = "DWord"
    )
    
    try {
        if (Create-RegistryPath -Path $Path) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Host "Successfully set $Name to $Value at $Path" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to set registry value: $Name at $Path`nError: $_"
    }
}

# Define registry changes as an array of objects
$registryChanges = @(
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
        Settings = @(
            @{Name = "NoLockScreenCamera"; Value = 1}
            @{Name = "NoLockScreenSlideshow"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Speech"
        Settings = @(
            @{Name = "AllowOnlineSpeechRecognition"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
        Settings = @(
            @{Name = "DisableSoftLanding"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc"
        Settings = @(
            @{Name = "EnableAuthEpResolution"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
        Settings = @(
            @{Name = "Start"; Value = 4}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Settings = @(
            @{Name = "SMB1"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Cryptography"
        Settings = @(
            @{Name = "EnableCertPaddingCheck"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        Settings = @(
            @{Name = "EnableSEHOP"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Settings = @(
            @{Name = "RunAsPPL"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        Settings = @(
            @{Name = "NodeType"; Value = 2}
            @{Name = "NoNameReleaseOnDemand"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Settings = @(
            @{Name = "UseLogonCredential"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Settings = @(
            @{Name = "AutoAdminLogon"; Value = 0}
            @{Name = "ScreenSaverGracePeriod"; Value = 5}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        Settings = @(
            @{Name = "DisableIPSourceRouting"; Value = 2}
            @{Name = "TcpMaxDataRetransmissions"; Value = 3}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Settings = @(
            @{Name = "DisableIPSourceRouting"; Value = 2}
            @{Name = "EnableICMPRedirect"; Value = 0}
            @{Name = "KeepAliveTime"; Value = 300000}
            @{Name = "PerformRouterDiscovery"; Value = 0}
            @{Name = "TcpMaxDataRetransmissions"; Value = 3}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
        Settings = @(
            @{Name = "DisableSavePassword"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        Settings = @(
            @{Name = "SafeDllSearchMode"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
        Settings = @(
            @{Name = "WarningLevel"; Value = 90}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Settings = @(
            @{Name = "EnableFontProviders"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
        Settings = @(
            @{Name = "AllowInsecureGuestAuth"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\LLTD"
        Settings = @(
            @{Name = "AllowLLTDIOOnDomain"; Value = 0}
            @{Name = "AllowLLTDIOOnPublicNet"; Value = 0}
            @{Name = "AllowRspndrOnDomain"; Value = 0}
            @{Name = "AllowRspndrOnPublicNet"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PeerToPeer"
        Settings = @(
            @{Name = "Disabled"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
        Settings = @(
            @{Name = "NC_AllowNetBridge_NLA"; Value = 0}
            @{Name = "NC_ShowSharedAccessUI"; Value = 0}
        )
    }
)

# Hardened UNC Paths settings
$hardenedPaths = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
    Settings = @{
        "\\*\NETLOGON" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
        "\\*\SYSVOL" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
    }
}

# Main execution block
try {
    Write-Host "Starting Windows Security Hardening Script..." -ForegroundColor Cyan
    
    # Apply regular registry changes
    foreach ($change in $registryChanges) {
        foreach ($setting in $change.Settings) {
            Set-RegistryValue -Path $change.Path -Name $setting.Name -Value $setting.Value
        }
    }
    
    # Apply Hardened UNC Paths
    if (Create-RegistryPath -Path $hardenedPaths.Path) {
        foreach ($path in $hardenedPaths.Settings.GetEnumerator()) {
            try {
                Set-ItemProperty -Path $hardenedPaths.Path -Name $path.Key -Value $path.Value -Type String -Force
                Write-Host "Successfully set hardened UNC path: $($path.Key)" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to set hardened UNC path: $($path.Key)`nError: $_"
            }
        }
    }
    
    Write-Host "`nWindows Security Hardening Script completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during script execution:`n$_"
    exit 1
}

# Requires -RunAsAdministrator
# Additional Windows Security Hardening Script
# This script implements various security measures through registry modifications

# Error handling preference
$ErrorActionPreference = 'Stop'

function Test-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    return Test-Path -Path $Path
}

function Create-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    if (-not (Test-RegistryPath -Path $Path)) {
        try {
            New-Item -Path $Path -Force | Out-Null
            Write-Host "Created registry path: $Path" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create registry path: $Path`nError: $_"
            return $false
        }
    }
    return $true
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        $Value,
        [string]$Type = "DWord"
    )
    
    try {
        if (Create-RegistryPath -Path $Path) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Host "Successfully set $Name to $Value at $Path" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to set registry value: $Name at $Path`nError: $_"
    }
}

# Define registry changes as an array of objects
$registryChanges = @(
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
        Settings = @(
            @{Name = "DisabledComponents"; Value = 255}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
        Settings = @(
            @{Name = "DisableRegistrars"; Value = 1}
            @{Name = "DisableWcnUi"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
        Settings = @(
            @{Name = "fMinimizeConnections"; Value = 1}
            @{Name = "AutoConnectAllowed"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        Settings = @(
            @{Name = "AllowPrintSpoolerToAcceptClientConnections"; Value = 0}
            @{Name = "RedirectionGuard"; Value = 1}
            @{Name = "LimitPrintDriverInstallation"; Value = 1}
            @{Name = "QueueSpecificFiles"; Value = 1}
            @{Name = "PointAndPrintRestrictions"; Value = 1}
            @{Name = "DisableWebPnPDownload"; Value = 1}
            @{Name = "DisableHTTPPrinting"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        Settings = @(
            @{Name = "UseTcp"; Value = 1}
            @{Name = "UseAuth"; Value = 1}
            @{Name = "AllowTcp"; Value = 1}
            @{Name = "AuthProtocol"; Value = 1}
            @{Name = "TcpPort"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
        Settings = @(
            @{Name = "NoNetworkUsage"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Settings = @(
            @{Name = "AuditProcessCreationIncludeCmdLine"; Value = 1}
            @{Name = "BootStartDriverInitPolicy"; Value = 1}
            @{Name = "AllowCrossDevice"; Value = 0}
            @{Name = "DisableInternetOpenWith"; Value = 1}
            @{Name = "BlockUserFromShowingAccountDetailsOnSignin"; Value = 1}
            @{Name = "DontDisplayNetworkSelectionUI"; Value = 1}
            @{Name = "DisableLockScreenAppNotifications"; Value = 1}
            @{Name = "AllowConveniencePIN"; Value = 0}
            @{Name = "AllowCrossDeviceClipboard"; Value = 0}
            @{Name = "AllowUploadOfUserActivities"; Value = 0}
            @{Name = "AllowNetworkConnectivityDuringConnectedStandby"; Value = 0}
            @{Name = "AllowStandbyStatesWhenSleeping"; Value = 0}
            @{Name = "RequirePasswordOnWake"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredSSP\Parameters"
        Settings = @(
            @{Name = "AllowEncryptionOracle"; Value = 2}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        Settings = @(
            @{Name = "DenyDeviceIDs"; Value = "PCI\CC_0C0A"}
            @{Name = "DenyDeviceIDsRetroactive"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata"
        Settings = @(
            @{Name = "PreventDeviceMetadataFromInternet"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\WindowsStore"
        Settings = @(
            @{Name = "RemoveWindowsStore"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\TabletPC"
        Settings = @(
            @{Name = "PreventHandwritingDataSharing"; Value = 1}
            @{Name = "PreventHandwritingErrorReports"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Internet Connection Wizard"
        Settings = @(
            @{Name = "ExitOnMSICW"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Registration Wizard Control"
        Settings = @(
            @{Name = "NoRegistration"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\SearchCompanion"
        Settings = @(
            @{Name = "DisableContentFileUpdates"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\Photo Acquisition"
        Settings = @(
            @{Name = "DisablePhotoOrderPrints"; Value = 1}
            @{Name = "DisablePhotoPublishingWizard"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Messenger"
        Settings = @(
            @{Name = "CEIP"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\SQMClient"
        Settings = @(
            @{Name = "CEIPEnable"; Value = 0}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting"
        Settings = @(
            @{Name = "Disabled"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\KDC"
        Settings = @(
            @{Name = "SupportDeviceAuth"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"
        Settings = @(
            @{Name = "EnumerationPolicy"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Windows\Lsa"
        Settings = @(
            @{Name = "DisableCustomSSPs"; Value = 1}
            @{Name = "RunAsPPL"; Value = 1}
        )
    },
    @{
        Path = "HKLM:\Software\Policies\Microsoft\Control Panel\International"
        Settings = @(
            @{Name = "BlockUserInputMethodsForSystemAccount"; Value = 1}
        )
    }
)

# Main execution block
try {
    Write-Host "Starting Additional Windows Security Hardening Script..." -ForegroundColor Cyan
    
    # Apply registry changes
    foreach ($change in $registryChanges) {
        foreach ($setting in $change.Settings) {
            # Check if the value should be a string (for device IDs)
            $valueType = if ($setting.Name -eq "DenyDeviceIDs") { "String" } else { "DWord" }
            Set-RegistryValue -Path $change.Path -Name $setting.Name -Value $setting.Value -Type $valueType
        }
    }
    
    Write-Host "`nAdditional Windows Security Hardening Script completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during script execution:`n$_"
    exit 1
}

# Requires -RunAsAdministrator
# Windows Security Hardening Script
# This script implements various security configurations for Windows systems

# Function to safely set registry properties
function Set-RegistryProperty {
    param (
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    
    try {
        # Create path if it doesn't exist
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        # Set the property
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Write-Host "Successfully set $Name to $Value at $Path" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to set $Name at $Path. Error: $_"
    }
}

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator!"
    Exit 1
}

# Network Security Settings
Write-Host "`nConfiguring Network Security Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value 255
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableRegistrars" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWcnUi" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "AutoConnectAllowed" -Value 0

# Printer Security Settings
Write-Host "`nConfiguring Printer Security Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "AllowPrintSpoolerToAcceptClientConnections" -Value 0
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RedirectionGuard" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "LimitPrintDriverInstallation" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "QueueSpecificFiles" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "PointAndPrintRestrictions" -Value 1

# RPC Configuration
Write-Host "`nConfiguring RPC Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "UseTcp" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "UseAuth" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "AllowTcp" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "AuthProtocol" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "TcpPort" -Value 0

# System Security Settings
Write-Host "`nConfiguring System Security Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoNetworkUsage" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AuditProcessCreationIncludeCmdLine" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 2

# Device Installation Settings
Write-Host "`nConfiguring Device Installation Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -Value "PCI\CC_0C0A" -Type "String"
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata" -Name "PreventDeviceMetadataFromInternet" -Value 1

# System Configuration
Write-Host "`nConfiguring System Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BootStartDriverInitPolicy" -Value 1
Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDevice" -Value 0

# Internet Communication Management
Write-Host "`nConfiguring Internet Communication Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableInternetOpenWith" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Photo Acquisition" -Name "DisablePhotoOrderPrints" -Value 1

# Security Features
Write-Host "`nConfiguring Security Features..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\KDC" -Name "SupportDeviceAuth" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "EnumerationPolicy" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Lsa" -Name "DisableCustomSSPs" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Lsa" -Name "RunAsPPL" -Value 1

# Logon and Authentication
Write-Host "`nConfiguring Logon and Authentication Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowConveniencePIN" -Value 0

# Privacy Settings
Write-Host "`nConfiguring Privacy Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowUploadOfUserActivities" -Value 0

# Sleep and Power Settings
Write-Host "`nConfiguring Sleep and Power Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowNetworkConnectivityDuringConnectedStandby" -Value 0
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowStandbyStatesWhenSleeping" -Value 0
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "RequirePasswordOnWake" -Value 1

Write-Host "`nScript execution completed!" -ForegroundColor Green
Write-Host "Please note that some changes may require a system restart to take effect." -ForegroundColor Yellow

# Remote Access Settings
Write-Host "`nConfiguring Remote Access Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0

# RPC Security Settings
Write-Host "`nConfiguring RPC Security Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value 1

# Diagnostics and Support Settings
Write-Host "`nConfiguring Diagnostics Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 1

# Privacy Settings
Write-Host "`nConfiguring Additional Privacy Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Value 2

# Time Settings
Write-Host "`nConfiguring Time Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1

# App Settings
Write-Host "`nConfiguring Application Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowSharedLocalAppData" -Value 0
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "RestrictAppxInstall" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "BlockHostedAppxContent" -Value 1

# System Settings
Write-Host "`nConfiguring Additional System Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "MSAOptional" -Value 1

# AutoPlay Settings
Write-Host "`nConfiguring AutoPlay Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoAutorun" -Value 1
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# Biometrics Settings
Write-Host "`nConfiguring Biometrics Settings..." -ForegroundColor Cyan
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1

#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Configures BitLocker security policies through registry settings.
.DESCRIPTION
    Configures comprehensive BitLocker security settings for fixed drives, OS drives,
    and removable drives through registry modifications. Includes error handling and
    validation.
.NOTES
    Version: 1.0
    Requires administrative privileges
#>

# Registry path constant
$REGISTRY_BASE = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
    }
    
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
}

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-RegistryPath {
    param([string]$Path)
    
    try {
        if (!(Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-LogMessage "Created registry path: $Path" -Type 'Success'
        }
        return $true
    }
    catch {
        Write-LogMessage "Failed to create registry path: $Path. Error: $_" -Type 'Error'
        return $false
    }
}

function Set-BitLockerRegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [int]$Value
    )
    
    try {
        $fullPath = Join-Path $REGISTRY_BASE $Name
        
        if (Initialize-RegistryPath -Path $REGISTRY_BASE) {
            Set-ItemProperty -Path $REGISTRY_BASE -Name $ValueName -Value $Value -Type DWord -ErrorAction Stop
            Write-LogMessage "Successfully set $ValueName to $Value" -Type 'Success'
            return $true
        }
        return $false
    }
    catch {
        Write-LogMessage "Failed to set $ValueName. Error: $_" -Type 'Error'
        return $false
    }
}

function Set-FixedDriveSettings {
    Write-LogMessage "Configuring Fixed Drive Settings..." -Type 'Info'
    
    $settings = @{
        'FDVAllowBDE' = 0              # Disable access from earlier Windows versions
        'FDVRecovery' = 1              # Enable fixed drive recovery
        'FDVRecoveryPassword' = 1      # Allow recovery password
        'FDVRecoveryKey' = 1           # Allow recovery key
        'FDVHardwareEncryption' = 0    # Disable hardware encryption
        'FDVRequireEncryption' = 1     # Require encryption
        'FDVRestrictHardwareEncryptionAlgorithms' = 1  # Restrict hardware encryption algorithms
    }
    
    foreach ($setting in $settings.GetEnumerator()) {
        Set-BitLockerRegistryValue -Name 'FixedDriveSettings' -ValueName $setting.Key -Value $setting.Value
    }
}

function Set-OSDriveSettings {
    Write-LogMessage "Configuring OS Drive Settings..." -Type 'Info'
    
    $settings = @{
        'OSEnhancedPIN' = 1            # Enable enhanced PINs
        'OSSecureBoot' = 1             # Enable Secure Boot validation
        'OSRecovery' = 1               # Enable OS drive recovery
        'OSRecoveryPassword' = 1       # Enable recovery password
        'OSHardwareEncryption' = 0     # Disable hardware encryption
        'OSRequireActiveDirectoryBackup' = 1  # Require AD backup
        'OSRequireEncryption' = 1      # Require encryption
        'OSAuthAtStartup' = 1          # Require startup authentication
        'OSAuthWithoutTPM' = 0         # Require TPM
    }
    
    foreach ($setting in $settings.GetEnumerator()) {
        Set-BitLockerRegistryValue -Name 'OSDriveSettings' -ValueName $setting.Key -Value $setting.Value
    }
}

function Set-RemovableDriveSettings {
    Write-LogMessage "Configuring Removable Drive Settings..." -Type 'Info'
    
    $settings = @{
        'RDVDiscoveryVolumeType' = 1   # Configure removable drive discovery
        'RDVRecovery' = 1              # Enable removable drive recovery
        'RDVRequireEncryption' = 1     # Require encryption
        'RDVDenyWriteAccess' = 0       # Allow write access
        'RDVHardwareEncryption' = 0    # Disable hardware encryption
    }
    
    foreach ($setting in $settings.GetEnumerator()) {
        Set-BitLockerRegistryValue -Name 'RemovableDriveSettings' -ValueName $setting.Key -Value $setting.Value
    }
}

function Test-BitLockerSettings {
    Write-LogMessage "Verifying BitLocker settings..." -Type 'Info'
    
    try {
        $manageBDE = manage-bde -status
        if ($manageBDE -match "Protection On") {
            Write-LogMessage "BitLocker is actively protecting at least one drive" -Type 'Success'
        }
        else {
            Write-LogMessage "BitLocker protection status could not be verified" -Type 'Warning'
        }
    }
    catch {
        Write-LogMessage "Failed to verify BitLocker status: $_" -Type 'Error'
    }
}

# Main execution block
try {
    if (-not (Test-AdminPrivileges)) {
        throw "This script requires administrator privileges."
    }
    
    Write-LogMessage "Starting BitLocker configuration..." -Type 'Info'
    
    # Configure each setting group
    Set-FixedDriveSettings
    Set-OSDriveSettings
    Set-RemovableDriveSettings
    
    # Verify settings
    Test-BitLockerSettings
    
    Write-LogMessage "BitLocker configuration completed successfully" -Type 'Success'
    Write-LogMessage "Please restart your system for all changes to take effect" -Type 'Warning'
}
catch {
    Write-LogMessage "Critical error during BitLocker configuration: $_" -Type 'Error'
    exit 1
}

#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Configures Windows security policies including BitLocker, privacy, and event log settings
.DESCRIPTION
    Applies security hardening settings to Windows through registry modifications
    including BitLocker configuration, privacy settings, and event log configuration
.NOTES
    Version: 1.0
    Requires administrative privileges
#>

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $colors = @{
        'Info' = 'White'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
    }
    
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): [$Type] $Message" -ForegroundColor $colors[$Type]
}

function Initialize-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-LogMessage "Created registry path: $Path" -Type 'Success'
        }
        return $true
    }
    catch {
        Write-LogMessage "Failed to create registry path: $Path. Error: $_" -Type 'Error'
        return $false
    }
}

function Set-SecurityPolicy {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [int]$Value
    )
    
    try {
        # Ensure the registry path exists
        $parentPath = Split-Path $Path -Parent
        if (Initialize-RegistryPath -Path $parentPath) {
            # Set the registry value
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
            Write-LogMessage "Successfully set $Name to $Value" -Type 'Success'
            return $true
        }
        return $false
    }
    catch {
        Write-LogMessage "Failed to set $Name. Error: $_" -Type 'Error'
        return $false
    }
}

# Main configuration hashtable
$configurations = @{
    # BitLocker Removable Drive Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\FVE" = @{
        "RDVBackupToADDS" = 1                  # Enable backup to AD DS
        "RDVRequireADDS" = 0                   # Don't require AD DS backup before encryption
        "RDVHardwareEncryption" = 0            # Disable hardware encryption
        "RDVUsePassphrase" = 0                 # Disable password use
        "RDVUseSmartCard" = 1                  # Enable smart card use
        "RDVRequireSmartCard" = 1              # Require smart card
        "RDVDenyWriteAccess" = 1               # Deny write access to unprotected drives
        "RDVDenyWriteAccessOtherOrg" = 0       # Allow write access to other org devices
        "DisableNewDMAWhenLocked" = 1          # Disable new DMA devices when locked
    }
    
    # Camera Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Camera" = @{
        "AllowUseOfCamera" = 0                 # Disable camera
    }
    
    # Cloud Content Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\CloudContent" = @{
        "TurnOffConsumerAccountStateContent" = 1    # Disable consumer account state
        "TurnOffCloudOptimizedContent" = 1         # Disable cloud optimized content
        "TurnOffMicrosoftConsumerExperiences" = 1  # Disable consumer experiences
    }
    
    # Windows Connect Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" = @{
        "RequirePinForPairing" = 1             # Require PIN for pairing
    }
    
    # Credential UI Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" = @{
        "DisablePasswordReveal" = 1            # Disable password reveal
        "DisableSecurityQuestions" = 1         # Disable security questions
    }
    
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" = @{
        "EnumerateAdministrators" = 0          # Disable admin enumeration
    }
    
    # Data Collection Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
        "AllowTelemetry" = 0                   # Disable telemetry
        "DisableAuthProxy" = 1                 # Disable authenticated proxy
        "DisableOneSettingsDownloads" = 1      # Disable OneSettings downloads
        "DoNotShowFeedbackNotifications" = 1   # Disable feedback notifications
        "EnableOneSettingsAuditing" = 1        # Enable OneSettings auditing
        "LimitDiagnosticLogCollection" = 1     # Limit diagnostic logs
        "LimitDumpCollection" = 1              # Limit dump collection
        "ToggleUserControlOverInsiderBuilds" = 0 # Disable insider builds
    }
    
    # Delivery Optimization Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" = @{
        "DownloadMode" = 0                     # Disable internet download mode
    }
    
    # App Installer Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" = @{
        "EnableAppInstaller" = 0               # Disable app installer
        "EnableAppInstallerExperimentalFeatures" = 0  # Disable experimental features
        "EnableAppInstallerHashOverride" = 0   # Disable hash override
        "EnableAppInstallerProtocol" = 0       # Disable ms-appinstaller protocol
    }
    
    # Event Log Settings
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" = @{
        "Retention" = 0                        # Override any retention policy
        "MaxSize" = 32768                      # 32MB max size
    }
    
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" = @{
        "Retention" = 0                        # Override any retention policy
        "MaxSize" = 196608                     # 192MB max size
    }
}

# Main execution block
try {
    Write-LogMessage "Starting security policy configuration..." -Type 'Info'
    
    foreach ($path in $configurations.Keys) {
        Write-LogMessage "Configuring settings in $path" -Type 'Info'
        
        foreach ($setting in $configurations[$path].GetEnumerator()) {
            Set-SecurityPolicy -Path $path -Name $setting.Key -Value $setting.Value
        }
    }
    
    Write-LogMessage "Security policy configuration completed successfully" -Type 'Success'
    Write-LogMessage "A system restart is recommended for all changes to take effect" -Type 'Warning'
}
catch {
    Write-LogMessage "Critical error during configuration: $_" -Type 'Error'
    exit 1
}
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [int]$Value
    )
    
    # Check if the registry key exists; if not, create it
    if (!(Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    # Try setting the registry value and catch any errors
    try {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Write-Host "Successfully applied setting for $Path\$Name with value $Value" -ForegroundColor Green
    } catch {
        Write-Host "Failed to apply setting for $Path\$Name with value $Value" -ForegroundColor Red
    }
}
$settings = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; Name = "Retention"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; Name = "MaxSize"; Type = "DWord"; Value = 32768 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name = "Retention"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name = "MaxSize"; Type = "DWord"; Value = 32768 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoDataExecutionPrevention"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoHeapTerminationOnCorruption"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "NoShellProtocolProtectedMode"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"; Name = "DisableIE11Standalone"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"; Name = "AllowMessageServiceCloudSync"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\MicrosoftAccount"; Name = "BlockAllConsumerMicrosoftAccountUserAuth"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "LocalSettingOverride"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SpynetReporting"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"; Name = "ConfigureASRRules"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"; Name = "EnableNetworkProtection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "EnableFileHashComputation"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "ScanAllDownloadedFilesAndAttachments"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "EnableBehaviorMonitoring"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "EnableScriptScanning"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Name = "DisableWatsonEvents"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "ScanPackedExecutables"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "ScanRemovableDrives"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name = "EnableEmailScanning"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name = "MpEnablePus"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Application Guard"; Name = "AllowAuditing"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Application Guard"; Name = "AllowCameraAndMicrophone"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Application Guard"; Name = "AllowPersistence"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Application Guard"; Name = "AllowFileSave"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Application Guard"; Name = "ClipboardBehavior"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Application Guard"; Name = "ManagedMode"; Type = "DWord"; Value = 1 }
)

# Apply each setting
foreach ($setting in $settings) {
    Set-RegistryValue -Path $setting.Path -Name $setting.Name -Type $setting.Type -Value $setting.Value
}
# Function to set a registry value and confirm status
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [int]$Value
    )
    
    # Check if the registry key exists; if not, create it
    if (!(Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    # Try setting the registry value and catch any errors
    try {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Write-Host "Successfully applied setting for $Path\$Name with value $Value" -ForegroundColor Green
    } catch {
        Write-Host "Failed to apply setting for $Path\$Name with value $Value" -ForegroundColor Red
    }
}

# Registry settings array
$settings = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"; Name = "EnableFeeds"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name = "DisableFileSync"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall"; Name = "DisablePushToInstall"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteFX USB Device Redirection"; Name = "DisablePasswordSaving"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "AllowRemoteConnections"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "AllowUIAutomationRedirection"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisableCOMPortRedirection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisableDriveRedirection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisableLocationRedirection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisableLPTPortRedirection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisablePnPDeviceRedirection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisableWebAuthnRedirection"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "PromptForPassword"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "RequireSecureRPC"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "SecurityLayer"; Type = "DWord"; Value = 2 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "RequireNLA"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "EncryptionLevel"; Type = "DWord"; Value = 3 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "IdleSessionLimit"; Type = "DWord"; Value = 15 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DisconnectedSessionLimit"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices"; Name = "DeleteTempFoldersOnExit"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RSSFeeds"; Name = "PreventDownloadingEnclosures"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCloudSearch"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortanaAboveLock"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowIndexingEncryptedStoresOrItems"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowSearchToUseLocation"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowSearchHighlights"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Software Protection Platform"; Name = "NoGenTicket"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "DisableStoreApps"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "OnlyDisplayPrivateStore"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "AutoDownloadAndInstallUpdates"; Type = "DWord"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "DisableOSUpgrade"; Type = "DWord"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "RemoveWindowsStore"; Type = "DWord"; Value = 1 }
)

# Apply each setting
foreach ($setting in $settings) {
    Set-RegistryValue -Path $setting.Path -Name $setting.Name -Type $setting.Type -Value $setting.Value
}

Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ConfigureWindowsDefenderSmartScreen" -Type DWord -Value 2

# Enable or disable Windows Game Recording and Broadcasting
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

# Allow suggested apps in Windows Ink Workspace
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedApps" -Type DWord -Value 0

# Allow Windows Ink Workspace
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Type DWord -Value 0

# Allow user control over installs
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -Type DWord -Value 0

# Always install with elevated privileges
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Type DWord -Value 0

# Prevent Internet Explorer security prompt for Windows Installer scripts
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "DisableIEPrompt" -Type DWord -Value 0

# Enable MPR notifications for the system
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMPRNotifications" -Type DWord -Value 0

# Sign-in and lock last interactive user automatically after a restart
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1

# Turn on PowerShell Script Block Logging
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1

# Turn on PowerShell Transcription
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscription" -Type DWord -Value 1

# Allow Basic authentication (WinRM Client)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Type DWord -Value 0

# Allow unencrypted traffic (WinRM Client)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencrypted" -Type DWord -Value 0

# Disallow Digest authentication (WinRM Client)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "DisallowDigest" -Type DWord -Value 1

# Allow Basic authentication (WinRM Service)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Type DWord -Value 0

# Allow remote server management through WinRM
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowRemoteManagement" -Type DWord -Value 0

# Allow unencrypted traffic (WinRM Service)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencrypted" -Type DWord -Value 0

# Disallow WinRM from storing RunAs credentials
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisallowRunAs" -Type DWord -Value 1

# Allow Remote Shell Access
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteShell" -Name "AllowRemoteShellAccess" -Type DWord -Value 0

# Allow clipboard sharing with Windows Sandbox
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsSandbox" -Name "AllowClipboardSharing" -Type DWord -Value 0

# Allow networking in Windows Sandbox
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsSandbox" -Name "AllowNetworking" -Type DWord -Value 0

# Prevent users from modifying settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "UILockdown" -Type DWord -Value 1

# No auto-restart with logged on users for scheduled automatic updates installations
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 0

# Configure Automatic Updates
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 4

# Configure Automatic Updates: Scheduled install day
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type DWord -Value 0

# Remove access to “Pause updates” feature
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Type DWord -Value 1

# Manage preview builds
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 0

# Select when Preview Builds and Feature Updates are received
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 180

# Select when Quality Updates are received
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 0
