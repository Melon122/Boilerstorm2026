# Requires -RunAsAdministrator

function Set-SmartScreenSettings {
    Write-Host "Configuring SmartScreen..." -ForegroundColor Green
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Required" -Type String
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord
}

function Disable-WiFiSense {
    Write-Host "Disabling Wi-Fi Sense..." -ForegroundColor Green
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Value 0
}

function Set-UACToMaximum {
    Write-Host "Setting UAC to maximum..." -ForegroundColor Green
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
}

function Configure-NetworkAdapters {
    Write-Host "Configuring network adapters..." -ForegroundColor Green
    
    # Get all network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($adapter in $adapters) {
        # Disable unwanted components
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_msclient"  # Client for MS Networks
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_server"    # File and Printer Sharing
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_pacer"     # QoS
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_lltdio"    # LLDP Protocol Driver
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_rspndr"    # Link-Layer Topology Discovery Responder
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_tcpip6"    # IPv6
        
        # Configure IPv4 settings
        $interface = Get-NetIPInterface -InterfaceAlias $adapter.Name -AddressFamily IPv4
        if ($interface) {
            # Disable NetBIOS over TCP/IP
            $netbiosSettings = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($interface.InterfaceIndex)"
            $netbiosSettings.SetTcpipNetbios(2)
            
            # Disable DNS registration
            Set-DnsClient -InterfaceAlias $adapter.Name -RegisterThisConnectionsAddress $false
        }
    }
}

function Disable-UPnPPort {
    Write-Host "Disabling UPnP port 1900..." -ForegroundColor Green
    $path = "HKLM:\Software\Microsoft\DirectplayNATHelp\DPNHUPnP"
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name "UPnPMode" -Value 2 -Type DWord
}

function Enable-WindowsDefender {
    Write-Host "Enabling Windows Defender..." -ForegroundColor Green
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
    Set-MpPreference -DisableRealtimeMonitoring $false
}

function Configure-WindowsFeatures {
    Write-Host "Configuring Windows Features..." -ForegroundColor Green
    
    # Features to disable
    $featuresToDisable = @(
        "TelnetClient",
        "TelnetServer",
        "SNMP",
        "RIP",
        "NFS-Client",
        "IIS-WebServer",
        "IIS-CommonHttpFeatures",
        "SMB1Protocol"
    )
    
    foreach ($feature in $featuresToDisable) {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
    }
}

function Configure-FirewallRules {
    Write-Host "Configuring firewall rules..." -ForegroundColor Green
    
    $appsToBlock = @(
        "Microsoft.MicrosoftEdge",
        "Microsoft.Windows.Cortana",
        "Microsoft.BingFinance",
        "Microsoft.BingSports",
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.Windows.Photos",
        "Microsoft.XboxApp"
    )
    
    foreach ($app in $appsToBlock) {
        New-NetFirewallRule -DisplayName "Block $app Inbound" -Direction Inbound -Program "C:\Program Files\WindowsApps\$app" -Action Block -Enabled True
    }
}

function Disable-AutoPlay {
    Write-Host "Disabling AutoPlay..." -ForegroundColor Green
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
}

function Main {
    Write-Host "Starting system configuration..." -ForegroundColor Cyan
    
    # Check for administrator privileges
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Administrator privileges required. Please run this script as Administrator."
        exit 1
    }
    
    # Execute all configurations
    Set-SmartScreenSettings
    Disable-WiFiSense
    Set-UACToMaximum
    Configure-NetworkAdapters
    Disable-UPnPPort
    Enable-WindowsDefender
    Configure-WindowsFeatures
    Configure-FirewallRules
    Disable-AutoPlay
    
    Write-Host "Configuration complete! A system restart is recommended." -ForegroundColor Green
    
    $restart = Read-Host "Would you like to restart the computer now? (y/n)"
    if ($restart -eq 'y') {
        Restart-Computer -Force
    }
}

# Run the script
Main
