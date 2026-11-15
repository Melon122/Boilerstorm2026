function Write-SecurityLog {
    param([string]$Message)
    $logPath = "C:\SecurityHardening\SecurityChanges.log"
    if (-not (Test-Path (Split-Path $logPath))) {
        New-Item -ItemType Directory -Path (Split-Path $logPath) | Out-Null
    }
    Add-Content -Path $logPath -Value "$(Get-Date) - $Message"
}

function Configure-Firewall {
    Write-Host "Configuring Windows Firewall..."
    netsh advfirewall set allprofiles state on
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
    netsh advfirewall firewall add rule name="Block Remote Desktop" dir=in protocol=TCP localport=3389 action=block
    $exploitPorts = @(135, 137, 138, 139, 445, 1433, 1434)
    foreach ($port in $exploitPorts) {
        netsh advfirewall firewall add rule name="Block Port $port" dir=in protocol=TCP localport=$port action=block
    }
    Write-SecurityLog "Firewall configuration completed"
}

function Configure-SecurityUpdates {
    Write-Host "Configuring Security Updates and Patch Management..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name AUOptions -Value 4
    $UpdateService = (New-Object -ComObject "Microsoft.Update.ServiceManager")
    $UpdateService.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-SecurityLog "Security updates and patch management configured"
}

function Configure-UserAccounts {
    Write-Host "Hardening User Accounts and Access Control..."
    net user guest /active:no
    net user administrator /active:no
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1
    net accounts /minpwlen:14
    net accounts /maxpwage:30
    net accounts /minpwage:1
    net accounts /lockoutthreshold:5
    net accounts /lockoutduration:30
    Write-SecurityLog "User account hardening completed"
}

function Configure-NetworkSecurity {
    Write-Host "Configuring Network Security..."
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    netsh interface ipv6 disable
    $servicesToDisable = @("Browser", "DiagTrack", "dmwappushservice", "HomeGroupListener", "HomeGroupProvider", "MapsBroker")
    foreach ($service in $servicesToDisable) {
        Stop-Service $service -Force
        Set-Service $service -StartupType Disabled
    }
    Write-SecurityLog "Network security configuration completed"
}

function Configure-AuditLogging {
    Write-Host "Configuring Advanced Security Logging..."
    auditpol /set /category:* /success:enable
    auditpol /set /category:* /failure:enable
    wevtutil sl Security /ms:268435456 /rt:1 /ab:true
    Write-SecurityLog "Advanced logging configuration completed"
}

function Disable-UnnecessaryFeatures {
    Write-Host "Disabling Unnecessary Windows Features..."
    $featuresToDisable = @("Internet-Explorer-Optional-amd64", "MediaPlayback", "WindowsMediaPlayer", "WorkFolders-Client")
    foreach ($feature in $featuresToDisable) {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
    }
    Write-SecurityLog "Unnecessary features disabled"
}

function Invoke-WindowsHardening {
    Write-Host "Starting Comprehensive Windows Security Hardening..."
    Configure-Firewall
    Configure-SecurityUpdates
    Configure-UserAccounts
    Configure-NetworkSecurity
    Configure-AuditLogging
    Disable-UnnecessaryFeatures
    Write-Host "Windows Hardening Complete. Reboot Recommended."
    Write-SecurityLog "Complete Windows Hardening Process Finished"
}
