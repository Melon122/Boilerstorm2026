# Prompt the user for critical services (separated by "|")
$criticalServicesInput = Read-Host "Enter the names of critical services to skip and keep enabled, separated by ' | '"
$criticalServices = $criticalServicesInput -split '\s*\|\s*'  # Split input by " | " and trim whitespace

# List of services to disable for CyberPatriot
$servicesToDisable = @(
    "BTAGService", "bthserv", "Browser", "MapsBroker", "lfsvc", "IISADMIN", "irmon",
    "SharedAccess", "lltdsvc", "LxssManager", "FTPSVC", "MSiSCSI", "sshd", "PNRPsvc",
    "p2psvc", "p2pimsvc", "PNRPAutoReg", "Spooler", "wercplsupport", "RasAuto",
    "SessionEnv", "TermService", "UmRdpService", "RpcLocator", "RemoteRegistry", 
    "RemoteAccess", "simptcp", "SNMP", "sacsvr", "SSDPSRV", "upnphost", "WMSvc", 
    "WerSvc", "Wecsvc", "WMPNetworkSvc", "icssvc", "WpnService", "PushToInstall", 
    "WinRM", "W3SVC", "XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc"
)

# Process each service in the list
foreach ($service in $servicesToDisable) {
    if ($criticalServices -contains $service) {
        # Skip disabling and instead ensure it's enabled and started
        try {
            Set-Service -Name $service -StartupType Automatic -ErrorAction Stop
            Start-Service -Name $service -ErrorAction Stop
            Write-Output "${service} is marked as critical, set to automatic, and started."
        } catch {
            Write-Output "Could not enable and start critical service ${service}: $($_.Exception.Message)"
        }
    } else {
        # Disable and stop non-critical services
        $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($null -ne $serviceObj) {
            try {
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-Output "${service} disabled and stopped."
            } catch {
                Write-Output "Could not disable and stop ${service}: $($_.Exception.Message)"
            }
        } else {
            Write-Output "${service} not found on this system."
        }
    }
}

Write-Output "All specified services have been processed."

$services2 = @(
    "wuauserv",     # Windows Update (ensure system is up-to-date)
    "BITS",         # Background Intelligent Transfer Service (supports updates)
    "WinDefend",    # Windows Defender Antivirus Service (essential for security)
    "EventLog",     # Windows Event Log (logs system events)
    "W32Time",      # Windows Time (time synchronization)
    "Dhcp",         # DHCP Client (required for network configuration)
    "Dnscache",     # DNS Client (supports DNS resolution)
    "Netlogon",     # Netlogon (authentication for domain accounts, if applicable)
    "TermService",  # Remote Desktop Services (if remote access is necessary)
    "SecurityHealthService", # Security Center (monitor system health)
    "LanmanWorkstation",    # Workstation Service (supports network connections)
    "LanmanServer"          # Server Service (file/printer sharing if needed)
)

# Enable and start each essential service
foreach ($service in $services2) {
    # Check if the service exists
    $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($null -ne $serviceObj) {
        Try {
            Start-Service -Name $service -ErrorAction Stop
            Set-Service -Name $service -StartupType Automatic -ErrorAction Stop
            Write-Output "${service} started and set to automatic."
        } Catch {
            Write-Output "Could not modify ${service}: $($_.Exception.Message)"
        }
    } else {
        Write-Output "${service} not found on this system."
    }
}

Write-Output "All specified services have been processed."
