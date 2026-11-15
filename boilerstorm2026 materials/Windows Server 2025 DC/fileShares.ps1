# Windows Security and File Share Audit Script

# Require admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges"
    exit
}

# Create output directory for logs
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = ".\SecurityAudit_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir

# Function to write findings to log
function Write-Finding {
    param($Category, $Finding, $Severity)
    $logEntry = "[$(Get-Date)] [$Severity] [$Category] $Finding"
    Add-Content -Path "$outputDir\findings.log" -Value $logEntry
    Write-Host $logEntry
}

# Check for unauthorized scheduled tasks
Write-Host "Checking scheduled tasks..."
$suspiciousTasks = Get-ScheduledTask | Where-Object {
    $_.Author -notlike "*Microsoft*" -and 
    $_.TaskPath -notlike "\Microsoft*"
}
foreach ($task in $suspiciousTasks) {
    Write-Finding -Category "ScheduledTasks" -Finding "Non-Microsoft scheduled task found: $($task.TaskName)" -Severity "INFO"
}

# Check for unusual service configurations
Write-Host "Checking services..."
$services = Get-WmiObject win32_service | Where-Object {
    $_.StartName -notlike "LocalSystem" -and
    $_.StartName -notlike "NT Authority*" -and
    $_.StartName -notlike "NT Service*"
}
foreach ($service in $services) {
    Write-Finding -Category "Services" -Finding "Unusual service account: $($service.DisplayName) running as $($service.StartName)" -Severity "WARNING"
}

# Check for unauthorized startup items
Write-Host "Checking startup items..."
$startupPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path | ForEach-Object {
            $_.PSObject.Properties | Where-Object {
                $_.Name -notlike "PSPath" -and
                $_.Name -notlike "PSParentPath" -and
                $_.Name -notlike "PSChildName" -and
                $_.Name -notlike "PSProvider"
            } | ForEach-Object {
                Write-Finding -Category "StartupItems" -Finding "Startup item found: $($_.Name) -> $($_.Value)" -Severity "INFO"
            }
        }
    }
}

# Check for unusual network connections
Write-Host "Checking network connections..."
$connections = Get-NetTCPConnection | Where-Object {
    $_.State -eq "Listen" -or
    $_.State -eq "Established"
}
foreach ($conn in $connections) {
    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($process) {
        Write-Finding -Category "NetworkConnections" -Finding "Active connection: $($process.ProcessName) ($($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort))" -Severity "INFO"
    }
}

# File Share Audit and Management Section
Write-Host "`nAuditing File Shares..."
Write-Host "========================`n"

# Get all file shares
$shares = Get-SmbShare | Select-Object Name, Path, Description

# Display all current shares
Write-Host "Current File Shares:"
$shares | Format-Table -AutoSize

# Default shares to exclude
$defaultShares = @('ADMIN$', 'C$', 'IPC$')

# Get authorized shares from user
Write-Host "`nPlease enter all authorized file share names (excluding $($defaultShares -join ', '))"
Write-Host "Separate multiple shares with ' | ' (Example: Share1 | Share2 | Share3)"
$authorizedInput = Read-Host "Authorized shares"

# Convert input to array and trim spaces
$authorizedShares = $authorizedInput -split '\s*\|\s*' | Where-Object { $_ }
$authorizedShares += $defaultShares

# Process unauthorized shares
$unauthorizedShares = $shares | Where-Object { $_.Name -notin $authorizedShares }

if ($unauthorizedShares) {
    Write-Host "`nUnauthorized shares found:"
    foreach ($share in $unauthorizedShares) {
        Write-Host "`nShare Name: $($share.Name)"
        Write-Host "Path: $($share.Path)"
        Write-Host "Description: $($share.Description)"
        
        $response = Read-Host "Do you want to stop this share? (Y/N)"
        if ($response.ToUpper() -eq 'Y') {
            try {
                Remove-SmbShare -Name $share.Name -Force
                Write-Finding -Category "FileShares" -Finding "Removed unauthorized share: $($share.Name)" -Severity "WARNING"
                Write-Host "Share $($share.Name) has been removed."
            }
            catch {
                Write-Finding -Category "FileShares" -Finding "Failed to remove share: $($share.Name). Error: $($_.Exception.Message)" -Severity "ERROR"
                Write-Host "Failed to remove share. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Finding -Category "FileShares" -Finding "Unauthorized share kept: $($share.Name)" -Severity "INFO"
            Write-Host "Share $($share.Name) has been kept."
        }
    }
}
else {
    Write-Host "`nNo unauthorized shares found."
}

# Export security event logs
Write-Host "`nExporting security event logs..."
$events = Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {
    $_.Id -in @(4624, 4625, 4648, 4728, 4732, 4756, 4738)
}
$events | Export-Csv -Path "$outputDir\security_events.csv" -NoTypeInformation

# Create file share audit report
$shareReport = @{
    TimeStamp = Get-Date
    TotalShares = $shares.Count
    AuthorizedShares = $authorizedShares
    UnauthorizedShares = $unauthorizedShares | Select-Object Name, Path, Description
}
$shareReport | ConvertTo-Json | Out-File "$outputDir\file_share_audit.json"

Write-Host "`nAudit complete. Results saved to $outputDir"
Write-Host "Please review:"
Write-Host "- findings.log: General security findings"
Write-Host "- security_events.csv: Security event logs"
Write-Host "- file_share_audit.json: File share audit details"
