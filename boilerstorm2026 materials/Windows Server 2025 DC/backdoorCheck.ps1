# Windows Security Audit Script
# This script performs checks for common security issues and unauthorized system modifications

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

# Export security event logs
Write-Host "Exporting security event logs..."
$events = Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {
    $_.Id -in @(4624, 4625, 4648, 4728, 4732, 4756, 4738)
}
$events | Export-Csv -Path "$outputDir\security_events.csv" -NoTypeInformation

Write-Host "`nAudit complete. Results saved to $outputDir"
Write-Host "Please review findings.log and security_events.csv for detailed results"
