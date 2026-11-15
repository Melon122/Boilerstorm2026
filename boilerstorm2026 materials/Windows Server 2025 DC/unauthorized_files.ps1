# Security Audit Script for CyberPatriot
# Purpose: Identify media files and security-relevant software for system auditing

# Get the current user's Downloads folder
$outputDir = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("MyDocuments"), "Downloads\SecurityAudit")
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}

# Function to write findings to a log file
function Write-Log {
    param($Message)
    Add-Content -Path "$outputDir\audit_log.txt" -Value $Message
    Write-Host $Message
}

Write-Log "=== Security Audit Started at $(Get-Date) ==="

# Define Windows folders to exclude from the scan
$windowsFolders = @(
    "C:\Windows", 
    "C:\Program Files", 
    "C:\Program Files (x86)", 
    "C:\ProgramData", 
    "C:\Users\Default", 
    "C:\Users\Public"
)

# Function to check if a file's path is in an excluded folder
function IsExcludedPath {
    param($path)
    foreach ($folder in $windowsFolders) {
        if ($path -like "$folder*") {
            return $true
        }
    }
    return $false
}

# Search for media files, excluding files in Windows system folders
Write-Log "`nScanning for media files..."
$mediaExtensions = @(
    "*.mp4", "*.avi", "*.mkv", "*.mov",  # Video
    "*.mp3", "*.wav", "*.flac", "*.m4a", # Audio
    "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp" # Images
)

foreach ($ext in $mediaExtensions) {
    Write-Log "`nLocating $ext files:"
    Get-ChildItem -Path "C:\" -Include $ext -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { -not (IsExcludedPath $_.FullName) } |  # Exclude Windows system folders
    ForEach-Object {
        Write-Log $_.FullName
    }
}

# Search for security tools and relevant software
Write-Log "`nScanning for security-related software..."
$securityTools = @(
    "wireshark", "nmap", "metasploit", "hashcat", "netcat", "aircrack",
    "burpsuite", "hydra", "john", "cain", "ophcrack", "malwarebytes",
    "kaspersky", "avast", "mcafee", "bitdefender", "norton"
)

foreach ($tool in $securityTools) {
    Write-Log "`nChecking for ${tool}:"
    Get-ChildItem -Path "C:\" -Include "*${tool}*" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Log $_.FullName
    }
}

# Search for games and specific apps
Write-Log "`nScanning for games and specific apps..."
$gamePaths = @(
    "C:\Program Files (x86)\Steam", "C:\Program Files\Steam", "C:\Games",
    "C:\Program Files (x86)\Epic Games", "C:\Program Files\Epic Games",
    "C:\Program Files (x86)\GOG Galaxy", "C:\Program Files\GOG Galaxy"
)

$gameApps = @("pong", "tetris", "minesweeper", "solitaire", "chess")

foreach ($path in $gamePaths) {
    if (Test-Path $path) {
        Write-Log "`nGames found in ${path}:"
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer } |
        ForEach-Object {
            Write-Log $_.FullName
        }
    }
}

foreach ($app in $gameApps) {
    Write-Log "`nChecking for ${app}:"
    Get-ChildItem -Path "C:\" -Include "*${app}*" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Log $_.FullName
    }
}

# Search for password files
Write-Log "`nScanning for password files..."
Get-ChildItem -Path "C:\" -Include "password.txt", "passwords.txt" -Recurse -ErrorAction SilentlyContinue |
ForEach-Object {
    Write-Log $_.FullName
}

Write-Log "`n=== Security Audit Completed at $(Get-Date) ==="
Write-Log "Results have been saved to $outputDir\audit_log.txt"
