#Requires -Version 5.1
<#
.SYNOPSIS
    stage.ps1 - BoilerStorm 2026 / CCDC Guacamole PowerShell Bootstrapper & 3-Min LAN Relay
    ClosedAI: CAI-DC01 (10.42.0.10) & CAI-WEB01 (10.42.0.20)
    Respects Competition TLS-Inspecting Proxy Root CA & System Proxy (NEVER disables cert checks!).
#>
param(
    [string]$Source = '',
    [string]$DestRoot = 'C:\ccdc',
    [string]$ServeLanIP = '',
    [int]$ServePort = 8888,
    [int]$ServeMinutes = 3,
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run stage.ps1 from an elevated (Administrator) PowerShell console!"
}

$defaultUrl = 'https://github.com/REPLACE_ORG/REPLACE_REPO/archive/refs/heads/main.zip'
$srcTarget  = if ($Source) { $Source } elseif ($env:CCDC_ZIP_URL) { $env:CCDC_ZIP_URL } else { $defaultUrl }

New-Item -Path $DestRoot -ItemType Directory -Force | Out-Null
& icacls.exe "$DestRoot" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /c /q | Out-Null

$zipPath = Join-Path $DestRoot 'ccdc_bundle.zip'
$extDir  = Join-Path $DestRoot 'extracted'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

Write-Host "[*] Staging archive from $srcTarget -> $zipPath" -ForegroundColor Cyan
if (Test-Path -LiteralPath $srcTarget -PathType Leaf) {
    Copy-Item -LiteralPath $srcTarget -Destination $zipPath -Force
} else {
    Invoke-WebRequest -Uri $srcTarget -OutFile $zipPath -UseBasicParsing -TimeoutSec 60
}

if (Test-Path -LiteralPath $extDir) { Remove-Item -LiteralPath $extDir -Recurse -Force }
Expand-Archive -LiteralPath $zipPath -DestinationPath $extDir -Force
Get-ChildItem -LiteralPath $DestRoot -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

$masterPs1 = Get-ChildItem -LiteralPath $extDir -Filter 'CCDC-Master.ps1' -Recurse -File | Select-Object -First 1
$workDir   = if ($masterPs1) { $masterPs1.DirectoryName } else { $extDir }
Write-Host "[+] Extracted & unblocked toolkit at: $workDir" -ForegroundColor Green

# Optional Time-Boxed (3-Min Auto-Terminating) 10.42.0.x LAN Relay so hosts keep their business roles!
if ($ServeLanIP -or (Read-Host "Start 3-min LAN relay on 10.42.0.x:$ServePort for sibling hosts? (y/N)") -match '^(?i)y') {
    if (-not $ServeLanIP) {
        $ServeLanIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -like '10.42.0.*' } | Select-Object -First 1 -ExpandProperty IPAddress)
    }
    if (-not $ServeLanIP -or $ServeLanIP -notmatch '^10\.42\.0\.\d+$') {
        throw "Refusing LAN relay: '$ServeLanIP' is not a valid ClosedAI 10.42.0.0/24 interface IP."
    }
    $maxMin = [math]::Min([math]::Max($ServeMinutes, 1), 3)
    $fwName = "CCDC_TEMP_STAGE_$ServePort"
    $prefix = "http://${ServeLanIP}:${ServePort}/"
    $linuxSh = Get-ChildItem -LiteralPath $extDir -Filter 'Linux-CCDC-Toolkit.sh' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1

    New-NetFirewallRule -DisplayName $fwName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $ServeLanIP -LocalPort $ServePort -RemoteAddress '10.42.0.0/24' | Out-Null
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix)
    $listener.Start()
    $deadline = (Get-Date).AddMinutes($maxMin)
    Write-Host "[*] LAN Relay LIVE until $($deadline.ToString('HH:mm:ss')) ($maxMin min max):" -ForegroundColor Yellow
    Write-Host "    Windows peer : .\stage.ps1 -Source ${prefix}ccdc.zip" -ForegroundColor Cyan
    Write-Host "    Linux peer   : sudo bash stage.sh ${prefix}Linux-CCDC-Toolkit.sh" -ForegroundColor Cyan

    try {
        $pending = $listener.BeginGetContext($null, $null)
        while ((Get-Date) -lt $deadline) {
            if ($pending.AsyncWaitHandle.WaitOne(1000)) {
                $ctx  = $listener.EndGetContext($pending)
                $reqP = $ctx.Request.Url.AbsolutePath.Trim('/').ToLowerInvariant()
                $sendFile = if ($reqP -match '\.sh$' -and $linuxSh) { $linuxSh.FullName } else { $zipPath }
                $bytes = [IO.File]::ReadAllBytes($sendFile)
                $ctx.Response.ContentLength64 = $bytes.Length
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $ctx.Response.OutputStream.Close()
                Write-Host "[+] Served $([IO.Path]::GetFileName($sendFile)) to $($ctx.Request.RemoteEndPoint)" -ForegroundColor Green
                $pending = $listener.BeginGetContext($null, $null)
            }
        }
    } finally {
        if ($listener.IsListening) { $listener.Stop() }
        $listener.Close()
        Remove-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue
        Write-Host "[*] LAN Relay auto-terminated & temporary firewall rule removed." -ForegroundColor Yellow
    }
}

if (-not $NoLaunch -and $masterPs1) {
    & $masterPs1.FullName
}
