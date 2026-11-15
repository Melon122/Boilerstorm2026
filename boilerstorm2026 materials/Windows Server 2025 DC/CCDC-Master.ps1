#Requires -Version 5.1
<#
.SYNOPSIS
    CCDC / BoilerStorm 2026 Unified CLI & Interactive Console Dashboard (ClosedAI).
.DESCRIPTION
    Master orchestration console for CAI-DC01 (Windows Server 2025 DC) and CAI-WEB01 (Windows Server 2022 IIS).
    Integrates StateEngine, BaselineAndPersistence, ADServer2025, HostAndWebHardening, and MonitorAndReport
    with 1-click granular rollback, /32-only IP blocking, Splunk/CA safety checks, and DryRun preview.
    100% Offline / Local - Zero external network calls.
#>
param(
    [string]$Action = 'Menu',
    [string]$TargetIP = '',
    [string]$Reason = '',
    [string]$CheckpointId = '',
    [int]$TeamNumber = 0,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

# Dot-source Core & Sibling Modules safely if present
. (Join-Path $PSScriptRoot 'CCDC-StateEngine.ps1')
foreach ($modFile in @(
    'CCDC-BaselineAndPersistence.ps1',
    'CCDC-ADServer2025.ps1',
    'CCDC-HostAndWebHardening.ps1',
    'CCDC-MonitorAndReport.ps1'
)) {
    $modPath = Join-Path $PSScriptRoot $modFile
    if (Test-Path -LiteralPath $modPath) {
        . $modPath
    }
}

Assert-CCDCAdmin
Initialize-CCDCState
if ($DryRun) { Set-CCDCDryRun -Enabled $true }

function Show-CCDCDashboardHeader {
    $role = Get-CCDCHostRole
    $roleLabel = if ($role.IsDC -and $role.IsServer2025) {
        'CAI-DC01 Server 2025 DC'
    } elseif ($role.IsDC) {
        'Active Directory Domain Controller'
    } elseif ($role.HasIIS) {
        'CAI-WEB01 IIS Web Server'
    } else {
        'Windows Member Server'
    }

    $now = Get-Date
    $timeTag = if ($now.Hour -ge 16) {
        'COMPETITION WINDOW CLOSED (16:00)'
    } elseif ($now.Hour -eq 15) {
        'FINAL HOUR FREEZE (>=15:00 — NO RISKY CHANGES! FOCUS REPORTS/UPTIME!)'
    } else {
        '15:00 Change Freeze | 16:00 Competition Close'
    }

    $lowestPct = 100.0
    $lowestDrv = 'C:'
    foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
        if ($d.Size -gt 0) {
            $pct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
            if ($pct -lt $lowestPct) {
                $lowestPct = $pct
                $lowestDrv = $d.DeviceID
            }
        }
    }

    $spSvc = Get-Service -Name 'SplunkForwarder', 'Splunkd' -ErrorAction SilentlyContinue | Select-Object -First 1
    $splunkTag = if ($null -eq $spSvc) {
        'NOT INSTALLED'
    } elseif ($spSvc.Status -eq 'Running') {
        'RUNNING [PROTECTED]'
    } else {
        "$($spSvc.Status.ToString().ToUpperInvariant()) [CHECK IMMEDIATELY!]"
    }

    $scoredCnt = @(Get-CCDCScoredUsers).Count
    $cpCnt     = @(Get-CCDCCheckpoints).Count
    $dryState  = if (Get-CCDCDryRun) { 'ENABLED (Preview Only)' } else { 'DISABLED (Live Execution)' }
    $teamTag   = if ($script:MasterTeamNumber -gt 0) { "Team $($script:MasterTeamNumber)" } else { 'Unset' }

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "   BOILERSTORM 2026 / CCDC MASTER CONSOLE — CLOSEDAI (closedai.com)" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host (" Hostname       : {0} ({1}) | Team: {2}" -f $role.ComputerName, $roleLabel, $teamTag) -ForegroundColor Green
    Write-Host (" Local Time     : {0}  [{1}]" -f $now.ToString('yyyy-MM-dd HH:mm:ss'), $timeTag) -ForegroundColor ($(if ($now.Hour -ge 15) { 'Red' } else { 'Yellow' }))
    Write-Host (" Lowest Disk    : {0} {1}% Free | SplunkForwarder: {2}" -f $lowestDrv, $lowestPct, $splunkTag) -ForegroundColor ($(if ($lowestPct -lt 15 -or ($spSvc -and $spSvc.Status -ne 'Running')) { 'Red' } else { 'Cyan' }))
    Write-Host (" Scored Users   : {0} Protected | Checkpoints: {1} | DryRun: {2}" -f $scoredCnt, $cpCnt, $dryState) -ForegroundColor ($(if (Get-CCDCDryRun) { 'DarkYellow' } else { 'White' }))
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Invoke-CCDCSafeEnableAuditingAndLogs {
    <#
        Applies Section 2.7 Auditing & 1GB Event Logs via HostAndWebHardening if loaded,
        or executes a checkpointed fallback so First-30-Minutes always works standalone.
    #>
    if (Get-Command -Name 'Invoke-CCDCAuditingAndLogging' -ErrorAction SilentlyContinue) {
        Invoke-CCDCAuditingAndLogging
        return
    }
    $cp = New-CCDCCheckpoint -ModuleName 'Section27_AuditingFallback' -Description 'Enable Section 2.7 Audit Policy, 4688 CmdLine, PS 4104, and 1GB Logs'
    Backup-CCDCAuditPolicy | Out-Null
    if (-not (Get-CCDCDryRun)) {
        foreach ($sub in @(
            'Logon', 'Logoff', 'Account Lockout', 'Special Logon', 'Other Logon/Logoff Events',
            'User Account Management', 'Security Group Management', 'Computer Account Management',
            'Directory Service Access', 'Directory Service Changes', 'Kerberos Service Ticket Operations',
            'Kerberos Authentication Service', 'Credential Validation', 'Process Creation',
            'Audit Policy Change', 'Authentication Policy Change', 'Security State Change',
            'Security System Extension', 'System Integrity', 'MPSSVC Rule-Level Policy Change',
            'Other Object Access Events', 'File Share', 'Detailed File Share'
        )) {
            & auditpol.exe /set /subcategory:"$sub" /success:enable /failure:enable 2>$null | Out-Null
        }
        foreach ($logName in @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')) {
            & wevtutil.exe sl "$logName" /ms:1073741824 /rt:false 2>$null | Out-Null
        }
    }
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type 'DWord'
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type 'DWord'
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1 -Type 'DWord'
    Complete-CCDCCheckpoint | Out-Null
}

function Invoke-CCDCRotateInitialAdmin {
    <#
        Safely rotates the unscored initial 'admin' account (Changeme2026!) interactively
        while verifying it is not on the ScoredUsers list.
    #>
    $initAdmin = $script:CCDCConfig.Competition.InitialAdminUser
    $scored    = Get-CCDCScoredUsers
    if ($scored -contains $initAdmin.ToLowerInvariant()) {
        Write-CCDCLog "Account '$initAdmin' is in ScoredUsers.txt! Rotate via Quotient PCR instead!" -Level 'WARN'
        return
    }
    $role = Get-CCDCHostRole
    $ans = Read-Host "Rotate unscored '$initAdmin' account password now? (Y/n)"
    if ($ans -match '^(?i)n') { return }

    if (Get-CCDCDryRun) {
        Write-CCDCLog "[DRYRUN] Would prompt for new SecureString password and rotate '$initAdmin'." -Level 'DRYRUN'
        return
    }

    $secPw = Read-CCDCSecurePassword -PromptLabel "$initAdmin (unscored initial admin)"
    $rotated = $false
    if ($role.IsDC -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adUsr = Get-ADUser -Filter "SamAccountName -eq '$initAdmin'" -ErrorAction SilentlyContinue
            if ($adUsr) {
                Set-ADAccountPassword -Identity $adUsr.DistinguishedName -NewPassword $secPw -Reset -ErrorAction Stop
                Write-CCDCLog "Rotated AD domain account '$initAdmin' password." -Level 'SUCCESS'
                $rotated = $true
            }
        } catch {
            Write-CCDCLog "AD password reset for '$initAdmin' failed: $($_.Exception.Message)" -Level 'ERROR'
        }
    } else {
        $locUsr = Get-LocalUser -Name $initAdmin -ErrorAction SilentlyContinue
        if ($locUsr) {
            try {
                Set-LocalUser -Name $initAdmin -Password $secPw -ErrorAction Stop
                Write-CCDCLog "Rotated local account '$initAdmin' password." -Level 'SUCCESS'
                $rotated = $true
            } catch {
                Write-CCDCLog "Local password reset for '$initAdmin' failed: $($_.Exception.Message)" -Level 'ERROR'
            }
        } else {
            Write-CCDCLog "Local account '$initAdmin' not present on this member server (domain account rotates on CAI-DC01)." -Level 'INFO'
        }
    }
    if ($rotated) {
        Add-CCDCChangeLogEntry -Module 'First30Min_AdminRotate' -Summary "Rotated unscored '$initAdmin' password" -ActionType 'APPLY'
    }
}

function Invoke-CCDCFirst30MinutesWorkflow {
    Write-Host ""
    Write-Host "================ FIRST 30 MINUTES GUIDED WORKFLOW ================" -ForegroundColor Green
    Write-CCDCLog "Step 1/5: Populate Quotient Scored Users Protection List..." -Level 'INFO'
    Edit-CCDCScoredUsersInteractive

    Write-CCDCLog "Step 2/5: Capturing Ground-Truth Initial Host Baseline..." -Level 'INFO'
    if (Get-Command -Name 'Invoke-CCDCBaseline' -ErrorAction SilentlyContinue) {
        Invoke-CCDCBaseline -Label 'First30Min_Initial' | Out-Null
    }
    if ((Get-CCDCHostRole).HasIIS -and (Get-Command -Name 'New-CCDCWebRootBaseline' -ErrorAction SilentlyContinue)) {
        New-CCDCWebRootBaseline
    }

    Write-CCDCLog "Step 3/5: Enabling Section 2.7 Advanced Auditing, PS 4104 & 1GB Event Logs..." -Level 'INFO'
    Invoke-CCDCSafeEnableAuditingAndLogs

    Write-CCDCLog "Step 4/5: Rotating Unscored 'admin' Password & Wiping PSReadLine History..." -Level 'INFO'
    Invoke-CCDCRotateInitialAdmin
    Clear-CCDCHistory

    Write-CCDCLog "Step 5/5: Running Initial Persistence Sweep & Leaked Password Hunt..." -Level 'INFO'
    if (Get-Command -Name 'Invoke-CCDCPersistenceSweep' -ErrorAction SilentlyContinue) {
        Invoke-CCDCPersistenceSweep | Out-Null
    }
    if ((Get-CCDCHostRole).IsDC -and (Get-Command -Name 'Invoke-CCDCADLeakedPasswordHunt' -ErrorAction SilentlyContinue)) {
        Invoke-CCDCADLeakedPasswordHunt
    }
    Write-CCDCLog "First 30 Minutes Guided Workflow Complete! Verify Quotient service checks before deep hardening." -Level 'SUCCESS'
}

$script:MasterTeamNumber = $TeamNumber

# Direct CLI Non-Interactive Dispatch
switch ($Action.ToLowerInvariant()) {
    'first30'    { Invoke-CCDCFirst30MinutesWorkflow; return }
    'baseline'   { Invoke-CCDCBaseline -Label 'CLI'; return }
    'diff'       { Compare-CCDCBaseline; return }
    'sweep'      { Invoke-CCDCPersistenceSweep | Out-Null; return }
    'hunt'       { Invoke-CCDCEventHunter -MinutesBack 120; return }
    'monitor'    { Start-CCDCMonitorLoop -IntervalMinutes 15; return }
    'inventory'  { Export-CCDCOnboardingInventory | Out-Null; return }
    'blockip'    {
        if ([string]::IsNullOrWhiteSpace($TargetIP)) { throw "-TargetIP is required for -Action BlockIP" }
        $why = if ($Reason) { $Reason } else { 'CLI single-host attacker block' }
        Block-CCDCAttackerIP -IPAddress $TargetIP -Reason $why
        return
    }
    'unblockip'  { Unblock-CCDCAttackerIP -IPAddress $TargetIP; return }
    'rollback'   { Invoke-CCDCCheckpointRollback -CheckpointId $CheckpointId; return }
    'admenu'     { if (Get-Command -Name 'Invoke-CCDCADServer2025Menu' -ErrorAction SilentlyContinue) { Invoke-CCDCADServer2025Menu }; return }
    'hostmenu'   { if (Get-Command -Name 'Invoke-CCDCHostAndWebMenu' -ErrorAction SilentlyContinue) { Invoke-CCDCHostAndWebMenu }; return }
    'menu'       { }
    default      { Write-CCDCLog "Unknown -Action '$Action'. Opening interactive menu..." -Level 'WARN' }
}

# Interactive Master Dashboard Loop
while ($true) {
    Show-CCDCDashboardHeader
    Write-Host " [1] First 30 Minutes Guided Workflow (ScoredUsers -> Baseline -> Audit/1GB -> Rotate admin -> Sweep)" -ForegroundColor Green
    Write-Host " [2] Server 2025 Domain Controller (CAI-DC01) Hardening & AD Suite" -ForegroundColor Cyan
    Write-Host " [3] Windows Host, Defender, Firewall & IIS (CAI-WEB01) Hardening Suite" -ForegroundColor Cyan
    Write-Host " [4] 22-Vector Windows Persistence Sweep & Baseline Diff" -ForegroundColor Yellow
    Write-Host " [5] Section 2.8 Event Log Threat Hunter & 15-Min Continuous Monitor" -ForegroundColor Yellow
    Write-Host " [6] Block / Unblock Single Attacker IP (/32 Validated — No Subnets!)" -ForegroundColor Magenta
    Write-Host " [7] 1-Click Rollback / Undo Checkpoint Browser & ChangeLog Viewer" -ForegroundColor Red
    Write-Host " [8] Incident Report Evidence Packager, Inject Skeleton & Onboarding Tech-Stack Exporter" -ForegroundColor White
    Write-Host " [9] Manage Quotient Scored Users / Check Splunk & CA Health / Toggle DryRun / Clear PS History" -ForegroundColor Gray
    Write-Host " [0] Exit Console" -ForegroundColor DarkGray
    Write-Host ""
    $choice = (Read-Host "Select option [0-9]").Trim()

    switch ($choice) {
        '1' {
            Invoke-CCDCFirst30MinutesWorkflow
            Read-Host "Press Enter to return to dashboard" | Out-Null
        }
        '2' {
            if (Get-Command -Name 'Invoke-CCDCADServer2025Menu' -ErrorAction SilentlyContinue) {
                Invoke-CCDCADServer2025Menu
            } else {
                Write-CCDCLog "CCDC-ADServer2025.ps1 is not present in $PSScriptRoot." -Level 'WARN'
                Read-Host "Press Enter to continue" | Out-Null
            }
        }
        '3' {
            if (Get-Command -Name 'Invoke-CCDCHostAndWebMenu' -ErrorAction SilentlyContinue) {
                Invoke-CCDCHostAndWebMenu
            } else {
                Write-CCDCLog "CCDC-HostAndWebHardening.ps1 is not present in $PSScriptRoot." -Level 'WARN'
                Read-Host "Press Enter to continue" | Out-Null
            }
        }
        '4' {
            Write-Host "`n [1] Run Full 22-Vector Persistence Sweep`n [2] Compare Live Host vs Initial Baseline`n [3] Capture Fresh Baseline Snapshot`n [4] Remove Malicious WMI Subscriptions`n [5] Quote Unquoted Service Paths`n [0] Back" -ForegroundColor Yellow
            switch ((Read-Host "Persistence sub-option").Trim()) {
                '1' { Invoke-CCDCPersistenceSweep | Out-Null }
                '2' { Compare-CCDCBaseline }
                '3' { $lbl = Read-Host "Baseline label (default: Manual)"; Invoke-CCDCBaseline -Label ($(if ($lbl) { $lbl } else { 'Manual' })) | Out-Null }
                '4' { Remove-CCDCWmiSubscriptions }
                '5' { Fix-CCDCUnquotedServicePaths }
            }
            Read-Host "Press Enter to return to dashboard" | Out-Null
        }
        '5' {
            Write-Host "`n [1] Run Section 2.8 Event Log Threat Hunter (Custom Lookback + Optional /32 Block)`n [2] Start 15-Minute Continuous Monitoring Loop (Ctrl+C to exit)`n [0] Back" -ForegroundColor Yellow
            $sub5 = (Read-Host "Monitoring sub-option").Trim()
            if ($sub5 -eq '1') {
                $minsRaw = Read-Host "Lookback window in minutes (default: 120)"
                $mins = if ($minsRaw -match '^\d+$') { [int]$minsRaw } else { 120 }
                Invoke-CCDCEventHunter -MinutesBack $mins -OfferIPBlock
                Read-Host "Press Enter to return to dashboard" | Out-Null
            } elseif ($sub5 -eq '2') {
                Start-CCDCMonitorLoop -IntervalMinutes 15
            }
        }
        '6' {
            Write-Host "`n [1] Block Single Attacker IP (/32 or /128 Validated)`n [2] Unblock Previously Blocked IP`n [3] View BlockedIPs.csv History`n [0] Back" -ForegroundColor Magenta
            $sub6 = (Read-Host "IP Block sub-option").Trim()
            if ($sub6 -eq '1') {
                $ip = Read-Host "Enter single confirmed malicious IP (NO subnets!)"
                $rs = Read-Host "Reason / IOC (e.g. RDP/SMB brute force or webshell C2)"
                if (-not [string]::IsNullOrWhiteSpace($ip)) {
                    Block-CCDCAttackerIP -IPAddress $ip -Reason ($(if ($rs) { $rs } else { 'Interactive operator block' }))
                }
            } elseif ($sub6 -eq '2') {
                Unblock-CCDCAttackerIP
            } elseif ($sub6 -eq '3' -and (Test-Path -LiteralPath $script:CCDCBlockedIPsCsv)) {
                Import-Csv -LiteralPath $script:CCDCBlockedIPsCsv | Format-Table -AutoSize | Out-Host
            }
            Read-Host "Press Enter to return to dashboard" | Out-Null
        }
        '7' {
            Write-Host "`n [1] Browse & Execute 1-Click Checkpoint Rollback`n [2] Rollback MOST RECENT Checkpoint Immediately`n [3] View Recent ChangeLog.csv Entries`n [0] Back" -ForegroundColor Red
            $sub7 = (Read-Host "Rollback sub-option").Trim()
            if ($sub7 -eq '1') {
                Invoke-CCDCCheckpointRollback
            } elseif ($sub7 -eq '2') {
                Invoke-CCDCCheckpointRollback -CheckpointId 'Latest'
            } elseif ($sub7 -eq '3' -and (Test-Path -LiteralPath $script:CCDCChangeLogPath)) {
                Import-Csv -LiteralPath $script:CCDCChangeLogPath | Select-Object -Last 25 Timestamp, ActionType, Module, Summary, CheckpointId | Format-Table -AutoSize | Out-Host
            }
            Read-Host "Press Enter to return to dashboard" | Out-Null
        }
        '8' {
            Write-Host "`n [1] Package Incident Evidence Bundle + BoilerStorm IR Skeleton (Tomas Whelan)`n [2] Generate Deterministic Inject Memo Skeleton (Tomas Whelan)`n [3] Export Onboarding Tech-Stack & Asset Inventory (MD + TXT)`n [0] Back" -ForegroundColor White
            switch ((Read-Host "Reporting sub-option").Trim()) {
                '1' { New-CCDCIncidentEvidenceBundle -TeamNumber $script:MasterTeamNumber | Out-Null }
                '2' { New-CCDCInjectMemoSkeleton -TeamNumber $script:MasterTeamNumber | Out-Null }
                '3' { Export-CCDCOnboardingInventory | Out-Null }
            }
            Read-Host "Press Enter to return to dashboard" | Out-Null
        }
        '9' {
            Write-Host "`n [1] Edit Quotient Scored Users Protection List`n [2] Check Out-of-Scope SplunkForwarder & Competition Root CA Health (Read-Only)`n [3] Toggle DryRun Mode (Currently: $(Get-CCDCDryRun))`n [4] Set Team Number (Currently: $($script:MasterTeamNumber))`n [5] Clear PowerShell & PSReadLine History Across All Profiles`n [0] Back" -ForegroundColor Gray
            switch ((Read-Host "Utility sub-option").Trim()) {
                '1' { Edit-CCDCScoredUsersInteractive }
                '2' { Test-CCDCSplunkAndCAHealth }
                '3' { Set-CCDCDryRun -Enabled (-not (Get-CCDCDryRun)) }
                '4' { $tn = Read-Host "Enter Team Number (1-20)"; if ($tn -match '^\d+$') { $script:MasterTeamNumber = [int]$tn } }
                '5' { Clear-CCDCHistory }
            }
            Read-Host "Press Enter to return to dashboard" | Out-Null
        }
        '0' {
            Write-CCDCLog "Exiting CCDC Master Console. Stay sharp and watch Quotient!" -Level 'INFO'
            break
        }
    }
}
