#Requires -Version 5.1
<#
.SYNOPSIS
    CCDC / BoilerStorm 2026 Core State Snapshot, Granular Rollback, ChangeLog, and Safety Guardrails Engine.
.DESCRIPTION
    Provides checkpoint creation, exact prior-state recording (Registry, Services, Secedit, Auditpol,
    Firewall, AD objects/ACLs, IIS configs, Files), executable Undo.ps1 generation, 1-click Rollback,
    automatic ChangeLog.csv tracking, /32-only IP block enforcement, Splunk/CA safety checks, and
    secure interactive password & history helpers.
    100% Offline / Local - Zero external network calls.
#>

Set-StrictMode -Version Latest

# Load Configuration
$script:CCDCScriptRoot = $PSScriptRoot
$script:CCDCConfigPath = Join-Path $PSScriptRoot 'CCDC-Config.psd1'
if (Test-Path -LiteralPath $script:CCDCConfigPath) {
    $script:CCDCConfig = Import-PowerShellDataFile -Path $script:CCDCConfigPath
} else {
    throw "Required configuration file not found: $script:CCDCConfigPath"
}

$script:CCDCStateRoot      = $script:CCDCConfig.Competition.StateRoot
$script:CCDCChangeLogPath  = $script:CCDCConfig.Competition.ChangeLogPath
$script:CCDCScoredUsersTxt = $script:CCDCConfig.Competition.ScoredUsersPath
$script:CCDCBlockedIPsCsv  = $script:CCDCConfig.Competition.BlockedIPsPath
$script:CCDCDryRun         = $false
$script:ActiveCheckpoint   = $null

function Set-CCDCDryRun {
    param([bool]$Enabled)
    $script:CCDCDryRun = $Enabled
    Write-CCDCLog -Message ("DryRun mode is now: " + ($(if ($Enabled) { 'ENABLED (No system changes will be made)' } else { 'DISABLED (Live execution)' }))) -Level 'WARN'
}

function Get-CCDCDryRun {
    return [bool]$script:CCDCDryRun
}

function Test-CCDCAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-CCDCAdmin {
    if (-not (Test-CCDCAdmin)) {
        throw "Administrator privileges are required. Please run PowerShell as Administrator."
    }
}

function Write-CCDCLog {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'ALERT', 'DRYRUN')][string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'ALERT'   { 'Magenta' }
        'DRYRUN'  { 'DarkYellow' }
        default   { 'White' }
    }
    $line = "[$ts] [$Level] $Message"
    Write-Host $line -ForegroundColor $color

    if (Test-Path -LiteralPath $script:CCDCStateRoot) {
        $runLog = Join-Path $script:CCDCStateRoot 'CCDC_Execution.log'
        try {
            Add-Content -LiteralPath $runLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {}
    }
}

function Initialize-CCDCState {
    <#
        Creates C:\CCDC_State locked down to SYSTEM and Administrators ONLY so
        unprivileged shells cannot read backups, baselines, or logs.
    #>
    Assert-CCDCAdmin

    $subDirs = @('', 'Checkpoints', 'Baselines', 'Evidence', 'WebBackups', 'GPOBackups', 'DNSBackups', 'Sweeps')
    foreach ($sub in $subDirs) {
        $target = if ([string]::IsNullOrEmpty($sub)) { $script:CCDCStateRoot } else { Join-Path $script:CCDCStateRoot $sub }
        if (-not (Test-Path -LiteralPath $target)) {
            New-Item -Path $target -ItemType Directory -Force | Out-Null
        }
    }

    # Lock down NTFS permissions on C:\CCDC_State to SYSTEM and Administrators only
    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false) # Disable inheritance, remove inherited rules
        $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propFlags    = [System.Security.AccessControl.PropagationFlags]::None
        $fullControl  = [System.Security.AccessControl.FileSystemRights]::FullControl

        $sysSid   = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')     # NT AUTHORITY\SYSTEM
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544') # BUILTIN\Administrators

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sysSid, $fullControl, $inheritFlags, $propFlags, 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, $fullControl, $inheritFlags, $propFlags, 'Allow')))
        Set-Acl -LiteralPath $script:CCDCStateRoot -AclObject $acl -ErrorAction SilentlyContinue
    } catch {
        Write-CCDCLog "Could not tighten ACL on $($script:CCDCStateRoot): $($_.Exception.Message)" -Level 'WARN'
    }

    if (-not (Test-Path -LiteralPath $script:CCDCChangeLogPath)) {
        "Timestamp,Host,Operator,ActionType,Module,Summary,CheckpointId,CheckpointPath,UndoCommand" |
            Set-Content -LiteralPath $script:CCDCChangeLogPath -Encoding UTF8
    }

    if (-not (Test-Path -LiteralPath $script:CCDCScoredUsersTxt)) {
        @(
            "# ====================================================================="
            "# Quotient Scored User Accounts (One username per line, no DOMAIN\)"
            "# IMPORTANT: Passwords for these users MUST ONLY change via Quotient PCR!"
            "# Scripts will NEVER reset, disable, or remove accounts listed below."
            "# Check https://quotient.purdueblue.team and populate before rotating!"
            "# ====================================================================="
            "itops"
        ) | Set-Content -LiteralPath $script:CCDCScoredUsersTxt -Encoding UTF8
    }

    if (-not (Test-Path -LiteralPath $script:CCDCBlockedIPsCsv)) {
        "Timestamp,IPAddress,RuleNameIn,RuleNameOut,Reason,Operator,Status" |
            Set-Content -LiteralPath $script:CCDCBlockedIPsCsv -Encoding UTF8
    }
}

function Add-CCDCChangeLogEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Summary,
        [string]$ActionType     = 'APPLY',
        [string]$CheckpointId   = '',
        [string]$CheckpointPath = '',
        [string]$UndoCommand    = ''
    )
    Initialize-CCDCState
    $entry = [PSCustomObject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Host           = $env:COMPUTERNAME
        Operator       = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
        ActionType     = $ActionType
        Module         = $Module
        Summary        = $Summary
        CheckpointId   = $CheckpointId
        CheckpointPath = $CheckpointPath
        UndoCommand    = $UndoCommand
    }
    $entry | Export-Csv -LiteralPath $script:CCDCChangeLogPath -Append -NoTypeInformation -Encoding UTF8
}

function ConvertTo-CCDCQuotedPSString {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '$null' }
    return "'" + ($Text -replace "'", "''") + "'"
}

# =========================================================================
# CHECKPOINT & GRANULAR ROLLBACK ENGINE
# =========================================================================

function New-CCDCCheckpoint {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleName,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Initialize-CCDCState
    $safeMod = ($ModuleName -replace '[^a-zA-Z0-9_-]', '_')
    $ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
    $cpId    = "${ts}_${safeMod}"
    $cpDir   = Join-Path (Join-Path $script:CCDCStateRoot 'Checkpoints') $cpId

    if (-not $script:CCDCDryRun) {
        New-Item -Path $cpDir -ItemType Directory -Force | Out-Null
        $undoPath = Join-Path $cpDir 'Undo.ps1'
        @(
            "#Requires -RunAsAdministrator"
            "# ====================================================================="
            "# CCDC Automatic Granular Rollback Script"
            "# Checkpoint ID : $cpId"
            "# Module        : $ModuleName"
            "# Description   : $Description"
            "# Created       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "# Host          : $env:COMPUTERNAME"
            "# ====================================================================="
            "`$ErrorActionPreference = 'Continue'"
            "Write-Host '[ROLLBACK] Reverting checkpoint $cpId ($ModuleName)...' -ForegroundColor Yellow"
            ""
        ) | Set-Content -LiteralPath $undoPath -Encoding UTF8
    } else {
        $undoPath = Join-Path $cpDir 'Undo.ps1'
    }

    $cpObj = [PSCustomObject]@{
        CheckpointId = $cpId
        ModuleName   = $ModuleName
        Description  = $Description
        CreatedAt    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Directory    = $cpDir
        UndoScript   = $undoPath
        UndoBlocks   = New-Object System.Collections.Generic.List[string]
        Changes      = New-Object System.Collections.Generic.List[string]
        DryRun       = [bool]$script:CCDCDryRun
    }
    $script:ActiveCheckpoint = $cpObj
    Write-CCDCLog "Started checkpoint [$cpId] - $Description" -Level ($(if ($script:CCDCDryRun) { 'DRYRUN' } else { 'INFO' }))
    return $cpObj
}

function Register-CCDCUndoBlock {
    <#
        Registers a PowerShell snippet to run during rollback.
        Undo blocks are executed in LIFO (reverse) order so dependent actions unwind cleanly!
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UndoCode,
        [string]$ChangeSummary = ''
    )
    if ($null -ne $script:ActiveCheckpoint) {
        $script:ActiveCheckpoint.UndoBlocks.Add($UndoCode)
        if (-not [string]::IsNullOrWhiteSpace($ChangeSummary)) {
            $script:ActiveCheckpoint.Changes.Add($ChangeSummary)
        }
    }
}

function Complete-CCDCCheckpoint {
    param(
        [string]$SummaryOverride = ''
    )
    if ($null -eq $script:ActiveCheckpoint) { return $null }
    $cp = $script:ActiveCheckpoint
    $summary = if (-not [string]::IsNullOrWhiteSpace($SummaryOverride)) {
        $SummaryOverride
    } elseif ($cp.Changes.Count -gt 0) {
        "$($cp.Description) ($($cp.Changes.Count) item(s) modified)"
    } else {
        "$($cp.Description) (No changes required)"
    }

    if (-not $cp.DryRun) {
        # Write Undo blocks in LIFO (reverse) order so rollback unwinds cleanly
        $blocksReversed = @($cp.UndoBlocks)
        [array]::Reverse($blocksReversed)

        $sb = New-Object System.Text.StringBuilder
        foreach ($blk in $blocksReversed) {
            [void]$sb.AppendLine($blk)
            [void]$sb.AppendLine("")
        }
        [void]$sb.AppendLine("Write-Host '[ROLLBACK COMPLETE] Checkpoint $($cp.CheckpointId) reverted.' -ForegroundColor Green")
        Add-Content -LiteralPath $cp.UndoScript -Value $sb.ToString() -Encoding UTF8

        $manifestPath = Join-Path $cp.Directory 'Manifest.json'
        [PSCustomObject]@{
            CheckpointId = $cp.CheckpointId
            ModuleName   = $cp.ModuleName
            Description  = $cp.Description
            Summary      = $summary
            CreatedAt    = $cp.CreatedAt
            CompletedAt  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Host         = $env:COMPUTERNAME
            Operator     = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            ChangeCount  = $cp.Changes.Count
            Changes      = @($cp.Changes)
            UndoScript   = $cp.UndoScript
            RolledBack   = $false
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        $undoCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$($cp.UndoScript)`""
        Add-CCDCChangeLogEntry -Module $cp.ModuleName -Summary $summary -ActionType 'APPLY' `
            -CheckpointId $cp.CheckpointId -CheckpointPath $cp.Directory -UndoCommand $undoCmd

        Write-CCDCLog "Completed checkpoint [$($cp.CheckpointId)] -> Undo ready at: $($cp.UndoScript)" -Level 'SUCCESS'
    } else {
        Write-CCDCLog "[DRYRUN] Completed preview of [$($cp.ModuleName)]: $summary" -Level 'DRYRUN'
    }

    $script:ActiveCheckpoint = $null
    return $cp
}

# =========================================================================
# STATE-AWARE MUTATION WRAPPERS (Registry, Services, Secedit, Auditpol, FW)
# =========================================================================

function Set-CCDCRegistryValue {
    <#
        Records exact prior registry key/value state before changing it so Undo.ps1
        either restores the exact previous value + type OR deletes the newly created value/key.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()]$Value,
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')]
        [string]$Type = 'DWord'
    )

    if ($script:CCDCDryRun) {
        Write-CCDCLog "[DRYRUN] Would set Registry $Path\$Name = $Value ($Type)" -Level 'DRYRUN'
        Register-CCDCUndoBlock -UndoCode "# DryRun" -ChangeSummary "Reg: $Path\$Name = $Value"
        return
    }

    $qPath = ConvertTo-CCDCQuotedPSString $Path
    $qName = ConvertTo-CCDCQuotedPSString $Name
    $keyExisted = Test-Path -LiteralPath $Path
    $valExisted = $false
    $priorVal   = $null
    $priorKind  = $Type

    if ($keyExisted) {
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            $rawPrior = $item.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -ne $rawPrior) {
                $valExisted = $true
                $priorVal   = $rawPrior
                $priorKind  = $item.GetValueKind($Name).ToString()
            }
        } catch {}
    }

    # Build Undo snippet BEFORE modifying
    $undoLines = @()
    if (-not $keyExisted) {
        $undoLines += "if (Test-Path -LiteralPath $qPath) { Remove-Item -LiteralPath $qPath -Recurse -Force -ErrorAction SilentlyContinue }"
    } elseif (-not $valExisted) {
        $undoLines += "if (Test-Path -LiteralPath $qPath) { Remove-ItemProperty -LiteralPath $qPath -Name $qName -Force -ErrorAction SilentlyContinue }"
    } else {
        $valExpr = switch ($priorKind) {
            'MultiString' {
                $arrItems = @($priorVal) | ForEach-Object { ConvertTo-CCDCQuotedPSString ([string]$_) }
                "@(" + ($arrItems -join ', ') + ")"
            }
            'Binary' {
                $bytes = @([byte[]]$priorVal) -join ', '
                "[byte[]]@($bytes)"
            }
            'DWord'  { "[int]$priorVal" }
            'QWord'  { "[long]$priorVal" }
            default  { ConvertTo-CCDCQuotedPSString ([string]$priorVal) }
        }
        $qPriorKind = ConvertTo-CCDCQuotedPSString $priorKind
        $undoLines += "if (-not (Test-Path -LiteralPath $qPath)) { New-Item -Path $qPath -Force | Out-Null }"
        $undoLines += "Set-ItemProperty -LiteralPath $qPath -Name $qName -Value $valExpr -Type $qPriorKind -Force -ErrorAction SilentlyContinue"
    }

    try {
        if (-not $keyExisted) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Register-CCDCUndoBlock -UndoCode ($undoLines -join "`r`n") -ChangeSummary "Reg: $Path\$Name = $Value"
        Write-CCDCLog "Set Registry: $Path\$Name = $Value ($Type)" -Level 'INFO'
    } catch {
        Write-CCDCLog "Failed to set Registry $Path\$Name : $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Remove-CCDCRegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $rawPrior = $item.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $rawPrior) { return }
        $priorKind = $item.GetValueKind($Name).ToString()

        if ($script:CCDCDryRun) {
            Write-CCDCLog "[DRYRUN] Would remove Registry value $Path\$Name (current: $rawPrior)" -Level 'DRYRUN'
            return
        }

        $qPath = ConvertTo-CCDCQuotedPSString $Path
        $qName = ConvertTo-CCDCQuotedPSString $Name
        $qKind = ConvertTo-CCDCQuotedPSString $priorKind
        $valExpr = switch ($priorKind) {
            'MultiString' { "@(" + ((@($rawPrior) | ForEach-Object { ConvertTo-CCDCQuotedPSString ([string]$_) }) -join ', ') + ")" }
            'Binary'      { "[byte[]]@($((@([byte[]]$rawPrior)) -join ', '))" }
            'DWord'       { "[int]$rawPrior" }
            'QWord'       { "[long]$rawPrior" }
            default       { ConvertTo-CCDCQuotedPSString ([string]$rawPrior) }
        }

        $undo = "if (-not (Test-Path -LiteralPath $qPath)) { New-Item -Path $qPath -Force | Out-Null }`r`n" +
                "Set-ItemProperty -LiteralPath $qPath -Name $qName -Value $valExpr -Type $qKind -Force -ErrorAction SilentlyContinue"

        Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
        Register-CCDCUndoBlock -UndoCode $undo -ChangeSummary "Removed Reg: $Path\$Name"
        Write-CCDCLog "Removed Registry Value: $Path\$Name (prior backed up)" -Level 'INFO'
    } catch {
        Write-CCDCLog "Failed to remove Registry value $Path\$Name : $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Test-CCDCProtectedService {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    foreach ($p in $script:CCDCConfig.ProtectedServices) {
        if ($ServiceName -ieq $p -or $ServiceName -ilike "*splunk*") {
            return $true
        }
    }
    return $false
}

function Set-CCDCServiceState {
    <#
        Records exact prior Start value (including DelayedAutoStart) and running status,
        enforces ProtectedServices guardrail (NEVER touches SplunkForwarder!), and updates service.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [ValidateSet('Disabled', 'Manual', 'Automatic')][string]$StartupType = 'Disabled',
        [ValidateSet('Stopped', 'Running', 'Unchanged')][string]$DesiredStatus = 'Stopped',
        [switch]$AllowProtectedOverride
    )

    if ((Test-CCDCProtectedService -ServiceName $ServiceName) -and (-not $AllowProtectedOverride)) {
        if ($StartupType -eq 'Disabled' -or $DesiredStatus -eq 'Stopped') {
            Write-CCDCLog "GUARDRAIL BLOCKED stopping/disabling protected service: $ServiceName" -Level 'WARN'
            return
        }
    }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return }

    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    $priorStartDword = $null
    $priorDelayed    = $null
    if (Test-Path -LiteralPath $svcRegPath) {
        $regProps = Get-ItemProperty -LiteralPath $svcRegPath -ErrorAction SilentlyContinue
        if ($null -ne $regProps) {
            if ($regProps.PSObject.Properties.Name -contains 'Start') { $priorStartDword = $regProps.Start }
            if ($regProps.PSObject.Properties.Name -contains 'DelayedAutostart') { $priorDelayed = $regProps.DelayedAutostart }
        }
    }
    $priorStatus = $svc.Status.ToString()

    if ($script:CCDCDryRun) {
        Write-CCDCLog "[DRYRUN] Would set Service '$($svc.Name)' (currently $priorStatus / Start=$priorStartDword) -> $StartupType / $DesiredStatus" -Level 'DRYRUN'
        Register-CCDCUndoBlock -UndoCode "# DryRun" -ChangeSummary "Service: $($svc.Name) -> $StartupType/$DesiredStatus"
        return
    }

    $qSvcName = ConvertTo-CCDCQuotedPSString $svc.Name
    $qRegPath = ConvertTo-CCDCQuotedPSString $svcRegPath
    $undoLines = @()
    if ($null -ne $priorStartDword) {
        $undoLines += "Set-ItemProperty -LiteralPath $qRegPath -Name 'Start' -Value $([int]$priorStartDword) -Type DWord -Force -ErrorAction SilentlyContinue"
    } else {
        $undoLines += "Set-Service -Name $qSvcName -StartupType '$($svc.StartType)' -ErrorAction SilentlyContinue"
    }
    if ($null -ne $priorDelayed) {
        $undoLines += "Set-ItemProperty -LiteralPath $qRegPath -Name 'DelayedAutostart' -Value $([int]$priorDelayed) -Type DWord -Force -ErrorAction SilentlyContinue"
    }
    if ($priorStatus -eq 'Running') {
        $undoLines += "Start-Service -Name $qSvcName -ErrorAction SilentlyContinue"
    } elseif ($priorStatus -eq 'Stopped') {
        $undoLines += "Stop-Service -Name $qSvcName -Force -ErrorAction SilentlyContinue"
    }

    try {
        Set-Service -Name $svc.Name -StartupType $StartupType -ErrorAction Stop
        if ($DesiredStatus -eq 'Stopped' -and $svc.Status -ne 'Stopped') {
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
        } elseif ($DesiredStatus -eq 'Running' -and $svc.Status -ne 'Running') {
            Start-Service -Name $svc.Name -ErrorAction Stop
        }
        Register-CCDCUndoBlock -UndoCode ($undoLines -join "`r`n") -ChangeSummary "Service: $($svc.Name) ($priorStatus -> $DesiredStatus, $StartupType)"
        Write-CCDCLog "Service '$($svc.Name)' set to $StartupType / $DesiredStatus" -Level 'INFO'
    } catch {
        Write-CCDCLog "Could not modify service '$($svc.Name)': $($_.Exception.Message)" -Level 'WARN'
    }
}

function Backup-CCDCSecurityPolicy {
    if ($null -eq $script:ActiveCheckpoint -or $script:CCDCDryRun) { return $null }
    $infPath = Join-Path $script:ActiveCheckpoint.Directory 'secpol_prior.inf'
    $sdbPath = Join-Path $script:ActiveCheckpoint.Directory 'secpol_rollback.sdb'
    & secedit.exe /export /cfg "$infPath" | Out-Null
    if (Test-Path -LiteralPath $infPath) {
        $qInf = ConvertTo-CCDCQuotedPSString $infPath
        $qSdb = ConvertTo-CCDCQuotedPSString $sdbPath
        $undo = "& secedit.exe /configure /db $qSdb /cfg $qInf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null`r`n" +
                "Remove-Item -LiteralPath $qSdb -Force -ErrorAction SilentlyContinue"
        Register-CCDCUndoBlock -UndoCode $undo -ChangeSummary "Backed up Local Security Policy to $infPath"
        Write-CCDCLog "Backed up Local Security Policy -> $infPath" -Level 'INFO'
        return $infPath
    }
    return $null
}

function Backup-CCDCAuditPolicy {
    if ($null -eq $script:ActiveCheckpoint -or $script:CCDCDryRun) { return $null }
    $csvPath = Join-Path $script:ActiveCheckpoint.Directory 'auditpol_prior.csv'
    & auditpol.exe /backup /file:"$csvPath" | Out-Null
    if (Test-Path -LiteralPath $csvPath) {
        $qCsv = ConvertTo-CCDCQuotedPSString $csvPath
        $undo = "& auditpol.exe /restore /file:$qCsv | Out-Null"
        Register-CCDCUndoBlock -UndoCode $undo -ChangeSummary "Backed up Audit Policy to $csvPath"
        Write-CCDCLog "Backed up Audit Policy -> $csvPath" -Level 'INFO'
        return $csvPath
    }
    return $null
}

function Backup-CCDCFirewall {
    if ($null -eq $script:ActiveCheckpoint -or $script:CCDCDryRun) { return $null }
    $wfwPath = Join-Path $script:ActiveCheckpoint.Directory 'firewall_prior.wfw'
    & netsh.exe advfirewall export "$wfwPath" | Out-Null
    if (Test-Path -LiteralPath $wfwPath) {
        $qWfw = ConvertTo-CCDCQuotedPSString $wfwPath
        $undo = "& netsh.exe advfirewall import $qWfw | Out-Null"
        Register-CCDCUndoBlock -UndoCode $undo -ChangeSummary "Backed up Windows Firewall to $wfwPath"
        Write-CCDCLog "Backed up Windows Firewall -> $wfwPath" -Level 'INFO'
        return $wfwPath
    }
    return $null
}

function Backup-CCDCFile {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $null }
    if ($null -eq $script:ActiveCheckpoint -or $script:CCDCDryRun) { return $null }

    $safeLeaf = [IO.Path]::GetFileName($FilePath) + '_' + ([guid]::NewGuid().ToString('N').Substring(0, 6)) + '.bak'
    $bakPath  = Join-Path $script:ActiveCheckpoint.Directory $safeLeaf
    Copy-Item -LiteralPath $FilePath -Destination $bakPath -Force
    $qSrc = ConvertTo-CCDCQuotedPSString $bakPath
    $qDst = ConvertTo-CCDCQuotedPSString $FilePath
    Register-CCDCUndoBlock -UndoCode "Copy-Item -LiteralPath $qSrc -Destination $qDst -Force" -ChangeSummary "Backed up file $FilePath"
    return $bakPath
}

function Backup-CCDCNtfsAcl {
    <#
        Saves NTFS ACL tree using icacls.exe /save so Undo.ps1 restores exact permissions via icacls.exe /restore.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [switch]$NoRecurse
    )
    if (-not (Test-Path -LiteralPath $TargetPath)) { return $null }
    if ($null -eq $script:ActiveCheckpoint -or $script:CCDCDryRun) { return $null }

    $parentDir = Split-Path -Parent $TargetPath
    if ([string]::IsNullOrWhiteSpace($parentDir)) { $parentDir = $TargetPath }
    $aclLeaf = 'ntfs_acl_' + ([IO.Path]::GetFileName($TargetPath.TrimEnd('\')) -replace '[^a-zA-Z0-9_-]', '_') + '_' + ([guid]::NewGuid().ToString('N').Substring(0, 6)) + '.acl'
    $aclFile = Join-Path $script:ActiveCheckpoint.Directory $aclLeaf

    if ($NoRecurse) {
        & icacls.exe "$TargetPath" /save "$aclFile" /c /q | Out-Null
    } else {
        & icacls.exe "$TargetPath" /save "$aclFile" /t /c /q | Out-Null
    }

    if (Test-Path -LiteralPath $aclFile) {
        $qParent = ConvertTo-CCDCQuotedPSString $parentDir
        $qAcl    = ConvertTo-CCDCQuotedPSString $aclFile
        Register-CCDCUndoBlock -UndoCode "& icacls.exe $qParent /restore $qAcl /c /q | Out-Null" -ChangeSummary "Saved NTFS ACL backup for $TargetPath"
        Write-CCDCLog "Saved NTFS ACL backup for $TargetPath -> $aclFile" -Level 'INFO'
        return $aclFile
    }
    return $null
}

function Backup-CCDCIisConfig {
    <#
        Runs appcmd.exe add backup so IIS global configuration can be restored in 1 command.
    #>
    param([string]$BackupLabel = '')
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (-not (Test-Path -LiteralPath $appcmd)) { return $null }
    if ($null -eq $script:ActiveCheckpoint -or $script:CCDCDryRun) { return $null }

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safe = if ([string]::IsNullOrWhiteSpace($BackupLabel)) { "CCDC_IIS_$ts" } else { "CCDC_IIS_${ts}_$($BackupLabel -replace '[^a-zA-Z0-9_-]', '_')" }
    & $appcmd add backup "$safe" | Out-Null
    $qAppcmd = ConvertTo-CCDCQuotedPSString $appcmd
    $qSafe   = ConvertTo-CCDCQuotedPSString $safe
    Register-CCDCUndoBlock -UndoCode "& $qAppcmd restore backup $qSafe | Out-Null" -ChangeSummary "Created IIS appcmd backup '$safe'"
    Write-CCDCLog "Created IIS configuration backup: $safe" -Level 'INFO'
    return $safe
}

function Get-CCDCCheckpoints {
    Initialize-CCDCState
    $cpRoot = Join-Path $script:CCDCStateRoot 'Checkpoints'
    $manifests = Get-ChildItem -LiteralPath $cpRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending
    $results = @()
    foreach ($dir in $manifests) {
        $mFile = Join-Path $dir.FullName 'Manifest.json'
        $uFile = Join-Path $dir.FullName 'Undo.ps1'
        if (Test-Path -LiteralPath $mFile) {
            try {
                $m = Get-Content -LiteralPath $mFile -Raw -Encoding UTF8 | ConvertFrom-Json
                $results += $m
            } catch {}
        } elseif (Test-Path -LiteralPath $uFile) {
            $results += [PSCustomObject]@{
                CheckpointId = $dir.Name
                ModuleName   = $dir.Name
                Description  = 'Checkpoint folder'
                Summary      = 'Undo.ps1 present'
                CreatedAt    = $dir.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                UndoScript   = $uFile
                RolledBack   = $false
            }
        }
    }
    return $results
}

function Invoke-CCDCCheckpointRollback {
    <#
        1-Click Rollback Engine!
        Supports interactive selection OR -CheckpointId 'Latest' / exact ID.
    #>
    param(
        [string]$CheckpointId = ''
    )
    Assert-CCDCAdmin
    $checkpoints = @(Get-CCDCCheckpoints)
    if ($checkpoints.Count -eq 0) {
        Write-CCDCLog "No checkpoints found in $script:CCDCStateRoot\Checkpoints." -Level 'WARN'
        return
    }

    $selected = $null
    if ($CheckpointId -ieq 'Latest') {
        $selected = $checkpoints | Where-Object { -not $_.RolledBack } | Select-Object -First 1
        if ($null -eq $selected) { $selected = $checkpoints[0] }
    } elseif (-not [string]::IsNullOrWhiteSpace($CheckpointId)) {
        $selected = $checkpoints | Where-Object { $_.CheckpointId -ieq $CheckpointId } | Select-Object -First 1
        if ($null -eq $selected) {
            Write-CCDCLog "Checkpoint '$CheckpointId' not found." -Level 'ERROR'
            return
        }
    } else {
        Write-Host ""
        Write-Host "================= CCDC ROLLBACK / UNDO ENGINE =================" -ForegroundColor Yellow
        for ($i = 0; $i -lt $checkpoints.Count; $i++) {
            $cp = $checkpoints[$i]
            $rbTag = if ($cp.RolledBack) { ' [ALREADY ROLLED BACK]' } else { '' }
            Write-Host ("[{0}] {1} | {2} | {3}{4}" -f ($i + 1), $cp.CheckpointId, $cp.ModuleName, $cp.Summary, $rbTag) -ForegroundColor Cyan
        }
        Write-Host "[0] Cancel" -ForegroundColor Gray
        $pick = Read-Host "Select checkpoint number to undo (or '1' for most recent)"
        if ([string]::IsNullOrWhiteSpace($pick) -or $pick -eq '0') { return }
        if ($pick -match '^\d+$') {
            $idx = [int]$pick - 1
            if ($idx -ge 0 -and $idx -lt $checkpoints.Count) {
                $selected = $checkpoints[$idx]
            }
        }
        if ($null -eq $selected) {
            Write-CCDCLog "Invalid selection." -Level 'WARN'
            return
        }
    }

    if (-not (Test-Path -LiteralPath $selected.UndoScript)) {
        Write-CCDCLog "Undo script missing: $($selected.UndoScript)" -Level 'ERROR'
        return
    }

    if ($script:CCDCDryRun) {
        Write-CCDCLog "[DRYRUN] Would execute rollback script: $($selected.UndoScript)" -Level 'DRYRUN'
        Get-Content -LiteralPath $selected.UndoScript | Write-Host -ForegroundColor Gray
        return
    }

    Write-CCDCLog "Executing Rollback for [$($selected.CheckpointId)] ($($selected.ModuleName))..." -Level 'WARN'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$($selected.UndoScript)"

    # Mark manifest as rolled back
    $mFile = Join-Path (Split-Path -Parent $selected.UndoScript) 'Manifest.json'
    if (Test-Path -LiteralPath $mFile) {
        try {
            $mObj = Get-Content -LiteralPath $mFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $mObj | Add-Member -NotePropertyName 'RolledBack' -NotePropertyValue $true -Force
            $mObj | Add-Member -NotePropertyName 'RolledBackAt' -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Force
            $mObj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $mFile -Encoding UTF8
        } catch {}
    }

    Add-CCDCChangeLogEntry -Module $selected.ModuleName -Summary "ROLLED BACK checkpoint $($selected.CheckpointId)" `
        -ActionType 'ROLLBACK' -CheckpointId $selected.CheckpointId -CheckpointPath (Split-Path -Parent $selected.UndoScript)
    Write-CCDCLog "Rollback finished for [$($selected.CheckpointId)]. Watch Quotient for next 2 check cycles!" -Level 'SUCCESS'
}

# =========================================================================
# COMPETITION SAFETY GUARDRAILS (Scored Users, Splunk/CA, /32 IP Block, History)
# =========================================================================

function Get-CCDCScoredUsers {
    Initialize-CCDCState
    $users = @()
    if (Test-Path -LiteralPath $script:CCDCScoredUsersTxt) {
        $lines = Get-Content -LiteralPath $script:CCDCScoredUsersTxt -Encoding UTF8
        foreach ($line in $lines) {
            $clean = ($line -replace '#.*$', '').Trim()
            if (-not [string]::IsNullOrWhiteSpace($clean)) {
                # Strip DOMAIN\ if accidentally pasted
                if ($clean -match '\\') { $clean = ($clean -split '\\')[-1] }
                if ($clean -match '@') { $clean = ($clean -split '@')[0] }
                $users += $clean.ToLowerInvariant()
            }
        }
    }
    return @($users | Select-Object -Unique)
}

function Edit-CCDCScoredUsersInteractive {
    Initialize-CCDCState
    $current = Get-CCDCScoredUsers
    Write-Host ""
    Write-Host "=== Quotient Scored User Protection List ($script:CCDCScoredUsersTxt) ===" -ForegroundColor Cyan
    Write-Host "Currently protected scored users ($($current.Count)): $($current -join ', ')" -ForegroundColor Yellow
    Write-Host "NOTE: Passwords for Quotient scored users MUST ONLY be changed via PCR in Quotient!" -ForegroundColor Red
    Write-Host "[1] Add usernames (comma/space separated)"
    Write-Host "[2] Open $script:CCDCScoredUsersTxt in Notepad"
    Write-Host "[0] Return"
    $ans = Read-Host "Choice"
    if ($ans -eq '1') {
        $raw = Read-Host "Enter scored usernames (e.g. jsmith, alee, mchen)"
        $toAdd = $raw -split '[,\s;]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($u in $toAdd) {
            $clean = (($u -split '\\')[-1] -split '@')[0].Trim()
            if ($clean -and ($current -notcontains $clean.ToLowerInvariant())) {
                Add-Content -LiteralPath $script:CCDCScoredUsersTxt -Value $clean -Encoding UTF8
                Write-CCDCLog "Added '$clean' to ScoredUsers protection list." -Level 'SUCCESS'
            }
        }
    } elseif ($ans -eq '2') {
        Start-Process notepad.exe -ArgumentList "`"$script:CCDCScoredUsersTxt`"" -Wait
    }
}

function Read-CCDCSecurePassword {
    <#
        Prompts interactively via Read-Host -AsSecureString with double-entry verification.
        NEVER echoes or logs plaintext passwords!
    #>
    param([string]$PromptLabel = 'account')
    while ($true) {
        $p1 = Read-Host "Enter NEW password for $PromptLabel (input hidden)" -AsSecureString
        $p2 = Read-Host "Confirm NEW password for $PromptLabel (input hidden)" -AsSecureString

        $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
        $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
        try {
            $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
            $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
            if ([string]::IsNullOrEmpty($plain1)) {
                Write-CCDCLog "Password cannot be empty." -Level 'WARN'
                continue
            }
            if ($plain1 -cne $plain2) {
                Write-CCDCLog "Passwords did not match. Please try again." -Level 'WARN'
                continue
            }
            if ($plain1.Length -lt 12) {
                $ok = Read-Host "Password is shorter than 12 chars ($($plain1.Length)). Use anyway? (y/N)"
                if ($ok -notmatch '^(?i)y') { continue }
            }
            return $p1
        } finally {
            if ($bstr1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1) }
            if ($bstr2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2) }
            $plain1 = $null
            $plain2 = $null
        }
    }
}

function Clear-CCDCHistory {
    <#
        Clears PowerShell session command history and PSReadLine disk history files across ALL user profiles
        so Red Team cannot steal typed commands/passwords, while NEVER touching Event Logs!
    #>
    Clear-History -ErrorAction SilentlyContinue
    $wipedCount = 0
    try {
        $histPaths = New-Object System.Collections.Generic.List[string]
        if (Get-Module -Name PSReadLine -ErrorAction SilentlyContinue) {
            try { [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory() } catch {}
            $currPath = (Get-PSReadLineOption).HistorySavePath
            if ($currPath) { $histPaths.Add($currPath) }
        }
        if ($env:APPDATA) {
            $histPaths.Add((Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'))
        }
        foreach ($uDir in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
            $histPaths.Add((Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'))
            $histPaths.Add((Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\VisualStudioCodeHost_history.txt'))
            $histPaths.Add((Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ServerRemoteHost_history.txt'))
        }

        foreach ($hp in ($histPaths | Select-Object -Unique)) {
            if ($hp -and (Test-Path -LiteralPath $hp)) {
                Clear-Content -LiteralPath $hp -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $hp -Force -ErrorAction SilentlyContinue
                $wipedCount++
            }
        }
        Write-CCDCLog "Cleared PowerShell session history and $wipedCount PSReadLine history file(s) across all profiles (Event Logs untouched per Legal Hold)." -Level 'SUCCESS'
    } catch {
        Write-CCDCLog "Partial error clearing PSReadLine history: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Get-CCDCSplunkAndProxyIPs {
    <#
        Read-only discovery of Splunk Universal Forwarder indexer IP(s), local interfaces, gateways,
        DNS servers, and system proxy IP(s) so we NEVER accidentally block them with host firewall rules!
    #>
    $protectedIPs = New-Object System.Collections.Generic.List[string]
    # Protect all ClosedAI LAN hosts
    foreach ($h in $script:CCDCConfig.Topology.Keys) {
        $protectedIPs.Add($script:CCDCConfig.Topology[$h].LAN)
    }
    # Protect local interfaces & gateways & DNS servers (IPv4 and IPv6)
    try {
        Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.IPAddress) { $protectedIPs.Add(($_.IPAddress -replace '%.*$', '')) }
        }
        Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.NextHop -and $_.NextHop -notin @('0.0.0.0', '::')) { $protectedIPs.Add(($_.NextHop -replace '%.*$', '')) }
        }
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($s in $_.ServerAddresses) {
                if ($s) { $protectedIPs.Add(($s -replace '%.*$', '')) }
            }
        }
    } catch {}

    # Read-only parse of Splunk Universal Forwarder outputs.conf
    $splunkPaths = @(
        'C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf',
        'C:\Program Files\SplunkUniversalForwarder\etc\apps',
        'C:\Program Files\Splunk\etc\system\local\outputs.conf'
    )
    foreach ($sp in $splunkPaths) {
        if (Test-Path -LiteralPath $sp) {
            $files = if ((Get-Item -LiteralPath $sp).PSIsContainer) {
                Get-ChildItem -LiteralPath $sp -Filter 'outputs.conf' -Recurse -ErrorAction SilentlyContinue
            } else {
                @(Get-Item -LiteralPath $sp)
            }
            foreach ($f in $files) {
                $content = Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue
                foreach ($line in $content) {
                    if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})') {
                        $protectedIPs.Add($Matches[1])
                    }
                }
            }
        }
    }

    # Read-only parse of WinHTTP and WinINET proxy settings
    try {
        $inet = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($inet -and $inet.ProxyServer -match '(\d{1,3}(?:\.\d{1,3}){3})') {
            $protectedIPs.Add($Matches[1])
        }
        $inetLM = Get-ItemProperty -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($inetLM -and $inetLM.ProxyServer -match '(\d{1,3}(?:\.\d{1,3}){3})') {
            $protectedIPs.Add($Matches[1])
        }
    } catch {}

    return @($protectedIPs | Select-Object -Unique)
}

function Test-CCDCSplunkAndCAHealth {
    <#
        Read-only health check of out-of-scope competition agents (SplunkForwarder, Proxy, Root CA).
        NEVER modifies them.
    #>
    Write-Host ""
    Write-CCDCLog "=== Checking Out-of-Scope Competition Infrastructure (READ-ONLY) ===" -Level 'INFO'

    $splunkSvc = Get-Service -Name 'SplunkForwarder', 'Splunkd' -ErrorAction SilentlyContinue
    if ($splunkSvc) {
        foreach ($s in $splunkSvc) {
            $lvl = if ($s.Status -eq 'Running') { 'SUCCESS' } else { 'ALERT' }
            Write-CCDCLog "Splunk Service '$($s.Name)' Status: $($s.Status) | StartType: $($s.StartType) [DO NOT TAMPER]" -Level $lvl
        }
    } else {
        Write-CCDCLog "SplunkForwarder service not detected on this host." -Level 'INFO'
    }

    $protectedIPs = Get-CCDCSplunkAndProxyIPs
    Write-CCDCLog "Auto-protected Infrastructure/LAN/Splunk/Proxy IPs: $($protectedIPs -join ', ')" -Level 'INFO'

    # Read-only Root CA inspection for non-Microsoft CAs (Competition Proxy CA)
    try {
        $customCAs = Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue | Where-Object {
            $_.Subject -notmatch 'Microsoft|DigiCert|VeriSign|GlobalSign|Entrust|Baltimore|Thawte|GeoTrust|Sectigo|USERTrust|ISRG|Comodo|Starfield|Go Daddy|Amazon'
        }
        foreach ($ca in $customCAs) {
            Write-CCDCLog "Detected Custom/Competition Root CA: Subject='$($ca.Subject)' Thumbprint=$($ca.Thumbprint) [PROTECTED - DO NOT REMOVE]" -Level 'SUCCESS'
        }
    } catch {}
}

function Test-CCDCSingleAttackerIP {
    <#
        Competition Rule Enforcement:
        "Teams may block individual addresses that are sending malicious traffic,
         but may not block whole subnets."
        Validates single IPv4 (/32) or IPv6 (/128) host address ONLY.
        Rejects any subnet mask (e.g., /24, /16, /64), 0.0.0.0, ::, wildcards, ranges,
        loopback, link-local, LAN 10.42.0.0/24, self, gateway, DNS, and Splunk/Proxy IPs!
    #>
    param([Parameter(Mandatory = $true)][string]$CandidateIP)

    $trimmed = ($CandidateIP.Trim() -replace '%.*$', '')
    $explicitMask = $null
    if ($trimmed -match '^(.+)/(\d+)$') {
        $trimmed = $Matches[1]
        $explicitMask = [int]$Matches[2]
    } elseif ($trimmed -match '/') {
        Write-CCDCLog "RULE VIOLATION PREVENTED: Invalid CIDR mask in '$CandidateIP'. Single host IP ONLY!" -Level 'ERROR'
        return $null
    }

    if ($trimmed -match '[-\*,]') {
        Write-CCDCLog "RULE VIOLATION PREVENTED: Ranges, wildcards, or lists ('$trimmed') are forbidden. Pass ONE single host IP." -Level 'ERROR'
        return $null
    }

    $ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($trimmed, [ref]$ipObj)) {
        Write-CCDCLog "Invalid IP address format: '$trimmed'" -Level 'ERROR'
        return $null
    }

    $isV4 = ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
    $isV6 = ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
    if (-not ($isV4 -or $isV6)) {
        Write-CCDCLog "Unsupported address family for '$trimmed'." -Level 'ERROR'
        return $null
    }

    if ($isV4 -and ($null -ne $explicitMask) -and ($explicitMask -ne 32)) {
        Write-CCDCLog "RULE VIOLATION PREVENTED: '$CandidateIP' specifies /$explicitMask subnet! BoilerStorm allows SINGLE IPv4 (/32) blocks ONLY." -Level 'ERROR'
        return $null
    }
    if ($isV6 -and ($null -ne $explicitMask) -and ($explicitMask -ne 128)) {
        Write-CCDCLog "RULE VIOLATION PREVENTED: '$CandidateIP' specifies /$explicitMask subnet! BoilerStorm allows SINGLE IPv6 (/128) blocks ONLY." -Level 'ERROR'
        return $null
    }

    $normalized = $ipObj.IPAddressToString
    if ($ipObj.IsIPv6LinkLocal -or [System.Net.IPAddress]::IsLoopback($ipObj) -or
        $normalized -in @('0.0.0.0', '255.255.255.255', '::', '::1') -or
        $normalized -match '^(127\.|169\.254\.|224\.|239\.|ff0)') {
        Write-CCDCLog "Refusing to block unspecified/loopback/link-local/multicast address: $normalized" -Level 'ERROR'
        return $null
    }
    if ($normalized -match '^10\.42\.0\.') {
        Write-CCDCLog "SELF-LOCKOUT PREVENTED: $normalized is inside ClosedAI LAN (10.42.0.0/24)!" -Level 'ERROR'
        return $null
    }

    $protected = Get-CCDCSplunkAndProxyIPs
    if ($protected -contains $normalized) {
        Write-CCDCLog "INFRASTRUCTURE LOCKOUT PREVENTED: $normalized is a protected local/gateway/DNS/Splunk/Proxy IP!" -Level 'ERROR'
        return $null
    }

    return $normalized
}

function Block-CCDCAttackerIP {
    param(
        [Parameter(Mandatory = $true)][string]$IPAddress,
        [string]$Reason = 'Confirmed Red Team malicious traffic'
    )
    Assert-CCDCAdmin
    $validIP = Test-CCDCSingleAttackerIP -CandidateIP $IPAddress
    if ($null -eq $validIP) { return }

    $parsed = [System.Net.IPAddress]::Parse($validIP)
    $hostCidr = if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "$validIP/128" } else { "$validIP/32" }
    $safeSlug = ($validIP -replace '[^a-zA-Z0-9]', '_')

    Write-CCDCLog "WARNING: Verify $validIP is NOT the Quotient scoring engine before keeping block! Watch Quotient for 2 minutes!" -Level 'WARN'
    $cp = New-CCDCCheckpoint -ModuleName "BlockIP_$safeSlug" -Description "Block single attacker IP $hostCidr - $Reason"

    $ruleIn  = "CCDC_BLOCK_IN_$validIP"
    $ruleOut = "CCDC_BLOCK_OUT_$validIP"

    if (-not $script:CCDCDryRun) {
        # Remove existing duplicate if any, then add clean single-host (/32 or /128) inbound + outbound block
        Remove-NetFirewallRule -DisplayName $ruleIn -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue

        New-NetFirewallRule -DisplayName $ruleIn -Direction Inbound -Action Block -RemoteAddress $hostCidr -Profile Any -Enabled True -Description "CCDC Single-Host Block: $Reason" | Out-Null
        New-NetFirewallRule -DisplayName $ruleOut -Direction Outbound -Action Block -RemoteAddress $hostCidr -Profile Any -Enabled True -Description "CCDC Single-Host Block: $Reason" | Out-Null

        $qIn  = ConvertTo-CCDCQuotedPSString $ruleIn
        $qOut = ConvertTo-CCDCQuotedPSString $ruleOut
        $undo = "Remove-NetFirewallRule -DisplayName $qIn -ErrorAction SilentlyContinue`r`n" +
                "Remove-NetFirewallRule -DisplayName $qOut -ErrorAction SilentlyContinue"
        Register-CCDCUndoBlock -UndoCode $undo -ChangeSummary "Blocked single IP $hostCidr ($Reason)"

        # Inspect active TCP sessions from/to this attacker IP by logging owning PIDs
        $activeConns = Get-NetTCPConnection -RemoteAddress $validIP -ErrorAction SilentlyContinue
        foreach ($c in $activeConns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            Write-CCDCLog "Active connection with [$validIP]:$($c.RemotePort) on local port $($c.LocalPort) owned by PID $($c.OwningProcess) ($($proc.ProcessName))" -Level 'ALERT'
        }

        [PSCustomObject]@{
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            IPAddress   = $validIP
            RuleNameIn  = $ruleIn
            RuleNameOut = $ruleOut
            Reason      = $Reason
            Operator    = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            Status      = 'BLOCKED'
        } | Export-Csv -LiteralPath $script:CCDCBlockedIPsCsv -Append -NoTypeInformation -Encoding UTF8
    } else {
        Register-CCDCUndoBlock -UndoCode "# DryRun" -ChangeSummary "Would block $hostCidr"
    }

    Complete-CCDCCheckpoint -SummaryOverride "Blocked single attacker IP $hostCidr ($Reason)" | Out-Null
}

function Unblock-CCDCAttackerIP {
    param([string]$IPAddress = '')
    Assert-CCDCAdmin
    Initialize-CCDCState

    $existingRules = @(Get-NetFirewallRule -DisplayName 'CCDC_BLOCK_*' -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        if ($existingRules.Count -eq 0) {
            Write-CCDCLog "No CCDC_BLOCK_* firewall rules currently active." -Level 'INFO'
            return
        }
        Write-Host ""
        Write-Host "=== Currently Blocked Single IPs ===" -ForegroundColor Cyan
        $ips = @($existingRules | ForEach-Object { ($_.DisplayName -replace '^CCDC_BLOCK_(IN|OUT)_', '') } | Select-Object -Unique)
        for ($i = 0; $i -lt $ips.Count; $i++) {
            Write-Host "[$($i + 1)] $($ips[$i])" -ForegroundColor Yellow
        }
        $pick = Read-Host "Enter number or IP to unblock (0 to cancel)"
        if ([string]::IsNullOrWhiteSpace($pick) -or $pick -eq '0') { return }
        if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $ips.Count) {
            $IPAddress = $ips[[int]$pick - 1]
        } else {
            $IPAddress = $pick.Trim()
        }
    }

    $cleanIP = ($IPAddress.Trim() -replace '/(32|128)$', '')
    Remove-NetFirewallRule -DisplayName "CCDC_BLOCK_IN_$cleanIP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "CCDC_BLOCK_OUT_$cleanIP" -ErrorAction SilentlyContinue
    Add-CCDCChangeLogEntry -Module 'UnblockIP' -Summary "Unblocked IP $cleanIP" -ActionType 'ROLLBACK'
    Write-CCDCLog "Removed CCDC firewall block rules for $cleanIP." -Level 'SUCCESS'
}

function Get-CCDCHostRole {
    <#
        Detects whether current host is Domain Controller, IIS Web Server, or Member Server.
    #>
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $isDC = ($null -ne $cs -and ($cs.DomainRole -in @(4, 5)))
    $hasIIS = ($null -ne (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue))
    $is2025 = ($null -ne $os -and ([int]$os.BuildNumber -ge 26100 -or $os.Caption -match '2025'))

    return [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Domain       = if ($cs) { $cs.Domain } else { '' }
        DomainRole   = if ($cs) { $cs.DomainRole } else { 0 }
        IsDC         = $isDC
        HasIIS       = $hasIIS
        IsServer2025 = $is2025
        OSCaption    = if ($os) { $os.Caption } else { '' }
        OSVersion    = if ($os) { $os.Version } else { '' }
        BuildNumber  = if ($os) { [int]$os.BuildNumber } else { 0 }
    }
}
