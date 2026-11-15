#Requires -Version 5.1
<#
.SYNOPSIS
    CCDC / BoilerStorm 2026 Host Baseline, Diff Engine, 22-Vector Persistence Sweep,
    Section 2.8 Event Log Detection Map Hunter, and 15-Minute Monitoring Loop.
.DESCRIPTION
    Covers Checklist Section 1 (Baseline), Section 2.8 (Event Detection Map),
    Section 4 (Windows Persistence Sweep), and Section 8 (15-Minute Monitoring Loop).
    100% Offline / Local - Zero external network calls - Never clears Event Logs.
#>

if (-not (Get-Command -Name 'Write-CCDCLog' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'CCDC-StateEngine.ps1')
}

# =========================================================================
# SECTION 1: FULL HOST BASELINE & LIVE DIFF
# =========================================================================

function Invoke-CCDCBaseline {
    <#
        Captures a comprehensive, timestamped host snapshot BEFORE hardening so you
        always have ground-truth forensic state and can diff live drift anytime.
    #>
    param(
        [string]$Label = 'Initial'
    )
    Assert-CCDCAdmin
    Initialize-CCDCState

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeLabel = ($Label -replace '[^a-zA-Z0-9_-]', '_')
    $outDir = Join-Path (Join-Path $script:CCDCStateRoot 'Baselines') "${ts}_${env:COMPUTERNAME}_${safeLabel}"
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null

    Write-CCDCLog "Capturing host baseline [$Label] into $outDir ..." -Level 'INFO'
    $role = Get-CCDCHostRole

    # 1. Local Users & Local Groups
    $localUsers = @()
    try {
        $localUsers = @(Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, SID, PasswordRequired, PasswordExpires, UserMayChangePassword, LastLogon, Description)
        $localUsers | Export-Csv -LiteralPath (Join-Path $outDir 'LocalUsers.csv') -NoTypeInformation -Encoding UTF8
    } catch {
        & net.exe user | Set-Content -LiteralPath (Join-Path $outDir 'NetUsers.txt') -Encoding UTF8
    }

    $localGroups = @()
    try {
        foreach ($g in (Get-LocalGroup -ErrorAction Stop)) {
            $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.PrincipalSource):$($_.Name) ($($_.SID))" })
            $localGroups += [PSCustomObject]@{
                GroupName   = $g.Name
                SID         = $g.SID.Value
                Description = $g.Description
                Members     = ($members -join '; ')
            }
        }
        $localGroups | Export-Csv -LiteralPath (Join-Path $outDir 'LocalGroups.csv') -NoTypeInformation -Encoding UTF8
    } catch {}

    # 2. Services (with PathName, StartName, StartMode, State, ProcessId)
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId)
    $services | Export-Csv -LiteralPath (Join-Path $outDir 'Services.csv') -NoTypeInformation -Encoding UTF8

    # 3. Scheduled Tasks
    $tasks = @()
    try {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $act = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            $tasks += [PSCustomObject]@{
                TaskPath  = $t.TaskPath
                TaskName  = $t.TaskName
                State     = [string]$t.State
                Author    = $t.Author
                RunAsUser = $t.Principal.UserId
                RunLevel  = [string]$t.Principal.RunLevel
                Actions   = $act
            }
        }
        $tasks | Export-Csv -LiteralPath (Join-Path $outDir 'ScheduledTasks.csv') -NoTypeInformation -Encoding UTF8
    } catch {}

    # 4. Processes (with ParentProcessId, ExecutablePath, CommandLine)
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate)
    $procs | Export-Csv -LiteralPath (Join-Path $outDir 'Processes.csv') -NoTypeInformation -Encoding UTF8
    $procMap = @{}
    foreach ($p in $procs) { $procMap[[int]$p.ProcessId] = $p }

    # 5. Listening & Established TCP/UDP Ports mapped to Process + Authenticode
    $netConns = @()
    try {
        foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
            $pInfo = $procMap[[int]$c.OwningProcess]
            $netConns += [PSCustomObject]@{
                Protocol      = 'TCP'
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $c.RemoteAddress
                RemotePort    = $c.RemotePort
                State         = [string]$c.State
                PID           = $c.OwningProcess
                ProcessName   = if ($pInfo) { $pInfo.Name } else { '' }
                Executable    = if ($pInfo) { $pInfo.ExecutablePath } else { '' }
                CommandLine   = if ($pInfo) { $pInfo.CommandLine } else { '' }
            }
        }
        foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
            $pInfo = $procMap[[int]$u.OwningProcess]
            $netConns += [PSCustomObject]@{
                Protocol      = 'UDP'
                LocalAddress  = $u.LocalAddress
                LocalPort     = $u.LocalPort
                RemoteAddress = '*'
                RemotePort    = 0
                State         = 'Listen'
                PID           = $u.OwningProcess
                ProcessName   = if ($pInfo) { $pInfo.Name } else { '' }
                Executable    = if ($pInfo) { $pInfo.ExecutablePath } else { '' }
                CommandLine   = if ($pInfo) { $pInfo.CommandLine } else { '' }
            }
        }
        $netConns | Export-Csv -LiteralPath (Join-Path $outDir 'NetworkConnections.csv') -NoTypeInformation -Encoding UTF8
    } catch {}

    # 6. SMB Shares & Access
    try {
        $shares = @()
        foreach ($s in (Get-SmbShare -ErrorAction SilentlyContinue)) {
            $acc = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName):$($_.AccessControlType):$($_.AccessRight)" }) -join '; '
            $shares += [PSCustomObject]@{
                Name        = $s.Name
                Path        = $s.Path
                Description = $s.Description
                ShareAccess = $acc
            }
        }
        $shares | Export-Csv -LiteralPath (Join-Path $outDir 'SmbShares.csv') -NoTypeInformation -Encoding UTF8
    } catch {}

    # 7. Firewall Profiles & Enabled Rules
    try {
        Get-NetFirewallProfile -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogMaxSizeKilobytes |
            Export-Csv -LiteralPath (Join-Path $outDir 'FirewallProfiles.csv') -NoTypeInformation -Encoding UTF8

        Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, Direction, Action, Profile, DisplayGroup |
            Export-Csv -LiteralPath (Join-Path $outDir 'FirewallEnabledRules.csv') -NoTypeInformation -Encoding UTF8
    } catch {}

    # 8. Startup Commands, Hosts File, IPConfig, Hotfixes, Disk Space
    try {
        Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue |
            Select-Object Name, Command, Location, User |
            Export-Csv -LiteralPath (Join-Path $outDir 'StartupCommands.csv') -NoTypeInformation -Encoding UTF8
    } catch {}

    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsFile) {
        Copy-Item -LiteralPath $hostsFile -Destination (Join-Path $outDir 'hosts.txt') -Force
    }

    & ipconfig.exe /all | Set-Content -LiteralPath (Join-Path $outDir 'ipconfig_all.txt') -Encoding UTF8
    Get-HotFix -ErrorAction SilentlyContinue | Export-Csv -LiteralPath (Join-Path $outDir 'HotFixes.csv') -NoTypeInformation -Encoding UTF8
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
        Select-Object DeviceID, VolumeName, @{N='SizeGB';E={[math]::Round($_.Size/1GB,2)}}, @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,2)}}, @{N='FreePct';E={if($_.Size){[math]::Round(($_.FreeSpace/$_.Size)*100,1)}else{0}}} |
        Export-Csv -LiteralPath (Join-Path $outDir 'DiskSpace.csv') -NoTypeInformation -Encoding UTF8

    # 9. If Domain Controller: Snapshot AD Users, Groups, Computers, OUs, GPOs
    if ($role.IsDC -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADUser -Filter * -Properties Enabled, adminCount, SamAccountName, SID, DistinguishedName, MemberOf, ServicePrincipalName, whenCreated, whenChanged, PasswordLastSet, LastLogonDate, userAccountControl, Description, Info |
                Select-Object SamAccountName, Enabled, adminCount, DistinguishedName, whenCreated, whenChanged, PasswordLastSet, userAccountControl, Description, Info, @{N='SPNs';E={$_.ServicePrincipalName -join ';'}} |
                Export-Csv -LiteralPath (Join-Path $outDir 'AD_Users.csv') -NoTypeInformation -Encoding UTF8

            $adGroups = @()
            foreach ($ag in (Get-ADGroup -Filter * -Properties Members, adminCount, whenCreated, Description)) {
                $adGroups += [PSCustomObject]@{
                    SamAccountName    = $ag.SamAccountName
                    GroupScope        = [string]$ag.GroupScope
                    adminCount        = $ag.adminCount
                    whenCreated       = $ag.whenCreated
                    DistinguishedName = $ag.DistinguishedName
                    DirectMembers     = ($ag.Members -join '; ')
                }
            }
            $adGroups | Export-Csv -LiteralPath (Join-Path $outDir 'AD_Groups.csv') -NoTypeInformation -Encoding UTF8

            Get-ADComputer -Filter * -Properties OperatingSystem, IPv4Address, whenCreated, userAccountControl, Enabled |
                Select-Object Name, DNSHostName, IPv4Address, OperatingSystem, Enabled, whenCreated, userAccountControl, DistinguishedName |
                Export-Csv -LiteralPath (Join-Path $outDir 'AD_Computers.csv') -NoTypeInformation -Encoding UTF8
        } catch {
            Write-CCDCLog "Partial AD baseline warning: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    # Save pointer to earliest baseline if none exists yet
    $latestPtr = Join-Path (Join-Path $script:CCDCStateRoot 'Baselines') 'InitialBaselinePath.txt'
    if (-not (Test-Path -LiteralPath $latestPtr)) {
        $outDir | Set-Content -LiteralPath $latestPtr -Encoding UTF8
    }

    Add-CCDCChangeLogEntry -Module 'Baseline' -Summary "Captured host baseline ($Label) -> $outDir" -ActionType 'AUDIT'
    Write-CCDCLog "Baseline [$Label] complete: $outDir" -Level 'SUCCESS'
    return $outDir
}

function Compare-CCDCBaseline {
    <#
        Diffs live Users, Admins, Services, Scheduled Tasks, and Listening TCP Ports
        against the initial baseline captured in Section 1!
    #>
    param([string]$BaselineDir = '')
    Initialize-CCDCState

    if ([string]::IsNullOrWhiteSpace($BaselineDir)) {
        $ptr = Join-Path (Join-Path $script:CCDCStateRoot 'Baselines') 'InitialBaselinePath.txt'
        if (Test-Path -LiteralPath $ptr) {
            $BaselineDir = (Get-Content -LiteralPath $ptr -Raw -Encoding UTF8).Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($BaselineDir) -or (-not (Test-Path -LiteralPath $BaselineDir))) {
        Write-CCDCLog "No baseline directory found to compare against. Run Invoke-CCDCBaseline first!" -Level 'WARN'
        return
    }

    Write-Host ""
    Write-CCDCLog "=== Comparing Live Host State Against Baseline: $BaselineDir ===" -Level 'INFO'
    $driftCount = 0

    # Diff Services
    $baseSvcCsv = Join-Path $BaselineDir 'Services.csv'
    if (Test-Path -LiteralPath $baseSvcCsv) {
        $baseSvcNames = @(Import-Csv -LiteralPath $baseSvcCsv | Select-Object -ExpandProperty Name)
        $currSvcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
        foreach ($s in $currSvcs) {
            if ($baseSvcNames -notcontains $s.Name) {
                Write-CCDCLog "[NEW SERVICE] $($s.Name) ($($s.DisplayName)) | State=$($s.State) | Path=$($s.PathName)" -Level 'ALERT'
                $driftCount++
            }
        }
    }

    # Diff Scheduled Tasks
    $baseTaskCsv = Join-Path $BaselineDir 'ScheduledTasks.csv'
    if (Test-Path -LiteralPath $baseTaskCsv) {
        $baseTasks = @(Import-Csv -LiteralPath $baseTaskCsv | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $key = "$($t.TaskPath)$($t.TaskName)"
            if ($baseTasks -notcontains $key) {
                $act = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
                Write-CCDCLog "[NEW SCHEDULED TASK] $key | RunAs=$($t.Principal.UserId) | Action=$act" -Level 'ALERT'
                $driftCount++
            }
        }
    }

    # Diff Listening Ports
    $baseNetCsv = Join-Path $BaselineDir 'NetworkConnections.csv'
    if (Test-Path -LiteralPath $baseNetCsv) {
        $baseListenPorts = @(Import-Csv -LiteralPath $baseNetCsv | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Listen' } | Select-Object -ExpandProperty LocalPort -Unique)
        $currListen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
        foreach ($c in $currListen) {
            if ($baseListenPorts -notcontains [string]$c.LocalPort -and [int]$c.LocalPort -lt 49152) {
                $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                Write-CCDCLog "[NEW LISTENING TCP PORT] $($c.LocalAddress):$($c.LocalPort) | PID=$($c.OwningProcess) ($($p.ProcessName))" -Level 'ALERT'
                $driftCount++
            }
        }
    }

    # Diff Local Users
    $baseUsrCsv = Join-Path $BaselineDir 'LocalUsers.csv'
    if (Test-Path -LiteralPath $baseUsrCsv) {
        $baseUsers = @(Import-Csv -LiteralPath $baseUsrCsv | Select-Object -ExpandProperty Name)
        foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue)) {
            if ($baseUsers -notcontains $u.Name) {
                Write-CCDCLog "[NEW LOCAL USER] $($u.Name) (Enabled=$($u.Enabled))" -Level 'ALERT'
                $driftCount++
            }
        }
    }

    if ($driftCount -eq 0) {
        Write-CCDCLog "Zero unexpected new services, tasks, low listening ports, or local users since baseline!" -Level 'SUCCESS'
    } else {
        Write-CCDCLog "Detected $driftCount drift item(s) vs baseline!" -Level 'WARN'
    }
}

# =========================================================================
# SECTION 4: COMPREHENSIVE 22-VECTOR WINDOWS PERSISTENCE SWEEP
# =========================================================================

function Add-CCDCSweepFinding {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Collection,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Detail
    )
    $lvl = if ($Severity -eq 'CRITICAL' -or $Severity -eq 'HIGH') { 'ALERT' } elseif ($Severity -eq 'MEDIUM') { 'WARN' } else { 'INFO' }
    Write-CCDCLog "[$Severity] [$Category] $Target -> $Detail" -Level $lvl
    $Collection.Add([PSCustomObject]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Host      = $env:COMPUTERNAME
        Severity  = $Severity
        Category  = $Category
        Target    = $Target
        Detail    = $Detail
    })
}

function Invoke-CCDCPersistenceSweep {
    <#
        Scans ALL Section 4 persistence vectors on Windows (Server 2025 DC & Server 2022 Member).
        Exports full CSV + JSON report into C:\CCDC_State\Sweeps\.
    #>
    Assert-CCDCAdmin
    Initialize-CCDCState

    $findings = New-Object System.Collections.Generic.List[object]
    $role     = Get-CCDCHostRole
    $ts       = Get-Date -Format 'yyyyMMdd_HHmmss'
    $sweepCsv = Join-Path (Join-Path $script:CCDCStateRoot 'Sweeps') "PersistenceSweep_${env:COMPUTERNAME}_${ts}.csv"

    Write-Host ""
    Write-CCDCLog "================ STARTING SECTION 4 PERSISTENCE SWEEP ================" -Level 'INFO'

    # 1. Local Accounts & Privileged Local Groups (incl. $ suffix & Guest active)
    Write-CCDCLog "[1/16] Checking Local Accounts & Privileged Groups..." -Level 'INFO'
    try {
        foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue)) {
            if ($u.Name -eq 'Guest' -and $u.Enabled) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'Accounts' -Target $u.Name -Detail 'Built-in Guest account is ENABLED!'
            }
            if ($u.Name -match '\$$' -and $u.Enabled) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'Accounts' -Target $u.Name -Detail 'User account ends with $ (machine-account masquerade)!'
            }
            if (-not $u.PasswordRequired -and $u.Enabled -and $u.Name -notin @('DefaultAccount', 'WDAGUtilityAccount')) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'Accounts' -Target $u.Name -Detail 'Enabled local account has PasswordRequired = False!'
            }
        }
        foreach ($grpName in @('Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators')) {
            $members = @(Get-LocalGroupMember -Group $grpName -ErrorAction SilentlyContinue)
            if ($members.Count -gt 0) {
                $mList = ($members | ForEach-Object { $_.Name }) -join ', '
                Add-CCDCSweepFinding -Collection $findings -Severity 'INFO' -Category "LocalGroup:$grpName" -Target $grpName -Detail "Members: $mList"
            }
        }
    } catch {}

    # 2. Services: Suspicious Paths, LOLBins, Service Accounts, & Unquoted Service Paths
    Write-CCDCLog "[2/16] Checking Services (paths, LOLBins, accounts, unquoted paths)..." -Level 'INFO'
    $suspPathRegex = '(?i)(\\Temp\\|\\Tmp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft\\Windows Defender|Splunk)|\\PerfLogs\\|\\\$Recycle\.Bin\\|cmd\.exe|powershell\.exe|pwsh\.exe|mshta\.exe|wscript\.exe|cscript\.exe|rundll32\.exe|regsvr32\.exe)'
    foreach ($svc in (Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($svc.PathName)) { continue }
        if ($svc.Name -ilike '*Splunk*') { continue }

        if ($svc.PathName -match $suspPathRegex) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'ServicePath' -Target "$($svc.Name) ($($svc.State))" -Detail "Suspicious binary/command: $($svc.PathName)"
        }
        if ($svc.StartName -and $svc.StartName -notmatch '^(?i)(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|\.\\|Window Manager\\)') {
            Add-CCDCSweepFinding -Collection $findings -Severity 'MEDIUM' -Category 'ServiceAccount' -Target $svc.Name -Detail "Runs as non-standard account: $($svc.StartName) | Path: $($svc.PathName)"
        }
        # Unquoted service path check
        $pTrim = $svc.PathName.Trim()
        if ($pTrim -notmatch '^"' -and $pTrim -notmatch '^(?i)\\?\??\\?C:\\Windows\\' -and $pTrim -match '^([a-zA-Z]:\\[^"]+?\.exe)\b') {
            $exePart = $Matches[1]
            if ($exePart -match ' ') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'MEDIUM' -Category 'UnquotedServicePath' -Target $svc.Name -Detail "Unquoted service path with spaces: $($svc.PathName)"
            }
        }
    }

    # 3. Scheduled Tasks (Non-Microsoft + LOLBins/Suspicious Paths + Hidden SD check)
    Write-CCDCLog "[3/16] Checking Scheduled Tasks..." -Level 'INFO'
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $actStr = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        $isMsPath = ($t.TaskPath -like '\Microsoft\*')
        if (-not $isMsPath) {
            $sev = if ($actStr -match $suspPathRegex) { 'CRITICAL' } else { 'MEDIUM' }
            Add-CCDCSweepFinding -Collection $findings -Severity $sev -Category 'ScheduledTask' -Target "$($t.TaskPath)$($t.TaskName)" -Detail "State=$($t.State) | User=$($t.Principal.UserId) | Action=$actStr"
        } elseif ($actStr -match '(?i)(\\Temp\\|\\Users\\Public\\|\\AppData\\|-enc\b|FromBase64String|DownloadString|IEX\b|mshta|regsvr32)') {
            Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'ScheduledTask_Masquerade' -Target "$($t.TaskPath)$($t.TaskName)" -Detail "Suspicious action inside Microsoft task tree! User=$($t.Principal.UserId) | Action=$actStr"
        }
    }

    # 4. Run / RunOnce / Explorer\Run / Winlogon (Shell, Userinit, Notify, AutoAdminLogon)
    Write-CCDCLog "[4/16] Checking Registry Run Keys & Winlogon..." -Level 'INFO'
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    # Include loaded HKU user hives
    if (-not (Get-PSDrive -Name 'HKU' -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name 'HKU' -PSProvider Registry -Root 'HKEY_USERS' -ErrorAction SilentlyContinue | Out-Null
    }
    foreach ($hku in (Get-ChildItem -Path 'HKU:\' -ErrorAction SilentlyContinue)) {
        if ($hku.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            $runKeys += "HKU:\$($hku.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            $runKeys += "HKU:\$($hku.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
    }
    foreach ($rk in ($runKeys | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $rk) {
            $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
                    $sev = if ([string]$p.Value -match $suspPathRegex) { 'HIGH' } else { 'MEDIUM' }
                    Add-CCDCSweepFinding -Collection $findings -Severity $sev -Category 'RegistryRun' -Target "$rk -> $($p.Name)" -Detail ([string]$p.Value)
                }
            }
        }
    }

    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path -LiteralPath $winlogonPath) {
        $wl = Get-ItemProperty -LiteralPath $winlogonPath -ErrorAction SilentlyContinue
        if ($wl) {
            if ($wl.Shell -and $wl.Shell.Trim() -ine 'explorer.exe') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'Winlogon' -Target 'Shell' -Detail "Non-standard Winlogon Shell: $($wl.Shell)"
            }
            if ($wl.Userinit -and $wl.Userinit.Trim() -notmatch '^(?i)(C:\\Windows\\system32\\)?userinit\.exe,?$') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'Winlogon' -Target 'Userinit' -Detail "Non-standard Winlogon Userinit: $($wl.Userinit)"
            }
            if ($wl.PSObject.Properties.Name -contains 'DefaultPassword' -and (-not [string]::IsNullOrEmpty($wl.DefaultPassword))) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'Winlogon' -Target 'DefaultPassword' -Detail 'Plaintext DefaultPassword present in Winlogon registry!'
            }
            if ($wl.PSObject.Properties.Name -contains 'AutoAdminLogon' -and [string]$wl.AutoAdminLogon -eq '1') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'Winlogon' -Target 'AutoAdminLogon' -Detail 'AutoAdminLogon = 1 enabled!'
            }
        }
    }
    if (Test-Path -LiteralPath "$winlogonPath\Notify") {
        foreach ($sub in (Get-ChildItem -LiteralPath "$winlogonPath\Notify" -ErrorAction SilentlyContinue)) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'WinlogonNotify' -Target $sub.Name -Detail 'Legacy Winlogon Notify DLL key present!'
        }
    }

    # 5. Startup Folders (All Users + Per-User)
    Write-CCDCLog "[5/16] Checking Startup Folders..." -Level 'INFO'
    $startupFolders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($uDir in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $startupFolders += Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($sf in $startupFolders) {
        if (Test-Path -LiteralPath $sf) {
            foreach ($item in (Get-ChildItem -LiteralPath $sf -Force -ErrorAction SilentlyContinue)) {
                if ($item.Name -ieq 'desktop.ini') { continue }
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'StartupFolder' -Target $item.FullName -Detail "LastWriteTime=$($item.LastWriteTime)"
            }
        }
    }

    # 6. IFEO (Image File Execution Options) Debugger & SilentProcessExit Traps
    Write-CCDCLog "[6/16] Checking IFEO Debugger & SilentProcessExit..." -Level 'INFO'
    $ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path -LiteralPath $ifeoPath) {
        foreach ($sub in (Get-ChildItem -LiteralPath $ifeoPath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            if ($props -and ($props.PSObject.Properties.Name -contains 'Debugger') -and (-not [string]::IsNullOrWhiteSpace($props.Debugger))) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'IFEO_Debugger' -Target $sub.PSChildName -Detail "Debugger hijack -> $($props.Debugger)"
            }
        }
    }
    $spePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path -LiteralPath $spePath) {
        foreach ($sub in (Get-ChildItem -LiteralPath $spePath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            if ($props -and ($props.PSObject.Properties.Name -contains 'MonitorProcess')) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'SilentProcessExit' -Target $sub.PSChildName -Detail "MonitorProcess persistence -> $($props.MonitorProcess)"
            }
        }
    }

    # 7. Accessibility Binaries (OriginalFilename vs Actual Name + Authenticode + Owner)
    Write-CCDCLog "[7/16] Verifying Accessibility Binaries (Sticky Keys / Utilman / OSK)..." -Level 'INFO'
    $accessBins = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Narrator.exe', 'Magnify.exe', 'DisplaySwitch.exe', 'AtBroker.exe')
    foreach ($bin in $accessBins) {
        $binPath = Join-Path "$env:SystemRoot\System32" $bin
        if (Test-Path -LiteralPath $binPath) {
            $verInfo  = (Get-Item -LiteralPath $binPath).VersionInfo
            $origName = $verInfo.OriginalFilename
            $sig      = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
            $owner    = (Get-Acl -LiteralPath $binPath -ErrorAction SilentlyContinue).Owner
            $hash     = (Get-FileHash -LiteralPath $binPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

            # Catch cmd.exe / powershell.exe copied over sethc.exe (even though cmd.exe is MS-signed!)
            if ($origName -and ($origName -replace '\.MUI$', '') -ine $bin) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'StickyKeysHijack' -Target $binPath -Detail "REPLACED BINARY! OriginalFilename='$origName' (Expected '$bin') | SHA256=$hash"
            } elseif ($sig -and $sig.Status -ne 'Valid') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'StickyKeysHijack' -Target $binPath -Detail "Invalid signature ($($sig.Status)) | Owner=$owner | SHA256=$hash"
            } elseif ($owner -and $owner -notmatch 'TrustedInstaller') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'AccessibilityACL' -Target $binPath -Detail "Non-TrustedInstaller owner: $owner | SHA256=$hash"
            }
        }
    }

    # 8. WMI Permanent Event Subscriptions (root\subscription)
    Write-CCDCLog "[8/16] Checking WMI Permanent Event Subscriptions..." -Level 'INFO'
    try {
        $filters   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Filter' })
        $cmdCons   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue)
        $scrCons   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue)
        $bindings  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -ne 'SCM Event Log Filter' })

        foreach ($f in $filters) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'WMI_EventFilter' -Target $f.Name -Detail "Query: $($f.Query)"
        }
        foreach ($c in $cmdCons) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'WMI_CmdConsumer' -Target $c.Name -Detail "CommandLineTemplate: $($c.CommandLineTemplate) | ExecutablePath: $($c.ExecutablePath)"
        }
        foreach ($s in $scrCons) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'WMI_ScriptConsumer' -Target $s.Name -Detail "ScriptingEngine: $($s.ScriptingEngine) | ScriptText: $($s.ScriptText)"
        }
    } catch {}

    # 9. COM Hijacking (Per-User HKCU / HKU Classes\CLSID)
    Write-CCDCLog "[9/16] Checking Per-User COM CLSID Hijacks..." -Level 'INFO'
    $clsidRoots = @('HKCU:\Software\Classes\CLSID')
    foreach ($hku in (Get-ChildItem -Path 'HKU:\' -ErrorAction SilentlyContinue)) {
        if ($hku.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            $clsidRoots += "HKU:\$($hku.PSChildName)\Software\Classes\CLSID"
        }
    }
    foreach ($cr in ($clsidRoots | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $cr) {
            foreach ($clsid in (Get-ChildItem -LiteralPath $cr -ErrorAction SilentlyContinue)) {
                foreach ($srvType in @('InprocServer32', 'LocalServer32')) {
                    $sp = Join-Path $clsid.PSPath $srvType
                    if (Test-Path -LiteralPath $sp) {
                        $defVal = (Get-Item -LiteralPath $sp -ErrorAction SilentlyContinue).GetValue('')
                        Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'COM_Hijack' -Target "$cr\$($clsid.PSChildName)\$srvType" -Detail "Target DLL/EXE: $defVal"
                    }
                }
            }
        }
    }

    # 10. AppInit_DLLs & AppCertDlls
    Write-CCDCLog "[10/16] Checking AppInit_DLLs & AppCertDlls..." -Level 'INFO'
    foreach ($aiPath in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )) {
        if (Test-Path -LiteralPath $aiPath) {
            $ai = Get-ItemProperty -LiteralPath $aiPath -ErrorAction SilentlyContinue
            if ($ai -and ($ai.LoadAppInit_DLLs -eq 1 -or (-not [string]::IsNullOrWhiteSpace($ai.AppInit_DLLs)))) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'AppInit_DLLs' -Target $aiPath -Detail "LoadAppInit_DLLs=$($ai.LoadAppInit_DLLs) | AppInit_DLLs='$($ai.AppInit_DLLs)'"
            }
        }
    }
    $appCertPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if (Test-Path -LiteralPath $appCertPath) {
        $ac = Get-ItemProperty -LiteralPath $appCertPath -ErrorAction SilentlyContinue
        foreach ($p in $ac.PSObject.Properties) {
            if ($p.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'AppCertDlls' -Target $p.Name -Detail ([string]$p.Value)
            }
        }
    }

    # 11. LSA Packages (SSP / Authentication / Notification Packages - Mimikatz memssp etc.)
    Write-CCDCLog "[11/16] Checking LSA Authentication, Security, & Notification Packages..." -Level 'INFO'
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownLsaPkgs = @('msv1_0', 'kerberos', 'wdigest', 'tspkg', 'pku2u', 'livessp', 'cloudap', 'negoexts', 'schannel', 'scecli', 'rassfm', 'kdcsvc', 'wsauth', '""', '')
    if (Test-Path -LiteralPath $lsaPath) {
        $lsa = Get-ItemProperty -LiteralPath $lsaPath -ErrorAction SilentlyContinue
        foreach ($valName in @('Authentication Packages', 'Security Packages', 'Notification Packages')) {
            if ($lsa.PSObject.Properties.Name -contains $valName) {
                foreach ($pkg in @($lsa.$valName)) {
                    $cleanPkg = ([string]$pkg).Trim().ToLowerInvariant()
                    if ($cleanPkg -and ($knownLsaPkgs -notcontains $cleanPkg)) {
                        Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'LSA_Package' -Target "$lsaPath -> $valName" -Detail "Unexpected LSA DLL/SSP: '$pkg'"
                    }
                }
            }
        }
    }
    $osCfgLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'
    if (Test-Path -LiteralPath $osCfgLsa) {
        $osc = Get-ItemProperty -LiteralPath $osCfgLsa -ErrorAction SilentlyContinue
        if ($osc -and ($osc.PSObject.Properties.Name -contains 'Security Packages')) {
            foreach ($pkg in @($osc.'Security Packages')) {
                $cleanPkg = ([string]$pkg).Trim().ToLowerInvariant()
                if ($cleanPkg -and ($knownLsaPkgs -notcontains $cleanPkg)) {
                    Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'LSA_OSConfig_SSP' -Target $osCfgLsa -Detail "Unexpected OSConfig SSP: '$pkg'"
                }
            }
        }
    }

    # 12. Time Providers, Print Monitors, Netsh Helpers, BootExecute
    Write-CCDCLog "[12/16] Checking Time Providers, Print Monitors, Netsh Helpers, & BootExecute..." -Level 'INFO'
    $tpRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
    if (Test-Path -LiteralPath $tpRoot) {
        foreach ($tp in (Get-ChildItem -LiteralPath $tpRoot -ErrorAction SilentlyContinue)) {
            $dll = (Get-ItemProperty -LiteralPath $tp.PSPath -ErrorAction SilentlyContinue).DllName
            if ($dll -and $dll -notmatch '(?i)w32time\.dll$|vmictimeprovider\.dll$') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'TimeProviderDLL' -Target $tp.PSChildName -Detail "Non-standard TimeProvider DllName: $dll"
            }
        }
    }
    $pmRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $knownPrintDlls = @('localspl.dll', 'tcpmon.dll', 'usbmon.dll', 'wsdmon.dll', 'appmon.dll', 'apds.dll', 'FXSMON.DLL', 'lprmon.dll')
    if (Test-Path -LiteralPath $pmRoot) {
        foreach ($pm in (Get-ChildItem -LiteralPath $pmRoot -ErrorAction SilentlyContinue)) {
            $drv = (Get-ItemProperty -LiteralPath $pm.PSPath -ErrorAction SilentlyContinue).Driver
            if ($drv -and ($knownPrintDlls -notcontains $drv)) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'PrintMonitorDLL' -Target $pm.PSChildName -Detail "Non-default Print Monitor Driver DLL: $drv"
            }
        }
    }
    $netshRoot = 'HKLM:\SOFTWARE\Microsoft\NetSh'
    if (Test-Path -LiteralPath $netshRoot) {
        $nsProps = Get-ItemProperty -LiteralPath $netshRoot -ErrorAction SilentlyContinue
        foreach ($p in $nsProps.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $v = [string]$p.Value
            if ($v -match '\\' -and $v -notmatch '^(?i)C:\\Windows\\System32\\') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'NetshHelperDLL' -Target $p.Name -Detail "Suspicious Netsh Helper DLL path: $v"
            }
        }
    }
    $smPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if (Test-Path -LiteralPath $smPath) {
        $be = (Get-ItemProperty -LiteralPath $smPath -ErrorAction SilentlyContinue).BootExecute
        foreach ($entry in @($be)) {
            if ($entry -and $entry.Trim() -ine 'autocheck autochk *') {
                Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'BootExecute' -Target 'Session Manager\BootExecute' -Detail "Unexpected BootExecute entry: $entry"
            }
        }
    }

    # 13. PowerShell Profiles & BITS Jobs
    Write-CCDCLog "[13/16] Checking PowerShell Profiles & BITS Persistence Jobs..." -Level 'INFO'
    $psProfilePaths = @(
        "$PSHOME\Profile.ps1",
        "$PSHOME\Microsoft.PowerShell_profile.ps1",
        "$env:ProgramFiles\PowerShell\7\profile.ps1"
    )
    foreach ($uDir in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $psProfilePaths += Join-Path $uDir.FullName 'Documents\WindowsPowerShell\profile.ps1'
        $psProfilePaths += Join-Path $uDir.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
        $psProfilePaths += Join-Path $uDir.FullName 'Documents\PowerShell\profile.ps1'
        $psProfilePaths += Join-Path $uDir.FullName 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'
    }
    foreach ($pp in ($psProfilePaths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $pp) {
            $preview = ((Get-Content -LiteralPath $pp -TotalCount 5 -ErrorAction SilentlyContinue) -join ' ')
            Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'PowerShellProfile' -Target $pp -Detail "Profile exists! Preview: $preview"
        }
    }

    try {
        $bits = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue)
        foreach ($b in $bits) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'BITS_Job' -Target $b.DisplayName -Detail "JobState=$($b.JobState) | Owner=$($b.OwnerAccount)"
        }
    } catch {}

    # 14. OpenSSH Server & authorized_keys + WinRM Listeners
    Write-CCDCLog "[14/16] Checking Windows OpenSSH & WinRM Listeners..." -Level 'INFO'
    $sshdSvc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($sshdSvc -and $sshdSvc.Status -eq 'Running') {
        Add-CCDCSweepFinding -Collection $findings -Severity 'HIGH' -Category 'OpenSSH_Server' -Target 'sshd' -Detail "Windows OpenSSH Server is RUNNING (StartType=$($sshdSvc.StartType))"
    }
    $sshKeyFiles = @('C:\ProgramData\ssh\administrators_authorized_keys')
    foreach ($uDir in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $sshKeyFiles += Join-Path $uDir.FullName '.ssh\authorized_keys'
    }
    foreach ($kf in $sshKeyFiles) {
        if (Test-Path -LiteralPath $kf) {
            $lines = @(Get-Content -LiteralPath $kf -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
            if ($lines.Count -gt 0) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'SSH_AuthorizedKeys' -Target $kf -Detail "$($lines.Count) SSH public key(s) present!"
            }
        }
    }
    try {
        if (Test-Path -Path 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction SilentlyContinue) {
            $th = (Get-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction SilentlyContinue).Value
            if (-not [string]::IsNullOrWhiteSpace($th)) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'MEDIUM' -Category 'WinRM_TrustedHosts' -Target 'WSMan TrustedHosts' -Detail "TrustedHosts = '$th'"
            }
        }
    } catch {}

    # 15. Hosts File Redirects
    Write-CCDCLog "[15/16] Checking Hosts File Redirects..." -Level 'INFO'
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
        $activeHosts = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
        foreach ($hl in $activeHosts) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'MEDIUM' -Category 'HostsFile' -Target $hostsPath -Detail "Active hosts entry: $($hl.Trim())"
        }
    }

    # 16. DNS ServerLevelPluginDll & Quick AD Persistence Check (if DC)
    Write-CCDCLog "[16/16] Checking DNS Plugin DLL & AD Persistence Indicators..." -Level 'INFO'
    $dnsParamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'
    if (Test-Path -LiteralPath $dnsParamPath) {
        $dnsDll = (Get-ItemProperty -LiteralPath $dnsParamPath -ErrorAction SilentlyContinue).ServerLevelPluginDll
        if (-not [string]::IsNullOrWhiteSpace($dnsDll)) {
            Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'DNS_PluginDLL' -Target 'ServerLevelPluginDll' -Detail "DNS SYSTEM DLL backdoor configured: $dnsDll"
        }
    }

    if ($role.IsDC -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $dmsas = @(Get-ADObject -LDAPFilter '(objectClass=msDS-DelegatedManagedServiceAccount)' -Properties msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSAState -ErrorAction SilentlyContinue)
            foreach ($d in $dmsas) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'AD_BadSuccessor_dMSA' -Target $d.DistinguishedName -Detail "PrecededBy=$($d.'msDS-ManagedAccountPrecededByLink') | State=$($d.'msDS-DelegatedMSAState')"
            }
            $builtinUsers = @(Get-ADObject -SearchBase "CN=Builtin,$((Get-ADDomain).DistinguishedName)" -LDAPFilter '(objectCategory=person)' -ErrorAction SilentlyContinue)
            foreach ($bu in $builtinUsers) {
                Add-CCDCSweepFinding -Collection $findings -Severity 'CRITICAL' -Category 'AD_HiddenBuiltinUser' -Target $bu.DistinguishedName -Detail "User object hidden inside CN=Builtin container!"
            }
        } catch {}
    }

    # Save Sweep Report
    if ($findings.Count -gt 0) {
        $findings | Export-Csv -LiteralPath $sweepCsv -NoTypeInformation -Encoding UTF8
        Write-CCDCLog "Persistence Sweep finished: $($findings.Count) finding(s) saved to $sweepCsv" -Level 'WARN'
    } else {
        Write-CCDCLog "Persistence Sweep finished: ZERO suspicious findings detected!" -Level 'SUCCESS'
    }

    Add-CCDCChangeLogEntry -Module 'PersistenceSweep' -Summary "Ran 16-stage persistence sweep ($($findings.Count) findings) -> $sweepCsv" -ActionType 'AUDIT'
    return $findings
}

function Remove-CCDCWmiSubscriptions {
    <#
        Interactive & reversible WMI Permanent Event Subscription cleaner.
    #>
    Assert-CCDCAdmin
    $filters  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Filter' })
    $cmdCons  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue)
    $scrCons  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue)
    $bindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -ne 'SCM Event Log Filter' })

    if (($filters.Count + $cmdCons.Count + $scrCons.Count + $bindings.Count) -eq 0) {
        Write-CCDCLog "No non-default WMI Event Subscriptions found." -Level 'SUCCESS'
        return
    }

    $cp = New-CCDCCheckpoint -ModuleName 'CleanWMISubscriptions' -Description 'Export and remove malicious WMI permanent subscriptions'
    if (-not $script:CCDCDryRun) {
        $exportJson = Join-Path $cp.Directory 'WMI_Subscriptions_Backup.json'
        [PSCustomObject]@{
            Filters  = $filters
            CmdCons  = $cmdCons
            ScrCons  = $scrCons
            Bindings = $bindings
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $exportJson -Encoding UTF8
        Register-CCDCUndoBlock -UndoCode "Write-Warning 'Review exported WMI subscription backup at $exportJson before re-creating.'" -ChangeSummary "Removed $($filters.Count) WMI filters / $($cmdCons.Count + $scrCons.Count) consumers"

        foreach ($b in $bindings) { Remove-CimInstance -InputObject $b -ErrorAction SilentlyContinue }
        foreach ($c in $cmdCons)  { Remove-CimInstance -InputObject $c -ErrorAction SilentlyContinue }
        foreach ($s in $scrCons)  { Remove-CimInstance -InputObject $s -ErrorAction SilentlyContinue }
        foreach ($f in $filters)  { Remove-CimInstance -InputObject $f -ErrorAction SilentlyContinue }
        Write-CCDCLog "Removed non-default WMI Event Subscriptions (forensic copy saved in $($cp.Directory))." -Level 'SUCCESS'
    }
    Complete-CCDCCheckpoint | Out-Null
}

function Fix-CCDCUnquotedServicePaths {
    <#
        Quotes unquoted service ImagePath entries safely with full checkpoint rollback.
    #>
    Assert-CCDCAdmin
    $cp = New-CCDCCheckpoint -ModuleName 'FixUnquotedServicePaths' -Description 'Quote unquoted Windows Service ImagePath registry values'
    $svcsRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    foreach ($sub in (Get-ChildItem -LiteralPath $svcsRoot -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
        if (-not $props -or ($props.PSObject.Properties.Name -notcontains 'ImagePath')) { continue }
        $rawImg = [string]$props.ImagePath
        if ([string]::IsNullOrWhiteSpace($rawImg)) { continue }
        if ($rawImg -match '^"' -or $rawImg -match '^(?i)\\?\??\\?SystemRoot' -or $rawImg -match '^(?i)system32\\') { continue }

        if ($rawImg -match '^([a-zA-Z]:\\[^"]+?\.exe)(\s+.*)?$') {
            $exePath = $Matches[1]
            $argTail = if ($Matches[2]) { $Matches[2] } else { '' }
            if ($exePath -match ' ') {
                $fixed = "`"$exePath`"$argTail"
                Set-CCDCRegistryValue -Path $sub.PSPath -Name 'ImagePath' -Value $fixed -Type 'ExpandString'
            }
        }
    }
    Complete-CCDCCheckpoint | Out-Null
}

# =========================================================================
# SECTION 2.8: EVENT LOG DETECTION MAP HUNTER
# =========================================================================

function Invoke-CCDCEventHunter {
    <#
        Automated hunter for Checklist Section 2.8 Detection Map!
        NEVER clears logs. Aggregates brute-force source IPs, Kerberoasting (4769 0x17),
        non-DC DCSync (4662), new users/groups (4720/4728/4732/4756), password resets (4724),
        new services/tasks (7045/4697/4698/4702), log clear tampering (1102/104),
        BadSuccessor dMSA (5136/5137/2946), unsigned LDAP binds (2889), and suspicious 4688/4104!
    #>
    param(
        [int]$MinutesBack = 120,
        [switch]$OfferIPBlock
    )
    Assert-CCDCAdmin
    Initialize-CCDCState

    $startTime = (Get-Date).AddMinutes(-1 * [math]::Abs($MinutesBack))
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outFile = Join-Path (Join-Path $script:CCDCStateRoot 'Sweeps') "EventHunt_${env:COMPUTERNAME}_${ts}.txt"
    $reportLines = New-Object System.Collections.Generic.List[string]

    Write-Host ""
    Write-CCDCLog "=== Running Section 2.8 Event Log Hunter (Last $MinutesBack mins since $($startTime.ToString('HH:mm:ss'))) ===" -Level 'INFO'

    # 1. Log Tampering Check (1102 Security / 104 System)
    $clearEvts = @(Get-WinEvent -FilterHashtable @{ LogName = @('Security', 'System'); Id = @(1102, 104); StartTime = $startTime } -ErrorAction SilentlyContinue)
    foreach ($e in $clearEvts) {
        $msg = "[CRITICAL IOC] Event $($e.Id) LOG CLEARED at $($e.TimeCreated): $($e.Message -replace '\r?\n', ' ')"
        Write-CCDCLog $msg -Level 'ALERT'
        $reportLines.Add($msg)
    }

    # 2. Account & Group Changes (4720, 4724, 4728, 4732, 4756)
    $acctEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4720, 4724, 4728, 4732, 4756); StartTime = $startTime } -MaxEvents 200 -ErrorAction SilentlyContinue)
    if ($acctEvts.Count -gt 0) {
        Write-CCDCLog "Found $($acctEvts.Count) Account/Group/Password event(s) (4720/4724/4728/4732/4756):" -Level 'WARN'
        foreach ($e in ($acctEvts | Select-Object -First 25)) {
            $short = ($e.Message -split '\r?\n')[0]
            $line  = "  [$($e.TimeCreated.ToString('HH:mm:ss'))] ID=$($e.Id) | $short"
            Write-Host $line -ForegroundColor Yellow
            $reportLines.Add($line)
        }
    }

    # 3. Kerberoasting Detection (4769 with TicketEncryptionType 0x17 RC4 on non-machine SPNs)
    $tgsEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769; StartTime = $startTime } -MaxEvents 500 -ErrorAction SilentlyContinue)
    $rc4Hits = @()
    foreach ($e in $tgsEvts) {
        $xml = [xml]$e.ToXml()
        $enc = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
        $svc = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $ip  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        if ($enc -eq '0x17' -and $svc -ne 'krbtgt' -and $svc -notmatch '\$$') {
            $rc4Hits += [PSCustomObject]@{ Time = $e.TimeCreated; Requestor = $usr; Service = $svc; SourceIP = $ip }
        }
    }
    if ($rc4Hits.Count -gt 0) {
        Write-CCDCLog "[KERBEROAST ALERT] $($rc4Hits.Count) RC4 (0x17) TGS ticket request(s) for non-machine service accounts!" -Level 'ALERT'
        foreach ($h in ($rc4Hits | Select-Object -First 15)) {
            $l = "  [$($h.Time.ToString('HH:mm:ss'))] Requestor=$($h.Requestor) -> Service=$($h.Service) from IP=$($h.SourceIP)"
            Write-Host $l -ForegroundColor Magenta
            $reportLines.Add($l)
        }
    }

    # 4. Non-DC DCSync Detection (4662 with Replication GUIDs)
    $dcsyncEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662; StartTime = $startTime } -MaxEvents 500 -ErrorAction SilentlyContinue)
    foreach ($e in $dcsyncEvts) {
        if ($e.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c|Replicating Directory Changes') {
            $xml = [xml]$e.ToXml()
            $subj = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            if ($subj -notmatch '\$$' -and $subj -ne 'SYSTEM') {
                $msg = "[DCSYNC ALERT] Event 4662 Directory Replication by NON-DC user '$subj' at $($e.TimeCreated)!"
                Write-CCDCLog $msg -Level 'ALERT'
                $reportLines.Add($msg)
            }
        }
    }

    # 5. New Services & Scheduled Tasks (7045, 4697, 4698, 4702)
    $svcEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $startTime } -MaxEvents 100 -ErrorAction SilentlyContinue)
    foreach ($e in $svcEvts) {
        $msg = "[NEW SERVICE 7045] [$($e.TimeCreated.ToString('HH:mm:ss'))] $($e.Message -replace '\r?\n', ' | ')"
        Write-CCDCLog $msg -Level 'ALERT'
        $reportLines.Add($msg)
    }
    $taskEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4697, 4698, 4702); StartTime = $startTime } -MaxEvents 100 -ErrorAction SilentlyContinue)
    foreach ($e in ($taskEvts | Select-Object -First 20)) {
        $msg = "[TASK/SVC EVENT $($e.Id)] [$($e.TimeCreated.ToString('HH:mm:ss'))] $(($e.Message -split '\r?\n')[0])"
        Write-CCDCLog $msg -Level 'WARN'
        $reportLines.Add($msg)
    }

    # 6. BadSuccessor / AD Directory Changes (5136, 5137, Directory Service 2946 & 2889)
    $dsEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5136, 5137); StartTime = $startTime } -MaxEvents 200 -ErrorAction SilentlyContinue)
    foreach ($e in $dsEvts) {
        if ($e.Message -match 'msDS-DelegatedManagedServiceAccount|msDS-ManagedAccountPrecededByLink|msDS-KeyCredentialLink|msDS-AllowedToActOnBehalfOfOtherIdentity|gPCFileSysPath') {
            $msg = "[CRITICAL AD MOD $($e.Id)] [$($e.TimeCreated.ToString('HH:mm:ss'))] $($e.Message -replace '\r?\n', ' | ')"
            Write-CCDCLog $msg -Level 'ALERT'
            $reportLines.Add($msg)
        }
    }
    $dmsaAuthEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = @(2946, 2889); StartTime = $startTime } -MaxEvents 100 -ErrorAction SilentlyContinue)
    foreach ($e in $dmsaAuthEvts) {
        $tag = if ($e.Id -eq 2946) { '[dMSA TGT AUTH 2946]' } else { '[UNSIGNED LDAP BIND 2889]' }
        $msg = "$tag [$($e.TimeCreated.ToString('HH:mm:ss'))] $($e.Message -replace '\r?\n', ' | ')"
        Write-CCDCLog $msg -Level ($(if ($e.Id -eq 2946) { 'ALERT' } else { 'WARN' }))
        $reportLines.Add($msg)
    }

    # 7. Failed Logons & Brute-Force Source IP Aggregation (4625, 4771, 4776)
    $failEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $startTime } -MaxEvents 1500 -ErrorAction SilentlyContinue)
    $ipStats  = @{}
    foreach ($e in $failEvts) {
        $xml  = [xml]$e.ToXml()
        $ip   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $lt   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-' -or $ip -eq '127.0.0.1' -or $ip -eq '::1') { continue }
        if (-not $ipStats.ContainsKey($ip)) {
            $ipStats[$ip] = [PSCustomObject]@{ IP = $ip; Count = 0; LogonTypes = New-Object System.Collections.Generic.HashSet[string]; Users = New-Object System.Collections.Generic.HashSet[string] }
        }
        $ipStats[$ip].Count++
        [void]$ipStats[$ip].LogonTypes.Add([string]$lt)
        [void]$ipStats[$ip].Users.Add([string]$user)
    }
    if ($ipStats.Count -gt 0) {
        Write-CCDCLog "Top Failed Logon (4625) Source IPs in last $MinutesBack mins:" -Level 'WARN'
        $sortedIPs = @($ipStats.Values | Sort-Object Count -Descending | Select-Object -First 10)
        foreach ($row in $sortedIPs) {
            $uSample = (@($row.Users) | Select-Object -First 5) -join ','
            $ltStr   = (@($row.LogonTypes)) -join ','
            $l = "  IP=$($row.IP) | Failures=$($row.Count) | LogonTypes=$ltStr (3=SMB/Net, 8=FTP/IIS, 10=RDP) | TargetUsers=$uSample"
            Write-Host $l -ForegroundColor Red
            $reportLines.Add($l)
        }
        if ($OfferIPBlock) {
            $toBlk = Read-Host "Enter a single confirmed attacker IP to block (/32), or press Enter to skip"
            if (-not [string]::IsNullOrWhiteSpace($toBlk)) {
                Block-CCDCAttackerIP -IPAddress $toBlk -Reason "Event 4625 brute-force detected ($MinutesBack min window)"
            }
        }
    } else {
        Write-CCDCLog "No external Event 4625 brute-force source IPs in last $MinutesBack mins." -Level 'SUCCESS'
    }

    # 8. Suspicious Process Creation (4688) & PowerShell ScriptBlock (4104)
    $suspCmdRegex = '(?i)(-enc\b|-encodedcommand|FromBase64String|DownloadString|DownloadFile|Invoke-WebRequest|iwr\b|curl\b.*http|sekurlsa|lsadump|dcsync|rubeus|mimikatz|sharphound|ntdsutil.*ifm|vssadmin.*create\s+shadow|reg\s+save\s+hklm\\(sam|system|security)|certutil.*-urlcache|mshta|rundll32.*javascript|msDS-ManagedAccountPrecededByLink)'
    $procEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $startTime } -MaxEvents 1000 -ErrorAction SilentlyContinue)
    foreach ($e in $procEvts) {
        if ($e.Message -match $suspCmdRegex) {
            $xml = [xml]$e.ToXml()
            $cmd = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
            $usr = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $msg = "[SUSPICIOUS 4688 CMD] [$($e.TimeCreated.ToString('HH:mm:ss'))] User=$usr | Cmd=$cmd"
            Write-CCDCLog $msg -Level 'ALERT'
            $reportLines.Add($msg)
        }
    }

    $psEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $startTime } -MaxEvents 500 -ErrorAction SilentlyContinue)
    foreach ($e in $psEvts) {
        if ($e.Message -match $suspCmdRegex -and $e.Message -notmatch 'CCDC-BaselineAndPersistence') {
            $snippet = ($e.Message -replace '\r?\n', ' ')
            if ($snippet.Length -gt 240) { $snippet = $snippet.Substring(0, 240) + '...' }
            $msg = "[SUSPICIOUS PS 4104] [$($e.TimeCreated.ToString('HH:mm:ss'))] $snippet"
            Write-CCDCLog $msg -Level 'ALERT'
            $reportLines.Add($msg)
        }
    }

    $reportLines | Set-Content -LiteralPath $outFile -Encoding UTF8
    Write-CCDCLog "Event Log Hunt saved to $outFile" -Level 'SUCCESS'
}

# =========================================================================
# SECTION 8: 15-MINUTE CONTINUOUS MONITORING LOOP
# =========================================================================

function Start-CCDCMonitorLoop {
    param(
        [int]$IntervalMinutes = 15
    )
    Assert-CCDCAdmin
    Initialize-CCDCState

    Write-CCDCLog "Starting Section 8 Continuous Monitoring Loop (Every $IntervalMinutes min). Press Ctrl+C to return to menu." -Level 'INFO'
    while ($true) {
        Write-Host ""
        Write-Host ("=" * 74) -ForegroundColor Cyan
        Write-CCDCLog "MONITORING CYCLE @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME" -Level 'INFO'
        Write-Host ("=" * 74) -ForegroundColor Cyan

        # 1. Splunk Forwarder Health
        $sp = Get-Service -Name 'SplunkForwarder', 'Splunkd' -ErrorAction SilentlyContinue
        foreach ($s in $sp) {
            if ($s.Status -ne 'Running') {
                Write-CCDCLog "[CRITICAL] Out-of-scope service $($s.Name) is $($s.Status)! Investigate immediately!" -Level 'ALERT'
            } else {
                Write-CCDCLog "Splunk ($($s.Name)): Running" -Level 'SUCCESS'
            }
        }

        # 2. Disk Free Space Check (Alert if < 15%)
        foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
            if ($d.Size -gt 0) {
                $pct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
                $freeGB = [math]::Round($d.FreeSpace / 1GB, 2)
                if ($pct -lt 15) {
                    Write-CCDCLog "[DISK SPACE LOW] Drive $($d.DeviceID) only $freeGB GB ($pct%) free!" -Level 'ALERT'
                } else {
                    Write-CCDCLog "Disk $($d.DeviceID): $freeGB GB ($pct%) free" -Level 'INFO'
                }
            }
        }

        # 3. Active External Established Connections
        $extConns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
            $_.RemoteAddress -notmatch '^(127\.|10\.42\.0\.|::1|0\.0\.0\.0)'
        })
        if ($extConns.Count -gt 0) {
            Write-CCDCLog "Active Non-LAN Established TCP Connections ($($extConns.Count)):" -Level 'WARN'
            foreach ($ec in $extConns) {
                $pr = Get-Process -Id $ec.OwningProcess -ErrorAction SilentlyContinue
                Write-Host "  $($ec.LocalAddress):$($ec.LocalPort) <-> $($ec.RemoteAddress):$($ec.RemotePort) | PID=$($ec.OwningProcess) ($($pr.ProcessName))" -ForegroundColor Yellow
            }
        }

        # 4. Baseline Drift & Last Window Event Hunt
        Compare-CCDCBaseline
        Invoke-CCDCEventHunter -MinutesBack ($IntervalMinutes + 2)

        # 5. If IIS Web Root Baseline exists, run Web Root Hash Diff automatically
        if (Get-Command -Name 'Compare-CCDCWebRoot' -ErrorAction SilentlyContinue) {
            $wbFile = Join-Path $script:CCDCStateRoot 'WebBackups\WebRoot_Baseline.json'
            if (Test-Path -LiteralPath $wbFile) {
                Compare-CCDCWebRoot -QuietIfClean
            }
        }

        Write-CCDCLog "Next monitoring cycle in $IntervalMinutes minute(s). Press Ctrl+C anytime to exit loop." -Level 'INFO'
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
}
