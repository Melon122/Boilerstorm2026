#Requires -Version 5.1
<#
.SYNOPSIS
    CCDC / BoilerStorm 2026 Asset & Tech-Stack Onboarding Exporter, Deterministic Incident Evidence Bundler,
    and BoilerStorm Incident Report & Inject Memo Skeleton Generators (ClosedAI).
#>

if (-not (Get-Command -Name 'Write-CCDCLog' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'CCDC-StateEngine.ps1')
}
if (-not (Get-Command -Name 'Invoke-CCDCEventHunter' -ErrorAction SilentlyContinue)) {
    $bpPath = Join-Path $PSScriptRoot 'CCDC-BaselineAndPersistence.ps1'
    if (Test-Path -LiteralPath $bpPath) { . $bpPath }
}

function Export-CCDCOnboardingInventory {
    param([string]$OutputDir = '')
    Assert-CCDCAdmin
    Initialize-CCDCState
    if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = Join-Path $script:CCDCStateRoot 'Evidence' }
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

    $ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
    $nowStr  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    $role    = Get-CCDCHostRole
    $mdPath  = Join-Path $OutputDir "TechStack_Inventory_${env:COMPUTERNAME}_${ts}.md"
    $txtPath = Join-Path $OutputDir "TechStack_Inventory_${env:COMPUTERNAME}_${ts}.txt"
    Write-CCDCLog "Generating Onboarding Tech Stack & Asset Inventory for $($env:COMPUTERNAME)..." -Level 'INFO'

    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)" })
    $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" })
    $ntpRaw = @(& w32tm.exe /query /status 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })

    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {
        $sz = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
        $free = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }
        $pct = if ($_.Size) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
        "| $($_.DeviceID) | $($_.VolumeName) | $sz GB | $free GB | $pct% |"
    })

    $rolesInstalled = @()
    if (Get-Command -Name 'Get-WindowsFeature' -ErrorAction SilentlyContinue) {
        try { $rolesInstalled = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed } | ForEach-Object { "- ``$($_.Name)`` ($($_.DisplayName))" }) } catch {}
    }

    $runningSvcs = @(Get-CimInstance -ClassName Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue | Sort-Object Name |
        ForEach-Object { "| ``$($_.Name)`` | $($_.DisplayName) | ``$($_.StartName)`` | ``$($_.PathName)`` |" })

    $procMap = @{}
    foreach ($p in (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) { $procMap[[int]$p.ProcessId] = $p }
    $listenRows = @()
    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique)) {
        $pr = $procMap[[int]$c.OwningProcess]
        $exe = if ($pr -and $pr.ExecutablePath) { $pr.ExecutablePath } elseif ($pr) { $pr.Name } else { 'System/Kernel' }
        $listenRows += "| TCP | $($c.LocalAddress):$($c.LocalPort) | $($c.OwningProcess) | ``$exe`` |"
    }
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -lt 49152 } | Sort-Object LocalPort -Unique)) {
        $pr = $procMap[[int]$u.OwningProcess]
        $exe = if ($pr -and $pr.ExecutablePath) { $pr.ExecutablePath } elseif ($pr) { $pr.Name } else { 'System/Kernel' }
        $listenRows += "| UDP | $($u.LocalAddress):$($u.LocalPort) | $($u.OwningProcess) | ``$exe`` |"
    }

    $shareRows = @(Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
        $acc = @(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName)($($_.AccessControlType):$($_.AccessRight))" }) -join '; '
        "| ``$($_.Name)`` | ``$($_.Path)`` | $($_.Description) | $acc |"
    })

    $iisSection = @()
    if ($role.HasIIS) {
        $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
        if (Test-Path -LiteralPath $appcmd) {
            $iisSection += "## IIS Web Sites, App Pools & Virtual Directories"
            $iisSection += "### Sites"; $iisSection += (@(& $appcmd list site 2>$null) | ForEach-Object { "- ``$_``" })
            $iisSection += "### Application Pools"; $iisSection += (@(& $appcmd list apppool 2>$null) | ForEach-Object { "- ``$_``" })
            $iisSection += "### Virtual Directories"; $iisSection += (@(& $appcmd list vdir 2>$null) | ForEach-Object { "- ``$_``" })
        }
    }

    $adSection = @()
    if ($role.IsDC -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $dom    = Get-ADDomain -ErrorAction Stop
            $dcs    = @(Get-ADDomainController -Filter * -ErrorAction SilentlyContinue)
            $ouCnt  = @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue).Count
            $usrAll = @(Get-ADUser -Filter * -Properties Enabled -ErrorAction SilentlyContinue)
            $usrEn  = @($usrAll | Where-Object { $_.Enabled }).Count
            $cmpCnt = @(Get-ADComputer -Filter * -ErrorAction SilentlyContinue).Count
            $gpoCnt = if (Get-Command -Name 'Get-GPO' -ErrorAction SilentlyContinue) { @(Get-GPO -All -ErrorAction SilentlyContinue).Count } else { 'N/A' }
            $adSection += "## Active Directory Domain Summary"
            $adSection += "- **Domain FQDN / NetBIOS / Mode**: ``$($dom.DNSRoot)`` / ``$($dom.NetBIOSName)`` (``$($dom.DomainMode)``)"
            $adSection += "- **Domain Controllers ($($dcs.Count))**: $(($dcs | ForEach-Object { "$($_.HostName) ($($_.IPv4Address))" }) -join ', ')"
            $adSection += "- **Counts**: OUs=$ouCnt | Users=$($usrAll.Count) ($usrEn enabled) | Computers=$cmpCnt | GPOs=$gpoCnt"
        } catch {
            $adSection += "## Active Directory Domain Summary`r`n- Warning querying AD: $($_.Exception.Message)"
        }
    }

    $lines = @(
        "# ClosedAI Host Tech Stack & Onboarding Asset Inventory: $($role.ComputerName)"
        "- **Generated**: $nowStr"
        "- **Organization**: $($script:CCDCConfig.Competition.Organization) ($($script:CCDCConfig.Competition.DomainFQDN))"
        "- **Hostname / Domain**: ``$($role.ComputerName)`` / ``$($role.Domain)``"
        "- **Detected Role**: DC=$($role.IsDC) | IIS=$($role.HasIIS) | Server2025=$($role.IsServer2025)"
        "- **OS / Version / Build**: $($role.OSCaption) | $($role.OSVersion) (Build $($role.BuildNumber))"
        "- **IPv4 Addresses**: $(if ($ips.Count) { $ips -join ' ; ' } else { 'None' })"
        "- **DNS Client Resolvers**: $(if ($dnsServers.Count) { $dnsServers -join ' ; ' } else { 'None' })"
        ""
        "## NTP / Time Sync Status (``w32tm /query /status``)"
        '```text'
        ($ntpRaw -join "`r`n")
        '```'
        ""
        "## Logical Disk Free Space"
        "| Drive | Label | Total Size | Free Space | Free % |"
        "|---|---|---|---|---|"
        ($disks -join "`r`n")
        ""
        "## Installed Windows Server Roles & Features ($($rolesInstalled.Count))"
        $(if ($rolesInstalled.Count -gt 0) { ($rolesInstalled | Select-Object -First 60) -join "`r`n" } else { "- (Feature query unavailable or none detected)" })
        ""
        "## Listening Network Ports Mapped to Binaries"
        "| Proto | Local Endpoint | PID | Executable / Process |"
        "|---|---|---|---|"
        ($listenRows -join "`r`n")
        ""
        "## SMB Shares & Permissions"
        "| Share Name | Path | Description | Access Rights |"
        "|---|---|---|---|"
        ($shareRows -join "`r`n")
    )
    if ($iisSection.Count -gt 0) { $lines += ""; $lines += $iisSection }
    if ($adSection.Count -gt 0)  { $lines += ""; $lines += $adSection }
    $lines += @(
        ""
        "## Running Windows Services ($($runningSvcs.Count))"
        "| Service Name | Display Name | RunAs Account | Binary Path |"
        "|---|---|---|---|"
        ($runningSvcs -join "`r`n")
    )

    $content = $lines -join "`r`n"
    $content | Set-Content -LiteralPath $mdPath -Encoding UTF8
    $content | Set-Content -LiteralPath $txtPath -Encoding UTF8

    Add-CCDCChangeLogEntry -Module 'OnboardingInventory' -Summary "Exported tech stack & asset inventory -> $mdPath" -ActionType 'AUDIT'
    Write-CCDCLog "Saved Onboarding Tech-Stack Inventory -> $mdPath (and .txt)" -Level 'SUCCESS'
    return $mdPath
}

function New-CCDCIncidentEvidenceBundle {
    <#
        Deterministic forensic bundler + BoilerStorm Incident Report skeleton generator.
        Preserves suspect artifact in place for Legal Hold (NEVER deletes/moves original artifact!).
    #>
    param(
        [int]$IncidentNumber = 0,
        [string]$Title = '',
        [string]$AttackerIP = '',
        [string]$CompromisedAccount = '',
        [int]$LookbackMinutes = 60,
        [string]$SuspectFilePath = '',
        [int]$TeamNumber = 0
    )
    Assert-CCDCAdmin
    Initialize-CCDCState

    if ($IncidentNumber -le 0) {
        $inRaw = Read-Host "Incident Number (e.g. 1)"
        $IncidentNumber = if ($inRaw -match '^\d+$') { [int]$inRaw } else { 1 }
    }
    if ([string]::IsNullOrWhiteSpace($Title)) {
        $Title = Read-Host "Short Incident Title (e.g. Unauthorized Webshell & Credential Abuse on $env:COMPUTERNAME)"
        if ([string]::IsNullOrWhiteSpace($Title)) { $Title = "Security Incident #$IncidentNumber on $env:COMPUTERNAME" }
    }
    if ([string]::IsNullOrWhiteSpace($AttackerIP)) {
        $AttackerIP = (Read-Host "Observed Attacker Source IP (or press Enter if unknown)").Trim()
    }
    if ([string]::IsNullOrWhiteSpace($CompromisedAccount)) {
        $CompromisedAccount = (Read-Host "Affected / Compromised Account (or press Enter if unknown)").Trim()
    }
    if ([string]::IsNullOrWhiteSpace($SuspectFilePath)) {
        $SuspectFilePath = (Read-Host "Optional Suspect Artifact File Path for SHA256/Metadata (preserved in place! Enter to skip)").Trim()
    }
    $teamStr = if ($TeamNumber -gt 0) { "Team $TeamNumber" } else { "Team <N>" }

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $bundleDir = Join-Path (Join-Path $script:CCDCStateRoot 'Evidence') "IR_${IncidentNumber}_${ts}"
    New-Item -Path $bundleDir -ItemType Directory -Force | Out-Null

    Write-CCDCLog "Collecting deterministic IR #$IncidentNumber forensic evidence into $bundleDir ..." -Level 'INFO'

    # 1. Live TCP connections + matching processes
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)
    $procMap = @{}
    foreach ($p in $procs) { $procMap[[int]$p.ProcessId] = $p }
    $procs | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
        Export-Csv -LiteralPath (Join-Path $bundleDir 'LiveProcesses.csv') -NoTypeInformation -Encoding UTF8

    $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        $pr = $procMap[[int]$_.OwningProcess]
        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = [string]$_.State
            OwningPID     = $_.OwningProcess
            ProcessName   = if ($pr) { $pr.Name } else { '' }
            Executable    = if ($pr) { $pr.ExecutablePath } else { '' }
            CommandLine   = if ($pr) { $pr.CommandLine } else { '' }
        }
    })
    $conns | Export-Csv -LiteralPath (Join-Path $bundleDir 'LiveTCPConnections.csv') -NoTypeInformation -Encoding UTF8

    if (-not [string]::IsNullOrWhiteSpace($AttackerIP)) {
        @($conns | Where-Object { $_.RemoteAddress -eq $AttackerIP }) |
            Export-Csv -LiteralPath (Join-Path $bundleDir 'AttackerIP_MatchingConnections.csv') -NoTypeInformation -Encoding UTF8
    }

    # 2. Recent Event Log Threat Hunter capture
    if (Get-Command -Name 'Invoke-CCDCEventHunter' -ErrorAction SilentlyContinue) {
        Invoke-CCDCEventHunter -MinutesBack $LookbackMinutes
        $latestHunt = Get-ChildItem -LiteralPath (Join-Path $script:CCDCStateRoot 'Sweeps') -Filter "EventHunt_${env:COMPUTERNAME}_*.txt" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestHunt) {
            Copy-Item -LiteralPath $latestHunt.FullName -Destination (Join-Path $bundleDir 'EventHunter_Hits.txt') -Force
        }
    }

    # 3. Copy BlockedIPs.csv and ChangeLog.csv snapshots
    if (Test-Path -LiteralPath $script:CCDCBlockedIPsCsv) {
        Copy-Item -LiteralPath $script:CCDCBlockedIPsCsv -Destination (Join-Path $bundleDir 'BlockedIPs_Snapshot.csv') -Force
    }
    if (Test-Path -LiteralPath $script:CCDCChangeLogPath) {
        Copy-Item -LiteralPath $script:CCDCChangeLogPath -Destination (Join-Path $bundleDir 'ChangeLog_Snapshot.csv') -Force
    }

    # 4. Optional Suspect Artifact SHA256 + Metadata (PRESERVE ORIGINAL IN PLACE FOR LEGAL HOLD!)
    $artifactNotes = "None specified during bundle creation."
    if (-not [string]::IsNullOrWhiteSpace($SuspectFilePath)) {
        if (Test-Path -LiteralPath $SuspectFilePath -PathType Leaf) {
            $fi   = Get-Item -LiteralPath $SuspectFilePath -Force
            $hash = (Get-FileHash -LiteralPath $SuspectFilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $sig  = Get-AuthenticodeSignature -FilePath $SuspectFilePath -ErrorAction SilentlyContinue
            $acl  = Get-Acl -LiteralPath $SuspectFilePath -ErrorAction SilentlyContinue
            $meta = [PSCustomObject]@{
                OriginalPath      = $fi.FullName
                LegalHoldPreserved = $true
                SHA256            = $hash
                SizeBytes         = $fi.Length
                CreationTimeUtc   = $fi.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss UTC')
                LastWriteTimeUtc  = $fi.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss UTC')
                LastAccessTimeUtc = $fi.LastAccessTimeUtc.ToString('yyyy-MM-dd HH:mm:ss UTC')
                Owner             = if ($acl) { $acl.Owner } else { '' }
                SignatureStatus   = if ($sig) { [string]$sig.Status } else { 'Unknown' }
                SignerSubject     = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'Unsigned' }
            }
            $meta | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $bundleDir 'SuspectArtifact_Metadata.json') -Encoding UTF8
            $artifactNotes = "Path: ``$($fi.FullName)`` | SHA256: ``$hash`` | Size: $($fi.Length) bytes | MTime(UTC): $($meta.LastWriteTimeUtc) | Owner: $($meta.Owner) | Legal Hold: Original file preserved in place."
            Write-CCDCLog "Recorded SHA256 ($hash) & MACB metadata for $SuspectFilePath (original untouched in place for Legal Hold)." -Level 'SUCCESS'
        } else {
            $artifactNotes = "Specified path not found as file: ``$SuspectFilePath``"
            Write-CCDCLog "Suspect file not found: $SuspectFilePath" -Level 'WARN'
        }
    }

    # 5. Deterministic BoilerStorm Incident Report Skeleton (Zero AI Prose)
    $role     = Get-CCDCHostRole
    $localIPs = (@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IPAddress) -join ', ')
    $detectTs = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    $srcIpVal = if ($AttackerIP) { "``$AttackerIP``" } else { "``[FILL REQUIRED: Attacker Source IP(s)]``" }
    $acctVal  = if ($CompromisedAccount) { "``$CompromisedAccount``" } else { "``[FILL REQUIRED: Compromised Account(s) or None]``" }
    $skelPath = Join-Path $bundleDir 'IncidentReport_Skeleton.md'

    @(
        "# INCIDENT REPORT #$IncidentNumber — $Title"
        ""
        "**To:** Tomas Whelan, Director of IT and Security, ClosedAI"
        "**From:** $teamStr (Blue Team Incident Response)"
        "**Date:** November 15, 2026"
        "**Subject:** Incident #$IncidentNumber — $Title on ``$($role.ComputerName)``"
        ""
        "> **CRITICAL REMINDER:** NEVER leave any timestamp or table cell blank! Use exact ``YYYY-MM-DD HH:MM:SS TZ`` timestamps verified from logs/screenshots."
        ""
        "## Incident Metadata Table (REQUIRED — DO NOT LEAVE ANY CELL BLANK)"
        "| Field | Value |"
        "|---|---|"
        "| **1. Incident ID & Title** | IR-$IncidentNumber — $Title |"
        "| **2. Affected Host(s) & IP(s)** | ``$($role.ComputerName)`` (``$localIPs``) — $($role.OSCaption) |"
        "| **3. Affected Service(s) / Account(s)** | Service: ``[FILL: e.g. IIS HTTP/80, AD LDAP, SMB, RDP]`` / Account(s): $acctVal |"
        "| **4. Attacker Source IP(s) / Indicators** | $srcIpVal |"
        "| **5. Incident Start Timestamp (First Activity)** | ``[FILL REQUIRED — NEVER BLANK: YYYY-MM-DD HH:MM:SS EST from earliest log entry]`` |"
        "| **6. Detection Timestamp** | ``$detectTs`` ``[VERIFY exact first alert timestamp]`` |"
        "| **7. Containment / Mitigation Timestamp** | ``[FILL REQUIRED — NEVER BLANK: YYYY-MM-DD HH:MM:SS EST when contained]`` |"
        "| **8. Current Status & Severity** | ``[FILL: Contained & Remediated / Monitoring]`` — Severity: ``[FILL: Critical / High / Medium]`` |"
        ""
        "---"
        ""
        "## 1. Executive Summary & Business Impact (10%)"
        "- **What Happened (1-2 factual sentences):** ``[FILL: On November 15, 2026 at HH:MM EST, unauthorized activity was identified on $($role.ComputerName)...]``"
        "- **Business / Operational Impact to ClosedAI:** ``[FILL: Quantify uptime/confidentiality/integrity impact on scored service(s) and confirm service restoration status.]``"
        "- **Legal Hold Compliance:** Original logs and forensic artifacts were preserved in place without deletion or log clearing."
        ""
        "## 2. Root Cause & Initial Access Vector (10%)"
        "- **Entry Vector / Vulnerability Exploited:** ``[FILL: Exact weak/default credential, misconfiguration, web vuln, or exposed service exploited]``"
        "- **Initial Access Account / Privilege Level:** $acctVal"
        "- **Supporting Log / Config Proof:** ``[FILL: Cite exact Event ID (e.g., 4624/4625/4688/7045/IIS W3SVC log line) + timestamp]``"
        ""
        "## 3. Attack Timeline & Technical Evidence (10%)"
        "| Timestamp (EST) | Host | Source -> Target | Event ID / Log Source | Technical Action Observed |"
        "|---|---|---|---|---|"
        "| ``[YYYY-MM-DD HH:MM:SS]`` | ``$($role.ComputerName)`` | $srcIpVal -> ``$localIPs`` | ``[Event ID / Log]`` | ``[Initial access / auth event]`` |"
        "| ``[YYYY-MM-DD HH:MM:SS]`` | ``$($role.ComputerName)`` | ``[Process / User]`` | ``[Event 4688 / 4104 / 7045]`` | ``[Execution / persistence / lateral movement]`` |"
        "| ``$detectTs`` | ``$($role.ComputerName)`` | Blue Team | ``Evidence\IR_${IncidentNumber}_${ts}`` | Evidence bundle captured (``LiveTCPConnections.csv``, ``LiveProcesses.csv``, ``EventHunter_Hits.txt``) |"
        "| ``[YYYY-MM-DD HH:MM:SS]`` | ``$($role.ComputerName)`` | Blue Team | ``ChangeLog.csv`` | ``[Containment & remediation applied; verified Quotient green]`` |"
        ""
        "- **Artifact Forensic Metadata:** $artifactNotes"
        "- **Screenshots Attached:** ``[FILL: Insert captioned screenshots showing timestamp, hostname, raw log event, and attacker indicator]``"
        ""
        "## 4. Scope of Compromise & Persistence Analysis (10%)"
        "- **Hosts Inspected Across ``10.42.0.0/24``:** ``[FILL: Confirm check across CAI-DC01 (.10), CAI-WEB01 (.20), cai-db01 (.30), cai-mail01 (.40), cai-fw01 (.1)]``"
        "- **Accounts / Groups Audited:** $acctVal ``[FILL: Confirm Tier-0 AD groups, local Administrators, and Quotient PCR usage if scored user]``"
        "- **Persistence Mechanisms Found & Neutralized:** ``[FILL: Services, Scheduled Tasks, Run keys, WMI subscriptions, webshells, SSH keys — or state none found after 22-vector sweep]``"
        "- **Data Exfiltration / Tampering Assessment:** ``[FILL: State what sensitive data/DB/mail/AD data was or was not accessed]``"
        ""
        "## 5. Containment & Eradication Actions Taken (10%)"
        "- **Immediate Containment:** ``[FILL: e.g., Blocked single host IP /32 via Block-CCDCAttackerIP (no subnet blocks), terminated rogue PID, disabled backdoor task/service while preserving binary in place for Legal Hold]``"
        "- **Credential Remediation:** ``[FILL: Rotated affected unscored credentials / submitted PCR in Quotient if scored user; cleared stale sessions]``"
        "- **Service Verification:** ``[FILL: Confirmed scored protocols remain operational in Quotient over 2+ check cycles]``"
        ""
        "## 6. Recovery, Hardening & Preventative Remediation Proof (50% — HIGHEST WEIGHT!)"
        "> **NOTE (50% OF POINTS):** Provide concrete before/after proof and screenshots proving the underlying weakness cannot be re-exploited!"
        ""
        "1. **Vulnerability Fix / Configuration Hardening Applied:**"
        "   - **Before State:** ``[FILL: Exact vulnerable setting/ACL/credential/rule prior to fix]``"
        "   - **After State:** ``[FILL: Exact hardened registry/GPO/IIS/firewall/AD setting applied + Checkpoint ID from ChangeLog.csv]``"
        "   - **Verification Proof (Screenshot / Command Output):** ``[INSERT FIGURE: Screenshot proving fix active + service still passing checks]``"
        "2. **Detection & Monitoring Controls Deployed:**"
        "   - **Audit / Logging Coverage:** ``[FILL: Section 2.7 Advanced Audit Policy + PowerShell 4104 + 1GB Event Logs + SplunkForwarder verified RUNNING]``"
        "   - **Ongoing Alerting:** ``[FILL: 15-minute CCDC monitor loop / webroot hash diff / firewall drop logging active]``"
        "3. **Enterprise-Wide Rollout Across ClosedAI:**"
        "   - ``[FILL: Detail equivalent hardening applied across remaining Windows & Linux hosts so attacker cannot pivot to sibling systems]``"
    ) | Set-Content -LiteralPath $skelPath -Encoding UTF8

    Add-CCDCChangeLogEntry -Module 'IncidentBundle' -Summary "Created IR #$IncidentNumber bundle & report skeleton -> $bundleDir" -ActionType 'AUDIT'
    Write-CCDCLog "Incident Evidence Bundle & Report Skeleton ready at: $bundleDir" -Level 'SUCCESS'
    return $bundleDir
}

function New-CCDCInjectMemoSkeleton {
    param(
        [string]$InjectNumber = '',
        [string]$Subject = '',
        [int]$TeamNumber = 0
    )
    Assert-CCDCAdmin
    Initialize-CCDCState
    if ([string]::IsNullOrWhiteSpace($InjectNumber)) {
        $InjectNumber = (Read-Host "Inject ID / Number (e.g. INJ-01)").Trim()
        if ([string]::IsNullOrWhiteSpace($InjectNumber)) { $InjectNumber = 'INJ-XX' }
    }
    if ([string]::IsNullOrWhiteSpace($Subject)) {
        $Subject = (Read-Host "Inject Subject / Deliverable Title").Trim()
        if ([string]::IsNullOrWhiteSpace($Subject)) { $Subject = 'Security & Operations Deliverable' }
    }
    $teamStr = if ($TeamNumber -gt 0) { "Team $TeamNumber" } else { "Team <N>" }
    $ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeInj = ($InjectNumber -replace '[^a-zA-Z0-9_-]', '_')
    $outPath = Join-Path (Join-Path $script:CCDCStateRoot 'Evidence') "InjectMemo_${safeInj}_${ts}.md"

    @(
        "# MEMORANDUM"
        ""
        "**To:** Tomas Whelan, Director of IT and Security, ClosedAI"
        "**From:** $teamStr (IT Operations & Security Engineering)"
        "**Date:** November 15, 2026"
        "**Subject:** [$InjectNumber] $Subject"
        ""
        "---"
        "## Executive Bottom Line"
        "- **Summary Decision / Outcome:** ``[FILL: 2-3 crisp factual sentences answering the prompt upfront—what was completed, verified, and delivered for ClosedAI.]``"
        "- **Operational Risk & Uptime Status:** ``[FILL: Confirm zero disruption to scored production services across closedai.com (10.42.0.0/24).]``"
        ""
        "## Numbered Prompt Tasks & Deliverables"
        "### Task 1: ``[FILL: Exact Sub-Requirement #1 Copied from Inject Prompt]``"
        "- **Action & Verification:** ``[FILL: Concrete steps, hostnames/IPs/accounts, and command/UI verification]`` (See **Figure 1**)"
        ""
        "### Task 2: ``[FILL: Exact Sub-Requirement #2 Copied from Inject Prompt]``"
        "- **Action & Verification:** ``[FILL: Concrete steps, hostnames/IPs/accounts, and command/UI verification]`` (See **Figure 2**)"
        ""
        "### Task 3: ``[FILL: Exact Sub-Requirement #3 Copied from Inject Prompt (match prompt 1-to-1)]``"
        "- **Action & Verification:** ``[FILL]``"
        ""
        "## Figure Placeholders (Captioned Verification Screenshots)"
        "- **Figure 1:** ``[INSERT SCREENSHOT — Hostname + Timestamp visible: Proof for Task 1]``"
        "- **Figure 2:** ``[INSERT SCREENSHOT — Hostname + Timestamp visible: Proof for Task 2]``"
        ""
        "## Recommended Security & Operational Controls Roadmap"
        "- **Immediate Controls (0–4 Hours, Deployed Today):** ``[FILL: Controls implemented across CAI-DC01 / CAI-WEB01 / cai-db01 / cai-mail01 / cai-fw01]``"
        "- **Short-Term Controls (1–14 Days):** ``[FILL: Patch validation, SIEM alert tuning, least-privilege review]``"
        "- **Medium-Term Controls (30–90 Days):** ``[FILL: Micro-segmentation, MFA/PKI rollout, DR failover exercises]``"
        ""
        "## Additional Files & Sources"
        "- **Additional Files:** ``[FILL: Attached inventories/configs or 'None (self-contained PDF)']``"
        "- **Sources:** Internal ClosedAI Host Telemetry (``C:\CCDC_State\``, November 15, 2026); ``[FILL IF CITED: NIST SP 800-61r2 / NIST CSF 2.0 / CIS Benchmarks]``"
    ) | Set-Content -LiteralPath $outPath -Encoding UTF8

    Add-CCDCChangeLogEntry -Module 'InjectSkeleton' -Summary "Generated Inject Memo skeleton [$InjectNumber] -> $outPath" -ActionType 'AUDIT'
    Write-CCDCLog "Inject Memo Skeleton created at: $outPath" -Level 'SUCCESS'
    return $outPath
}
