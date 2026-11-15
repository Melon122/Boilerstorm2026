#Requires -Version 5.1
<#
.SYNOPSIS
    CCDC / BoilerStorm 2026 Windows Host, Auditing, Defender, Firewall, and IIS (CAI-WEB01) Hardening.
.DESCRIPTION
    Covers Checklist Section 2.7 (Auditing), Section 3 (CAI-WEB01 IIS / ClosedChat / FTP), and the
    universal Windows local sweep. Every change goes through a CCDC-StateEngine checkpoint so it can
    be undone from the Rollback menu.
    Legal Hold: accounts are disabled, never deleted. Event logs are resized, never cleared.
    SplunkForwarder and the competition CA are never touched.
#>

if (-not (Get-Command -Name 'Write-CCDCLog' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'CCDC-StateEngine.ps1')
}

# =========================================================================
# SHARED HELPERS
# =========================================================================

function Get-CCDCListenerMap {
    <#
        Returns one object per non-loopback listening TCP port / bound UDP port with owning PID,
        process name, and every service hosted in that PID (svchost-aware).
    #>
    $svcByPid = @{}
    foreach ($s in (Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 0 })) {
        $key = [int]$s.ProcessId
        if (-not $svcByPid.ContainsKey($key)) { $svcByPid[$key] = New-Object System.Collections.Generic.List[string] }
        $svcByPid[$key].Add($s.Name)
    }

    $results = New-Object System.Collections.Generic.List[object]
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
    foreach ($c in $tcp) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $svcs = if ($svcByPid.ContainsKey([int]$c.OwningProcess)) { @($svcByPid[[int]$c.OwningProcess]) } else { @() }
        $results.Add([PSCustomObject]@{
            Protocol = 'TCP'; Port = [int]$c.LocalPort; Address = $c.LocalAddress; PID = [int]$c.OwningProcess
            Process  = if ($proc) { $proc.ProcessName } else { '' }; Services = $svcs
        })
    }
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
    foreach ($u in $udp) {
        $proc = Get-Process -Id $u.OwningProcess -ErrorAction SilentlyContinue
        $svcs = if ($svcByPid.ContainsKey([int]$u.OwningProcess)) { @($svcByPid[[int]$u.OwningProcess]) } else { @() }
        $results.Add([PSCustomObject]@{
            Protocol = 'UDP'; Port = [int]$u.LocalPort; Address = $u.LocalAddress; PID = [int]$u.OwningProcess
            Process  = if ($proc) { $proc.ProcessName } else { '' }; Services = $svcs
        })
    }
    return $results
}

function Read-CCDCYesNo {
    param([string]$Prompt, [bool]$DefaultYes = $false)
    $suffix = if ($DefaultYes) { '(Y/n)' } else { '(y/N)' }
    $ans = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }
    return ($ans -match '^(?i)y')
}

function Test-CCDCIisPresent {
    return ($null -ne (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue))
}

function Import-CCDCWebAdministration {
    if (-not (Test-CCDCIisPresent)) { return $false }
    try {
        Import-Module WebAdministration -ErrorAction Stop
        return $true
    } catch {
        Write-CCDCLog "WebAdministration module unavailable: $($_.Exception.Message)" -Level 'WARN'
        return $false
    }
}

function Get-CCDCIisSitePaths {
    $paths = New-Object System.Collections.Generic.List[object]
    if (-not (Import-CCDCWebAdministration)) { return $paths }
    foreach ($site in (Get-Website -ErrorAction SilentlyContinue)) {
        $phys = [Environment]::ExpandEnvironmentVariables([string]$site.PhysicalPath)
        if ($phys -and (Test-Path -LiteralPath $phys)) {
            $paths.Add([PSCustomObject]@{ Site = $site.Name; Path = $phys })
        }
        foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction SilentlyContinue)) {
            $appPhys = [Environment]::ExpandEnvironmentVariables([string]$app.PhysicalPath)
            if ($appPhys -and (Test-Path -LiteralPath $appPhys) -and -not ($paths | Where-Object { $_.Path -ieq $appPhys })) {
                $paths.Add([PSCustomObject]@{ Site = "$($site.Name)$($app.Path)"; Path = $appPhys })
            }
        }
    }
    return $paths
}

# =========================================================================
# LOCAL ACCOUNT HYGIENE (Section 3 / Local sweep)
# =========================================================================

function Invoke-CCDCLocalAccountHygiene {
    Assert-CCDCAdmin
    Initialize-CCDCState
    $role = Get-CCDCHostRole
    if ($role.IsDC) {
        Write-CCDCLog "This host is a Domain Controller; local SAM accounts do not apply. Use the AD menu (CCDC-ADServer2025.ps1)." -Level 'WARN'
        return
    }

    $scored   = Get-CCDCScoredUsers
    $excluded = @($script:CCDCConfig.SystemAccountExclusions | ForEach-Object { $_.ToLowerInvariant() })
    $cp = New-CCDCCheckpoint -ModuleName 'Local_Accounts' -Description 'Local account hygiene (admin rotation, Guest off, group review)'

    foreach ($name in @('admin', 'Administrator')) {
        $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $u) { continue }
        if ($scored -contains $name.ToLowerInvariant()) {
            Write-CCDCLog "Skipping '$name': listed as a Quotient scored user (use PCR)." -Level 'WARN'
            continue
        }
        if (Read-CCDCYesNo -Prompt "Rotate local '$name' password now?" -DefaultYes $true) {
            $sec = Read-CCDCSecurePassword -PromptLabel "local $name"
            if (-not $script:CCDCDryRun) {
                try {
                    Set-LocalUser -Name $name -Password $sec -ErrorAction Stop
                    Register-CCDCUndoBlock -UndoCode "# Password rotation for local $name is not reverted automatically." -ChangeSummary "Rotated local $name password"
                    Write-CCDCLog "Rotated local '$name' password." -Level 'SUCCESS'
                } catch {
                    Write-CCDCLog "Failed to rotate '$name': $($_.Exception.Message)" -Level 'ERROR'
                }
            }
        }
    }

    foreach ($name in @('Guest', 'DefaultAccount')) {
        $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($u -and $u.Enabled) {
            if ($script:CCDCDryRun) {
                Write-CCDCLog "[DRYRUN] Would disable local '$name'." -Level 'DRYRUN'
            } else {
                Disable-LocalUser -Name $name
                Register-CCDCUndoBlock -UndoCode "Enable-LocalUser -Name $(ConvertTo-CCDCQuotedPSString $name) -ErrorAction SilentlyContinue" -ChangeSummary "Disabled local $name"
                Write-CCDCLog "Disabled local '$name'." -Level 'SUCCESS'
            }
        }
    }

    foreach ($grp in @('Administrators', 'Remote Desktop Users', 'Remote Management Users', 'WinRMRemoteWMIUsers__')) {
        $g = Get-LocalGroup -Name $grp -ErrorAction SilentlyContinue
        if ($null -eq $g) { continue }
        $members = @(Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue)
        Write-CCDCLog "Local group [$grp] members ($($members.Count)):" -Level 'INFO'
        foreach ($m in $members) {
            Write-Host "    [$($m.PrincipalSource)] $($m.Name) ($($m.ObjectClass))" -ForegroundColor Gray
        }
        if ($grp -eq 'Administrators' -and $members.Count -gt 0 -and (Read-CCDCYesNo -Prompt "Remove any member from local Administrators?")) {
            foreach ($m in $members) {
                $short = ($m.Name -split '\\')[-1].ToLowerInvariant()
                if ($short -in @('administrator', 'admin', 'domain admins') -or $scored -contains $short) { continue }
                if (Read-CCDCYesNo -Prompt "  Remove '$($m.Name)' from Administrators?") {
                    if ($script:CCDCDryRun) {
                        Write-CCDCLog "[DRYRUN] Would remove $($m.Name) from Administrators." -Level 'DRYRUN'
                        continue
                    }
                    try {
                        Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name -ErrorAction Stop
                        Register-CCDCUndoBlock -UndoCode "Add-LocalGroupMember -Group 'Administrators' -Member $(ConvertTo-CCDCQuotedPSString $m.Name) -ErrorAction SilentlyContinue" -ChangeSummary "Removed $($m.Name) from Administrators"
                        Write-CCDCLog "Removed $($m.Name) from Administrators." -Level 'SUCCESS'
                    } catch {
                        Write-CCDCLog "Could not remove $($m.Name): $($_.Exception.Message)" -Level 'WARN'
                    }
                }
            }
        }
    }

    $unknown = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -and
        $_.Name.ToLowerInvariant() -notin $excluded -and
        $_.Name.ToLowerInvariant() -ne 'admin' -and
        $scored -notcontains $_.Name.ToLowerInvariant()
    })
    if ($unknown.Count -gt 0) {
        Write-CCDCLog "Enabled local users not in exclusions or scored list: $($unknown.Name -join ', ')" -Level 'WARN'
        if (Read-CCDCYesNo -Prompt "Review and disable any of them (Disable-LocalUser, never deleted)?") {
            foreach ($u in $unknown) {
                if (-not (Read-CCDCYesNo -Prompt "  Disable '$($u.Name)' (Description: $($u.Description))?")) { continue }
                if ($script:CCDCDryRun) {
                    Write-CCDCLog "[DRYRUN] Would disable $($u.Name)." -Level 'DRYRUN'
                    continue
                }
                Disable-LocalUser -Name $u.Name
                Register-CCDCUndoBlock -UndoCode "Enable-LocalUser -Name $(ConvertTo-CCDCQuotedPSString $u.Name) -ErrorAction SilentlyContinue" -ChangeSummary "Disabled local user $($u.Name)"
                Write-CCDCLog "Disabled local user '$($u.Name)' (preserved for Legal Hold)." -Level 'SUCCESS'
            }
        }
    }

    Complete-CCDCCheckpoint | Out-Null
    Clear-CCDCHistory
}

# =========================================================================
# SECTION 2.7: AUDITING & LOGGING
# =========================================================================

function Invoke-CCDCAuditingAndLogging {
    param([string]$SysmonPath = '', [string]$SysmonConfigPath = '')
    Assert-CCDCAdmin
    Initialize-CCDCState
    $cp = New-CCDCCheckpoint -ModuleName 'Auditing_Logging' -Description 'Section 2.7 Advanced Audit Policy, PowerShell logging, 1GB event logs'
    Backup-CCDCAuditPolicy | Out-Null

    Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord

    $subcategories = @(
        'Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations',
        'Other Account Logon Events', 'User Account Management', 'Security Group Management',
        'Computer Account Management', 'Other Account Management Events', 'Directory Service Access',
        'Directory Service Changes', 'Directory Service Replication', 'Logon', 'Logoff', 'Account Lockout',
        'Special Logon', 'Other Logon/Logoff Events', 'Audit Policy Change', 'Authentication Policy Change',
        'Authorization Policy Change', 'Sensitive Privilege Use', 'Process Creation', 'Other Object Access Events',
        'System Integrity', 'Security System Extension', 'Security State Change'
    )
    foreach ($sub in $subcategories) {
        if ($script:CCDCDryRun) {
            Write-CCDCLog "[DRYRUN] Would enable audit subcategory '$sub' (Success+Failure)." -Level 'DRYRUN'
            continue
        }
        $out = & auditpol.exe /set /subcategory:"$sub" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-CCDCLog "auditpol could not set '$sub': $out" -Level 'WARN'
        }
    }
    if (-not $script:CCDCDryRun) { Write-CCDCLog "Advanced Audit Policy applied ($($subcategories.Count) subcategories)." -Level 'SUCCESS' }

    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -Type String

    $logs = @('Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'DNS Server')
    $targetBytes = 1073741824
    foreach ($log in $logs) {
        $info = & wevtutil.exe gl "$log" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $info) { continue }
        $prior = 0
        foreach ($line in $info) {
            if ($line -match '^\s*maxSize:\s*(\d+)') { $prior = [long]$Matches[1] }
        }
        if ($prior -ge $targetBytes) {
            Write-CCDCLog "Log '$log' already >= 1GB ($prior bytes)." -Level 'INFO'
            continue
        }
        if ($script:CCDCDryRun) {
            Write-CCDCLog "[DRYRUN] Would raise '$log' max size $prior -> $targetBytes." -Level 'DRYRUN'
            continue
        }
        & wevtutil.exe sl "$log" /ms:$targetBytes 2>$null
        if ($LASTEXITCODE -eq 0) {
            $qLog = ConvertTo-CCDCQuotedPSString $log
            Register-CCDCUndoBlock -UndoCode "& wevtutil.exe sl $qLog /ms:$prior" -ChangeSummary "Raised '$log' log size $prior -> $targetBytes"
            Write-CCDCLog "Raised '$log' max size to 1GB (was $prior)." -Level 'SUCCESS'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($SysmonPath)) {
        if (Test-Path -LiteralPath $SysmonPath) {
            if ($script:CCDCDryRun) {
                Write-CCDCLog "[DRYRUN] Would install Sysmon from $SysmonPath." -Level 'DRYRUN'
            } else {
                $sysmonArgs = @('-accepteula', '-i')
                if ($SysmonConfigPath -and (Test-Path -LiteralPath $SysmonConfigPath)) { $sysmonArgs += $SysmonConfigPath }
                & $SysmonPath @sysmonArgs
                Register-CCDCUndoBlock -UndoCode "& $(ConvertTo-CCDCQuotedPSString $SysmonPath) -u" -ChangeSummary "Installed Sysmon"
                Write-CCDCLog "Sysmon installed from $SysmonPath." -Level 'SUCCESS'
            }
        } else {
            Write-CCDCLog "Sysmon binary not found at $SysmonPath." -Level 'WARN'
        }
    }

    Complete-CCDCCheckpoint | Out-Null
}

# =========================================================================
# LOCAL SECURITY OPTIONS, USER RIGHTS, SERVICES, FEATURES
# =========================================================================

function Set-CCDCUserRights {
    <#
        Rewrites selected [Privilege Rights] entries via secedit. Prior policy is captured by
        Backup-CCDCSecurityPolicy in the active checkpoint, so rollback re-imports it.
    #>
    param([hashtable]$Rights)
    if ($script:CCDCDryRun) {
        foreach ($k in $Rights.Keys) { Write-CCDCLog "[DRYRUN] Would set $k = '$($Rights[$k])'" -Level 'DRYRUN' }
        return
    }
    $work = Join-Path $env:TEMP ("ccdc_rights_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path $work -ItemType Directory -Force | Out-Null
    try {
        $inf = Join-Path $work 'current.inf'
        $sdb = Join-Path $work 'rights.sdb'
        & secedit.exe /export /cfg "$inf" /areas USER_RIGHTS | Out-Null
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.AddRange([string[]](Get-Content -LiteralPath $inf -Encoding Unicode))
        $privIdx = $lines.IndexOf('[Privilege Rights]')
        if ($privIdx -lt 0) {
            $lines.Add('[Privilege Rights]')
            $privIdx = $lines.Count - 1
        }
        foreach ($k in $Rights.Keys) {
            $newLine = "$k = $($Rights[$k])"
            $existing = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match "^\s*$([regex]::Escape($k))\s*=") { $existing = $i; break }
            }
            if ($existing -ge 0) { $lines[$existing] = $newLine } else { $lines.Insert($privIdx + 1, $newLine) }
        }
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
        & secedit.exe /configure /db "$sdb" /cfg "$inf" /areas USER_RIGHTS /quiet | Out-Null
        Write-CCDCLog "Applied user rights: $($Rights.Keys -join ', ')" -Level 'SUCCESS'
    } catch {
        Write-CCDCLog "secedit user rights update failed: $($_.Exception.Message)" -Level 'ERROR'
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-CCDCLocalSecurityAndOSHardening {
    param([switch]$RemoveFeatures)
    Assert-CCDCAdmin
    Initialize-CCDCState
    $role = Get-CCDCHostRole
    $cp = New-CCDCCheckpoint -ModuleName 'Local_SecurityOS' -Description 'UAC, AutoRun, anonymous access, WDigest, sudo, user rights, unneeded services'
    Backup-CCDCSecurityPolicy | Out-Null

    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-CCDCRegistryValue -Path $sys -Name 'EnableLUA' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path $sys -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
    Set-CCDCRegistryValue -Path $sys -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path $sys -Name 'FilterAdministratorToken' -Value 1 -Type DWord

    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -Type DWord

    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-CCDCRegistryValue -Path $lsa -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path $lsa -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path $lsa -Name 'RestrictAnonymous' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path $lsa -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -Name 'Enabled' -Value 0 -Type DWord

    if ($role.IsDC) {
        Write-CCDCLog "DC detected: local user rights are overridden by the Default Domain Controllers Policy GPO. Applying anyway; check the GPO too." -Level 'WARN'
    }
    Set-CCDCUserRights -Rights @{
        'SeDebugPrivilege'          = '*S-1-5-32-544'
        'SeTcbPrivilege'            = ''
        'SeTakeOwnershipPrivilege'  = '*S-1-5-32-544'
        'SeRemoteShutdownPrivilege' = '*S-1-5-32-544'
        'SeLoadDriverPrivilege'     = '*S-1-5-32-544'
    }

    $listeners = Get-CCDCListenerMap
    $listeningSvcs = @($listeners | ForEach-Object { $_.Services } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($svcName in $script:CCDCConfig.UnneededServicesCommon) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -eq $svc) { continue }
        if (Test-CCDCProtectedService -ServiceName $svc.Name) { continue }
        if ($listeningSvcs -contains $svc.Name) {
            Write-CCDCLog "Skipping '$($svc.Name)': it owns an active listener (may be scored)." -Level 'WARN'
            continue
        }
        if ($svc.Name -eq 'Spooler' -and (Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared })) {
            Write-CCDCLog "Skipping Spooler: shared printers exist." -Level 'WARN'
            continue
        }
        if ($svc.StartType -ne 'Disabled' -or $svc.Status -ne 'Stopped') {
            Set-CCDCServiceState -ServiceName $svc.Name -StartupType 'Disabled' -DesiredStatus 'Stopped'
        }
    }

    if ($RemoveFeatures -or (Read-CCDCYesNo -Prompt "Disable optional features (SMB1, Telnet, TFTP, PowerShell v2)?")) {
        foreach ($feat in $script:CCDCConfig.UnneededWindowsFeatures) {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction SilentlyContinue
            if ($null -eq $f -or $f.State -ne 'Enabled') { continue }
            if ($script:CCDCDryRun) {
                Write-CCDCLog "[DRYRUN] Would disable optional feature $feat." -Level 'DRYRUN'
                continue
            }
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop | Out-Null
                Register-CCDCUndoBlock -UndoCode "Enable-WindowsOptionalFeature -Online -FeatureName $(ConvertTo-CCDCQuotedPSString $feat) -NoRestart -All -ErrorAction SilentlyContinue | Out-Null" -ChangeSummary "Disabled optional feature $feat"
                Write-CCDCLog "Disabled optional feature $feat (reboot may be needed)." -Level 'SUCCESS'
            } catch {
                Write-CCDCLog "Could not disable $feat : $($_.Exception.Message)" -Level 'WARN'
            }
        }
    }

    Complete-CCDCCheckpoint | Out-Null
}

# =========================================================================
# DEFENDER RESTORE & HARDEN
# =========================================================================

function Invoke-CCDCDefenderRestoreAndHarden {
    Assert-CCDCAdmin
    Initialize-CCDCState
    $cp = New-CCDCCheckpoint -ModuleName 'Defender' -Description 'Remove Defender kill switches, review exclusions, enable protections'

    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    foreach ($n in @('DisableAntiSpyware', 'DisableAntiVirus', 'DisableRoutinelyTakingAction')) {
        Remove-CCDCRegistryValue -Path $pol -Name $n
    }
    foreach ($n in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableOnAccessProtection')) {
        Remove-CCDCRegistryValue -Path "$pol\Real-Time Protection" -Name $n
    }
    Remove-CCDCRegistryValue -Path "$pol\Spynet" -Name 'SpynetReporting'

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-CCDCLog "Defender cmdlets not available on this host." -Level 'WARN'
        Complete-CCDCCheckpoint | Out-Null
        return
    }
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if ($null -eq $mp) {
        Write-CCDCLog "Get-MpPreference returned nothing (Defender service stopped?)." -Level 'WARN'
        Complete-CCDCCheckpoint | Out-Null
        return
    }

    $exclusionTypes = @(
        @{ Prop = 'ExclusionPath';      Param = 'ExclusionPath' },
        @{ Prop = 'ExclusionProcess';   Param = 'ExclusionProcess' },
        @{ Prop = 'ExclusionExtension'; Param = 'ExclusionExtension' },
        @{ Prop = 'ExclusionIpAddress'; Param = 'ExclusionIpAddress' }
    )
    foreach ($t in $exclusionTypes) {
        $vals = @($mp.($t.Prop) | Where-Object { $_ -and $_ -notmatch '^N/A' })
        if ($vals.Count -eq 0) { continue }
        Write-CCDCLog "Defender $($t.Prop) entries: $($vals -join ' | ')" -Level 'ALERT'
        foreach ($v in $vals) {
            if ($v -match '(?i)splunk') {
                Write-CCDCLog "  Keeping Splunk-related exclusion '$v'." -Level 'INFO'
                continue
            }
            if (-not (Read-CCDCYesNo -Prompt "  Remove $($t.Prop) '$v'?")) { continue }
            if ($script:CCDCDryRun) {
                Write-CCDCLog "[DRYRUN] Would remove $($t.Prop) '$v'." -Level 'DRYRUN'
                continue
            }
            $splat = @{ $t.Param = $v }
            try {
                Remove-MpPreference @splat -ErrorAction Stop
                Register-CCDCUndoBlock -UndoCode "Add-MpPreference -$($t.Param) $(ConvertTo-CCDCQuotedPSString $v) -ErrorAction SilentlyContinue" -ChangeSummary "Removed Defender $($t.Prop) '$v'"
                Write-CCDCLog "Removed Defender $($t.Prop) '$v'." -Level 'SUCCESS'
            } catch {
                Write-CCDCLog "Could not remove '$v' (Tamper Protection or GPO?): $($_.Exception.Message)" -Level 'WARN'
            }
        }
    }

    $boolPrefs = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableBlockAtFirstSeen')
    foreach ($p in $boolPrefs) {
        $prior = $mp.$p
        if ($prior -ne $true) { continue }
        if ($script:CCDCDryRun) {
            Write-CCDCLog "[DRYRUN] Would set $p = False." -Level 'DRYRUN'
            continue
        }
        try {
            $splat = @{ $p = $false }
            Set-MpPreference @splat -ErrorAction Stop
            Register-CCDCUndoBlock -UndoCode "Set-MpPreference -$p `$true -ErrorAction SilentlyContinue" -ChangeSummary "Defender $p True -> False"
            Write-CCDCLog "Defender $p set to False." -Level 'SUCCESS'
        } catch {
            Write-CCDCLog "Could not set $p : $($_.Exception.Message)" -Level 'WARN'
        }
    }
    if ($mp.PUAProtection -ne 1 -and -not $script:CCDCDryRun) {
        try {
            $priorPua = [int]$mp.PUAProtection
            Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
            Register-CCDCUndoBlock -UndoCode "Set-MpPreference -PUAProtection $priorPua -ErrorAction SilentlyContinue" -ChangeSummary "Defender PUAProtection enabled"
        } catch {}
    }

    $wd = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    if ($wd -and $wd.Status -ne 'Running') {
        Set-CCDCServiceState -ServiceName 'WinDefend' -StartupType 'Automatic' -DesiredStatus 'Running' -AllowProtectedOverride
    }
    Complete-CCDCCheckpoint | Out-Null
}

# =========================================================================
# SMART HOST FIREWALL
# =========================================================================

function Invoke-CCDCSmartFirewall {
    Assert-CCDCAdmin
    Initialize-CCDCState
    $role = Get-CCDCHostRole
    $roleName = if ($role.IsDC) { 'DC' } elseif ($role.HasIIS) { 'IIS' } else { 'Custom' }
    Write-CCDCLog "Smart Firewall: detected role = $roleName" -Level 'INFO'

    $listeners = Get-CCDCListenerMap
    $tcpPorts = @($listeners | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -lt 49152 } | Sort-Object Port -Unique)
    Write-CCDCLog "Listening TCP ports (<49152) that will get explicit allow rules:" -Level 'INFO'
    $tcpPorts | Select-Object Port, Process, @{ N = 'Services'; E = { $_.Services -join ',' } } | Format-Table -AutoSize

    $knownUdp = @(53, 67, 69, 88, 123, 137, 138, 161, 389, 464, 500, 514, 1812, 4500)
    $udpPorts = @($listeners | Where-Object { $_.Protocol -eq 'UDP' -and $knownUdp -contains $_.Port } | Sort-Object Port -Unique)

    if (-not (Read-CCDCYesNo -Prompt "Apply firewall: profiles ON, inbound default Block, outbound default Allow, allow detected listeners?" -DefaultYes $true)) { return }

    $cp = New-CCDCCheckpoint -ModuleName 'Smart_Firewall' -Description "Host firewall ($roleName): allow detected listeners, block other inbound"
    Backup-CCDCFirewall | Out-Null

    if ($script:CCDCDryRun) {
        Write-CCDCLog "[DRYRUN] Would create $($tcpPorts.Count) TCP + $($udpPorts.Count) UDP allow rules and enable all profiles." -Level 'DRYRUN'
        Complete-CCDCCheckpoint | Out-Null
        return
    }

    foreach ($l in $tcpPorts) {
        $name = "CCDC_ALLOW_TCP_$($l.Port)"
        Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $l.Port -Action Allow -Profile Any -Description "CCDC listener $($l.Process)" | Out-Null
    }
    foreach ($l in $udpPorts) {
        $name = "CCDC_ALLOW_UDP_$($l.Port)"
        Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol UDP -LocalPort $l.Port -Action Allow -Profile Any -Description "CCDC listener $($l.Process)" | Out-Null
    }
    Remove-NetFirewallRule -DisplayName 'CCDC_ALLOW_ICMPv4_Echo' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'CCDC_ALLOW_ICMPv4_Echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null

    if ($role.IsDC) {
        foreach ($grp in @('Active Directory Domain Services', 'DNS Service', 'Kerberos Key Distribution Center', 'File and Printer Sharing', 'Remote Desktop', 'Windows Remote Management')) {
            Enable-NetFirewallRule -DisplayGroup $grp -ErrorAction SilentlyContinue
        }
        Write-CCDCLog "DC: enabled built-in AD DS / DNS / Kerberos / SMB / RDP / WinRM rule groups (covers dynamic RPC ports)." -Level 'INFO'
    }
    if ($role.HasIIS) {
        Enable-NetFirewallRule -DisplayGroup 'World Wide Web Services (HTTP)' -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup 'Secure World Wide Web Services (HTTPS)' -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup 'FTP Server' -ErrorAction SilentlyContinue
    }

    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogMaxSizeKilobytes 16384
    Write-CCDCLog "Firewall profiles enabled: inbound Block by default, outbound Allow (Splunk, proxy, AD/DNS, mail.closedai.com unaffected)." -Level 'SUCCESS'

    $rogue = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -notlike 'CCDC_*' -and [string]::IsNullOrEmpty($_.Group)
    } | Where-Object {
        $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $af = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $adf = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        ($pf.LocalPort -eq 'Any') -and ($af.Program -eq 'Any') -and ($adf.RemoteAddress -eq 'Any')
    })
    if ($rogue.Count -gt 0) {
        Write-CCDCLog "Custom inbound allow-ALL rules (any port, any program, any source): $($rogue.DisplayName -join ' | ')" -Level 'ALERT'
        foreach ($r in $rogue) {
            if (Read-CCDCYesNo -Prompt "  Disable rule '$($r.DisplayName)'?" -DefaultYes $true) {
                Disable-NetFirewallRule -Name $r.Name
                Register-CCDCUndoBlock -UndoCode "Enable-NetFirewallRule -Name $(ConvertTo-CCDCQuotedPSString $r.Name) -ErrorAction SilentlyContinue" -ChangeSummary "Disabled allow-all rule $($r.DisplayName)"
            }
        }
    }

    Complete-CCDCCheckpoint | Out-Null
    Write-CCDCLog "Watch Quotient for the next 2 checks. If anything goes red, roll back this checkpoint." -Level 'ALERT'
}

# =========================================================================
# SECTION 3: IIS WEB ROOT BASELINE, DIFF & WEBSHELL SCAN
# =========================================================================

$script:CCDCWebExtensions = @('.aspx', '.asp', '.ashx', '.asmx', '.ascx', '.php', '.config', '.dll', '.ps1', '.exe', '.jsp', '.cshtml', '.bat', '.cmd', '.vbs')
$script:CCDCWebshellRegex = '(?i)(cmd\.exe|powershell|ProcessStartInfo|Process\.Start|eval\s*\(|FromBase64String|base64_decode|shell_exec|passthru|system\s*\(|WScript\.Shell|Request\.Form\[.{0,40}\]\s*\)|Assembly\.Load)'

function Get-CCDCWebRootHashes {
    param([object[]]$SitePaths)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($sp in $SitePaths) {
        foreach ($f in (Get-ChildItem -LiteralPath $sp.Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            $rows.Add([PSCustomObject]@{
                Site = $sp.Site; Path = $f.FullName; Length = $f.Length
                LastWrite = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); SHA256 = if ($h) { $h.Hash } else { '' }
            })
        }
    }
    return $rows
}

function New-CCDCWebRootBaseline {
    Assert-CCDCAdmin
    Initialize-CCDCState
    $sites = @(Get-CCDCIisSitePaths)
    if ($sites.Count -eq 0) {
        Write-CCDCLog "No IIS site physical paths found." -Level 'WARN'
        return
    }
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $webDir = Join-Path $script:CCDCStateRoot 'WebBackups'
    foreach ($sp in $sites) {
        $zip = Join-Path $webDir ("{0}_{1}.zip" -f $ts, ($sp.Site -replace '[^a-zA-Z0-9_-]', '_'))
        try {
            Compress-Archive -Path (Join-Path $sp.Path '*') -DestinationPath $zip -CompressionLevel Optimal -Force -ErrorAction Stop
            Write-CCDCLog "Backed up '$($sp.Site)' ($($sp.Path)) -> $zip" -Level 'SUCCESS'
        } catch {
            Write-CCDCLog "Zip backup of '$($sp.Site)' partially failed (locked files?): $($_.Exception.Message)" -Level 'WARN'
        }
    }
    $rows = Get-CCDCWebRootHashes -SitePaths $sites
    $csv = Join-Path $webDir "WebRootBaseline_$ts.csv"
    $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Copy-Item -LiteralPath $csv -Destination (Join-Path $webDir 'WebRootBaseline_LATEST.csv') -Force
    Write-CCDCLog "Web root SHA256 baseline: $($rows.Count) files -> $csv" -Level 'SUCCESS'
}

function Compare-CCDCWebRootBaseline {
    Assert-CCDCAdmin
    Initialize-CCDCState
    $webDir = Join-Path $script:CCDCStateRoot 'WebBackups'
    $latest = Join-Path $webDir 'WebRootBaseline_LATEST.csv'
    if (-not (Test-Path -LiteralPath $latest)) {
        Write-CCDCLog "No web root baseline yet. Run New-CCDCWebRootBaseline first." -Level 'WARN'
        return
    }
    $base = @{}
    foreach ($r in (Import-Csv -LiteralPath $latest)) { $base[$r.Path] = $r }
    $sites = @(Get-CCDCIisSitePaths)
    $current = Get-CCDCWebRootHashes -SitePaths $sites
    $curMap = @{}
    foreach ($r in $current) { $curMap[$r.Path] = $r }

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($r in $current) {
        $status = $null
        if (-not $base.ContainsKey($r.Path)) { $status = 'NEW' }
        elseif ($base[$r.Path].SHA256 -ne $r.SHA256) { $status = 'CHANGED' }
        if ($status) {
            $findings.Add([PSCustomObject]@{ Status = $status; Path = $r.Path; LastWrite = $r.LastWrite; SHA256 = $r.SHA256 })
        }
    }
    foreach ($p in $base.Keys) {
        if (-not $curMap.ContainsKey($p)) {
            $findings.Add([PSCustomObject]@{ Status = 'REMOVED'; Path = $p; LastWrite = $base[$p].LastWrite; SHA256 = $base[$p].SHA256 })
        }
    }

    foreach ($sp in $sites) {
        foreach ($f in (Get-ChildItem -LiteralPath $sp.Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $ext = $f.Extension.ToLowerInvariant()
            $inRiskyDir = ($f.DirectoryName -match '(?i)\\(upload|uploads|temp|tmp|files|images|media)(\\|$)')
            if ($inRiskyDir -and $script:CCDCWebExtensions -contains $ext) {
                $findings.Add([PSCustomObject]@{ Status = 'SCRIPT_IN_UPLOAD_DIR'; Path = $f.FullName; LastWrite = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); SHA256 = '' })
            }
            if ($ext -in @('.aspx', '.asp', '.ashx', '.asmx', '.php', '.jsp', '.cshtml') -and $f.Length -lt 2MB) {
                $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                if ($raw -and $raw -match $script:CCDCWebshellRegex) {
                    $findings.Add([PSCustomObject]@{ Status = "WEBSHELL_SIGNATURE ($($Matches[1]))"; Path = $f.FullName; LastWrite = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); SHA256 = '' })
                }
            }
        }
    }

    if ($findings.Count -eq 0) {
        Write-CCDCLog "Web roots match baseline. No webshell signatures found." -Level 'SUCCESS'
        return
    }
    $out = Join-Path (Join-Path $script:CCDCStateRoot 'Sweeps') ("WebRootDiff_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
    $findings | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    $findings | Format-Table Status, LastWrite, Path -AutoSize
    Write-CCDCLog "$($findings.Count) web root finding(s) saved -> $out. Do not delete suspects (Legal Hold); copy to Evidence, then remediate." -Level 'ALERT'
}

# =========================================================================
# SECTION 3: IIS CONFIG AUDIT & HARDEN
# =========================================================================

function Invoke-CCDCIisConfigAuditAndHarden {
    Assert-CCDCAdmin
    Initialize-CCDCState
    if (-not (Import-CCDCWebAdministration)) {
        Write-CCDCLog "IIS (W3SVC) not present on this host." -Level 'WARN'
        return
    }

    $appHost = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $appHost) {
        [xml]$ah = Get-Content -LiteralPath $appHost -Raw
        Write-CCDCLog "Native global modules outside the standard IIS / .NET folders:" -Level 'INFO'
        foreach ($m in $ah.configuration.'system.webServer'.globalModules.add) {
            $img = [Environment]::ExpandEnvironmentVariables([string]$m.image)
            if ($img -notmatch '(?i)\\(System32|SysWOW64)\\inetsrv\\|\\Microsoft\.NET\\|\\IIS\\|\\IIS Express\\') {
                Write-CCDCLog "  SUSPECT native module '$($m.name)' -> $img" -Level 'ALERT'
            }
        }
    }

    foreach ($sp in (Get-CCDCIisSitePaths)) {
        $wc = Join-Path $sp.Path 'web.config'
        if (-not (Test-Path -LiteralPath $wc)) { continue }
        try {
            [xml]$x = Get-Content -LiteralPath $wc -Raw
            $ws = $x.configuration.'system.webServer'
            if ($ws) {
                foreach ($h in @($ws.handlers.add)) {
                    if ($h) { Write-CCDCLog "  [$($sp.Site)] handler '$($h.name)' path='$($h.path)' verb='$($h.verb)' type='$($h.type)$($h.scriptProcessor)'" -Level 'WARN' }
                }
                foreach ($m in @($ws.modules.add)) {
                    if ($m) { Write-CCDCLog "  [$($sp.Site)] module '$($m.name)' type='$($m.type)'" -Level 'WARN' }
                }
            }
            $raw = Get-Content -LiteralPath $wc -Raw
            if ($raw -match '(?i)(password|pwd)\s*=\s*[^;"]+') {
                Write-CCDCLog "  [$($sp.Site)] Plaintext DB password in $wc. Restrict NTFS read to the app pool identity and Administrators." -Level 'ALERT'
            }
        } catch {
            Write-CCDCLog "Could not parse $wc : $($_.Exception.Message)" -Level 'WARN'
        }
    }

    $cp = New-CCDCCheckpoint -ModuleName 'IIS_Harden' -Description 'IIS: app pools, directory browsing, request filtering, headers'
    Backup-CCDCIisConfig -BackupLabel 'PreHarden' | Out-Null
    foreach ($f in @($appHost)) { Backup-CCDCFile -FilePath $f | Out-Null }

    foreach ($pool in (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue)) {
        $idType = [string]$pool.processModel.identityType
        $user   = [string]$pool.processModel.userName
        $flag   = ($idType -eq 'LocalSystem') -or ($idType -eq 'SpecificUser' -and $user -match '(?i)admin')
        $lvl    = if ($flag) { 'ALERT' } else { 'INFO' }
        Write-CCDCLog "AppPool '$($pool.Name)': identity=$idType $user" -Level $lvl
        if ($flag -and (Read-CCDCYesNo -Prompt "  Switch '$($pool.Name)' to ApplicationPoolIdentity? (check the site afterwards)")) {
            if ($script:CCDCDryRun) {
                Write-CCDCLog "[DRYRUN] Would set $($pool.Name) to ApplicationPoolIdentity." -Level 'DRYRUN'
            } else {
                Set-ItemProperty -Path "IIS:\AppPools\$($pool.Name)" -Name processModel.identityType -Value 'ApplicationPoolIdentity'
                Register-CCDCUndoBlock -UndoCode "Import-Module WebAdministration; Set-ItemProperty -Path 'IIS:\AppPools\$($pool.Name)' -Name processModel.identityType -Value '$idType'" -ChangeSummary "AppPool $($pool.Name) $idType -> ApplicationPoolIdentity"
            }
        }
    }

    if (-not $script:CCDCDryRun) {
        $psPath = 'MACHINE/WEBROOT/APPHOST'
        try {
            Set-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $false
            Write-CCDCLog "Directory browsing disabled server-wide." -Level 'SUCCESS'
        } catch { Write-CCDCLog "Directory browsing: $($_.Exception.Message)" -Level 'WARN' }

        try {
            $verbs = @(Get-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/security/requestFiltering/verbs' -Name 'Collection' -ErrorAction SilentlyContinue)
            foreach ($v in @('TRACE', 'TRACK')) {
                if (-not ($verbs | Where-Object { $_.verb -eq $v })) {
                    Add-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/security/requestFiltering/verbs' -Name '.' -Value @{ verb = $v; allowed = 'false' }
                }
            }
            Write-CCDCLog "Request filtering: TRACE/TRACK denied." -Level 'SUCCESS'
        } catch { Write-CCDCLog "Verb filtering: $($_.Exception.Message)" -Level 'WARN' }

        $webdav = Get-WindowsFeature -Name 'Web-DAV-Publishing' -ErrorAction SilentlyContinue
        if ($webdav -and $webdav.Installed) {
            Write-CCDCLog "WebDAV Publishing is installed." -Level 'WARN'
            if (Read-CCDCYesNo -Prompt "  Deny PROPFIND/PROPPATCH/MKCOL/COPY/MOVE/LOCK/UNLOCK verbs (only if no scored check uses WebDAV)?") {
                foreach ($v in @('PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK')) {
                    try { Add-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/security/requestFiltering/verbs' -Name '.' -Value @{ verb = $v; allowed = 'false' } -ErrorAction Stop } catch {}
                }
            }
        }

        try {
            foreach ($seg in @('bin', 'App_Data', 'App_Code', 'web.config')) {
                $hidden = @(Get-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/security/requestFiltering/hiddenSegments' -Name 'Collection' -ErrorAction SilentlyContinue)
                if (-not ($hidden | Where-Object { $_.segment -eq $seg })) {
                    Add-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/security/requestFiltering/hiddenSegments' -Name '.' -Value @{ segment = $seg }
                }
            }
        } catch {}

        try {
            Remove-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -AtElement @{ name = 'X-Powered-By' } -ErrorAction Stop
            Write-CCDCLog "Removed X-Powered-By header." -Level 'SUCCESS'
        } catch {}
        try {
            Set-WebConfigurationProperty -PSPath $psPath -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -Value $true -ErrorAction Stop
            Write-CCDCLog "Enabled removeServerHeader." -Level 'SUCCESS'
        } catch { Write-CCDCLog "removeServerHeader not supported on this IIS version." -Level 'INFO' }
        Register-CCDCUndoBlock -UndoCode "# IIS settings are restored by the appcmd backup above." -ChangeSummary "IIS directory browsing off, TRACE/TRACK denied, headers stripped"
    }

    if (Read-CCDCYesNo -Prompt "Lock down web root NTFS (Users/Everyone/IIS_IUSRS write -> read-only, except folders you name)?") {
        $keepWritable = Read-Host "Folder names that must stay writable (comma separated, e.g. App_Data,uploads) or Enter for none"
        $keepList = @($keepWritable -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($sp in (Get-CCDCIisSitePaths)) {
            Backup-CCDCNtfsAcl -TargetPath $sp.Path | Out-Null
            if ($script:CCDCDryRun) {
                Write-CCDCLog "[DRYRUN] Would set read-only ACLs on $($sp.Path)." -Level 'DRYRUN'
                continue
            }
            foreach ($id in @('Everyone', 'BUILTIN\Users', 'BUILTIN\IIS_IUSRS', 'IUSR')) {
                & icacls.exe "$($sp.Path)" /grant:r "${id}:(OI)(CI)RX" /c /q 2>$null | Out-Null
            }
            foreach ($k in $keepList) {
                $kp = Join-Path $sp.Path $k
                if (Test-Path -LiteralPath $kp) {
                    & icacls.exe "$kp" /grant "BUILTIN\IIS_IUSRS:(OI)(CI)M" /c /q 2>$null | Out-Null
                    Write-CCDCLog "Kept $kp writable for IIS_IUSRS." -Level 'INFO'
                }
            }
            Write-CCDCLog "Web root $($sp.Path) set read-only for low-privilege identities." -Level 'SUCCESS'
        }
    }

    Complete-CCDCCheckpoint | Out-Null
    Write-CCDCLog "Check the HTTP/HTTPS checks in Quotient now. Roll back this checkpoint if a site breaks." -Level 'ALERT'
}

function Invoke-CCDCSchannelTlsHardening {
    Assert-CCDCAdmin
    Initialize-CCDCState
    Write-CCDCLog "SCHANNEL changes need a reboot and can break old HTTPS/SMTP/LDAPS clients. Confirm the HTTPS check after reboot." -Level 'WARN'
    if (-not (Read-CCDCYesNo -Prompt "Disable SSL 2.0/3.0 and TLS 1.0/1.1, enable TLS 1.2/1.3?")) { return }
    $cp = New-CCDCCheckpoint -ModuleName 'SCHANNEL_TLS' -Description 'Disable SSL2/SSL3/TLS1.0/TLS1.1, enable TLS1.2/1.3'
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    foreach ($proto in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
        foreach ($side in @('Server', 'Client')) {
            Set-CCDCRegistryValue -Path "$base\$proto\$side" -Name 'Enabled' -Value 0 -Type DWord
            Set-CCDCRegistryValue -Path "$base\$proto\$side" -Name 'DisabledByDefault' -Value 1 -Type DWord
        }
    }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $enable = @('TLS 1.2')
    if ($os -and [int]$os.BuildNumber -ge 20348) { $enable += 'TLS 1.3' }
    foreach ($proto in $enable) {
        foreach ($side in @('Server', 'Client')) {
            Set-CCDCRegistryValue -Path "$base\$proto\$side" -Name 'Enabled' -Value 1 -Type DWord
            Set-CCDCRegistryValue -Path "$base\$proto\$side" -Name 'DisabledByDefault' -Value 0 -Type DWord
        }
    }
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
    Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
    Complete-CCDCCheckpoint | Out-Null
}

# =========================================================================
# SECTION 3: FTP SECURITY AUDIT
# =========================================================================

function Invoke-CCDCFtpSecurityAudit {
    param([int]$LookbackHours = 6)
    Assert-CCDCAdmin
    Initialize-CCDCState
    Write-CCDCLog "=== FTP Security Audit ===" -Level 'INFO'

    if ((Get-Service -Name 'FTPSVC' -ErrorAction SilentlyContinue) -and (Import-CCDCWebAdministration)) {
        foreach ($site in (Get-Website | Where-Object { $_.Bindings.Collection.protocol -contains 'ftp' })) {
            $anon = (Get-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -ErrorAction SilentlyContinue).Value
            $basic = (Get-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.security.authentication.basicAuthentication.enabled -ErrorAction SilentlyContinue).Value
            $iso = (Get-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.userIsolation.mode -ErrorAction SilentlyContinue)
            $ssl = (Get-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.security.ssl.controlChannelPolicy -ErrorAction SilentlyContinue)
            $anonLvl = if ($anon) { 'ALERT' } else { 'SUCCESS' }
            Write-CCDCLog "IIS FTP site '$($site.Name)': Anonymous=$anon Basic=$basic Isolation=$iso SSL=$ssl" -Level $anonLvl
            if ($anon -and (Read-CCDCYesNo -Prompt "  Disable anonymous FTP on '$($site.Name)'? (only if the FTP check logs in as a named user)")) {
                $cp = New-CCDCCheckpoint -ModuleName 'FTP_Anonymous' -Description "Disable anonymous FTP on $($site.Name)"
                Backup-CCDCIisConfig -BackupLabel 'FTP' | Out-Null
                if (-not $script:CCDCDryRun) {
                    Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
                }
                Complete-CCDCCheckpoint | Out-Null
            }
        }
    } else {
        Write-CCDCLog "IIS FTP service (FTPSVC) not installed." -Level 'INFO'
    }

    $fz = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)filezilla' -or $_.DisplayName -match '(?i)filezilla' }
    foreach ($s in $fz) {
        Write-CCDCLog "FileZilla service '$($s.Name)' is $($s.Status). Review users, anonymous access, and home directories in its config under ProgramData/Program Files." -Level 'WARN'
    }

    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) { Write-CCDCLog "Guest account is ENABLED (FTP risk)." -Level 'ALERT' }

    $start = (Get-Date).AddHours(-$LookbackHours)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction SilentlyContinue)
    $type8 = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        if ($d['LogonType'] -eq '8') {
            $type8.Add([PSCustomObject]@{ Time = $e.TimeCreated; User = $d['TargetUserName']; IP = $d['IpAddress'] })
        }
    }
    if ($type8.Count -gt 0) {
        Write-CCDCLog "4625 LogonType 8 (cleartext, typical of FTP) failures in last $LookbackHours h: $($type8.Count)" -Level 'ALERT'
        $type8 | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 10 |
            Select-Object @{ N = 'SourceIP'; E = { $_.Name } }, Count,
                @{ N = 'First'; E = { ($_.Group | Sort-Object Time | Select-Object -First 1).Time } },
                @{ N = 'Last'; E = { ($_.Group | Sort-Object Time | Select-Object -Last 1).Time } },
                @{ N = 'Users'; E = { ($_.Group.User | Select-Object -Unique) -join ',' } } | Format-Table -AutoSize
        Write-CCDCLog "Record IP and times for the incident report. Block a single IP with Block-CCDCAttackerIP (never a subnet)." -Level 'INFO'
    } else {
        Write-CCDCLog "No 4625 LogonType 8 failures in the last $LookbackHours h." -Level 'SUCCESS'
    }
}

# =========================================================================
# PROHIBITED / REMOTE ACCESS SOFTWARE AUDIT (read-only)
# =========================================================================

function Invoke-CCDCProhibitedSoftwareAudit {
    Assert-CCDCAdmin
    Initialize-CCDCState
    $patterns = @($script:CCDCConfig.SuspiciousSoftwarePatterns | ForEach-Object { [regex]::Escape($_) })
    $rx = '(?i)(' + ($patterns -join '|') + ')'
    $hits = New-Object System.Collections.Generic.List[object]

    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($k in $uninstallKeys) {
        foreach ($p in (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue)) {
            $dn = [string]$p.DisplayName
            if ($dn -and $dn -match $rx -and $dn -notmatch '(?i)splunk') {
                $hits.Add([PSCustomObject]@{ Type = 'Installed'; Name = $dn; Detail = "$($p.Publisher) $($p.InstallLocation)" })
            }
        }
    }
    foreach ($proc in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $text = "$($proc.Name) $($proc.ExecutablePath)"
        if ($text -match $rx -and $text -notmatch '(?i)splunk') {
            $hits.Add([PSCustomObject]@{ Type = 'Process'; Name = "$($proc.Name) (PID $($proc.ProcessId))"; Detail = $proc.CommandLine })
        }
    }
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $text = "$($svc.Name) $($svc.DisplayName) $($svc.PathName)"
        if ($text -match $rx -and $text -notmatch '(?i)splunk') {
            $hits.Add([PSCustomObject]@{ Type = 'Service'; Name = $svc.Name; Detail = $svc.PathName })
        }
    }
    $dirs = @('C:\Users', 'C:\ProgramData', 'C:\Temp', 'C:\Windows\Temp', 'C:\inetpub', 'C:\PerfLogs')
    $exts = @('.exe', '.dll', '.ps1', '.bat', '.zip', '.7z', '.msi', '.py', '.vbs')
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($exts -contains $f.Extension.ToLowerInvariant() -and $f.Name -match $rx -and $f.FullName -notmatch '(?i)splunk') {
                $hits.Add([PSCustomObject]@{ Type = 'File'; Name = $f.FullName; Detail = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
            }
        }
    }

    if ($hits.Count -eq 0) {
        Write-CCDCLog "No prohibited / remote-access software matched." -Level 'SUCCESS'
        return
    }
    $out = Join-Path (Join-Path $script:CCDCStateRoot 'Sweeps') ("ProhibitedSoftware_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
    $hits | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    $hits | Format-Table Type, Name, Detail -AutoSize -Wrap
    Write-CCDCLog "$($hits.Count) match(es) saved -> $out. Audit only: verify each, preserve evidence, then stop/disable rather than delete." -Level 'ALERT'
}

# =========================================================================
# IIS WRAPPER & INTERACTIVE MENU
# =========================================================================

function Invoke-CCDCIisAndWebHardening {
    if (-not (Test-CCDCIisPresent)) {
        Write-CCDCLog "IIS is not installed on this host." -Level 'WARN'
        return
    }
    while ($true) {
        Write-Host ""
        Write-Host "=========== CAI-WEB01: IIS / ClosedChat Hardening ===========" -ForegroundColor Cyan
        Write-Host "[1] Back up web roots + create SHA256 baseline"
        Write-Host "[2] Compare web roots to baseline + webshell scan (run every 30 min)"
        Write-Host "[3] Audit & harden IIS config (handlers, modules, app pools, filtering, headers, NTFS)"
        Write-Host "[4] SCHANNEL TLS hardening (reboot required)"
        Write-Host "[5] FTP security audit"
        Write-Host "[0] Back"
        switch (Read-Host "Select") {
            '1' { New-CCDCWebRootBaseline }
            '2' { Compare-CCDCWebRootBaseline }
            '3' { Invoke-CCDCIisConfigAuditAndHarden }
            '4' { Invoke-CCDCSchannelTlsHardening }
            '5' { Invoke-CCDCFtpSecurityAudit }
            '0' { return }
        }
    }
}

function Invoke-CCDCHostAndWebMenu {
    while ($true) {
        $role = Get-CCDCHostRole
        Write-Host ""
        Write-Host "=========== Windows Host, Defender, Firewall & IIS Hardening ($($role.ComputerName)) ===========" -ForegroundColor Cyan
        Write-Host "[1] Local account hygiene (admin rotation, Guest off, group review)"
        Write-Host "[2] Section 2.7 auditing & logging (audit policy, PS logging, 1GB logs)"
        Write-Host "[3] Local security options, user rights, unneeded services & features"
        Write-Host "[4] Defender restore & harden (kill switches, exclusions)"
        Write-Host "[5] Smart host firewall (allow detected listeners, block other inbound)"
        Write-Host "[6] IIS / ClosedChat / FTP submenu"
        Write-Host "[7] Prohibited / remote-access software audit (read-only)"
        Write-Host "[0] Back"
        switch (Read-Host "Select") {
            '1' { Invoke-CCDCLocalAccountHygiene }
            '2' {
                $sm = Read-Host "Path to Sysmon64.exe (Enter to skip)"
                $sc = if ($sm) { Read-Host "Path to Sysmon config XML (Enter for default)" } else { '' }
                Invoke-CCDCAuditingAndLogging -SysmonPath $sm -SysmonConfigPath $sc
            }
            '3' { Invoke-CCDCLocalSecurityAndOSHardening }
            '4' { Invoke-CCDCDefenderRestoreAndHarden }
            '5' { Invoke-CCDCSmartFirewall }
            '6' { Invoke-CCDCIisAndWebHardening }
            '7' { Invoke-CCDCProhibitedSoftwareAudit }
            '0' { return }
        }
    }
}
