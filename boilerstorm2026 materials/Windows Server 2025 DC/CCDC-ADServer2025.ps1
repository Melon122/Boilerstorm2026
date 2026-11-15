#Requires -Version 5.1
<#
.SYNOPSIS
    CCDC / BoilerStorm 2026 Windows Server 2025 Domain Controller & Active Directory Hardening Suite (CAI-DC01).
.DESCRIPTION
    Covers Checklist Section 2 (2.1 - 2.6) for Windows Server 2025 Tier-0 DC & DNS:
      - 2.1 Credentials (CLOSEDAI\admin, RID-500, Guest, DSRM, Double krbtgt reset, Non-scored users, Leaked Pwds & GPP cPassword)
      - 2.2 Groups & Odd Objects (Tier-0 recursive audit, Builtin users, look-alike groups like "Computer", "$" user accounts, adminCount=1)
      - 2.3 Attributes & ACLs (AS-REP, Kerberoast, Delegation/RBCD, ShadowCreds, SIDHistory, MachineAccountQuota=0, DCSync, AdminSDHolder)
      - 2.4 Server 2025 Specific (BadSuccessor / dMSA CVE-2025-53779 hunt, OU CreateChild ACLs, Windows sudo disable, 2025 baselines)
      - 2.5 Protocol Hardening (Safe vs MailSensitive toggle for cai-mail01 IMAP/Roundcube safety, with 1-click Rollback!)
      - 2.6 GPO, DNS, Shares, ADCS (Full GPO & DNS zone backups, GPO XML/ACL audit, safe Lockout Policy, ServerLevelPluginDll, Share ACLs)
    100% Offline / Local - Legal Hold safe (Disable-ADAccount, NEVER Remove-ADUser!) - Full StateEngine Rollback.
#>

if (-not (Get-Command -Name 'Write-CCDCLog' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'CCDC-StateEngine.ps1')
}

function Assert-CCDCADModule {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

# =========================================================================
# 2.1 CREDENTIALS, DOUBLE KRBTGT RESET & LEAKED PASSWORD HUNT
# =========================================================================

function Invoke-CCDCADCredentialHygiene {
    param([switch]$ForceScoredWithPCR)
    Assert-CCDCAdmin
    Assert-CCDCADModule
    Initialize-CCDCState

    $scored = Get-CCDCScoredUsers
    $domain = Get-ADDomain
    $cp = New-CCDCCheckpoint -ModuleName 'AD_Credentials' -Description 'Section 2.1 AD Credential Hygiene (admin, Guest, non-scored users)'

    Write-Host ""
    Write-CCDCLog "=== Section 2.1: AD Credentials ($($domain.DNSRoot)) ===" -Level 'INFO'
    Write-CCDCLog "Protected Quotient Scored Users ($($scored.Count)): $($scored -join ', ')" -Level 'YELLOW' -ErrorAction SilentlyContinue
    Write-CCDCLog "NOTE: Scored users are NEVER rotated unless -ForceScoredWithPCR is set. Use Quotient PCR for scored users!" -Level 'WARN'

    # 1. Rotate CLOSEDAI\admin (Initial packet password Changeme2026!)
    $adminAcct = Get-ADUser -Filter "SamAccountName -eq 'admin'" -ErrorAction SilentlyContinue
    if ($adminAcct) {
        $ans = Read-Host "Rotate password for CLOSEDAI\admin now? (Y/n)"
        if ($ans -notmatch '^(?i)n') {
            $secPwd = Read-CCDCSecurePassword -PromptLabel 'CLOSEDAI\admin'
            if (-not $script:CCDCDryRun) {
                Set-ADAccountPassword -Identity $adminAcct.DistinguishedName -Reset -NewPassword $secPwd -ErrorAction Stop
                Register-CCDCUndoBlock -UndoCode "# Password rotations are not auto-reverted; record new password securely." -ChangeSummary "Rotated CLOSEDAI\admin password"
                Write-CCDCLog "Rotated CLOSEDAI\admin password." -Level 'SUCCESS'
            }
        }
    }

    # 2. Built-in RID-500 Administrator & Guest
    $rid500 = Get-ADUser -Filter * -Properties objectSid | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($rid500) {
        Write-CCDCLog "Built-in RID-500 account: $($rid500.SamAccountName) | Enabled=$($rid500.Enabled)" -Level 'INFO'
        $ans = Read-Host "Rotate password for RID-500 ($($rid500.SamAccountName))? (Y/n)"
        if ($ans -notmatch '^(?i)n') {
            $secPwd = Read-CCDCSecurePassword -PromptLabel "RID-500 $($rid500.SamAccountName)"
            if (-not $script:CCDCDryRun) {
                Set-ADAccountPassword -Identity $rid500.DistinguishedName -Reset -NewPassword $secPwd -ErrorAction Stop
                Register-CCDCUndoBlock -UndoCode "# Password rotation recorded" -ChangeSummary "Rotated RID-500 $($rid500.SamAccountName)"
            }
        }
    }

    $guest = Get-ADUser -Filter "SamAccountName -eq 'Guest'" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        if (-not $script:CCDCDryRun) {
            Disable-ADAccount -Identity $guest.DistinguishedName
            $qDn = ConvertTo-CCDCQuotedPSString $guest.DistinguishedName
            Register-CCDCUndoBlock -UndoCode "Enable-ADAccount -Identity $qDn" -ChangeSummary "Disabled AD Guest account"
        }
        Write-CCDCLog "Disabled AD Guest account." -Level 'SUCCESS'
    }

    # 3. Check DsrmAdminLogonBehavior
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $dsrmVal = (Get-ItemProperty -LiteralPath $lsaPath -Name 'DsrmAdminLogonBehavior' -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior
    if ($null -ne $dsrmVal -and $dsrmVal -ne 0) {
        Write-CCDCLog "ALERT: DsrmAdminLogonBehavior = $dsrmVal (non-default! Attacker may log in with DSRM hash)." -Level 'ALERT'
        $fixDsrm = Read-Host "Reset DsrmAdminLogonBehavior to 0 (default)? (Y/n)"
        if ($fixDsrm -notmatch '^(?i)n') {
            Set-CCDCRegistryValue -Path $lsaPath -Name 'DsrmAdminLogonBehavior' -Value 0 -Type DWord
        }
    } else {
        Write-CCDCLog "DsrmAdminLogonBehavior is default (0/unset). To rotate DSRM password run: ntdsutil `"set dsrm password`" `"reset password on server null`" q q" -Level 'INFO'
    }

    # 4. Non-scored privileged / service accounts review
    $allUsers = @(Get-ADUser -Filter { Enabled -eq $true } -Properties adminCount, Description, ServicePrincipalName, PasswordLastSet)
    $unscoredPriv = $allUsers | Where-Object {
        $_.SamAccountName.ToLowerInvariant() -notin $scored -and
        $_.SamAccountName -notin @('krbtgt', 'admin', 'Administrator', 'Guest') -and
        ($_.adminCount -eq 1 -or $_.ServicePrincipalName.Count -gt 0)
    }
    if ($unscoredPriv) {
        Write-CCDCLog "Unscored Privileged / Service Accounts found ($($unscoredPriv.Count)):" -Level 'WARN'
        $unscoredPriv | Select-Object SamAccountName, adminCount, PasswordLastSet, @{N='SPNs';E={$_.ServicePrincipalName.Count}} | Format-Table -AutoSize
        $rot = Read-Host "Interactively rotate any listed unscored privileged account? (y/N)"
        if ($rot -match '^(?i)y') {
            foreach ($u in $unscoredPriv) {
                $doThis = Read-Host "  Rotate '$($u.SamAccountName)'? (y/N/q)"
                if ($doThis -match '^(?i)q') { break }
                if ($doThis -match '^(?i)y') {
                    $sp = Read-CCDCSecurePassword -PromptLabel $u.SamAccountName
                    if (-not $script:CCDCDryRun) {
                        Set-ADAccountPassword -Identity $u.DistinguishedName -Reset -NewPassword $sp
                        Register-CCDCUndoBlock -UndoCode "# Rotated $($u.SamAccountName)" -ChangeSummary "Rotated $($u.SamAccountName)"
                        Write-CCDCLog "Rotated $($u.SamAccountName)." -Level 'SUCCESS'
                    }
                }
            }
        }
    }

    Clear-CCDCHistory
    Complete-CCDCCheckpoint | Out-Null
}

function Invoke-CCDCKrbtgtDoubleReset {
    <#
        Resets krbtgt password TWICE to invalidate all forged Golden Tickets!
        Single-DC environment (CAI-DC01) requires no replication wait, but all existing TGTs die immediately.
    #>
    Assert-CCDCAdmin
    Assert-CCDCADModule
    Write-Host ""
    Write-CCDCLog "=== DOUBLE KRBTGT RESET (Kills Forged Golden Tickets) ===" -Level 'WARN'
    Write-CCDCLog "WARNING: Single DC (CAI-DC01) -> All active Kerberos TGTs/sessions will invalidate immediately and re-authenticate." -Level 'WARN'
    $confirm = Read-Host "Type 'RESET KRBTGT TWICE' to proceed"
    if ($confirm -cne 'RESET KRBTGT TWICE') {
        Write-CCDCLog "Aborted krbtgt reset." -Level 'INFO'
        return
    }

    $cp = New-CCDCCheckpoint -ModuleName 'AD_KrbtgtDoubleReset' -Description 'Double krbtgt password reset'
    if (-not $script:CCDCDryRun) {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        for ($round = 1; $round -le 2; $round++) {
            $bytes = New-Object byte[] 48
            $rng.GetBytes($bytes)
            $randStr = [Convert]::ToBase64String($bytes) + '!Aa1'
            $sec = ConvertTo-SecureString -String $randStr -AsPlainText -Force
            Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword $sec -ErrorAction Stop
            $randStr = $null
            Write-CCDCLog "krbtgt reset $round/2 completed." -Level 'SUCCESS'
            Start-Sleep -Seconds 2
        }
        $rng.Dispose()
        Register-CCDCUndoBlock -UndoCode "# krbtgt reset cannot be reverted." -ChangeSummary "Executed double krbtgt reset"
    }
    Complete-CCDCCheckpoint | Out-Null
}

function Invoke-CCDCADLeakedPasswordHunt {
    <#
        Scans AD Description/info attributes, SYSVOL/NETLOGON scripts, GPP cPassword XMLs, and Desktops for leaked credentials.
    #>
    Assert-CCDCAdmin
    Assert-CCDCADModule
    $outFile = Join-Path $script:CCDCStateRoot ("Sweeps\LeakedCreds_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt")
    Initialize-CCDCState

    Write-CCDCLog "=== Section 2.1: Leaked Password & GPP cPassword Hunt ===" -Level 'INFO'
    $findings = New-Object System.Collections.Generic.List[string]

    # 1. AD Description / Info fields
    $adObjs = Get-ADObject -Filter * -Properties Description, info, SamAccountName, ObjectClass |
        Where-Object { $_.Description -or $_.info }
    foreach ($o in $adObjs) {
        $text = "$($o.Description) $($o.info)"
        if ($text -match '(?i)(pass|pwd|pw:|secret|changeme|login|cred|key|token)') {
            $msg = "[AD-ATTR] $($o.ObjectClass) '$($o.Name)' ($($o.SamAccountName)): Description='$($o.Description)' Info='$($o.info)'"
            $findings.Add($msg)
            Write-CCDCLog $msg -Level 'ALERT'
        }
    }

    # 2. SYSVOL / NETLOGON scripts & GPP cPassword
    $domainDns = (Get-ADDomain).DNSRoot
    $sysvolPaths = @("\\$domainDns\SYSVOL", "\\$domainDns\NETLOGON")
    foreach ($sp in $sysvolPaths) {
        if (Test-Path -LiteralPath $sp) {
            $files = Get-ChildItem -LiteralPath $sp -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @('.xml', '.ps1', '.bat', '.cmd', '.vbs', '.txt', '.ini', '.config') }
            foreach ($f in $files) {
                $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                if ($raw -match 'cpassword\s*=\s*"([^"]+)"') {
                    $cpass = $Matches[1]
                    $msg = "[GPP-CPASSWORD] Found cpassword in $($f.FullName) (length=$($cpass.Length))!"
                    $findings.Add($msg)
                    Write-CCDCLog $msg -Level 'ALERT'
                } elseif ($raw -match '(?i)(password|pwd|changeme2026|net\s+user|convertto-securestring)') {
                    $msg = "[SYSVOL-SCRIPT] Potential credential string in $($f.FullName)"
                    $findings.Add($msg)
                    Write-CCDCLog $msg -Level 'WARN'
                }
            }
        }
    }

    # 3. Local Desktops & Public Documents (former IT handover notes)
    $noteDirs = @('C:\Users\Public', 'C:\inetpub') + @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Desktop' })
    foreach ($nd in $noteDirs) {
        if (Test-Path -LiteralPath $nd) {
            Get-ChildItem -LiteralPath $nd -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.txt', '.md', '.ps1', '.bat', '.csv') } | ForEach-Object {
                $findings.Add("[LOCAL-NOTE] $($_.FullName) (Modified: $($_.LastWriteTime))")
            }
        }
    }

    if ($findings.Count -gt 0) {
        $findings | Set-Content -LiteralPath $outFile -Encoding UTF8
        Write-CCDCLog "Saved $($findings.Count) credential/note findings -> $outFile" -Level 'SUCCESS'
    } else {
        Write-CCDCLog "No obvious leaked passwords or GPP cPassword entries found." -Level 'SUCCESS'
    }
}

# =========================================================================
# 2.2 GROUPS & ODD OBJECTS (Builtin users, "$" names, look-alike groups)
# =========================================================================

function Invoke-CCDCADGroupsAndObjectsAudit {
    Assert-CCDCAdmin
    Assert-CCDCADModule
    Initialize-CCDCState

    Write-Host ""
    Write-CCDCLog "=== Section 2.2: Tier-0 Groups & Odd AD Objects Audit ===" -Level 'INFO'
    $domain = Get-ADDomain

    # 1. Recursive Tier-0 Group Membership
    foreach ($gName in $script:CCDCConfig.Tier0Groups) {
        $grp = Get-ADGroup -Filter "Name -eq '$gName'" -ErrorAction SilentlyContinue
        if ($grp) {
            $members = @(Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue)
            $direct  = @(Get-ADGroupMember -Identity $grp -ErrorAction SilentlyContinue)
            Write-CCDCLog "Group [$gName] -> Direct: $($direct.Count), Recursive: $($members.Count)" -Level ($(if ($members.Count -gt 5) { 'WARN' } else { 'INFO' }))
            foreach ($m in $direct) {
                $tag = if ($m.objectClass -eq 'group') { '[NESTED GROUP!]' } else { "[$($m.objectClass)]" }
                Write-Host "    $tag $($m.SamAccountName) ($($m.distinguishedName))" -ForegroundColor Gray
            }
        }
    }

    # 2. Users hidden in CN=Builtin or non-standard containers
    $builtinUsers = @(Get-ADUser -Filter * -SearchBase "CN=Builtin,$($domain.DistinguishedName)" -ErrorAction SilentlyContinue)
    foreach ($bu in $builtinUsers) {
        Write-CCDCLog "TRAP DETECTED: User object inside CN=Builtin -> $($bu.SamAccountName) ($($bu.DistinguishedName))" -Level 'ALERT'
    }

    # 3. User accounts whose SamAccountName ends in '$' (Nationals 2026 backdoor DA named '$')
    $dollarUsers = @(Get-ADUser -Filter * -Properties SamAccountName, adminCount, whenCreated | Where-Object { $_.SamAccountName -match '\$$' })
    foreach ($du in $dollarUsers) {
        Write-CCDCLog "TRAP DETECTED: User account ending in '$' -> $($du.SamAccountName) (Enabled=$($du.Enabled), Created=$($du.WhenCreated))" -Level 'ALERT'
    }

    # 4. Look-alike names & recent creations (last 48h)
    $cutoff = (Get-Date).AddHours(-48)
    $recentObjs = @(Get-ADObject -Filter { whenCreated -ge $cutoff } -Properties whenCreated, SamAccountName, objectClass |
        Where-Object { $_.objectClass -in @('user', 'group', 'computer', 'msDS-DelegatedManagedServiceAccount') })
    if ($recentObjs.Count -gt 0) {
        Write-CCDCLog "Recently created AD objects (last 48h): $($recentObjs.Count)" -Level 'WARN'
        $recentObjs | Select-Object objectClass, Name, SamAccountName, whenCreated | Format-Table -AutoSize
    }

    # 5. Orphaned adminCount=1 accounts
    $adminCountUsers = @(Get-ADUser -Filter { adminCount -eq 1 } -Properties adminCount, MemberOf, Enabled)
    Write-CCDCLog "Accounts with adminCount=1 ($($adminCountUsers.Count)):" -Level 'INFO'
    $adminCountUsers | Select-Object SamAccountName, Enabled, @{N='Groups';E={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join '; '}} | Format-Table -AutoSize

    # 6. Legal-Hold Safe Interactive Disable (NEVER Remove-ADUser!)
    $scored = Get-CCDCScoredUsers
    $fix = Read-Host "Disable a suspicious AD user account (Legal Hold safe: Disable-ADAccount, never Delete)? Enter SamAccountName or press Enter to skip"
    if (-not [string]::IsNullOrWhiteSpace($fix)) {
        if ($scored -contains $fix.Trim().ToLowerInvariant()) {
            Write-CCDCLog "GUARDRAIL BLOCKED: '$fix' is in Quotient ScoredUsers list!" -Level 'ERROR'
            return
        }
        $target = Get-ADUser -Identity $fix.Trim() -Properties MemberOf -ErrorAction SilentlyContinue
        if ($target) {
            $cp = New-CCDCCheckpoint -ModuleName "AD_DisableUser_$($target.SamAccountName)" -Description "Disable suspicious AD user $($target.SamAccountName) & strip groups"
            if (-not $script:CCDCDryRun) {
                $qDn = ConvertTo-CCDCQuotedPSString $target.DistinguishedName
                Disable-ADAccount -Identity $target.DistinguishedName
                Register-CCDCUndoBlock -UndoCode "Enable-ADAccount -Identity $qDn" -ChangeSummary "Disabled $($target.SamAccountName)"
                foreach ($grpDn in $target.MemberOf) {
                    Remove-ADGroupMember -Identity $grpDn -Members $target.DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                    $qGrp = ConvertTo-CCDCQuotedPSString $grpDn
                    Register-CCDCUndoBlock -UndoCode "Add-ADGroupMember -Identity $qGrp -Members $qDn -ErrorAction SilentlyContinue" -ChangeSummary "Removed from $grpDn"
                }
                Write-CCDCLog "Disabled $($target.SamAccountName) and stripped $($target.MemberOf.Count) group memberships (preserved for Legal Hold)." -Level 'SUCCESS'
            }
            Complete-CCDCCheckpoint | Out-Null
        }
    }
}

# =========================================================================
# 2.3 ATTRIBUTES, DELEGATION, SHADOW CREDS & ACLs (DCSync / AdminSDHolder)
# =========================================================================

function Invoke-CCDCADAttributesAndACLs {
    Assert-CCDCAdmin
    Assert-CCDCADModule
    Initialize-CCDCState

    Write-Host ""
    Write-CCDCLog "=== Section 2.3: AD Risky Attributes, Delegation & ACL Audit ===" -Level 'INFO'
    $domain = Get-ADDomain

    # Risky user flags
    $users = @(Get-ADUser -Filter * -Properties PasswordNotRequired, PasswordNeverExpires, AllowReversiblePasswordEncryption, UseDESKeyOnly, DoesNotRequirePreAuth, ServicePrincipalName, AccountNotDelegated, sIDHistory, ScriptPath, ProfilePath, msDS-KeyCredentialLink, altSecurityIdentities, adminCount)

    $asrep   = @($users | Where-Object { $_.DoesNotRequirePreAuth })
    $kerb    = @($users | Where-Object { $_.ServicePrincipalName.Count -gt 0 -and $_.SamAccountName -ne 'krbtgt' })
    $pwdNotR = @($users | Where-Object { $_.PasswordNotRequired })
    $revEnc  = @($users | Where-Object { $_.AllowReversiblePasswordEncryption })
    $desOnly = @($users | Where-Object { $_.UseDESKeyOnly })
    $sidHist = @($users | Where-Object { $_.sIDHistory.Count -gt 0 })
    $shadCrd = @($users | Where-Object { $_.'msDS-KeyCredentialLink'.Count -gt 0 })
    $altSec  = @($users | Where-Object { $_.altSecurityIdentities.Count -gt 0 })
    $logonSc = @($users | Where-Object { $_.ScriptPath -or $_.ProfilePath })

    if ($asrep)   { Write-CCDCLog "AS-REP Roastable (DoesNotRequirePreAuth): $($asrep.SamAccountName -join ', ')" -Level 'ALERT' }
    if ($kerb)    { Write-CCDCLog "Kerberoastable User SPNs: $($kerb.SamAccountName -join ', ')" -Level 'WARN' }
    if ($pwdNotR) { Write-CCDCLog "PasswordNotRequired: $($pwdNotR.SamAccountName -join ', ')" -Level 'ALERT' }
    if ($revEnc)  { Write-CCDCLog "Reversible Encryption Enabled: $($revEnc.SamAccountName -join ', ')" -Level 'ALERT' }
    if ($desOnly) { Write-CCDCLog "DES Keys Only: $($desOnly.SamAccountName -join ', ')" -Level 'WARN' }
    if ($sidHist) { Write-CCDCLog "SIDHistory populated: $($sidHist.SamAccountName -join ', ')" -Level 'ALERT' }
    if ($shadCrd) { Write-CCDCLog "Shadow Credentials (msDS-KeyCredentialLink): $($shadCrd.SamAccountName -join ', ')" -Level 'ALERT' }
    if ($altSec)  { Write-CCDCLog "altSecurityIdentities populated: $($altSec.SamAccountName -join ', ')" -Level 'ALERT' }
    if ($logonSc) { Write-CCDCLog "Logon scriptPath/profilePath set on: $($logonSc.SamAccountName -join ', ')" -Level 'WARN' }

    # Unconstrained Delegation on non-DCs + RBCD
    $unconstrained = @(Get-ADObject -Filter { TrustedForDelegation -eq $true } -Properties PrimaryGroupID, SamAccountName, objectClass |
        Where-Object { $_.PrimaryGroupID -ne 516 })
    if ($unconstrained) {
        Write-CCDCLog "CRITICAL: Unconstrained Delegation on NON-DC object(s): $($unconstrained.SamAccountName -join ', ')" -Level 'ALERT'
    }
    $rbcd = @(Get-ADObject -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', SamAccountName |
        Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' })
    if ($rbcd) {
        Write-CCDCLog "CRITICAL: RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) set on: $($rbcd.SamAccountName -join ', ')" -Level 'ALERT'
    }

    # MachineAccountQuota
    $maq = (Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    Write-CCDCLog "Current ms-DS-MachineAccountQuota = $maq (recommended: 0)" -Level ($(if ($maq -gt 0) { 'WARN' } else { 'SUCCESS' }))

    # DCSync ACL audit on domain root
    $dcSyncGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes-All
        '89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
    )
    try {
        $domAcl = Get-Acl -Path "AD:\$($domain.DistinguishedName)"
        foreach ($ace in $domAcl.Access) {
            if ($ace.AccessControlType -eq 'Allow' -and ($dcSyncGuids -contains $ace.ObjectType.ToString())) {
                if ($ace.IdentityReference -notmatch '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|.*\\Domain Controllers|.*\\Enterprise Domain Controllers|.*\\Enterprise Read-only Domain Controllers)$') {
                    Write-CCDCLog "SUSPECT DCSync Right on Domain Root: $($ace.IdentityReference) -> $($ace.ObjectType)" -Level 'ALERT'
                }
            }
        }
    } catch {}

    # Optional safe fixes
    $applyFixes = Read-Host "Apply safe Attribute fixes (MachineAccountQuota=0, AccountNotDelegated on admins, clear DoesNotRequirePreAuth)? (y/N)"
    if ($applyFixes -match '^(?i)y') {
        $cp = New-CCDCCheckpoint -ModuleName 'AD_Attributes' -Description 'Harden MAQ=0, AccountNotDelegated, PreAuth'
        if (-not $script:CCDCDryRun) {
            if ($maq -ne 0) {
                $qDom = ConvertTo-CCDCQuotedPSString $domain.DistinguishedName
                Set-ADDomain -Identity $domain.DistinguishedName -Replace @{'ms-DS-MachineAccountQuota' = 0}
                Register-CCDCUndoBlock -UndoCode "Set-ADDomain -Identity $qDom -Replace @{'ms-DS-MachineAccountQuota' = $maq}" -ChangeSummary "Set MAQ 0 (was $maq)"
            }
            foreach ($u in $asrep) {
                $qDn = ConvertTo-CCDCQuotedPSString $u.DistinguishedName
                Set-ADAccountControl -Identity $u.DistinguishedName -DoesNotRequirePreAuth $false
                Register-CCDCUndoBlock -UndoCode "Set-ADAccountControl -Identity $qDn -DoesNotRequirePreAuth `$true" -ChangeSummary "Enabled Kerberos PreAuth on $($u.SamAccountName)"
            }
            foreach ($adm in ($users | Where-Object { $_.adminCount -eq 1 -and -not $_.AccountNotDelegated -and $_.SamAccountName -ne 'krbtgt' })) {
                $qDn = ConvertTo-CCDCQuotedPSString $adm.DistinguishedName
                Set-ADAccountControl -Identity $adm.DistinguishedName -AccountNotDelegated $true
                Register-CCDCUndoBlock -UndoCode "Set-ADAccountControl -Identity $qDn -AccountNotDelegated `$false" -ChangeSummary "Set AccountNotDelegated on $($adm.SamAccountName)"
            }
        }
        Complete-CCDCCheckpoint | Out-Null
    }
}

# =========================================================================
# 2.4 WINDOWS SERVER 2025 SPECIFIC (BadSuccessor / dMSA & 2025 Defaults)
# =========================================================================

function Invoke-CCDCServer2025BadSuccessorAndDefaults {
    <#
        Server 2025 BadSuccessor (CVE-2025-53779) Audit & Remediation:
        - Checks hotfixes
        - Hunts ALL msDS-DelegatedManagedServiceAccount (dMSA) objects & msDS-ManagedAccountPrecededByLink
        - Audits non-admin CreateChild permissions on OUs
        - Disables Windows sudo & enforces WDigest=0, LSA RunAsPPL
    #>
    Assert-CCDCAdmin
    Assert-CCDCADModule
    Initialize-CCDCState

    Write-Host ""
    Write-CCDCLog "=== Section 2.4: Windows Server 2025 BadSuccessor (dMSA) & Baselines ===" -Level 'INFO'

    # 1. Recent Hotfixes
    $hf = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 8)
    Write-CCDCLog "Latest installed Hotfixes (verify KB for CVE-2025-53779):" -Level 'INFO'
    $hf | Format-Table HotFixID, Description, InstalledOn -AutoSize

    # 2. Hunt dMSA objects (There should be ZERO dMSAs in BoilerStorm)
    $dmsas = @(Get-ADObject -Filter { objectClass -eq 'msDS-DelegatedManagedServiceAccount' } -Properties 'msDS-ManagedAccountPrecededByLink', 'msDS-DelegatedMSAState', whenCreated, Enabled -ErrorAction SilentlyContinue)
    if ($dmsas.Count -gt 0) {
        Write-CCDCLog "CRITICAL ALERT: Found $($dmsas.Count) dMSA object(s) (BadSuccessor vector)!" -Level 'ALERT'
        $dmsas | Select-Object Name, DistinguishedName, 'msDS-ManagedAccountPrecededByLink', 'msDS-DelegatedMSAState', whenCreated | Format-List
        $qAns = Read-Host "Disable & clear msDS-ManagedAccountPrecededByLink on all found dMSAs (Legal Hold safe)? (y/N)"
        if ($qAns -match '^(?i)y') {
            $cp = New-CCDCCheckpoint -ModuleName 'Server2025_dMSA_Quarantine' -Description 'Quarantine suspect dMSA objects'
            if (-not $script:CCDCDryRun) {
                foreach ($d in $dmsas) {
                    $qDn = ConvertTo-CCDCQuotedPSString $d.DistinguishedName
                    Disable-ADAccount -Identity $d.DistinguishedName -ErrorAction SilentlyContinue
                    Register-CCDCUndoBlock -UndoCode "Enable-ADAccount -Identity $qDn -ErrorAction SilentlyContinue" -ChangeSummary "Disabled dMSA $($d.Name)"
                    if ($d.'msDS-ManagedAccountPrecededByLink') {
                        Set-ADObject -Identity $d.DistinguishedName -Clear 'msDS-ManagedAccountPrecededByLink' -ErrorAction SilentlyContinue
                        Write-CCDCLog "Cleared predecessor link and disabled dMSA $($d.Name)." -Level 'SUCCESS'
                    }
                }
            }
            Complete-CCDCCheckpoint | Out-Null
        }
    } else {
        Write-CCDCLog "Zero dMSA (msDS-DelegatedManagedServiceAccount) objects found." -Level 'SUCCESS'
    }

    # 3. Audit OU CreateChild permissions (BadSuccessor prerequisite)
    $ous = @(Get-ADOrganizationalUnit -Filter *)
    $riskyOUs = @()
    foreach ($ou in $ous) {
        try {
            $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -eq 'Allow' -and ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)) {
                    if ($ace.IdentityReference -notmatch '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|.*\\Domain Admins|.*\\Enterprise Admins)$') {
                        Write-CCDCLog "OU CreateChild Right: [$($ou.Name)] -> $($ace.IdentityReference) ($($ace.ObjectType))" -Level 'WARN'
                        $riskyOUs += $ou
                    }
                }
            }
        } catch {}
    }

    # 4. Enforce Server 2025 Baseline Hardening (Windows sudo off, WDigest off, LSA RunAsPPL)
    $apply2025 = Read-Host "Enforce Server 2025 defaults (Disable Windows sudo, WDigest=0, LSA RunAsPPL=1)? (Y/n)"
    if ($apply2025 -notmatch '^(?i)n') {
        $cp = New-CCDCCheckpoint -ModuleName 'Server2025_Defaults' -Description 'Disable Windows sudo, WDigest=0, LSA RunAsPPL=1'
        Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -Name 'Enabled' -Value 0 -Type DWord
        if ((Get-Command 'sudo.exe' -ErrorAction SilentlyContinue) -and (-not $script:CCDCDryRun)) {
            & sudo.exe config --enable disable 2>$null | Out-Null
        }
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord
        Complete-CCDCCheckpoint | Out-Null
    }
}

# =========================================================================
# 2.5 DC PROTOCOL HARDENING (MAIL-SAFE vs MAIL-SENSITIVE WITH ROLLBACK)
# =========================================================================

function Invoke-CCDCDCProtocolHardening {
    param(
        [ValidateSet('Safe', 'MailSensitive', 'Prompt')][string]$Profile = 'Prompt'
    )
    Assert-CCDCAdmin
    Initialize-CCDCState

    if ($Profile -eq 'Prompt') {
        Write-Host ""
        Write-Host "=== Section 2.5: DC Protocol Hardening ===" -ForegroundColor Cyan
        Write-Host "[1] Safe DC Hardening (SMBv1 off, Spooler/RemoteReg off, LLMNR off, WPAD block, DHCPv6 mitm6 filter, Netlogon secure channel, Null session restrict)" -ForegroundColor Green
        Write-Host "[2] Mail-Sensitive Auth Hardening (NTLM Audit/Restrict, LmCompatibilityLevel=5, SMB Signing, LDAP Signing & Channel Binding)" -ForegroundColor Yellow
        Write-Host "    WARNING: cai-mail01 (10.42.0.40) uses AD/LDAP for IMAP/Roundcube! Apply [2] one step at a time & watch Quotient for 2 mins!" -ForegroundColor Red
        Write-Host "[0] Cancel"
        $p = Read-Host "Select profile"
        if ($p -eq '1') { $Profile = 'Safe' }
        elseif ($p -eq '2') { $Profile = 'MailSensitive' }
        else { return }
    }

    if ($Profile -eq 'Safe') {
        $cp = New-CCDCCheckpoint -ModuleName 'DC_Protocol_Safe' -Description 'DC Safe Protocol Hardening (SMBv1, Spooler, LLMNR, WPAD, mitm6, Netlogon)'
        Backup-CCDCFirewall | Out-Null

        # Disable SMBv1
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -Type DWord
        if (-not $script:CCDCDryRun) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue }

        # Disable Print Spooler & Remote Registry on DC
        Set-CCDCServiceState -ServiceName 'Spooler' -StartupType 'Disabled' -DesiredStatus 'Stopped'
        Set-CCDCServiceState -ServiceName 'RemoteRegistry' -StartupType 'Disabled' -DesiredStatus 'Stopped'

        # Disable LLMNR & mDNS
        Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 0 -Type DWord

        # Block WPAD via DNS GlobalQueryBlockList
        if (-not $script:CCDCDryRun -and (Get-Command Set-DnsServerGlobalQueryBlockList -ErrorAction SilentlyContinue)) {
            Set-DnsServerGlobalQueryBlockList -Enable $true -List @('wpad', 'isatap') -ErrorAction SilentlyContinue
        }

        # Filter DHCPv6 (mitm6) in host firewall
        if (-not $script:CCDCDryRun) {
            Remove-NetFirewallRule -DisplayName 'CCDC_Block_DHCPv6_mitm6' -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'CCDC_Block_DHCPv6_mitm6' -Direction Inbound -Protocol UDP -LocalPort 546,547 -Action Block -Profile Any -Enabled True | Out-Null
            Register-CCDCUndoBlock -UndoCode "Remove-NetFirewallRule -DisplayName 'CCDC_Block_DHCPv6_mitm6' -ErrorAction SilentlyContinue" -ChangeSummary "Blocked DHCPv6 UDP 546/547 (mitm6)"
        }

        # Anonymous / Null session restrictions + Netlogon Secure Channel
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Value 1 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1 -Type DWord

        # RDP NLA
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord

        # Check OpenSSH administrators_authorized_keys
        $sshKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
        if (Test-Path -LiteralPath $sshKeys) {
            Write-CCDCLog "ALERT: $sshKeys exists! Inspect immediately:" -Level 'ALERT'
            Get-Content -LiteralPath $sshKeys | Write-Host -ForegroundColor Yellow
        }

        Complete-CCDCCheckpoint | Out-Null
    }
    elseif ($Profile -eq 'MailSensitive') {
        $cp = New-CCDCCheckpoint -ModuleName 'DC_Protocol_MailSensitive' -Description 'Mail-Sensitive DC Auth Hardening (NTLMv2, SMB Signing, LDAP Signing/ChannelBinding)'
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Value 2 -Type DWord
        Set-CCDCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord
        Complete-CCDCCheckpoint | Out-Null
        Write-CCDCLog "WATCH QUOTIENT FOR 2 CHECK CYCLES (IMAP / SMTP / Webmail)! If red, run Rollback immediately!" -Level 'ALERT'
    }
}

# =========================================================================
# 2.6 GPO, DNS, SHARES, ADCS
# =========================================================================

function Invoke-CCDCGpoDnsSharesAdcs {
    Assert-CCDCAdmin
    Assert-CCDCADModule
    Initialize-CCDCState

    Write-Host ""
    Write-CCDCLog "=== Section 2.6: GPO, DNS, Shares & ADCS Audit & Backup ===" -Level 'INFO'
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'

    # 1. Backup ALL GPOs
    $gpoDir = Join-Path $script:CCDCStateRoot "GPOBackups\$ts"
    New-Item -Path $gpoDir -ItemType Directory -Force | Out-Null
    if (Get-Command Backup-GPO -ErrorAction SilentlyContinue) {
        Backup-GPO -All -Path $gpoDir -ErrorAction SilentlyContinue | Out-Null
        Write-CCDCLog "Backed up all GPOs -> $gpoDir" -Level 'SUCCESS'

        foreach ($gpo in (Get-GPO -All -ErrorAction SilentlyContinue)) {
            $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
            if ($xml -match '(?i)(ImmediateTask|ScheduledTasks|RunOnce|DisableAntiSpyware|DisableRealtimeMonitoring|RestrictedGroups|StartupScript|LogonScript)') {
                Write-CCDCLog "SUSPECT GPO CONTENT in '$($gpo.DisplayName)': matched '$($Matches[1])'" -Level 'WARN'
            }
            $perms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue |
                Where-Object { $_.Trustee.Name -in @('Authenticated Users', 'Domain Users', 'Everyone') -and $_.Permission -match 'Edit|Modify|All' }
            foreach ($p in $perms) {
                Write-CCDCLog "CRITICAL GPO BACKDOOR ACL: '$($gpo.DisplayName)' gives $($p.Permission) to $($p.Trustee.Name)!" -Level 'ALERT'
            }
        }
    }

    # 2. Backup ALL DNS Zones & Check ServerLevelPluginDll
    $dnsDir = Join-Path $script:CCDCStateRoot "DNSBackups\$ts"
    New-Item -Path $dnsDir -ItemType Directory -Force | Out-Null
    if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
        foreach ($z in (Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })) {
            try {
                $expName = "CCDC_${ts}_$($z.ZoneName).dns"
                Export-DnsServerZone -Name $z.ZoneName -FileName $expName -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-CCDCLog "Exported DNS zones to System32\dns (CCDC_${ts}_*.dns)." -Level 'SUCCESS'
    }
    $pluginDll = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name 'ServerLevelPluginDll' -ErrorAction SilentlyContinue).ServerLevelPluginDll
    if ($pluginDll) {
        Write-CCDCLog "CRITICAL: DNS ServerLevelPluginDll is set to '$pluginDll' (DnsAdmins DLL injection)!" -Level 'ALERT'
    }

    # 3. Shares check (warn on Everyone write, never break scored SMB reads)
    foreach ($sh in (Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('IPC$', 'ADMIN$', 'C$') })) {
        $acc = Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue | Where-Object { $_.AccountName -match 'Everyone|Authenticated Users' -and $_.AccessRight -in @('Full', 'Change') }
        if ($acc) {
            Write-CCDCLog "WARN Share '$($sh.Name)' ($($sh.Path)) grants $($acc.AccessRight) to $($acc.AccountName)" -Level 'WARN'
        }
    }

    # 4. Safe Account Lockout Policy
    $setLock = Read-Host "Set safe Domain Account Lockout Policy (Threshold=10, Duration=5m, Window=5m)? (Y/n)"
    if ($setLock -notmatch '^(?i)n') {
        $cp = New-CCDCCheckpoint -ModuleName 'AD_LockoutPolicy' -Description 'Set safe Domain Account Lockout Policy (10 / 5m / 5m)'
        if (-not $script:CCDCDryRun) {
            $dom = Get-ADDomain
            $cur = Get-ADDefaultDomainPasswordPolicy
            $qDom = ConvertTo-CCDCQuotedPSString $dom.DistinguishedName
            $undo = "Set-ADDefaultDomainPasswordPolicy -Identity $qDom -LockoutThreshold $($cur.LockoutThreshold) -LockoutDuration '$($cur.LockoutDuration)' -LockoutObservationWindow '$($cur.LockoutObservationWindow)'"
            Set-ADDefaultDomainPasswordPolicy -Identity $dom.DistinguishedName -LockoutThreshold 10 -LockoutDuration (New-TimeSpan -Minutes 5) -LockoutObservationWindow (New-TimeSpan -Minutes 5)
            Register-CCDCUndoBlock -UndoCode $undo -ChangeSummary "Set Lockout 10 / 5m / 5m"
        }
        Complete-CCDCCheckpoint | Out-Null
    }
}

# =========================================================================
# INTERACTIVE SUB-MENU
# =========================================================================

function Invoke-CCDCADServer2025Menu {
    while ($true) {
        Write-Host ""
        Write-Host "=========== CAI-DC01: Server 2025 AD & DNS Hardening ===========" -ForegroundColor Cyan
        Write-Host "[1] 2.1 Credential Hygiene (CLOSEDAI\admin, RID-500, Guest, DSRM, Non-Scored)"
        Write-Host "[2] 2.1 Double krbtgt Reset (Kills Forged Golden Tickets)"
        Write-Host "[3] 2.1 Leaked Password & GPP cPassword Hunt"
        Write-Host "[4] 2.2 Tier-0 Groups, Builtin/`$ Users & Orphaned Objects Audit"
        Write-Host "[5] 2.3 Attributes, Delegation/RBCD, ShadowCreds & DCSync ACL Audit"
        Write-Host "[6] 2.4 Server 2025 BadSuccessor (dMSA CVE-2025-53779) & Windows sudo Off"
        Write-Host "[7] 2.5 DC Protocol Hardening (Safe Profile vs Mail-Sensitive Profile)"
        Write-Host "[8] 2.6 GPO/DNS Backup & Audit, Shares, Safe Lockout Policy"
        Write-Host "[0] Return to Main Menu"
        $c = Read-Host "Select"
        switch ($c) {
            '1' { Invoke-CCDCADCredentialHygiene }
            '2' { Invoke-CCDCKrbtgtDoubleReset }
            '3' { Invoke-CCDCADLeakedPasswordHunt }
            '4' { Invoke-CCDCADGroupsAndObjectsAudit }
            '5' { Invoke-CCDCADAttributesAndACLs }
            '6' { Invoke-CCDCServer2025BadSuccessorAndDefaults }
            '7' { Invoke-CCDCDCProtocolHardening -Profile Prompt }
            '8' { Invoke-CCDCGpoDnsSharesAdcs }
            '0' { return }
        }
    }
}
