#Requires -RunAsAdministrator

$logPath = "C:\SecurityHardening\Logs"
if (-not (Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory | Out-Null }
$logFile = "$logPath\HardeningLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logFile

function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$Level] $timestamp - $Message"
    Write-Host $Message
}

function Configure-ADSecurity {
    Write-SecurityLog "Configuring Active Directory Security Settings"

    try {
        $domain = Get-ADDomain
        
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName `
            -ComplexityEnabled $true `
            -MinPasswordLength 16 `
            -PasswordHistoryCount 24 `
            -MaxPasswordAge 30 `
            -MinPasswordAge 1 `
            -ReversibleEncryptionEnabled $false

        Set-ADAccountControl -Identity $domain.DistinguishedName `
            -AccountNotDelegated $true `
            -AllowReversiblePasswordEncryption $false `
            -PasswordNeverExpires $false

        Set-ADDomainController -Identity (Get-ADDomainController).HostName `
            -SysvolReady $true `
            -LogReplicationTraffic $true

        Get-ADUser -Filter * | Set-ADUser -PasswordNotRequired $false -CannotChangePassword $false

        $gpoName = "Enhanced Security Policy"
        New-GPO -Name $gpoName | New-GPLink -Target $domain.DistinguishedName

        Set-GPRegistryValue -Name $gpoName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -ValueName "NoRun" -Type DWord -Value 1

        Set-GPRegistryValue -Name $gpoName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName "DisableRegistryTools" -Type DWord -Value 1

        Write-SecurityLog "Advanced AD Security Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "AD Security Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-NetworkSecurity {
    Write-SecurityLog "Configuring Advanced Network Security"

    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallRule -Group "@FirewallAPI.dll,-25000" -Enabled False
        
        $restrictedServices = @(
            "Browser", "RemoteRegistry", "NetTcpPortSharing", 
            "SSDPSRV", "upnphost", "WinRM", "RemoteAccess"
        )

        foreach ($service in $restrictedServices) {
            Set-Service -Name $service -StartupType Disabled
            Stop-Service -Name $service -Force
        }

        Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
        
        netsh advfirewall set allprofiles state on
        netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound

        Write-SecurityLog "Network Security Enhanced" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Network Security Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-RegistrySecurity {
    Write-SecurityLog "Configuring Advanced Registry Lockdown"

    $criticalRegistrySettings = @{
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
            "DisableCAD" = 0;
            "DontDisplayLastUserName" = 1;
            "EnableLUA" = 1;
            "ConsentPromptBehaviorAdmin" = 2;
            "ConsentPromptBehaviorUser" = 1;
        }
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
            "RestrictAnonymous" = 1;
            "EveryoneIncludesAnonymous" = 0;
            "NoLMHash" = 1;
            "LmCompatibilityLevel" = 5;
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
            "NoAutoUpdate" = 0;
            "AUOptions" = 4;
        }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
            "NoRun" = 1;
            "DisallowRun" = 1;
        }
    }

    foreach ($path in $criticalRegistrySettings.Keys) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        foreach ($key in $criticalRegistrySettings[$path].Keys) {
            Set-ItemProperty -Path $path -Name $key -Value $criticalRegistrySettings[$path][$key] -ErrorAction SilentlyContinue
        }
    }

    Write-SecurityLog "Registry Security Lockdown Completed" -Level "SUCCESS"
}

function Configure-ServerManagerSecurity {
    Write-SecurityLog "Configuring Server Manager Security"

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name "CheckedUnlicensedBuilds" -Value 1

        Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Print-Client" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart
        
        $serverManagerTweaks = @{
            "EnableAutoTiles" = 0;
            "FirstRunComplete" = 1;
        }

        foreach ($tweak in $serverManagerTweaks.Keys) {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name $tweak -Value $serverManagerTweaks[$tweak]
        }

        Write-SecurityLog "Server Manager Security Enhanced" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Server Manager Security Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-AuthenticationSecurity {
    Write-SecurityLog "Configuring Advanced Authentication Security"

    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNTLMInDomain" -Value 7
        
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
        
        $policyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $policyPath -Name "DisableAutomaticRestartSignOn" -Value 1
        Set-ItemProperty -Path $policyPath -Name "ScaleLoginFormHorizontally" -Value 0

        Write-SecurityLog "Advanced Authentication Security Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Authentication Security Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-AuditLogging {
    Write-SecurityLog "Configuring Advanced Audit Logging"

    try {
        auditpol /set /category:* /success:enable /failure:enable
        
        $criticalAudits = @(
            "Account Logon",
            "Account Management",
            "DS Access",
            "Logon/Logoff",
            "Object Access",
            "Policy Change",
            "Privilege Use",
            "System"
        )

        foreach ($audit in $criticalAudits) {
            auditpol /set /category:"$audit" /success:enable /failure:enable
        }

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "SCENoApplyLegacyAuditPolicy" -Value 1

        Write-SecurityLog "Advanced Audit Logging Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Audit Logging Configuration Failed: $_" -Level "ERROR"
    }
}

function Execute-ServerHardening {
    Write-SecurityLog "Initiating Comprehensive Server Hardening"

    Configure-ADSecurity
    Configure-NetworkSecurity
    Configure-RegistrySecurity
    Configure-ServerManagerSecurity
    Configure-AuthenticationSecurity
    Configure-AuditLogging

    gpupdate /force
    
    Write-SecurityLog "Server Hardening Complete" -Level "SUCCESS"
}

Execute-ServerHardening

Stop-Transcript
