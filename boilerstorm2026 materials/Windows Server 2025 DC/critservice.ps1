param(
    [switch]$FullHardening = $true,
    [switch]$ForceApply = $false
)

function Invoke-ExtremeSecurity {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    function Set-RegistryValue {
        param(
            [string]$Path,
            [string]$Name,
            [object]$Value,
            [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
        )
        try {
            if (!(Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        }
        catch {}
    }

    function Disable-WindowsFeatures {
        $featuresToDisable = @(
            "Internet-Explorer-Optional-amd64",
            "MediaPlayback",
            "WindowsMediaPlayer",
            "Printing-XPSServices-Features",
            "WorkFolders-Client",
            "SMB1Protocol",
            "MicrosoftWindowsPowerShellV2",
            "MicrosoftWindowsPowerShellV2Root"
        )
        
        foreach ($feature in $featuresToDisable) {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
        }
    }

    function Configure-NetworkSecurity {
        netsh advfirewall set allprofiles state on
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
        
        $blockPorts = @(135, 137, 138, 139, 445, 1433, 1434, 3389, 5985, 5986)
        foreach ($port in $blockPorts) {
            netsh advfirewall firewall add rule name="Block Port $port" dir=in protocol=TCP localport=$port action=block
        }

        netsh int ipv6 disable
        netsh advfirewall firewall set rule group="Remote Desktop" new enable=No
    }

    function Secure-RemoteDesktopServices {
        $rdpRegistryPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        )

        $rdpSecuritySettings = @{
            "fDenyTSConnections" = 1
            "SecurityLayer" = 2
            "UserAuthentication" = 1
            "MinEncryptionLevel" = 3
            "MaxInstanceCount" = 1
        }

        foreach ($path in $rdpRegistryPaths) {
            foreach ($setting in $rdpSecuritySettings.GetEnumerator()) {
                Set-RegistryValue -Path $path -Name $setting.Key -Value $setting.Value
            }
        }
    }

    function Configure-ServiceSecurity {
        $servicesToDisable = @(
            "RemoteRegistry", "NetTcpPortSharing", "WinRM", "Browser", 
            "MSSQL$SQLEXPRESS", "SQLBrowser", "MSSQLServerADHelper", 
            "VSS", "DiagTrack", "HomeGroupListener", "HomeGroupProvider",
            "WSearch", "SensrSvc", "ShellHWDetection", "TabletInputService"
        )

        $servicesToManual = @(
            "Spooler", "SSDPSRV", "upnphost", "PhoneSvc", "WpcMonSvc"
        )

        foreach ($service in $servicesToDisable) {
            Stop-Service $service -Force
            Set-Service $service -StartupType Disabled
        }

        foreach ($service in $servicesToManual) {
            Stop-Service $service -Force
            Set-Service $service -StartupType Manual
        }
    }

    function Secure-RegistryConfigurations {
        $registryHardeningConfigs = @{
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                "DisableCAD" = 1
                "EnableInstallerDetection" = 1
                "EnableSecureUIAPaths" = 1
                "ConsentPromptBehaviorAdmin" = 2
                "ConsentPromptBehaviorUser" = 0
                "ValidateAdminCodeSignatures" = 1
                "FilterAdministratorToken" = 1
            }
            
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
                "NoAutorun" = 1
                "NoDriveTypeAutoRun" = 255
            }
            
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
                "RestrictAnonymous" = 1
                "EveryoneIncludesAnonymous" = 0
                "LimitBlankPasswordUse" = 1
                "NoLMHash" = 1
                "AuditBaseObjects" = 1
                "CrashOnAuditFail" = 1
            }
            
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" = @{
                "EnableScripts" = 0
                "ExecutionPolicy" = "Restricted"
            }
        }

        foreach ($path in $registryHardeningConfigs.Keys) {
            $settings = $registryHardeningConfigs[$path]
            foreach ($name in $settings.Keys) {
                Set-RegistryValue -Path $path -Name $name -Value $settings[$name]
            }
        }
    }

    function Configure-AuthenticationSecurity {
        net accounts /maxpwage:30
        net accounts /minpwlen:14
        net accounts /lockoutthreshold:5
        net accounts /lockoutduration:30

        auditpol /set /category:"Account Logon" /success:enable /failure:enable
        auditpol /set /category:"Logon" /success:enable /failure:enable
        auditpol /set /category:"Account Management" /success:enable /failure:enable
    }

    function Disable-WindowsTelemetry {
        $telemetryPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        )

        foreach ($path in $telemetryPaths) {
            Set-RegistryValue -Path $path -Name "AllowTelemetry" -Value 0
        }

        Stop-Service DiagTrack -Force
        Set-Service DiagTrack -StartupType Disabled
    }

    function Secure-WindowsDefender {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -SubmitSamplesConsent 0
        Set-MpPreference -MAPSReporting 0
        Set-MpPreference -PUAProtection 2
    }

    function Main-HardeningProcess {
        Disable-WindowsFeatures
        Configure-NetworkSecurity
        Secure-RemoteDesktopServices
        Configure-ServiceSecurity
        Secure-RegistryConfigurations
        Configure-AuthenticationSecurity
        Disable-WindowsTelemetry
        Secure-WindowsDefender

        Write-Host "Extreme Security Hardening Completed. Immediate System Reboot Recommended."
    }

    if ($FullHardening -or $ForceApply) {
        Main-HardeningProcess
    }
}

Invoke-ExtremeSecurity -FullHardening
