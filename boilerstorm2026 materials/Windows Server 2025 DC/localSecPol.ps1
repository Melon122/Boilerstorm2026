# Requires -RunAsAdministrator

function Set-LocalSecurityPolicy {
    Write-Host "Configuring Local Security Policies..." -ForegroundColor Green
    
    # Create the security policy INF file
    $securityPolicy = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
EnableAdminAccount=0
EnableGuestAccount=0
LimitBlankPasswordUse=1
[System Log]
MaximumLogSize=16384
[Security Log]
MaximumLogSize=81920
[Event Audit]
AuditSystemEvents=3
AuditLogonEvents=3
AuditObjectAccess=3
AuditPrivilegeUse=3
AuditPolicyChange=3
AuditAccountManage=3
AuditProcessTracking=3
AuditDSAccess=3
AuditAccountLogon=3
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts=4,10
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogoff=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
[Service General Setting]
"DCOM Server Process Launcher",2,""
"Remote Registry",4,""
[Privilege Rights]
SeTrustedCredManAccessPrivilege=
SeNetworkLogonRight=*S-1-5-32-544,*S-1-5-32-545
SeInteractiveLogonRight=*S-1-5-32-544,*S-1-5-32-545
SeRemoteInteractiveLogonRight=*S-1-5-32-544
[Registry Keys]
"MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",0,"D:PAR(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KA;;;SY)"
"@

    # Create a temporary security policy file
    $tempPath = "$env:TEMP\secpol.inf"
    $securityPolicy | Out-File $tempPath -Force -Encoding Unicode

    try {
        # Import the security policy
        Write-Host "Importing security policy..." -ForegroundColor Yellow
        $result = secedit /configure /db secedit.sdb /cfg $tempPath /areas SECURITYPOLICY

        # Configure additional settings using registry
        Write-Host "Configuring additional security settings..." -ForegroundColor Yellow
        
        # Configure DCOM settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "MachineLaunchRestriction" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "MachineAccessRestriction" -Value 1
        
        # Configure device settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "undockwithoutlogon" -Value 0
        
        # Configure network security
        $ntlmParams = @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            Name = "RestrictSendingNTLMTraffic"
            Value = 2
            Type = "DWord"
        }
        Set-ItemProperty @ntlmParams

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully configured Local Security Policies" -ForegroundColor Green
        } else {
            Write-Host "Failed to configure Local Security Policies. Exit code: $LASTEXITCODE" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "An error occurred while configuring Local Security Policies: $_" -ForegroundColor Red
    }
    finally {
        # Cleanup
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force
        }
        if (Test-Path "secedit.sdb") {
            Remove-Item "secedit.sdb" -Force
        }
    }

    # Refresh Group Policy
    Write-Host "Refreshing Group Policy..." -ForegroundColor Yellow
    gpupdate /force
}

function Verify-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main execution
function Main {
    Write-Host "Starting Local Security Policy Configuration..." -ForegroundColor Cyan
    
    if (-not (Verify-AdminPrivileges)) {
        Write-Error "This script requires administrator privileges. Please run as administrator."
        exit 1
    }
    
    Set-LocalSecurityPolicy
    
    Write-Host "Configuration complete!" -ForegroundColor Green
}

# Run the script
Main
