# Requires -RunAsAdministrator

function Set-UserRightsAssignment {
    Write-Host "Configuring User Rights Assignment..." -ForegroundColor Green
    
    # Create the security policy INF file
    $securityPolicy = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeBackupPrivilege = *S-1-5-32-544
SeChangeNotifyPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20
SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege =
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113
SeEnableDelegationPrivilege =
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege =
SeBatchLogonRight = *S-1-5-32-544
SeServiceLogonRight = *S-1-5-80-0
SeSecurityPrivilege = *S-1-5-32-544
SeRelabelPrivilege =
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
"@

    # Create a temporary security policy file
    $tempPath = "$env:TEMP\secpol.inf"
    $securityPolicy | Out-File $tempPath -Force -Encoding Unicode

    try {
        # Import the security policy
        Write-Host "Importing security policy..." -ForegroundColor Yellow
        $result = secedit /configure /db secedit.sdb /cfg $tempPath /areas USER_RIGHTS
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully configured User Rights Assignment" -ForegroundColor Green
        } else {
            Write-Host "Failed to configure User Rights Assignment. Exit code: $LASTEXITCODE" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "An error occurred while configuring User Rights Assignment: $_" -ForegroundColor Red
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
    Write-Host "Starting User Rights Assignment Configuration..." -ForegroundColor Cyan
    
    if (-not (Verify-AdminPrivileges)) {
        Write-Error "This script requires administrator privileges. Please run as administrator."
        exit 1
    }
    
    Set-UserRightsAssignment
    
    Write-Host "Configuration complete!" -ForegroundColor Green
}

# Run the script
Main
