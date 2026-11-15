# Define the user rights assignments
$userRights = @{
    "SeTrustedCredManAccessPrivilege" = @()
    "SeNetworkLogonRight" = @("Administrators", "Remote Desktop Users")
    "SeTcbPrivilege" = @()
    "SeIncreaseQuotaPrivilege" = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE")
    "SeInteractiveLogonRight" = @("Administrators", "Users")
    "SeRemoteInteractiveLogonRight" = @("Administrators", "Remote Desktop Users")
    "SeBackupPrivilege" = @("Administrators")
    "SeSystemtimePrivilege" = @("Administrators", "LOCAL SERVICE")
    "SeTimeZonePrivilege" = @("Administrators", "LOCAL SERVICE", "Users")
    "SeCreatePagefilePrivilege" = @("Administrators")
    "SeCreateTokenPrivilege" = @()
    "SeCreateGlobalPrivilege" = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")
    "SeCreatePermanentPrivilege" = @()
    "SeDebugPrivilege" = @("Administrators")
    "SeDenyNetworkLogonRight" = @("Guests")
    "SeDenyBatchLogonRight" = @("Guests")
    "SeDenyServiceLogonRight" = @("Guests")
    "SeDenyInteractiveLogonRight" = @("Guests")
    "SeDenyRemoteInteractiveLogonRight" = @("Guests")
    "SeEnableDelegationPrivilege" = @()
    "SeRemoteShutdownPrivilege" = @("Administrators")
    "SeAuditPrivilege" = @("LOCAL SERVICE", "NETWORK SERVICE")
    "SeImpersonatePrivilege" = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")
    "SeIncreaseBasePriorityPrivilege" = @("Administrators", "Window Manager\\Window Manager Group")
    "SeLoadDriverPrivilege" = @("Administrators")
    "SeLockMemoryPrivilege" = @()
    "SeBatchLogonRight" = @("Administrators")
    "SeServiceLogonRight" = @()
    "SeSecurityPrivilege" = @("Administrators")
    "SeRelabelPrivilege" = @()
    "SeSystemEnvironmentPrivilege" = @("Administrators")
    "SeManageVolumePrivilege" = @("Administrators")
    "SeProfileSingleProcessPrivilege" = @("Administrators")
    "SeSystemProfilePrivilege" = @("Administrators", "NT SERVICE\\WdiServiceHost")
    "SeAssignPrimaryTokenPrivilege" = @("LOCAL SERVICE", "NETWORK SERVICE")
    "SeRestorePrivilege" = @("Administrators")
    "SeShutdownPrivilege" = @("Administrators", "Users")
    "SeTakeOwnershipPrivilege" = @("Administrators")
}

# Apply the user rights assignments
foreach ($right in $userRights.Keys) {
    $users = $userRights[$right] -join ","
    secedit /export /cfg C:\Windows\Temp\secedit.cfg
    (Get-Content C:\Windows\Temp\secedit.cfg) -replace "($right = ).*", "`$1$users" | Set-Content C:\Windows\Temp\secedit.cfg
    secedit /configure /db C:\Windows\Temp\secedit.sdb /cfg C:\Windows\Temp\secedit.cfg /areas USER_RIGHTS
    Remove-Item C:\Windows\Temp\secedit.cfg
}

Write-Output "User rights assignments have been configured."
