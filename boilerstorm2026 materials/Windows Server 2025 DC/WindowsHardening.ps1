function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = 'String'  # Default as string
    )

    # Convert string to RegistryValueKind enum if needed
    $enumValueType = [Microsoft.Win32.RegistryValueKind]::$Type

    # Check if the registry path exists
    if (-not (Test-Path -LiteralPath $Path)) {
        # Create the registry key if it does not exist
        New-Item -Path $Path -Force | Out-Null
        Write-Host "Created registry path: $Path"
    }

    # Set the item property, creating it if necessary
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $enumValueType
    Write-Host "Set registry value: $Name to $Value at $Path"
}


function Initialize-UserManagement {
    # Function to write colored log messages
    function Write-Log {
        param($Message, $ForegroundColor = 'White')
        Add-Content -Path "$outputDir\UserManagement_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    $currentUsername = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\' | Select-Object -Last 1

    # Regular expression for username validation (max 15 characters)
    $usernameRegex = [regex]::new('^[a-zA-Z][a-zA-Z0-9._-]{0,14}$')

    function Test-Username {
        param([string]$Username)
    
        # Windows username requirements
        $reservedNames = @(
            'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount',
            'system', 'localservice', 'networkservice', 'cyberadmin', 'cyberguest'
        ) | ForEach-Object { $_.ToLower() }
    
        if ($usernameRegex.IsMatch($Username) -and 
            $reservedNames -notcontains $Username.ToLower()) {
            return $true
        }
        Write-Log "Invalid username format or reserved username: $Username" 'Red'
        return $false
    }

    # Main script starts here
    # Function to write colored log messages
    function Write-Log {
        param($Message, $ForegroundColor = 'White')
        Add-Content -Path "$outputDir\UserManagement_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    $currentUsername = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\' | Select-Object -Last 1

    # Regular expression for username validation (max 15 characters)
    $usernameRegex = [regex]::new('^[a-zA-Z][a-zA-Z0-9._-]{0,14}$')

    function Test-Username {
        param([string]$Username)
    
        # Windows username requirements
        $reservedNames = @(
            'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount',
            'system', 'localservice', 'networkservice', 'cyberadmin', 'cyberguest'
        ) | ForEach-Object { $_.ToLower() }
    
        if ($usernameRegex.IsMatch($Username) -and 
            $reservedNames -notcontains $Username.ToLower()) {
            return $true
        }
        Write-Log "Invalid username format or reserved username: $Username" 'Red'
        return $false
    }

    # Main script starts here
    function Initialize-UserManagement {
        # Check if running as administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Log "This script must be run as Administrator" 'Red'
            return $false
        }
        return $true
    }

    function Get-SecureDefaultPassword {
        # In a production environment, this should be replaced with a more secure method
        # such as reading from an encrypted configuration file or secure secret storage
        $defaultPass = "CyberPatriot101!#"
        return ConvertTo-SecureString $defaultPass -AsPlainText -Force
    }

    # Main script
    try {
        if (-not (Initialize-UserManagement)) {
            return
        }

        # Define constants
        $FILE = "correctUsers.txt"
        $SECURE_PASSWORD = Get-SecureDefaultPassword
    
        # Define default/built-in accounts to disable (explicitly lowercase)
        $DEFAULT_ACCOUNTS = @(
            'guest',
            'defaultaccount',
            'wdagutilityaccount',
            'administrator',
            'cyberadmin',
            'cyberguest'
        )

        # Verify file exists
        if (-not (Test-Path $FILE)) {
            Write-Log "Error: $FILE not found. The script requires this file to proceed." 'Red'
            return
        }

        # Read and parse file
        try {
            $rawContent = Get-Content -Path $FILE -Raw
        
            if ([string]::IsNullOrEmpty($rawContent)) {
                Write-Log "Error: $FILE is empty. The script requires valid user lists to proceed." 'Red'
                return
            }

            # Parse sections with improved validation
            $sections = $rawContent -split '(?=Authorized (Administrators|Users):)'
            $adminSection = $sections | Where-Object { $_ -match 'Authorized Administrators:' }
            $userSection = $sections | Where-Object { $_ -match 'Authorized Users:' }

            if (-not $adminSection -or -not $userSection) {
                Write-Log "Error: File format is invalid. Must contain both 'Authorized Administrators:' and 'Authorized Users:' sections." 'Red'
                return
            }

            # Parse sections into arrays with validation
            $correctAdmins = @($adminSection -replace 'Authorized Administrators:', '' -split '\r?\n' | 
                Where-Object { $_.Trim() -and (-not $_.Contains('password:')) } | 
                ForEach-Object { 
                    $username = $_.Trim()
                    if (Test-Username $username) { $username.ToLower() }
                } | Where-Object { $_ })
            
            $correctUsers = @($userSection -replace 'Authorized Users:', '' -split '\r?\n' | 
                Where-Object { $_.Trim() -and (-not $_.Contains('password:')) } | 
                ForEach-Object { 
                    $username = $_.Trim()
                    if (Test-Username $username) { $username.ToLower() }
                } | Where-Object { $_ })

            # Verify we have valid data
            if ($correctAdmins.Count -eq 0 -and $correctUsers.Count -eq 0) {
                Write-Log "Error: No valid administrators or users found in $FILE" 'Red'
                Write-Log "The file must contain at least one administrator or user" 'Red'
                return
            }

            # Cache current system state to minimize API calls
            $currentUsers = @{}
            Get-LocalUser | ForEach-Object {
                $currentUsers[$_.Name.ToLower()] = @{
                    Name    = $_.Name
                    Enabled = $_.Enabled
                    Object  = $_
                }
            }

            $currentAdmins = @{}
            Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
            ForEach-Object {
                $name = ($_.Name -split "\\")[1]
                $currentAdmins[$name.ToLower()] = $name
            }

            # Handle user removal
            $usersToRemove = $currentUsers.Keys | Where-Object { 
                $_ -notin $correctAdmins -and 
                $_ -notin $correctUsers -and
                $_ -notin $DEFAULT_ACCOUNTS -and
                $_ -ne $currentUsername.ToLower()
            }

            if ($usersToRemove) {
                Write-Log "`nUsers to be removed:" 'Yellow'
                $usersToRemove | ForEach-Object { Write-Log "  - $($currentUsers[$_].Name)" 'White' }
            
                $confirm = Read-Host "`nWARNING: Are you sure you want to remove these users? (y/n)"
                if ($confirm.ToLower() -eq 'y') {
                    foreach ($username in $usersToRemove) {
                        try {
                            Remove-LocalUser -Name $currentUsers[$username].Name -ErrorAction Stop
                            Write-Log "Removed user: $($currentUsers[$username].Name)" 'Green'
                        }
                        catch {
                            Write-Log "Failed to remove user $($currentUsers[$username].Name): $($_.Exception.Message)" 'Red'
                        }
                    }
                }
            }

            # Track password update status
            $updatedUsers = @()

            # Enable all required users and create if necessary
            $allRequired = $correctAdmins + $correctUsers | Select-Object -Unique
            foreach ($username in $allRequired) {
                if (-not (Test-Username $username)) { continue }
            
                try {
                    if (-not $currentUsers.ContainsKey($username)) {
                        # Create new user
                        New-LocalUser -Name $username -Password $SECURE_PASSWORD -PasswordNeverExpires $false
                        $currentName = $username
                        Write-Log "Created user: $username" 'Green'
                    }
                    else {
                        $currentName = $currentUsers[$username].Name
                        # Update existing user's password
                        Set-LocalUser -Name $currentName -Password $SECURE_PASSWORD
                        Write-Log "Updated password for: $currentName" 'Green'
                    }

                    # Apply all user settings in one go
                    Enable-LocalUser -Name $currentName
                    Set-LocalUser -Name $currentName -PasswordNeverExpires $false
                    Set-LocalUser -Name $currentName -UserMayChangePassword $true
                
                    $updatedUsers += $username
                    Write-Log "Applied security settings to: $currentName" 'Green'
                
                }
                catch {
                    Write-Log "Failed to process user $currentName`: $($_.Exception.Message)" 'Red'
                    continue
                }
            }

            # Disable default accounts
            foreach ($defaultAccount in $DEFAULT_ACCOUNTS) {
                $account = Get-LocalUser -Name $defaultAccount -ErrorAction SilentlyContinue
                if ($account) {
                    try {
                        Disable-LocalUser -Name $defaultAccount
                        Write-Log "Disabled default account: $defaultAccount" 'Green'
                    }
                    catch {
                        Write-Log "Failed to disable ${defaultAccount}: $($_.Exception.Message)" 'Red'
                    }
                }
            }

            # Update administrator memberships
            Write-Log "`nAdministrator changes needed:" 'Cyan'
            $adminsToAdd = $correctAdmins | Where-Object { 
                $_ -notin $currentAdmins.Keys -and 
                $currentUsers.ContainsKey($_)  # Only add existing users
            }
            $adminsToRemove = $currentAdmins.Keys | Where-Object { 
                $_ -notin $correctAdmins -and 
                $_ -notin $DEFAULT_ACCOUNTS -and
                $_ -ne $currentUsername.ToLower()
            }

            if ($adminsToAdd -or $adminsToRemove) {
                if ($adminsToAdd) {
                    Write-Log "`nAdministrators to add:" 'Yellow'
                    $adminsToAdd | ForEach-Object { Write-Log "  - $_" 'White' }
                }
                if ($adminsToRemove) {
                    Write-Log "`nAdministrators to remove:" 'Yellow'
                    $adminsToRemove | ForEach-Object { Write-Log "  - $_" 'White' }
                }

                $confirm = Read-Host "`nWARNING: Do you want to proceed with these administrator changes? (y/n)"
                if ($confirm.ToLower() -eq 'y') {
                    foreach ($admin in $adminsToAdd) {
                        try {
                            Add-LocalGroupMember -Group "Administrators" -Member $currentUsers[$admin].Name
                            Write-Log "Added to administrators: $($currentUsers[$admin].Name)" 'Green'
                        }
                        catch {
                            Write-Log "Failed to add $($currentUsers[$admin].Name) to administrators: $($_.Exception.Message)" 'Red'
                        }
                    }

                    foreach ($admin in $adminsToRemove) {
                        try {
                            Remove-LocalGroupMember -Group "Administrators" -Member $currentAdmins[$admin]
                            Write-Log "Removed from administrators: $($currentAdmins[$admin])" 'Green'
                        }
                        catch {
                            Write-Log "Failed to remove $($currentAdmins[$admin]) from administrators: $($_.Exception.Message)" 'Red'
                        }
                    }
                }
            }
            else {
                Write-Log "No administrator changes needed" 'Green'
            }

            Write-Log "`nScript completed successfully" 'Green'
            if ($updatedUsers) {
                Write-Log "The following users have been set with the default password:" 'Yellow'
                $updatedUsers | ForEach-Object { Write-Log "  - $_" 'White' }
                Write-Log "Please ensure to check groups and permissions" 'Magenta'
            }

        }
        catch {
            Write-Log "Error reading or parsing $FILE`: $($_.Exception.Message)" 'Red'
            Write-Log "Please verify the file format and try again" 'Red'
            return
        }

    }
    catch {
        Write-Log "`nAn error occurred: $($_.Exception.Message)" 'Red'
        return
    }
}
function Set-SecPol {
    function Write-Log {
        param($Message, $ForegroundColor = 'White')
    
        Add-Content -Path "$outputDir\SecPol_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    function Set-UserRightsAssignment {
        Write-Log "Configuring User Rights Assignment..." 'Green'
        
        # Create the security policy INF file
        $securityPolicy = @"
[Unicode]
Unicode=yes

[Version]
signature="`$CHICAGO`$"
Revision=1

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3

[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,"1"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,"1"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"0"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"1"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483640
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"AUTHORIZED ACCESS ONLY!"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,Authorized access only. Any unlawful access to this machine will be dealt with in the full extent of the law.
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts=4,5
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,1
MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection=4,2
MACHINE\Software\Policies\Microsoft\Windows NT\DCOM\MachineAccessRestriction=1,""
MACHINE\Software\Policies\Microsoft\Windows NT\DCOM\MachineLaunchRestriction=1,""
MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,1
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers=7,
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,"O:BAG:BAD:(A;;RC;;;BA)"
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,1
MACHINE\System\CurrentControlSet\Control\SAM\ComputerAccountReuseAllowList=1,""
MACHINE\System\CurrentControlSet\Control\SAM\MinimumPasswordLengthAudit=4,14
MACHINE\System\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits=4,1
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableS4U2SelfForClaims=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel=4,2
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,2
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain=4,7
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DCAllowedNTLMServers=7,
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain=4,7
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList=1,""
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding=4,2
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2

[Privilege Rights]

; Logon Rights
SeBatchLogonRight = *S-1-5-32-544 ; Administrators only (Log on as a batch job) CIS 2.2.28 L2
SeDenyBatchLogonRight = *S-1-5-32-546 ; Guests (Deny logon as a batch job) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:929d77cdd3ddec8b336a22f009bf6b03
SeInteractiveLogonRight = *S-1-5-32-544, *S-1-5-32-545; Administrators and Users (Log on locally) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:3910a2887a3837e367d9c23c074083f3
SeDenyInteractiveLogonRight = *S-1-5-32-546 ; Guests (Deny local logon) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:39fe2410f87f6c58b68dd5d0ad886ca0
SeServiceLogonRight = ; No one (Log on as a service) CIS 2.2.29 L2
SeDenyServiceLogonRight = *S-1-5-32-546 ; Guests (Deny logon as a service) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:776bdd53c1947c77c9040727efe1151e
SeNetworkLogonRight = *S-1-5-32-544, *S-1-5-32-555; Administrators and RDP (Access this Computer from the Network) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a6d46ecce5f0d506b6775eb06d9cffac
SeDenyNetworkLogonRight = *S-1-5-32-546 ; Guest only (Deny Access to this computer via network) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:9dc79d00871379d91ddde4c332846e0e
SeRemoteInteractiveLogonRight = *S-1-5-32-544, *S-1-5-32-555 ; Administrators and RDP (Allow logon through RDP/Terminal Services) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:bde3e21915b85075789f53eaed43b7a4
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546 ; Users group (Deny logon through RDP/Terminal Services) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:ff6058882444ce03fbedd0cdf9cec51b

; System Admin Privileges
SeAuditPrivilege = *S-1-5-19, *S-1-5-20 ; Administrators only (Generate security audits) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:39c67ccbfc6194b6d384b7a2785395d4
SeSecurityPrivilege = *S-1-5-32-544 ; Administrators only (Manage auditing and security log) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:ec026f79b76d737892bb49b45cf9b7c9
SeBackupPrivilege = *S-1-5-32-544 ; Administrators only (Backup files and directories) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e69aa3c164210bd793660cbeabf6f9e2
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544 ; Administrators only (Create symbolic links) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f3d5f831782de1e66ad8d5766581d190
SeMachineAccountPrivilege = *S-1-5-32-544   ; Administrators only (Add workstations to the domain) don't think important for windows 10/11 but https://www.stigviewer.com/stig/windows_server_2019/2019-07-09/finding/V-93039
SeShutdownPrivilege = *S-1-5-32-544, *S-1-5-32-545 ; Administrators and Users (Shut down the system) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:9eb5abc7d7fb665dba2b67635cddb212
SeRemoteShutdownPrivilege = *S-1-5-32-544 ; Administrators only (Force shutdown from a remote system) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6db39f126fb0c851b037feec90ccc551
SeCreatePagefilePrivilege = *S-1-5-32-544 ; Administrators only (Create a pagefile) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:45defc1b45146f1885a0e3fe1a71c9f1
SeIncreaseQuotaPrivilege = *S-1-5-32-544, *S-1-5-19, *S-1-5-20 ; Administrators, Local Service, and Network Service (Increase quotas) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:386b81db0e38c1f60f76adb7c487a12f
SeRestorePrivilege = *S-1-5-32-544 ; Administrators only (Restore files and directories) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:889abca31d60614a715092d00788bb76
SeSystemTimePrivilege = *S-1-5-32-544, *S-1-5-19 ; Administrators and Local System (Change the system time) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f8f2c2850c5af82d59a681279b380152
SeTimeZonePrivilege = *S-1-5-32-544, *S-1-5-19, *S-1-5-32-545 ; Administrators, Local System, and Users (Change the time zone) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a62542a41625dbe1ff2afdf70b4f43f1
SeTakeOwnershipPrivilege = *S-1-5-32-544 ; Administrators only (Take ownership of files/objects) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6716d560f89c77bc8fa079614d984c6f
SeEnableDelegationPrivilege = ; No one (Enable computer/user accounts to be trusted for delegation) https://www.stigviewer.com/stig/microsoft_windows_11/2022-06-24/finding/V-253492
SeUndockPrivilege = *S-1-5-32-544   ; Administrators only (Remove computer from docking station)

; Service Privileges
SeCreatePermanentPrivilege = ; No one (Create permanent shared objects) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:5c6e085963fe2770b056500ed5197275
SeCreateTokenPrivilege = ; No one (Create a token object) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7bc9954f5e30662c6a33d131d3342bca
SeAssignPrimaryTokenPrivilege = *S-1-5-19, *S-1-5-20 ; Local Service and Network Service (Replace a process-level token) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:53676066b5ee4ec7ffba3fe5c9c540fb
SeImpersonatePrivilege = *S-1-5-32-544, *S-1-5-19, *S-1-5-20, *S-1-5-6; Administrators, Local Service, Network Service, and Service (Impersonate a client after authentication) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:4e9c510f21c091e1899aa3727e554998
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544, *S-1-5-90-0; Administrators and Windows Manager Group (Increase scheduling priority) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:b86e5778a5043fa85ed085bf4aa74d3e
SeTcbPrivilege = ; No one (Act as part of the Operating System) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:29203db8418ace4373400c652f0305af
SeProfileSingleProcessPrivilege = *S-1-5-32-544 ; Administrators only (Profile a single process) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6e9d41f5b88f3cb06977fdc6c8878080
SeLoadDriverPrivilege = *S-1-5-32-544 ; Administrators only (Load and unload device drivers) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:3657940a47edff55d56ae6b3464652e3
SeLockMemoryPrivilege = ; No one (Lock pages in memory) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:9bd42558bbbaefca0b0900b1d12799a8
SeCreateGlobalPrivilege = *S-1-5-32-544, *S-1-5-19, *S-1-5-20, *S-1-5-6 ; Administrators, Local Service, Network Service, Service (Create global objects) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:860cac4c84de1958ab14514c687b53d4

; Misc Privileges
SeDebugPrivilege = *S-1-5-32-544 ; Administrators only (Debug programs) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:36c8305febb6ae13b193e0dc5a1e649f
SeChangeNotifyPrivilege = *S-1-5-32-544, *S-1-5-32-545, *S-1-5-19, *S-1-5-20, *S-1-5-90-0; Administrators, Users, Local Service, Network Service, Windows Manager Group (Bypass traverse checking) idk how accurate this is https://www.stigviewer.com/stig/windows_server_2012_2012_r2_member_server/2015-06-26/finding/V-26475
SeIncreaseWorkingSetPrivilege = *S-1-5-32-544, *S-1-5-19 ; Administrators and Local Service (Increase a process working set) https://www.stigviewer.com/stig/windows_7/2016-07-22/finding/V-26491
SeRelabelPrivilege = ; No one (Modify an object label) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:1e7f6bc22dd57be458c59673f5089890
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544   ; Administrators only (Obtain an impersonation token for another user in the same session)
SeSyncAgentPrivilege = ; No one (Sync directory service data) https://www.stigviewer.com/stig/windows_server_2012_domain_controller/2014-01-07/finding/V-12780
SeSystemEnvironmentPrivilege = *S-1-5-32-544 ; Administrators only (Edit firmware environment values) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7c439b1c36a7e7cc2a6343dd40c63e83
SeTrustedCredManAccessPrivilege = ; No one (Access Credential Manager as a trusted caller) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:cb606ee3225bf264efe40276b6f6efbe
SeManageVolumePrivilege = *S-1-5-32-544 ; Administrators only (Perform volume maintenance tasks) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:4893b98e3edd63bf0a6a0ba080f63f3f
SeSystemProfilePrivilege = *S-1-5-32-544, *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420 ; Administrators and NT SERVICE/WdiServiceHost (Profile system performance) https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:041e8ce68f1ceb3d94958714c8b4bf68

[System Access]
PasswordHistorySize = 24
MaximumPasswordAge = 90
MinimumPasswordAge = 5
MinimumPasswordLength = 14
PasswordComplexity = 1
MinimumPasswordLengthLimits = 1 ; Check in registry too
ClearTextPassword = 0 ; 
AccountLockoutDuration = 0
AccountLockoutThreshold = 5
ResetLockoutCount = 15
LockoutBadCount = 5 ; This is the same as AccountLockoutThreshold pretty sure this is the one that actually does stuff tho
EnableAdminAccountLockout = 1
ResetLockoutCount = 30
LockoutDuration = 30
AllowAdministratorLockout = 1
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 1
NewAdministratorName = "cyberadmin"
NewGuestName = "cyberguest"
LSAAnonymousNameLookup = 0
EnableAdminAccount = 0
EnableGuestAccount = 0 ;
"@
        # Create a temporary security policy file
        $tempPath = "$env:TEMP\secpol.inf"
        $securityPolicy | Out-File $tempPath -Force -Encoding Unicode
        Get-Content $tempPath
    
        #prompts user to confirm
        $confirm = Read-Host "Do you want to import the security policy? (y/n)"
        if ($confirm -eq "y") {
            Write-Log "Importing security policy..."  'Yellow'
    
    
    
            try {
                # Import the security policy
                Write-Log "Importing security policy..."  Yellow
                secedit /configure /db secedit.sdb /cfg $tempPath /overwrite /areas securitypolicy group_mgmt user_rights regkeys filestore services
            
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Successfully configured User Rights Assignment"  Green
                }
                else {
                    Write-Log "Failed to configure User Rights Assignment. Exit code: $LASTEXITCODE"  Red
                }
            }
            catch {
                Write-Log "An error occurred while configuring User Rights Assignment: $_"  Red
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
            Write-Log "Refreshing Group Policy..."  Yellow
        }
    }
    
    # Main execution
    function Execute {
        Write-Log "Starting Security Policy Configuration..."  Cyan
        
        Set-UserRightsAssignment
        
        Write-Log "Configuration complete!"  Green
    }
    
    # Run the script
    Execute
}

function Remove-Packages {
    function Write-Log {
        param($Message, $ForegroundColor = 'White')
    
        Add-Content -Path "$outputDir\RemovePackages_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    Write-Log "Launching Uninstall Packages GUI" 'Cyan'
    try {
        Start-Process "appwiz.cpl"
        Write-Log "Uninstall Packages GUI launched successfully." Green
    }
    catch {
        Write-Log "Error launching Uninstall Packages GUI: $_" Red
    }
    return
}

function Repair-Windows {
    function Repair-WindowsTools {
        # Run System File Checker (SFC) to repair corrupted system files
        function Enter-SFC {
            Write-Host "Running System File Checker (sfc /scannow) to check and repair system files..." -ForegroundColor DarkYellow
      
            # Run the SFC scan to fix any corrupted system files
            try {
                sfc /scannow
                Write-Host "System File Checker completed. Please review any errors above." -ForegroundColor Cyan
            }
            catch {
                Write-Host "Failed to run System File Checker. Please check your system." -ForegroundColor Red
            }
        }
      
        # Check and Fix DISM
        function Repair-DISM {
            Write-Host "Checking for DISM tool..." -ForegroundColor Yellow
        
            # Try to run a simple DISM command to see if it's working
            try {
                DISM /Online /Cleanup-Image /CheckHealth
                Write-Host "DISM is available and working." -ForegroundColor Green
            }
            catch {
                Write-Host "DISM tool is missing or not working. Attempting to repair..." -ForegroundColor DarkYellow
            
                # Run a repair operation if DISM is broken
                try {
                    Write-Host "Running DISM /RestoreHealth to repair system image..." -ForegroundColor DarkYellow
                    DISM /Online /Cleanup-Image /RestoreHealth
                }
                catch {
                    Write-Host "Failed to repair DISM. Please check your Windows installation." -ForegroundColor Red
                }
            }
        }
      
        # Reinstall and Re-register AppX modules (Get-AppxPackage and Reset-AppxPackage)
        function Repair-AppXModule {
            Write-Host "Checking for AppX module..." -ForegroundColor Yellow
      
            # Try to import the AppX module
            try {
                Import-Module AppX
                Write-Host "AppX module is available." -ForegroundColor Green
            }
            catch {
                Write-Host "AppX module is missing. Attempting to reinstall it..." -ForegroundColor DarkYellow
      
                # Get all app packages
                $apps = Get-AppxPackage -AllUsers
      
                # Total number of apps to process
                $totalApps = $apps.Count
                $currentAppIndex = 0
      
                # Attempt to re-register all Windows Store apps, which should reinstall the AppX module
                try {
                    Write-Host "Re-registering all Windows Store apps..." -ForegroundColor DarkYellow
      
                    foreach ($app in $apps) {
                        # Update the progress bar
                        $currentAppIndex++
                        Write-Progress -PercentComplete (($currentAppIndex / $totalApps) * 100) `
                            -Status "Re-registering AppX" ` -ForegroundColor Green `
                            -Activity "$currentAppIndex of ${totalApps}: $($app.PackageFullName)" 
      
                        # Register the app
                        Add-AppxPackage -Register "$($app.InstallLocation)\AppXManifest.xml" -DisableDevelopmentMode
                    }
      
                    Write-Host "AppX module re-registered successfully." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to re-register AppX module. Please check your Windows Store installation." -ForegroundColor Red
                }
            }
        }
      
        # Reinstall or repair Microsoft Store and related components
        function Repair-MicrosoftStore {
            Write-Host "Checking Microsoft Store..." -ForegroundColor Yellow
      
            # Try to re-register the Microsoft Store if it's missing or broken
            try {
                Write-Host "Re-registering Microsoft Store..." -ForegroundColor DarkYellow
                Get-AppxPackage -AllUsers Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -Register "$($_.InstallLocation)\AppXManifest.xml" -DisableDevelopmentMode }
                Write-Host "Microsoft Store re-registered successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to re-register Microsoft Store. Please check your Windows Store installation." -ForegroundColor Red
            }
        }
      
      
        # Asks user if they want to repair their system and which ones to run, and has an all options (1,2,3,4 and all, and exit to leave this portion of the script)
      
        do {
            $repairSystem = Read-Host "Do you want to repair your system? (y/n)"
        } while (! $repairSystem -match "(?i)^(y|yes)$")
      
        do {
            Write-Host "Choose which tools to repair:"
            Write-Host "1. System File Checker (SFC)" -ForegroundColor DarkCyan
            Write-Host "2. DISM (System Image Repair)" -ForegroundColor DarkCyan
            Write-Host "3. AppX (Windows Store and related components)" -ForegroundColor DarkCyan
            Write-Host "4. Microsoft Store (optional)" -ForegroundColor DarkCyan
            Write-Host "5. All of the above" -ForegroundColor Cyan
            Write-Host "6. Exit (do not repair)" -ForegroundColor Yellow
            $repairTools = Read-Host "Enter your choice (1-6)" -ForegroundColor Black
            switch ($repairTools) {
                1 {
                    Enter-SFC
                    return 1
                    break
                }
                2 {
                    Repair-DISM
                    return 1
                    break
                }
                3 {
                    Repair-AppXModule
                    return 1
                    break
                }
                4 {
                    Repair-MicrosoftStore
                    return 1
                    break
                }
                5 {
                    Enter-SFC
                    Repair-DISM
                    Repair-MicrosoftStore
                    Repair-AppXModule
                    return 1
                    break
                }
                6 {
                    return 1
                    break
                }
                default {
                    Write-Host "Invalid choice. Please enter a valid option." -ForegroundColor Red
                }
            }
        } while ($true)
      
    }
}

function Remove-MediaFiles {
    
    function Write-Log {
        param($Message, $ForegroundColor = 'White')

        Add-Content -Path "$outputDir\MediaFilesScanner_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }

    # Function to prompt for file deletion
    function Remove-FileToRecycleBin {
        param($filePath)
        try {
           
            $shell = New-Object -ComObject Shell.Application
            $folder = $shell.Namespace(10)  # 10 is the Recycle Bin
            $file = $shell.Namespace((Get-Item $filePath).DirectoryName).ParseName((Get-Item $filePath).Name)
            $folder.MoveHere($file)
            Write-Log "Moved file to Recycle Bin: $filePath" Yellow
        }
        catch {
            Write-Log "Error moving file to Recycle Bin: $filePath - $_" Red
        }
    }

    # Define the path to the Start Menu Programs folder
    $currentUsername = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Split('\')[1]
    $startMenuPath = "C:\Users\$currentUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
    $recycleBinShortcutPath = "$startMenuPath\Recycle Bin.lnk"

    # Check if the Recycle Bin shortcut already exists
    if (-not (Test-Path -Path $recycleBinShortcutPath)) {
        Write-Log "Recycle Bin shortcut not found. Creating shortcut..."

        # Create a new shortcut for the Recycle Bin
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($recycleBinShortcutPath)
        $shortcut.TargetPath = "explorer.exe"
        $shortcut.Arguments = "shell:RecycleBinFolder"
        $shortcut.IconLocation = "C:\Windows\System32\imageres.dll,54"
        $shortcut.Save()

        Write-Log "Recycle Bin shortcut created successfully." Green
    }
    else {
        Write-Log "Recycle Bin shortcut already exists." Green
    }

    Write-Log "=== Media File Removal Started at $(Get-Date) ===" -ForegroundColor Cyan

    $response = Read-Host "Do you want to continue? This will delete every file with Image, Video, and Audio Extensions" 
    if (-not ($response -match '^(?i)y(es)?$')) {
        return 
        Write-Log "Aborted Media File Removal" -ForegroundColor Red
    }

    # Search for media files, excluding files in Windows system folders
    Write-Log "`nScanning for media files..." -ForegroundColor Green
    $mediaExtensions = @(
        "*.mp4", "*.avi", "*.mkv", "*.mov", # Video
        "*.mp3", "*.wav", "*.flac", "*.m4a", # Audio
        "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.webp" # Images
    )

    $excludeDirectories = @(
        "C:\CyberPatriot",
        "C:\Windows\ImmersiveControlPanel",
        "C:\Program Files\Windows Media Player\Media Renderer",
        "C:\Windows\Web\Screen",
        "C:\Program Files (x86)\Windows Media Player\Media Renderer",
        "C:\Windows\Microsoft.NET\Framework64",
        "C:\Windows\Web\4K\Wallpaper",
        "C:\Windows\WinSxS",
        "C:\Windows\ImmersiveControlPanel"
        "C:\Windows\IME\IMEJP\Assets",
        "C:\Windows\media", 
        "C:\Windows\SystemApps",
        "C:\Program Files\Windows Media Player\Network Sharing"
    )

    foreach ($ext in $mediaExtensions) {
        Write-Log "`nLocating $ext files:" -ForegroundColor Magenta
    
        # Prompt user before scanning for next extension
        $continueResponse = Read-Host "Enter y/yes to scan for $ext files, or enter to skip this extension"
        if (($continueResponse.Length -eq 0) -or (-not $response -match '^(?i)y(es)?$')) {
            Write-Log "Skipped scanning for $ext files" -ForegroundColor Yellow
            continue
        }
        $filesFound = $false

        Get-ChildItem -Path "C:\" -Include $ext -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            # Check if file is not in any of the excluded directories
            $isNotInExcludedDirectories = $true
            foreach ($excludedDir in $excludeDirectories) {
                if ($_.FullName -like "$excludedDir*") {
                    $isNotInExcludedDirectories = $false
                    break
                }
            }
            $isNotInWindowsForPng = $true
            # Special condition for PNG files to exclude C:\Windows\SystemApps
            if ($ext -eq "*.png") {
                $isNotInWindowsForPng = $isNotInWindowsForPng = ($_.FullName -notmatch [regex]::Escape("C:\Windows"))
            }
        
        
            # Main condition for excluding files
        ($isNotInExcludedDirectories -and $isNotInWindowsForPng)
        } |
        ForEach-Object {
            $filesFound = $true
            Remove-FileToRecycleBin -filePath $_.FullName
        }

    
        if (-not $filesFound) {
            Write-Log "No $ext files found" -ForegroundColor Cyan
        }
    }

    Write-Log "`n=== Media File Removal Finished at $(Get-Date) ===" -ForegroundColor Green
    Write-Log "Check Recyle Bin!! Use it to Restore Any Problematic Files" -ForegroundColor Cyan
}

function Search-UnwantedFiles {
    

    function Write-Log {
        param($Message, $ForegroundColor = 'White')
        Add-Content -Path "$outputDir\HackerTools_Games_Password_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }

    # Search for security tools and relevant software
    Write-Log "`nScanning for security-related software..."
    $securityTools = @(
        "wireshark", "nmap", "metasploit", "hashcat", "netcat", "aircrack",
        "burpsuite", "hydra", "john", "cain", "ophcrack", "sploit", "keylogger", 
        "netcat", "backdoor", "sniff", "rootkit", "openssh", "putty", "rdp", "hack", "ccleaner"
    )

    foreach ($tool in $securityTools) {
        Write-Log "`nChecking for ${tool}:"
        Get-ChildItem -Path "C:\" -Include "*${tool}*" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Log $_.FullName
        }
    }

    # Search for games and specific apps
    Write-Log "`nScanning for game directories..."
    $gamePaths = @(
        "C:\Program Files (x86)\Steam", "C:\Program Files\Steam", "C:\Games",
        "C:\Program Files (x86)\Epic Games", "C:\Program Files\Epic Games",
        "C:\Program Files (x86)\GOG Galaxy", "C:\Program Files\GOG Galaxy"
    )
    Write-Log "`nDone."

    foreach ($path in $gamePaths) {
        if (Test-Path $path) {
            Write-Host "`nFound Game related directory. Found in ${path}:"
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer } |
            ForEach-Object {
                Write-Host $_.FullName
            }
        }
    }

    $gameApps = @("pong", "tetris", "minesweeper", "solitaire", "chess", "hearts", "freecell", "mahjong", "pinball", "sudoku", "crossword", "jigsaw", "backgammon", "checkers", "reversi", "tic-tac-toe", "snake", "pac-man", "space invaders", "breakout", "asteroids", "freeciv")

    foreach ($app in $gameApps) {
        Write-Log "`nChecking for ${app}:"
        Get-ChildItem -Path "C:\" -Include "*${app}*" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Log $_.FullName
        }
    }

    # Search for password files
    Write-Log "`nScanning for password files..."
    Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*password*" } |
    ForEach-Object {
        Write-Log $_.FullName
    }

    #add script scan?

    Write-Log "`n=== Security Audit Completed at $(Get-Date) ==="
    Write-Log "Results have been saved to $outputDir\audit_log.txt"
    
}

function Set-Services {
    Get-Service -Name Bluetooth* | Stop-Service ; Get-Service -Name Bluetooth* | Set-Service -StartupType Disabled
    Get-Service -Name CaptureService* | Stop-Service ; Get-Service -Name CaptureService* | Set-Service -StartupType Disabled
    Get-Service -Name OneSyncSvc* | Stop-Service ; Get-Service -Name OneSyncSvc* | Set-Service -StartupType Disabled
    Get-Service -Name CDPUserSvc* | Stop-Service ; Get-Service -Name CDPUserSvc* | Set-Service -StartupType Disabled
    Get-Service -Name WpnUserService* | Stop-Service ; Get-Service -Name WpnUserService* | Set-Service -StartupType Disabled
    Get-Service -Name PrintWorkflowUserSvc* | Stop-Service ; Get-Service -Name PrintWorkflowUserSvc* | Set-Service -StartupType Disabled
    Get-Service -Name MessagingService* | Stop-Service ; Get-Service -Name MessagingService* | Set-Service -StartupType Disabled
    Get-Service -Name DevicesFlowUserSvc* | Stop-Service ; Get-Service -Name DevicesFlowUserSvc* | Set-Service -StartupType Disabled
    Get-Service -Name DevicePickerUserSvc* | Stop-Service ; Get-Service -Name DevicePickerUserSvc* | Set-Service -StartupType Disabled
    Get-Service -Name BcastDVRUserService* | Stop-Service ; Get-Service -Name BcastDVRUserService* | Set-Service -StartupType Disabled
    Get-Service -Name PimIndexMaintenanceSvc* | Stop-Service ; Get-Service -Name PimIndexMaintenanceSvc* | Set-Service -StartupType Disabled 
    Get-Service -Name UnistoreSvc* | Stop-Service ; Get-Service -Name UnistoreSvc* | Set-Service -StartupType Disabled
    Get-Service -Name UserDataSvc* | Stop-Service ; Get-Service -Name UserDataSvc* | Set-Service -StartupType Disabled
        
    Stop-Service -Name seclogon ; Set-Service -Name seclogon -StartupType Disabled
    Stop-Service -Name bthserv ; Set-Service -Name bthserv -StartupType Disabled
    Stop-Service -Name Fax ; Set-Service -Name Fax -StartupType Disabled
    Stop-Service -Name icssvc ; Set-Service -Name icssvc -StartupType Disabled
    Stop-Service -Name ICS ; Set-Service -Name ICS -StartupType Disabled
    Stop-Service -Name irmon ; Set-Service -Name irmon -StartupType Disabled
    Stop-Service -Name lfsvc ; Set-Service -Name lfsvc -StartupType Disabled
    Stop-Service -Name lltdsvc ; Set-Service -Name lltdsvc -StartupType Disabled
    Stop-Service -Name MapsBroker ; Set-Service -Name MapsBroker -StartupType Disabled
    Stop-Service -Name MSiSCSI ; Set-Service -Name MSiSCSI -StartupType Disabled
    Stop-Service -Name p2pimsvc ; Set-Service -Name p2pimsvc -StartupType Disabled
    Stop-Service -Name p2psvc ; Set-Service -Name p2psvc -StartupType Disabled
    Stop-Service -Name PhoneSvc ; Set-Service -Name PhoneSvc -StartupType Disabled
    Stop-Service -Name PlugPlay ; Set-Service -Name PlugPlay -StartupType Disabled
    Stop-Service -Name PNRPAutoReg ; Set-Service -Name PNRPAutoReg -StartupType Disabled
    Stop-Service -Name RasAuto ; Set-Service -Name RasAuto -StartupType Disabled
    Stop-Service -Name RemoteAccess ; Set-Service -Name RemoteAccess -StartupType Disabled
    Stop-Service -Name RemoteRegistry ; Set-Service -Name RemoteRegistry -StartupType Disabled
    Stop-Service -Name RpcLocator ; Set-Service -Name RpcLocator -StartupType Disabled
    Stop-Service -Name SessionEnv ; Set-Service -Name SessionEnv -StartupType Disabled
    Stop-Service -Name SharedAccess ; Set-Service -Name SharedAccess -StartupType Disabled
    Stop-Service -Name SSDPSRV ; Set-Service -Name SSDPSRV -StartupType Disabled
    Stop-Service -Name TermService ; Set-Service -Name TermService -StartupType Disabled
    Stop-Service -Name upnphost ; Set-Service -Name upnphost -StartupType Disabled
    Stop-Service -Name vmicrdv ; Set-Service -Name vmicrdv -StartupType Disabled
    Stop-Service -Name W3SVC ; Set-Service -Name W3SVC -StartupType Disabled
    Stop-Service -Name wercplsupport ; Set-Service -Name wercplsupport -StartupType Disabled
    Stop-Service -Name WerSvc ; Set-Service -Name WerSvc -StartupType Disabled
    Stop-Service -Name Wecsvc ; Set-Service -Name Wecsvc -StartupType Disabled
    Stop-Service -Name WinHttpAutoProxySvc ; Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled
    Stop-Service -Name WinRM ; Set-Service -Name WinRM -StartupType Disabled
    Stop-Service -Name WlanSvc ; Set-Service -Name WlanSvc -StartupType Disabled
    Stop-Service -Name W32Time ; Set-Service -Name W32Time -StartupType Disabled
    Stop-Service -Name WMPNetworkSvc ; Set-Service -Name WMPNetworkSvc -StartupType Disabled
    Stop-Service -Name WpnService ; Set-Service -Name WpnService -StartupType Disabled
    Stop-Service -Name xbgm ; Set-Service -Name xbgm -StartupType Disabled
    Stop-Service -Name XblAuthManager ; Set-Service -Name XblAuthManager -StartupType Disabled
    Stop-Service -Name XblGameSave ; Set-Service -Name XblGameSave -StartupType Disabled
    Stop-Service -Name XboxGipSvc ; Set-Service -Name XboxGipSvc -StartupType Disabled
    Stop-Service -Name XboxNetApiSvc ; Set-Service -Name XboxNetApiSvc -StartupType Disabled
    Stop-Service -Name PushToInstall ; Set-Service -Name PushToInstall -StartupType Disabled
    Stop-Service -Name spectrum ; Set-Service -Name spectrum -StartupType Disabled
    Stop-Service -Name wisvc ; Set-Service -Name wisvc -StartupType Disabled
    Stop-Service -Name StiSvc ; Set-Service -Name StiSvc -StartupType Disabled
    Stop-Service -Name FrameServer ; Set-Service -Name FrameServer -StartupType Disabled
    Stop-Service -Name WbioSrvc ; Set-Service -Name WbioSrvc -StartupType Disabled
    Stop-Service -Name WFDSConSvc ; Set-Service -Name WFDSConSvc -StartupType Disabled
    Stop-Service -Name WebClient ; Set-Service -Name WebClient -StartupType Disabled
    Stop-Service -Name WMSvc ; Set-Service -Name WMSvc -StartupType Disabled
    Stop-Service -Name WalletService ; Set-Service -Name WalletService -StartupType Disabled
    Stop-Service -Name UevAgentService ; Set-Service -Name UevAgentService -StartupType Disabled
    Stop-Service -Name UwfServcingSvc ; Set-Service -Name UwfServcingSvc -StartupType Disabled
    Stop-Service -Name TabletInputService ; Set-Service -Name TabletInputService -StartupType Disabled
    Stop-Service -Name TapiSrv ; Set-Service -Name TapiSrv -StartupType Disabled
    Stop-Service -Name WiaRpc ; Set-Service -Name WiaRpc -StartupType Disabled
    Stop-Service -Name SharedRealitySvc ; Set-Service -Name SharedRealitySvc -StartupType Disabled
    Stop-Service -Name SNMP ; Set-Service -Name SNMP -StartupType Disabled
    Stop-Service -Name ScDeviceEnum ; Set-Service -Name ScDeviceEnum -StartupType Disabled
    Stop-Service -Name simptcp ; Set-Service -Name simptcp -StartupType Disabled
    Stop-Service -Name shpamsvc ; Set-Service -Name shpamsvc -StartupType Disabled
    Stop-Service -Name SensorService ; Set-Service -Name SensorService -StartupType Disabled
    Stop-Service -Name SensrSvc ; Set-Service -Name SensrSvc -StartupType Disabled
    Stop-Service -Name SstpSvc ; Set-Service -Name SstpSvc -StartupType Disabled
    Stop-Service -Name iprip ; Set-Service -Name iprip -StartupType Disabled
    Stop-Service -Name RetailDemo ; Set-Service -Name RetailDemo -StartupType Disabled
    Stop-Service -Name RasMan ; Set-Service -Name RasMan -StartupType Disabled
    Stop-Service -Name RmSvc ; Set-Service -Name RmSvc -StartupType Disabled
    Stop-Service -Name PrintNotify ; Set-Service -Name PrintNotify -StartupType Disabled
    Stop-Service -Name WpcMonSvc ; Set-Service -Name WpcMonSvc -StartupType Disabled
    Stop-Service -Name SEMgrSvc ; Set-Service -Name SEMgrSvc -StartupType Disabled
    Stop-Service -Name CscService ; Set-Service -Name CscService -StartupType Disabled
    Stop-Service -Name NcaSVC ; Set-Service -Name NcaSVC -StartupType Disabled
    Stop-Service -Name NcbService ; Set-Service -Name NcbService -StartupType Disabled
    Stop-Service -Name NcdAutoSetup ; Set-Service -Name NcdAutoSetup -StartupType Disabled
    Stop-Service -Name Netlogon ; Set-Service -Name Netlogon -StartupType Disabled
    Stop-Service -Name NetTcpPortSharing ; Set-Service -Name NetTcpPortSharing -StartupType Disabled
    Stop-Service -Name NetTcpActivator ; Set-Service -Name NetTcpActivator -StartupType Disabled
    Stop-Service -Name NetMsmqActivator ; Set-Service -Name NetMsmqActivator -StartupType Disabled
    Stop-Service -Name Wms ; Set-Service -Name Wms -StartupType Disabled
    Stop-Service -Name WmsRepair ; Set-Service -Name WmsRepair -StartupType Disabled
    Stop-Service -Name SmsRouter ; Set-Service -Name SmsRouter -StartupType Disabled
    Stop-Service -Name MsKeyboardFilter ; Set-Service -Name MsKeyboardFilter -StartupType Disabled
    Stop-Service -Name ftpsvc ; Set-Service -Name ftpsvc -StartupType Disabled
    Stop-Service -Name AppVClient ; Set-Service -Name AppVClient -StartupType Disabled
    Stop-Service -Name wlidsvc ; Set-Service -Name wlidsvc -StartupType Disabled
    Stop-Service -Name diagnosticshub.standardcollector.service ; Set-Service -Name diagnosticshub.standardcollector.service -StartupType Disabled
    Stop-Service -Name MSMQTriggers ; Set-Service -Name MSMQTriggers -StartupType Disabled
    Stop-Service -Name MSMQ ; Set-Service -Name MSMQ -StartupType Disabled
    Stop-Service -Name LxssManager ; Set-Service -Name LxssManager -StartupType Disabled
    Stop-Service -Name LPDSVC ; Set-Service -Name LPDSVC -StartupType Disabled
    Stop-Service -Name IISADMIN ; Set-Service -Name IISADMIN -StartupType Disabled
    Stop-Service -Name vmicvss ; Set-Service -Name vmicvss -StartupType Disabled
    Stop-Service -Name vmms ; Set-Service -Name vmms -StartupType Disabled
    Stop-Service -Name vmictimesync ; Set-Service -Name vmictimesync -StartupType Disabled
    Stop-Service -Name vmicrdv ; Set-Service -Name vmicrdv -StartupType Disabled
    Stop-Service -Name vmicmsession ; Set-Service -Name vmicmsession -StartupType Disabled
    Stop-Service -Name vmcompute ; Set-Service -Name vmcompute -StartupType Disabled
    Stop-Service -Name vmicheartbeat ; Set-Service -Name vmicheartbeat -StartupType Disabled
    Stop-Service -Name vmicshutdown ; Set-Service -Name vmicshutdown -StartupType Disabled
    Stop-Service -Name vmickvpexchange ; Set-Service -Name vmickvpexchange -StartupType Disabled
    Stop-Service -Name vmicguestinterface ; Set-Service -Name vmicguestinterface -StartupType Disabled
    Stop-Service -Name HvHost ; Set-Service -Name HvHost -StartupType Disabled
    Stop-Service -Name EapHost ; Set-Service -Name EapHost -StartupType Disabled
    Stop-Service -Name dmwappushsvc ; Set-Service -Name dmwappushsvc -StartupType Disabled
    Stop-Service -Name TrkWks ; Set-Service -Name TrkWks -StartupType Disabled
    Stop-Service -Name DiagTrack ; Set-Service -Name DiagTrack -StartupType Disabled
    Stop-Service -Name NfsClnt ; Set-Service -Name NfsClnt -StartupType Disabled
    Stop-Service -Name CertPropSvc ; Set-Service -Name CertPropSvc -StartupType Disabled
    Stop-Service -Name camsvc ; Set-Service -Name camsvc -StartupType Disabled
    Stop-Service -Name PeerDistSvc ; Set-Service -Name PeerDistSvc -StartupType Disabled
    Stop-Service -Name BTAGService ; Set-Service -Name BTAGService -StartupType Disabled
    Stop-Service -Name BthAvctpSvc ; Set-Service -Name BthAvctpSvc -StartupType Disabled
    Stop-Service -Name tzautoupdate ; Set-Service -Name tzautoupdate -StartupType Disabled
    Stop-Service -Name ALG ; Set-Service -Name ALG -StartupType Disabled
    Stop-Service -Name AJRouter ; Set-Service -Name AJRouter -StartupType Disabled
    Stop-Service -Name TlntSvr ; Set-Service -Name TlntSvr -StartupType Disabled
    Stop-Service -Name Browser ; Set-Service -Name Browser -StartupType Disabled
    Stop-Service -Name sshd ; Set-Service -Name sshd -StartupType Disabled
    Stop-Service -Name sacsvr ; Set-Service -Name sacsvr -StartupType Disabled
    Stop-Service -Name HomeGroupListener ; Set-Service -Name HomeGroupListener -StartupType Disabled
    Stop-Service -Name HomeGroupProvider ; Set-Service -Name HomeGroupProvider -StartupType Disabled
    Stop-Service -Name Mcx2Svc ; Set-Service -Name Mcx2Svc -StartupType Disabled
    Stop-Service -Name idsvc ; Set-Service -Name idsvc -StartupType Disabled
    Stop-Service -Name ehRecvr ; Set-Service -Name ehRecvr -StartupType Disabled
    Stop-Service -Name RpcEptMapper ; Set-Service -Name RpcEptMapper -StartupType Disabled
    Stop-Service -Name Spooler ; Set-Service -Name Spooler -StartupType Disabled
    Stop-Service -Name WPDBusEnum ; Set-Service -Name WPDBusEnum -StartupType Disabled
    Stop-Service -Name CDPSvc ; Set-Service -Name CDPSvc -StartupType Disabled
    Stop-Service -Name AppHostSvc ; Set-Service -Name AppHostSvc -StartupType Disabled
    Stop-Service -Name BITS ; Set-Service -Name BITS -StartupType Disabled
    Stop-Service -Name InstallService ; Set-Service -Name InstallService -StartupType Disabled
    Stop-Service -Name PNRPsvc ; Set-Service -Name PNRPsvc -StartupType Disabled
    Stop-Service -Name UmRdpService ; Set-Service -Name UmRdpService -StartupType Disabled
    Stop-Service -Name LanmanServer ; Set-Service -Name LanmanServer -StartupType Disabled
    Stop-Service -Name Wecsvc ; Set-Service -Name Wecsvc -StartupType Disabled
    Stop-Service -Name FDResPub ; Set-Service -Name FDResPub -StartupType Disabled
    Stop-Service -Name fdPHost ; Set-Service -Name fdPHost -StartupType Disabled
    Stop-Service -Name MSDTC ; Set-Service -Name MSDTC -StartupType Disabled
    Stop-Service -Name DeviceAssociationService ; Set-Service -Name DeviceAssociationService -StartupType Disabled
    Stop-Service -Name PolicyAgent ; Set-Service -Name PolicyAgent -StartupType Disabled
    Stop-Service -Name EntAppSvc ; Set-Service -Name EntAppSvc -StartupType Disabled
    Stop-Service -Name AssignedAccessManagerSvc ; Set-Service -Name AssignedAccessManagerSvc -StartupType Disabled 
    Stop-Service -Name Tftpd64 ; Set-Service -Name Tftpd64 -StartupType Disabled
    Stop-Service -Name IE11 ; Set-Service -Name IE11 -StartupType Disabled
      
    Start-Service -Name BDESVC ; Set-Service -Name BDESVC -StartupType Automatic
    Start-Service -Name BFE ; Set-Service -Name BFE -StartupType Automatic
    Start-Service -Name CryptSvc ; Set-Service -Name CryptSvc -StartupType Automatic
    Start-Service -Name DcomLaunch ; Set-Service -Name DcomLaunch -StartupType Automatic
    Start-Service -Name DHCP ; Set-Service -Name DHCP -StartupType Automatic
    Start-Service -Name Dnscache ; Set-Service -Name Dnscache -StartupType Automatic
    Start-Service -Name EventLog ; Set-Service -Name EventLog -StartupType Automatic
    Start-Service -Name MpsSvc ; Set-Service -Name MpsSvc -StartupType Automatic
    Start-Service -Name nsi ; Set-Service -Name nsi -StartupType Automatic
    Start-Service -Name Power ; Set-Service -Name Power -StartupType Automatic
    Start-Service -Name SamSs ; Set-Service -Name SamSs -StartupType Automatic
    Start-Service -Name SecurityHealthService ; Set-Service -Name SecurityHealthService -StartupType Automatic
    Start-Service -Name Sense ; Set-Service -Name Sense -StartupType Automatic
    Start-Service -Name WdNisSvc ; Set-Service -Name WdNisSvc -StartupType Automatic
    Start-Service -Name WEPHOSTSVC ; Set-Service -Name WEPHOSTSVC -StartupType Automatic
    Start-Service -Name WinDefend ; Set-Service -Name WinDefend -StartupType Automatic
    Start-Service -Name wuauserv ; Set-Service -Name wuauserv -StartupType Automatic
    Start-Service -Name WSearch ; Set-Service -Name WSearch -StartupType Automatic
    Start-Service -Name TrustedInstaller ; Set-Service -Name TrustedInstaller -StartupType Automatic
    Start-Service -Name Winmgmt ; Set-Service -Name Winmgmt -StartupType Automatic
    Start-Service -Name msiserver ; Set-Service -Name msiserver -StartupType Automatic
    Start-Service -Name FontCache ; Set-Service -Name FontCache -StartupType Automatic
    Start-Service -Name Wcmsvc ; Set-Service -Name Wcmsvc -StartupType Automatic
    Start-Service -Name AudioSrv ; Set-Service -Name AudioSrv -StartupType Automatic
    Start-Service -Name AudioEndpointBuilder ; Set-Service -Name AudioEndpointBuilder -StartupType Automatic
    Start-Service -Name vds ; Set-Service -Name vds -StartupType Automatic
    Start-Service -Name ProfSvc ; Set-Service -Name ProfSvc -StartupType Automatic
    Start-Service -Name UserManager ; Set-Service -Name UserManager -StartupType Automatic
    Start-Service -Name UsoSvc ; Set-Service -Name UsoSvc -StartupType Automatic
    Start-Service -Name Themes ; Set-Service -Name Themes -StartupType Automatic
    Start-Service -Name Schedule ; Set-Service -Name Schedule -StartupType Automatic
    Start-Service -Name SgrmBroker ; Set-Service -Name SgrmBroker -StartupType Automatic
    Start-Service -Name SystemEventsBroker ; Set-Service -Name SystemEventsBroker -StartupType Automatic
    Start-Service -Name SENS ; Set-Service -Name SENS -StartupType Automatic
    Start-Service -Name SysMain ; Set-Service -Name SysMain -StartupType Automatic
    Start-Service -Name sppsvc ; Set-Service -Name sppsvc -StartupType Automatic
    Start-Service -Name wscsvc ; Set-Service -Name wscsvc -StartupType Automatic
    Start-Service -Name PcaSvc ; Set-Service -Name PcaSvc -StartupType Automatic
    Start-Service -Name RpcSs; Set-Service -Name RpcSs -StartupType Automatic
    Start-Service -Name NlaSvc ; Set-Service -Name NlaSvc -StartupType Automatic
    Start-Service -Name LSM ; Set-Service -Name LSM -StartupType Automatic
    Start-Service -Name gpsvc ; Set-Service -Name gpsvc -StartupType Automatic
    Start-Service -Name EFS ; Set-Service -Name EFS -StartupType Automatic
    Start-Service -Name DPS ; Set-Service -Name DPS -StartupType Automatic
    Start-Service -Name DoSvc ; Set-Service -Name DoSvc -StartupType Automatic
    Start-Service -Name DusmSvc ; Set-Service -Name DusmSvc -StartupType Automatic
    Start-Service -Name CoreMessagingRegistrar ; Set-Service -Name CoreMessagingRegistrar -StartupType Automatic
    Start-Service -Name EventSystem ; Set-Service -Name EventSystem -StartupType Automatic
    Start-Service -Name BrokerInfrastructure ; Set-Service -Name BrokerInfrastructure -StartupType Automatic
    Start-Service -Name StorSvc ; Set-Service -Name StorSvc -StartupType Automatic
    Start-Service -Name ClipSVC ; Set-Service -Name ClipSVC -StartupType Automatic
    Start-Service -Name c2wts ; Set-Service -Name c2wts -StartupType Automatic
      
    Set-Service -Name dot3svc -StartupType Manual  
    Set-Service -Name WaaSMedicSvc -StartupType Manual  
    Set-Service -Name wmiApSrv -StartupType Manual  
    Set-Service -Name LicenseManager -StartupType Manual  
    Set-Service -Name SDRSVC -StartupType Manual  
    Set-Service -Name TokenBroker -StartupType Manual  
    Set-Service -Name W3LOGSVC -StartupType Manual  
    Set-Service -Name VSS -StartupType Manual  
    Set-Service -Name TimeBroker -StartupType Manual  
    Set-Service -Name TieringEngineService -StartupType Manual  
    Set-Service -Name StateRepository -StartupType Manual  
    Set-Service -Name svsvc -StartupType Manual  
    Set-Service -Name QWAVE -StartupType Manual  
    Set-Service -Name pla -StartupType Manual  
    Set-Service -Name PerfHost -StartupType Manual  
    Set-Service -Name defragsvc -StartupType Manual  
    Set-Service -Name NetSetupSvc -StartupType Manual  
    Set-Service -Name netprofm -StartupType Manual  
    Set-Service -Name NetMan -StartupType Manual  
    Set-Service -Name smphost -StartupType Manual  
    Set-Service -Name swprv -StartupType Manual  
    Set-Service -Name NgcCtnrSvc -StartupType Manual  
    Set-Service -Name NgcSvc -StartupType Manual  
    Set-Service -Name wlpasvc -StartupType Manual  
    Set-Service -Name KtmRm -StartupType Manual  
    Set-Service -Name IKEEXT -StartupType Manual  
    Set-Service -Name hidserv -StartupType Manual  
    Set-Service -Name hns -StartupType Manual  
    Set-Service -Name GraphicsPerfSvc -StartupType Manual  
    Set-Service -Name fhsvc -StartupType Manual  
    Set-Service -Name embeddedmode -StartupType Manual  
    Set-Service -Name DsRoleSvc -StartupType Manual  
    Set-Service -Name DevQueryBroker -StartupType Manual  
    Set-Service -Name DsmSVC -StartupType Manual  
    Set-Service -Name DmEnrollmentSvc -StartupType Manual  
    Set-Service -Name DeviceInstall -StartupType Manual  
    Set-Service -Name DsSvc -StartupType Manual  
    Set-Service -Name COMSysApp -StartupType Manual  
    Set-Service -Name KeyIso -StartupType Manual  
    Set-Service -Name wbegine -StartupType Manual  
    Set-Service -Name aspnet_state -StartupType Manual  
    Set-Service -Name AppXSVC -StartupType Manual  
    Set-Service -Name AppMgmt -StartupType Manual  
    Set-Service -Name Appinfo -StartupType Manual  
    Set-Service -Name AppIDSvc -StartupType Manual  
    Set-Service -Name AppReadiness -StartupType Manual  
    Set-Service -Name AxInstSV -StartupType Manual  
    Set-Service -Name dot3svc -StartupType Manual  
    Set-Service -Name dot3svc -StartupType Manual  
    Set-Service -Name dot3svc -StartupType Manual  

}

function Set-Defender {
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' /v 'ExploitGuard_ASR_ASROnlyExclusions' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' /v 'ExploitGuard_ControlledFolderAccess_AllowedApplications' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'Exclusions_Extensions' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'Exclusions_Paths' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'Exclusions_Processes' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'RealtimeScanDirection' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /f
    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Threats' /v 'Threats_ThreatSeverityDefaultAction' /f

    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' /v 'EnableControlledFolderAccess' /t 'REG_DWORD' /d '1' /f

    REG DELETE 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications' /f

    # Removable Device Protection
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions' /v 'DenyRemovableDevices' /t 'REG_DWORD' /d '1' /f

    # Network Protection
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\AllowNetworkProtectionOnWinServer' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f

    Set-MpPreference -DisableRealtimeMonitoring $false
    # Disable Cloud-Delivered Protection and Automatic Sample Submission
    Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent 0
    # Set Threat Severity Actions (Choose max security actions for each level)
    Set-MpPreference -ThreatSeverityDefaultAction High Block -ThreatSeverityDefaultAction Moderate Block -ThreatSeverityDefaultAction Low Block -ThreatSeverityDefaultAction Severe Block
    # Enable PUA Protection (Potentially Unwanted Applications)
    Set-MpPreference -PUAProtection Enabled
    # Enable Scans for all downloaded files and attachments
    Set-MpPreference -DisableArchiveScanning $false -DisableScriptScanning $false -DisableIntrusionPreventionSystem $false
    # Enable Periodic Full Scans (Every day at 2:00 AM)
    Set-MpPreference -ScanScheduleQuickScanTime 120 -ScanScheduleDay 0
    # Schedule a Daily Full Scan at 2:00 AM
    Set-MpPreference -ScanParameters 2 -RemediationScheduleDay 0 -RemediationScheduleTime 120
    # Enable Network Protection for blocking suspicious connections
    Set-MpPreference -EnableNetworkProtection Enabled
    # Enable Controlled Folder Access for ransomware protection
    Set-MpPreference -EnableControlledFolderAccess Enabled
    # Start an Immediate Full Scan
    # Start-MpScan -ScanType FullScan
    # Verify the configuration
    Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring, MAPSReporting, PUAProtection, SubmitSamplesConsent, ScanParameters, ScanScheduleQuickScanTime, EnableNetworkProtection, EnableControlledFolderAccess
    # Set Defender Settings
    Set-MpPreference -AllowDatagramProcessingOnWinServer $true
    Set-MpPreference -AllowNetworkProtectionDownLevel $true
    Set-MpPreference -AllowNetworkProtectionOnWinServer $true
    Set-MpPreference -AllowSwitchToAsyncInspection $true
    Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
    Set-MpPreference -CloudBlockLevel "zeroTolerance"
    Set-MpPreference -CloudExtendedTimeout 50
    Set-MpPreference -DisableArchiveScanning $false
    Set-MpPreference -DisableAutoExclusions $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableBlockAtFirstSeen $false
    Set-MpPreference -DisableCacheMaintenance $false
    Set-MpPreference -DisableCatchupFullScan $false
    Set-MpPreference -DisableCatchupQuickScan $false
    Set-MpPreference -DisableCpuThrottleOnIdleScans $true
    Set-MpPreference -DisableDatagramProcessing $false
    Set-MpPreference -DisableDnsOverTcpParsing $false
    Set-MpPreference -DisableDnsParsing $false
    Set-MpPreference -DisableEmailScanning $false
    Set-MpPreference -DisableFtpParsing $false
    Set-MpPreference -DisableGradualRelease $false
    Set-MpPreference -DisableHttpParsing $false
    Set-MpPreference -DisableInboundConnectionFiltering $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true
    Set-MpPreference -DisablePrivacyMode $false
    Set-MpPreference -DisableRdpParsing $false
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableRemovableDriveScanning $false
    Set-MpPreference -DisableRestorePoint $false
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
    Set-MpPreference -DisableScanningNetworkFiles $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableSmtpParsing $false
    Set-MpPreference -DisableSshParsing $false
    Set-MpPreference -DisableTlsParsing $false
    Set-MpPreference -EnableControlledFolderAccess "Enabled"
    Set-MpPreference -EnableDnsSinkhole $true
    Set-MpPreference -EnableFileHashComputation $true
    Set-MpPreference -EnableFullScanOnBatteryPower $true
    Set-MpPreference -EnableLowCpuPriority $false
    Set-MpPreference -EnableNetworkProtection "Enabled"
    Set-MpPreference -EngineUpdatesChannel "NotConfigured"
    Set-MpPreference -HighThreatDefaultAction "Remove"
    Set-MpPreference -IntelTDTEnabled 1
    Set-MpPreference -LowThreatDefaultAction "Remove"
    Set-MpPreference -MAPSReporting 0
    Set-MpPreference -MeteredConnectionUpdates $true
    Set-MpPreference -ModerateThreatDefaultAction "Remove"
    Set-MpPreference -OobeEnableRtpAndSigUpdate $true
    Set-MpPreference -PlatformUpdatesChannel "NotConfigured"
    Set-MpPreference -PUAProtection "Enabled"
    Set-MpPreference -QuarantinePurgeItemsAfterDelay 1
    Set-MpPreference -RandomizeScheduleTaskTimes $true
    Set-MpPreference -RealTimeScanDirection "Both"
    Set-MpPreference -RemediationScheduleDay "Everyday"
    Set-MpPreference -ScanOnlyIfIdleEnabled $false
    Set-MpPreference -ScanParameters "FullScan"
    Set-MpPreference -ScanScheduleDay "Everyday"
    Set-MpPreference -SchedulerRandomizationTime $true
    Set-MpPreference -ServiceHealthReportInterval 60
    Set-MpPreference -SevereThreatDefaultAction "Remove"
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
    Set-MpPreference -SignatureScheduleDay "Everyday"
    Set-MpPreference -SignaturesUpdatesChannel "Everyday"
    Set-MpPreference -SignatureUpdateCatchupInterval 0
    Set-MpPreference -SubmitSamplesConsent "NeverSend"
    Set-MpPreference -UILockdown $true
    Set-MpPreference -UnknownThreatDefaultAction "Remove"

    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'PUAProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'DisableAntiSpyware' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /v 'ASSignatureDue' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /v 'AVSignatureDue' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' /v 'EnableNetworkProtection' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableRealtimeMonitoring' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableBehaviorMonitoring' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableIOAVProtection' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'DisableScanOnRealtimeEnable' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideRealtimeScanDirection' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'LocalSettingOverrideDisableOnAccessProtection' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\NIS' /v 'DisableProtocolRecognition' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions' /v 'DisableAutoExclusions' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'DisableRealtimeMonitoring' /t 'REG_DWORD' /d '0' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'DisableRoutinelyTakingAction' /t 'REG_DWORD' /d '0' /f

    # Remove Defender Exclusions
    Remove-MpPreference -AttackSurfaceReductionRules_Ids * -AttackSurfaceReductionRules_Actions * -AttackSurfaceReductionOnlyExclusions *
    Remove-MpPreference -ExclusionPath *
    Remove-MpPreference -ExclusionExtension *
    Remove-MpPreference -ExclusionProcess *
    Remove-MpPreference -ExclusionIpAddress *
    Remove-MpPreference -ThreatIDDefaultAction_Ids * -ThreatIDDefaultAction_Actions *
    Remove-MpPreference -ControlledFolderAccessAllowedApplications * -ControlledFolderAccessProtectedFolders *

    # Add ASR Rules (TODO: Add registry)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions 1
    Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions 1

    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' /v 'ExploitGuard_ASR_Rules' /t 'REG_DWORD' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '56a863a9-875e-4185-98a7-b882c64b5ce5' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '01443614-cd74-433a-b99e-2ecdc07bfc25' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '5beb7efe-fd9a-4556-801d-275e5ffc04cc' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd3e037e1-3eb8-44c8-a917-57927947596d' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '3b576869-a4ec-4529-8536-b80a7769e899' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '26190899-1602-49e8-8b27-eb1d0a1ce869' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'e6db77e5-3df2-4cf1-b95a-636979351e5b' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd1e49aac-8f56-4280-b9ba-993a6d77406c' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'a8f5898e-1dc8-49a9-9878-85004b8a61e6' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' /t 'REG_SZ' /d '1' /f
    REG ADD 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'c1db55ab-c21a-4637-bb3f-a12568109d35' /t 'REG_SZ' /d '1' /f

    Update-MpSignature
    Start-Service -Name MpsSvc ; Set-Service -Name MpsSvc -StartupType Automatic

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:15a48a8a7ce15e1ea5de2640cc9b88d0 Block inbound
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e5cf6c2e883ac7903f1c27958fbdc014 Notifications don't do anything so disable
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:78389af6e1a3fd3c52dfe24239307253 Log file location
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\privatefw.log" -Type String
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e8e07cc6a526889c48335584e7d24619
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFilePath" -Value 16384 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:507f46ffd1f5a45d56f41ccee2ede33d Dropped packets should be logged
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:03bdc66ebfe3fe79b8d0a3e2ca28d31f Self-explanatory
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:58ae3ece1e97c50ae1463e1031411f1a Turn on firewall (public)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:d38be9bbfed27cc78ab0a3acf82950ec Block inbound
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DefaultInboundAction" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:0ff19950d76e18a2d73065795ae8bea7 Notifications don't do anything so disable
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:250c8bd7c2032d59ff172621ff12b146 Local policy should not be on public firewall
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -Value 0 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:37b5821ace9e20bb0288dbcd8a5280e9 No IP local either
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -Value 0 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:0347d26a75e3d7090b049283bc9c0b6f Log file location
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\publicfw.log" -Type String
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f11e3db6a7db00643dd983639057186c Log file size
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Value 16384 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a66badb66b4ce17cbb5b8730815bb44d Log dropped packets
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:c228ad8112726bb75f3cff0d49769d4a Log successful connections
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:026015e1236786f4dc63c10de351a823 No proxy
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:2d5b95e84da2b1c3b672745b328d2c3a Disable onesetting download
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1 -Type DWord
    # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:082d7017a8ca66527ec01685c51fe40d No notifications
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
    # Firewall with commands
    # Enable the firewall on all profiles
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    # Block all incoming connections by default and allow only outbound connections
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    # Disable all inbound rules to prevent exceptions
    Set-NetFirewallProfile -Profile Domain, Public, Private -AllowInboundRules False
    # Enable logging for allowed and blocked connections
    Set-NetFirewallProfile -Profile Domain, Public, Private -LogAllowed True -LogBlocked True -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    # Disable all existing inbound rules for maximum security
    Get-NetFirewallRule -Direction Inbound | Set-NetFirewallRule -Enabled False
    # Verify the configuration
    Write-Host "Please check Firewall configuration:"
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules
}



function Set-CIS10 {
    function CIS10 {
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_Server_2022_v3.0.0_L1_Member_Server.audit:67cb7b5a9a54bdeba2c00ea9cb4e11f1
        Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:180bca857a1f8078031a85a301c6e8a0 Block Microsoft Accounts
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:12779ff1bcd9ccdd7ace592cee89ff6c No old audit policy
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:9a3d1dbf481fd763d22208ae8ad379e6 Do not crash when audit fails
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:8aa75ee488c2d8b07b2d2e3c4d8dbdd4 Makes users no have printers
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:9477dc53ffd6ed940d1ef3557c1536af Should require Ctrl+Alt+Del so user is at computer
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:183e3583133feb68a21ff537a2e406f2 Last username should not be visible
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord
        # Self-explanatory
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:32e9ace9e02ea98bc0933bfd5fcbeb7a Warn user about password expiring
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -Value 9 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:dfaef98704ec34ff0486256bdfd3afde Do signature if server agrees
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:14ea1ae654de2106eb2ece0de87be29b Disconnect after 15 mins for microsoft
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "AutoDisconnect" -Value 15 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e3b5a159e789a9f065012bf07770dc60 Require signature for client
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:38fd015c90f3c68447f3fab3db6ca99e Require signature for client if agrees
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:0405dec78e0fbd6cc6a018e658165df9 Force logoff microsoft
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "enableforcedlogoff" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:04700a3f6896ae98764a44e8a378a6e7 Harden
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "SMBServerNameHardeningLevel" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:55ba06541e5f17c5a34354a1ee68f59e NOT SURE (Undocumented reg key)
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:1675cda2fe85903062bc1c2ef8039c49 
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:babb97a878ae426da588a9f947077078 Named pipes cannot be accessed anonymously
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value @() -Type MultiString
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6dcc69e9dc45bd51ffdd687bfb052600 Remote registries configured
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -Value @("System\CurrentControlSet\Control\ProductOptions", "System\CurrentControlSet\Control\Server Applications", "Software\Microsoft\Windows NT\CurrentVersion") -Type MultiString
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:0203048eb7429e44b1695dc9d0bc2d23 Remove sub paths configured
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -Value @("System\CurrentControlSet\Control\Print\Printers", "System\CurrentControlSet\Services\Eventlog", "Software\Microsoft\OLAP Server", "Software\Microsoft\Windows NT\CurrentVersion\Print", "Software\Microsoft\Windows NT\CurrentVersion\Windows", "System\CurrentControlSet\Control\ContentIndex", "System\CurrentControlSet\Control\Terminal Server", "System\CurrentControlSet\Control\Terminal Server\UserConfig", "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration", "Software\Microsoft\Windows NT\CurrentVersion\Perflib", "System\CurrentControlSet\Services\SysmonLog") -Type MultiString
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f9d5504d67e9914a3d991bf671fd46a3 more null stuff idk
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value @() -Type MultiString
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:32078a05a09204a6a3bbbef20b179b48 Make users be themselves
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:2986d2fb0a4e46b121dcf074c3c80e7a Allow machine to be machine NTLM
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:8a1540d54f2c879172c0f4598086485b Audit all acounts
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:dafaf0a9560e0b90e63bb167ba5c85fa Audit NTLM traffic
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:f5db505b73769052ca8ddf4206a550bc Tell user about key
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:63d5ac5b5ac49add9ea9184ed53b20c5 Prevents file names from being the same
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "ObCaseInsensitive" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:d3f0e38e3fe6670a159cc9cd0b1cb51d No speech recognition
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:50614fed5cfdb63f6535b5ae5c465551 No online tips
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:12fac34d26f83bcb56ce5dcde9deb4e2 Packet privacy
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:61047a1f4851e7e53ca93a54f3a49a0e Cert Padding
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a7a499cee127a23a75cd14dd8f0d293a Do LSA
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:b921154be60d9cae77f3e80aaa28ccae
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:c65d95da60bec8d051838aac309428f9 No save password
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:c81021a054c79efcb6c797a8a2eec237 Disconnect idle sessions
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:da91758d6e20b4e21df0db12c8f9f9e1 Prevent impersonation of router
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:3b1c7fcc2deadf974e25fedd979d00f5 Safe DLL
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6851bc3e3664a032147cc14d8e66f4ed Screen saver grace period
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 5 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:4db82e9572e3d51b94123043130472f8 Unacknowledged data ipv6
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:e594a3af15f3914adbf22b36ab7db95e Unacknowledged data
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:cf4ba36c687fa7a301563dfa18651f7c Warning level at 90%
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:80d004b3f57419f089985815819a7e06 No online fonts
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:1bbeb62ba20578f5e9ee2a0661d0b9ed Turn off mapper I/O driver
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnDomain" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnPublicNet" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "EnableLLTDIO" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "ProhibitLLTDIOOnPrivateNet" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:2a9bb69a9207704693a9ed696d99ad76 Turn of responder driver
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndrOnDomain" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndrOnPublicNet" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "EnableRspndr" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "ProhibitRspndrOnPrivateNet" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:a58f4274840083fe40d806deea82fc47 Turn of peernet
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6c2abaf8dfb336694e72b4556657150f No network bridge
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e36388e52bf15964310717f4d4e21ae9 No ICS
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:dfa501cc2059b53b11f78fb37ca152f2 Disable IPv6
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value 255 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:faf5a57e88506e0c833c8739b2bb0f1d Turn off wireless for WCN
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:fcc5ededd338987e9d985e4e7368dd28 No WCN
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:5e213ebe88d438cc8c2f50f2c1a7f7e4 Disable print spooler
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7f5b32f7f84d06693e09bd8945c4de54 User redirection guard for spooler
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RedirectionguardPolicy" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:cd2ac082bd77bce40200a494e4d1f5f0 Have RPC over TCP
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcUseNamedPipeProtocol" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:cd2ac082bd77bce40200a494e4d1f5f0 RPC over TCP outgoing
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcAuthentication" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:868c182f520e1ee8d4517649e6307d31 Use RPC over TCP 
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcProtocols" -Value 5 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:47512cf719f25254e0ed85808b222c26 authentication
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "ForceKerberosForRpc" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:88010719e5230c02c1d560530299c99a
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" -Name "RpcTcpPort" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:3cb51fa9f0c49cf4a04a4e6dc54623fa Only admins can do printer driver
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:2048956daab8ad6854eadb61df93e79c Queue stuff
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "CopyFilesPolicy" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:d65a83a9758824a66388cf24095bd779 Elevation prompt
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e35855ce0ae6bc97d717808bd72f4ac9 More elevation prompt
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -Type DWord 
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:d2d6e77e2b72def58b373a8c1512ef56 No notifications
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:8d6643f1f6d4ce895eeb63f2f9ea93fd Force update clients
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:37ce9f8f643c9becb6958df80eae08cc Deny Device IDs
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:3965df9fe18a428e955e17ba71e6996d Deny USBC
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name "1" -Value "PCI\CC_0C0A" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:c1f89b733492f250bb5ab39f6e23138b Deny current devices too
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:f096e7de4de2baaa6a11458d23569ad5 Prevent instillatin
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:b0cfdada768a3ea365e77242f13d4c6b No IEEE 1394
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" -Name "<numeric value>" -Value "{d48179be-ec20-11d1-b6b8-00c04fa372a7}, {7ebefbc0-3200-11d2-b4c2-00a0C9697d07}, {c06ff265-ae09-48f0-812c-16753d7cba83}, {6bdd1fc1-810f￾11d0-bec7-08002be2092f}" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:0dba16890a62ef203552653b52c54140 Do for current drives
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f9e4e5c09c455992705bfd23ea904bd5 No metadata
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:303529af24992cac427ff989048329bc No cross-device experience
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:8dbea8ca8880fe116a7346862af3e78e No store
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord
        # Dont send handwriting
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord
        # More dont send handwriting
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:2cefb124f986ea0ec80e0b20ed1562d9 No ICW if microsoft
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:10637ae2622dfc9f42dc4fe01db2f243 
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:d450c574c80e05bdcd05ebafa41028d8 Turn off search companion downloading updates
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:1c871e9b2760c79206c1452282c2cb71 No order prints online
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:24a8e01f2e1f79c6f2ecb80333be0242 Do not public to web
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:d51f7795c1fad74e0c5dfa773c192924 No customer experience improvement program
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2 -Type DWord
        # Same thing as above
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:df2505854225fd8eec2a4393f2167a96 Don't report errors
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:792db0d66df20225f1e10efb30162f12 Kerebos on
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -Name "DevicePKInitBehavior" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:fdcdcf2b9cd791d9b41202f2a3d4a616 No custom SSPs
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:abf22fb84df481c48cb56eb4e48d79a2 No copying user input methods
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7cff598462ad1d32751562dc1402bbad Just read the key
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:13bd67d583af183f462b16b4050f8f20 Turn off app notis on lock screen
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:b0e219698e6fff5e68492e981fa25a45 Cant copy and paste between devices
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:ca4f61be9787e20a72193259cbbaf36c Dont upload user activities
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:518e457c9831e1d2ec44402179b6b174 No network activity during connected-standby (on battery)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:11104dd3de94216694a9734099ec51ec No network activity during connected-standby (plugged-in)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:04554858b280b3b9ab8a895364d7b41f Disallow standby states when sleeping (on battery)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea￾171b0ed546ab" -Name "DCSettingIndex" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:6c1cc74fa778938811d971518d7d14cf Disallow standby states when sleeping (plugged in)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea￾171b0ed546ab" -Name "ACSettingIndex" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:b7a533c3485858f6fd795c7d09ee985d Require password when computer wakes (on battery)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:79323bdaf37e44ca3ca9db75f3d8e0f2 Require password when computer wakes (plugged in)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f4b0916d096358c7cdffe9b3b3e5ebac No remote assistance
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:86eea337b08962a8021a85c9b9e72bba More no remote assistance
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:d7dffa0540965740f5b0aeb27ed69e38 RPC endpoint mapper authentication
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:3f1a502ef6ea7df8dff17e339f830027 Restrict unauthenticated rpc
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:04d467ba93737c1db707fee369f6bdfe Turn off diagnostic tool
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:fdea4890b81361e81168fda91aad49ad Perftrack disabled
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:cd9e839cd949b4a7c7ea519588ff3925 No advertising ID
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:757f7ed8a63bb055e6bd28c1bf9b5964 Have an accurate time
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:4aa1917e24f2ba6cada06e6d886e7754 Don't share data between users
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name "AllowSharedLocalAppData" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e51d2b8ec2e27568ac7e2050599c6f57 Don't have users install apps
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:d9b74453d65a53c952e97cca6dfc1950 lots of words
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockHostedAppAccessWinRT" -Value 1 -Type DWord 
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:6af173f591248a6667377918210c4c21 Don't do earlier versions
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVDiscoveryVolumeType" -Value "" -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:0dbc2fc20763a871b875417c6382cc64 Make recoverable
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:1d50530d2dd8530fb8a8190db724a9ce Allow data recovery agent
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:2ef46da780ad2e45e53809d284e208d8 48 digit recovery password
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:4f8b3a8b39d44b3663770343df9392ae Have recovery ley
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:db54f1031df4aaa45c243a8859a76481 Omit recovery options
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:0d862aef04727a97c8bcf0c3543fc288 Save bitlocker recovery info
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 0 -Type DWord 
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:996c274b914bf9e6d6b1a79243ac615f More enable backup
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:232178d938e795553095de071da754e9 More backup
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:c363c1609da82da208f552e46182070b No hardware encryption
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:04bc3cee1a1e2c8030d2ada6d9355c82 No password
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:a0631662765d9f554adfe0aebf260fab Use smart cards
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowUserCert" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:22d4e2b6df60cd5ad56e1f587913f4e7 More smart cards
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVEnforceUserCert" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:84cf890af0f03484e5937e3d46800bb4 Better pin for better entropy
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:27bab39d82adab44a0cd87d23ebd7721 More integrity validation
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSecureBootForIntegrity" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:e475f9ac6f14cb2b68a94a7d8daf93b2 Choose how to recover
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecovery" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:4b8871c0623fda2d2bacbb092ddf39e0 
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSManageDRA" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:64020681efefab6bf617f77f13ce9da8 48 length password
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:f10885825483983a85b7f3e71aa093a9 No key recover
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:e1d82b862a45887c129ac365b08fc90d Omit recovery
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:e01671358aee3e0ceac6dc275f5c1c08 backup
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryBackup" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:c73dc87c95d6573414343543ec4d7faf what to store
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryInfoToStore" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:217146e0c461f2158dc349a6635f0c81 
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRequireActiveDirectoryBackup" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:2f53b21f7538d62d5fa4d3f95795445e No hardware encryption
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHardwareEncryption" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:cc0c47dfcc6e711157a2ef753d60ce1f no password
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSPassphrase" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:c3e82ce3ce3e2ebf6a84558e7703c5c6 More authentication
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:61ed62b0167b2fc33fed69286446df25 
        # Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableBDEWithNoTPM" -Value 0 -Type DWord physical requirement
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:6732fa7156839bada914bea14ff461bc
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDiscoveryVolumeType" -Value "" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:5cbee731bd97924de428212cd6807181 
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecovery" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:40ad86ce23e8595a814cb6fc4cce6601
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVManageDRA" -Value 1 -Type DWord 
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:8b107ffd283330a0d4c2c1eb6ec5718e
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryPassword" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:afcc9c9e510d7594531fecfa396f1b7b No key
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryKey" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:52a419e67fbb95f80c1aba920e688edd Omit recovery
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHideRecoveryPage" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:dbb0e8184ee425e52d4c832b25f3fc20 Recovery
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryBackup" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:237afa3d44189c1065da03d87fcfc2d2 Recovery
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryInfoToStore" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:c58145f0f202efc96c7668d3919aa0b9 recovery
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRequireActiveDirectoryBackup" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:210b45c43aadf24e6fc9b6bd4269ad7f No hardware encryption
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHardwareEncryption" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:6ca496168a94c96428e7983997d3d9ed No passwords
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVPassphrase" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:6e07b11ff72a13277a583074ee3a7c6c Use smartcards
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowUserCert" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:0ccf25ed36acb2447fae8bb61162d0b4 Use smartcards
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVEnforceUserCert" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:a0b6f560c567082d7f5d56db9da5a9b9 Deny write access
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:c861d3d3961889fbe35447fed54dbc94 More deny write access
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyCrossOrg" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1_BL.audit:94d09259b9a1ee23b4bd90a843f97eb7 Disable new DMA devices
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:ecdf620b74b745c6bae4434e3caa218d No camera
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:64048c0b1e183a9dec9566e7b08d8b22 Disable cloud content
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:54070dc6a8d98186b0d7e8f952498f5d No cloud optimization
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:fc523d6beda8e1e4e78185dcf270745a Require pin
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:89b71b221867511be778b7537933a1b3 No reveal password
        Set-Registryvalue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnableSecureCredentialPrompting" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7f81c17fe73765b4d33230c6aa74b0cb No security questions
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:082d7017a8ca66527ec01685c51fe40d No Notifications
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:8fc0af3f8cb2d7638fc4421a287462ec Onesetting auditing
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:092166ccb598c0158856c4333da5dc3b Limit diagnostic
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:c7e84c5f91b5f1edd7afa80c8feb09bb Limit dump collection
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:8495cb36039c353c0547ed47ef130c2a Less user control
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:357ae5993895d32c1a5693d9d6689df2 No app installer
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableAppInstaller" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f33219f56c610b23ea41f036f5311494 No experimental features
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:1bcb7d5cd0302fc281c3ab784c280856 No hash override
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:785bdf9d6d83958d57ccca59d02aa04c Don't use the protocol
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a84366341e798fe48d3f9792f326dba8 Log file max (not sure if it should be string)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:cf8fcc7bac274cd4c3420622acc8f8de Log file max
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:94730e9ea62cd8f96d414e92963c657f Log file max
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:785e84960ff1f9b403b65131904c1524 Setup size
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:656a3a14724571c3c2dc5b7c7d0024be Log file max
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:bd67b8438c3b4296598f9f5b0ef4b8a0 IE disable
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "NotifyDisableIEOptions" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:831b3a87594473709c096ecfe47e5742 Turn off location
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:637af90961058036ceb41b44e0c43f18  No messaging
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:2a08305d07c3256da025b25cedf84d16 No consumer microsoft
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:1f7bb58b75c0082e5e4ff96df2a1ab3d Don't report to MAPS Windows Defender
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:55251fd14002cb35af632b41574048fe Windows Defender
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:ab35ff3c357ce249239a0e565dd6e336 Do ASR rules
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:b8cc83c8788edf57312b3d17a087a70c More ASR rules
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "26190899-1602-49e8-8b27-eb1d0a1ce869" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "3b576869-a4ec-4529-8536-b80a7769e899" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "56a863a9-875e-4185-98a7-b882c64b5ce5" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "d3e037e1-3eb8-44c8-a917-57927947596d" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -Value "1" -Type String
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "e6db77e5-3df2-4cf1-b95a-636979351e5b" -Value "1" -Type String
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:62e4c7c84a1767cf1406f94e1abc1ec7 Don't access dangerous websites
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:bc19398528826e8bf073b47a58e37863 Do hash
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:afa19352aca86218aa3c9edf7bc3d889 Scan Downloaded
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:2e385f9eb7fd6a00e7c8652d7d3316aa Use real time protection
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f585a93980dc6cf549c1d8c3c74d4322 Monitor behavior
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:5714d0672be5cc3f5f53c253f930c3e0 Script scanning
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:62c34bd75188987a519889977c46006f Don't do watson events
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:6e662ad813c61ee1493a2f9e02c0898d Scan packed executables
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:72033d143dd3796f88752e870020ccd5 Scan removable drives
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:32530fbe0ce3b84111a6e17ad61fb7a2 Email scanning
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7125f048aaaaa361963c3d56c5eb4f9b Unwanted applications blocked
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:2b1f1e9ba7b7e3d5bc907e8e5fac9738 Turn on Microsoft Defender Antivirus
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWord
        # Defender auditing
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditApplicationGuard" -Value 1 -Type DWord
        # Defender should not access camera
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraMicrophoneRedirection" -Value 0 -Type DWord
        # No data persistance
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0 -Type DWord
        # Don't save file to host
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "SaveFilesToHost" -Value 0 -Type DWord
        # Have clipboard isolated
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIClipboardSettings" -Value 1 -Type DWord
        # Defender for edge
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowAppHVSI_ProviderSet" -Value 1 -Type DWord
        # END OF DEFENDER #
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:4319576838a638e5347dff0c31c1a052 No news and interests
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a27641456afa641930fbaa8443f72855 Prevent the use of OneDrive for file storage
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:f426194766e8b06c32953a39372def2a Turn of PushToInstall
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" -Name "DisablePushToInstall" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:d8aa98de216c7827eb78cd32270d93d0 Don't allow rdp?
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:d9584d024fba69aa2448f0f086ec36ba No UI automation
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "EnableUiaRedirection" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:eec6f4a60892d0e1f6b7bec969dc134a No COM port redirection
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:939396e07cba56d47e7b0a29c0e035de No redirection of location
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLocationRedir" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:af3db0fe337c093db1faefbd7ff95a1e No LPT port redirectiob
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:627f44ca780905ca3dba7114b98a3577 No plug and play redirection
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:c856e4813f8b8f0848ec951d7516c28a No webauthn redirection
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableWebAuthn" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:b529b56be848b17c43839609e1f32947 SSL for RDP
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:60249a438191ea08e920586bbad5b608 User authentication for remote connections
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:970efd811eb23a762dc591e9376e16fe Use high encryption
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:2cfdf3ea30b08a35948601ae6587207a Max idle time 15 mins
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:4be6a7be18296f4e0caad916d6741b11 Time limit for disconnected sessions
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 60000 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:fea6b65a395358ffde8475dadf5d85a7 Delete temp folders on exit
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:c704a67db45f47d5557c95220636fabf Prevent downloading of enclosures
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:f144b3aafc4f180dbc25a97bcf2dbef0 Allow cloud search
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:9c1e77be5ae6cc680f29aa9668721d76 Don't allow cortana
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:c72b6eb13dcd23dedb8eb70b6244824e More don't allow cortana
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:5b300c77ffa93e7bd89341f6bd4846b8 No location
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:1d82d2c8db13f5e94f7a287b949223c8 Don't allow search highlights
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:7ffc9d3441219965c6251eef38a681db Turn off KMS client
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:5b8a43a3e4198ecbc5dcf8f8b94f7781 Funny story Note #2: The name of this setting and the Enabled/Disabled values are incorrectly worded – logically, the title implies that configuring it to Enabled will disable all apps from the Microsoft Store, and configuring it to Disabled will enable all apps from the Microsoft Store. The opposite is true (and is consistent with the GPME help text). This is a logical wording mistake by Microsoft in the Administrative Template.
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f3f6869515e6f9f7bb7f8467e1c8734e Only secure apps
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a8cf723c117ff288409c6be71f4b54b0 Auto updates of windows store
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 4 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:712c90eeb152cff789dfdd1967cb9f53 Not latest update??? less support calls ig
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:e9c8c7afa4e7fe5751bf223e4cf791dd Turn off windows store
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f8556f588f42e5e52c2faaed0d84f08c Disable widgets
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:55c0906100f381c1e8d16a8e0e6ae6ea No screen recording
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:e1a4a744f660560198742c862b02854f No suggested
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:665224c9146552c7b718e8cddba80c91 Turn off MPR notis
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableMPR" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:b68e46481ade4dda697b73706b054702 No auto config
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:77f744e3165d2c42f36575874bba6c46 No remote shell
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:766014cb0447235edb997cc254a262fb No clipboard in sandbox
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:f706e4fcdc97b93b36e0c360f606f9e5 No networking sanbox
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:5f2b79f86f81c4fe08b10fb6edd95afd Users can't modify settings
        #Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:75b65ecb00106871cb46381e548b1bf9 Do auto restart (I added more update keys)
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 3 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:0a4752714387131062b3c00825d171ed Do automatic updates
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e72a51ff11fc16e50c0520c68b4c7142 It's everyday bro with the automatic updates flow
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:0bfca566db005539ef4fa803de7f969c No pause updates feature
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:a2161b7fc988860e794b6a08de4e9abe No preview builds
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:e61626b5c50f47250665de63822963c0 180 days for preview
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:7aa9fe0b747f1db1b971103201020435 quality updates
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value 0 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:cc8482fe41ab9c6c37d11fd60fdf1c60 Turn off help
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:d43c97d77a3d60207d79e74dd7f740d2 Notify antvirus when opening attachments
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:fb5d576f5f64114e7c26a588d22ffb4b No spotlight on lockscreen
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:e55bf536d59a311d919af03451ab2daa No diagnostic data
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:96dca44c8d638508ed956b0439b1c5da Turn off spotlight
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:5605fd9c489f55b3ce37f3dab7f44269 No splotlight collection
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:d7944d54243fcffd7a4032af56cbb42a No sharing within profile
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -Value 1 -Type DWord
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:b639f4d0508bfef7566ff831fdc9b483 Don't install with elevated privileges
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Type DWord 
        # https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L2.audit:9296f9c4f4a9e82de255373fbfe026da No codec download
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCodecDownload" -Value 1 -Type DWord
    }
}

function Set-Misc-Reg {
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SyncForegroundPolicy" -Value 1 -Type DWord
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 1 -Type DWord
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'DisableSmartNameResolution' -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "ActiveDebugging" -Value "1" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "DisplayLogo" -Value "1" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "SilentTerminate" -Value "0" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "UseWINSAFER" -Value "1" -Type String
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsMenu" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCR:\Windows.IsoFile\shell\mount" -Name "ProgrammaticAccessOnly" -Value "" -Type String
    Set-RegistryValue -Path "HKCR:\Windows.VhdFile\shell\mount" -Name "ProgrammaticAccessOnly" -Value "" -Type String
    # Disable Sticky Keys (Current User)
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String
    # Disable Filter Keys (Current User)
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122" -Type String
    # Disable Toggle Keys (Current User)
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -Type String
    # Disable Sticky Keys (Default User)
    Set-RegistryValue -Path "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String
    # Disable Filter Keys (Default User)
    Set-RegistryValue -Path "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122" -Type String
    # Disable Toggle Keys (Default User)
    Set-RegistryValue -Path "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -Type String
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCloudFilesInQuickAccess" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SCMApiConnectionParam" -Value 0x80000000 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 0x8 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bAcroSuppressUpsell" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisablePDFHandlerSwitching" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisableTrustedFolders" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisableTrustedSites" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnableFlash" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnhancedSecurityInBrowser" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnhancedSecurityStandalone" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bProtectedMode" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "iFileAttachmentPerms" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "iProtectedView" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name "bAdobeSendPluginToggle" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iURLPerms" -Value 3 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iUnknownURLPerms" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleAdobeDocumentServices" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleAdobeSign" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bTogglePrefsSync" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleWebConnectors" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bUpdater" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name "bDisableSharePointFeatures" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name "bDisableWebmail" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name "bShowWelcomeScreen" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 -Type DWord
    # EDGE HARDENING
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SitePerProcess" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLVersionMin" -Value "tls1.2^@" -Type String
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "NativeMessagingUserLevelHosts" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLErrorOverrideAllowed" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AllowDeletingBrowserHistory" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String
    Set-RegistryValue -Path "HKLM:\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" -Name "update_url" -Value "https://edge.microsoft.com/extensionwebstorebase/v1/crx" -Type String
    # CHROME HARDENING
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AdvancedProtectionAllowed" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AllowCrossOriginAuthPrompt" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AlwaysOpenPdfExternally" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AmbientAuthenticationInPrivateModesEnabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AudioCaptureAllowed" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AudioSandboxEnabled" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BlockExternalExtensions" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "on" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SSLVersionMin" -Value "tls1" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ScreenCaptureAllowed" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SitePerProcess" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "TLS13HardeningForLocalAnchorsEnabled" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "VideoCaptureAllowed" -Value 0 -Type DWord

    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main" -Name "Depoff" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DoNotInstallCompatibleDriverFromWindowsUpdate" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "UndockWithoutLogon" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowDomainDelayLock" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "CorpConnStartTimeoutPolicyValue" -Value 60 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UserPolicyMode" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "RSoPLogging" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "GroupPolicyRefreshTimeDC" -Value 45 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "GroupPolicyRefreshTimeOffsetDC" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "GroupPolicyRefreshTime" -Value 90 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "GroupPolicyRefreshTimeOffset" -Value 30 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DenyRsopToInteractiveUser" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowX-ForestPolicy-and-RUP" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "GpNetworkStartTimeoutPolicyValue" -Value 120 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLGPOProcessing" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowlinkDefaultToAsync" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowLinkDefaultForDirectAccess" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableAOACProcessing" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ResetDfsClientInfoDuringRefreshPolicy" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableLogonScriptDelay" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AsyncScriptDelay" -Value 5 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableLogonOptimizationOnServerSKU" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableLogonOptimization" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SyncModeSlowLinkThreshold" -Value 500 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SyncModeNoDCThreshold" -Value 5000 -Type DWord  
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableAppUriHandlers" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowLinkDetectEnabled" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "CompatibleRUPSecurity" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableForceUnload" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "CleanupProfiles" -Value 30 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UserProfileMinTransferRate" -Value 500 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowLinkTimeOut" -Value 120 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowLinkProfileDefault" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ReadOnlyProfile" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProfileUnloadTimeout" -Value 60 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProfileErrorAction" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProfileDlgTimeOut" -Value 30 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "LocalProfile" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "LeaveAppMgmtData" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowLinkUIEnabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "SlowLinkDetectEnabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DeleteRoamingCache" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowBlockingAppsAtShutdown" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "HiberbootEnabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "PrimaryComputerEnabledRUP" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowUserInfoAccess" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProcessTSUserLogonAsync" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DLT_AllowDomainMode" -Value 0 -Type DWord

}

function Set-STIGS10 {
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220932 Anonymous Shares Disabled
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220930 Anonymous SAM enumeration disabled
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220937 Insecure hashing disabled
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220938 Refuse some LM stuff
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220823 No remote assistance
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220828 Prevent autorun commands
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220727 SEHOP turned on
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220857 Do not install as elevated
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220747 No reversible encryption for password - lgpo
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220910 No blank passwords
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220812 Turns on Credential Guard
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220827 Turning off autoplay
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220829 Turning off autoplay
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220830 No spoofing
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220836 Smart Screen config
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord 
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type String 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220837 Data Execution Prevention On 
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220834 security for telemetry
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord 
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220703 Bitlocker stuff?
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1 -Type DWord 
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord 
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKeyPIN" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220704 Set minimum pin for bitlocker
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN" -Value 6 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220933 Perms for restricting remote sam
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220931 Anonymous should have less rights
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220936 Kerebos Parameters
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220935 PKU2U authentication disabled
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u" -Name "AllowOnlineID" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220934 NTLM preventing from falling back
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220939 Require LDAP signing
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220742 Password History
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordHistorySize" -Value 24 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220779 Logging size
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Value 32768 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220824 restricing remote
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'RestrictRemoteClients' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220821 Require password on reboot
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220820 No enumerate local users
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220822 Require password after sleep
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220717 Ever
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220902 Protect Kernel
    Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection' -Name 'DeviceEnumerationPolicy' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220908 No auto login
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Value '0' -Type String 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220909 Disable guest account
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'GuestAccountEnabled' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220780 Security log size
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Value 0x000fa000 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63527 System log size
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Value 0x000fa000 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220839 File Explorer Shell Must Run In Protect Shell
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220919 Require strong key
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220728 Disabled Powershellv2
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart 
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220729 Disable SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220724 Enabling firewall
    # do firewall?
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220915 Secure Channel Outgoing
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220914 Secure Channel Outgoing
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220850 Password Required for RDP
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220851 Encrypt for RDP
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220852 Encryption level for RDP
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Value 3 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220853 Prventing downloads from RSS
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220855 No indexing of encrypted files
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220856 Users cant change intall options
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220858 Notify users when web wants to download something
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220859 No automatic sign in after restart
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220866 Disallow unencrypted traffic
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220793 Turn off webcam, better not be a vuln
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Deny' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220792 Lock Camera, better not be a vuln
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220796 prevent IP Spoofing
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Type DWord 
    # https://www.stigviewer.com/stig/microsoft_windows_11/2024-06-10/finding/V-253353 prevent IP spoofing ipv6
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220794 The display of slide shows on the lock screen must be disabled
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220799 Privleged token filters for admins
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220731 SMBv1 disabled
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220730 SMBv1 disabled
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220843 No suggesting passwords
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'FormSuggest Passwords' -Value 'no' -Type String 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220842 Prevents user from ignoring certificate errors
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -Name 'PreventCertErrorOverrides' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220841 Can't ignore windows defender warnings for unverified files
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220840 Can't ignore windows defender warning for malicious websites
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220847 PIN minimum length
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name 'MinimumPINLength' -Value 10 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220846 Requires hardware security device
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'RequireSecurityDevice' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220845 Prevent screen recording
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220844 Windows defender smartscreen filter turned on for edge
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220849 Drives no longer able to be remotely shared
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220848 In RDP do not save passwords
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220926 Don't enable plain text passwords for smb third party servers
    # New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220832 Admins should not be enumerated during elevation
    # New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220870 Convenience PIN must be disabled
    # New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\System'
    Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'AllowDomainPINLogon' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220871 Disallow access above the lock for Windows Ink
    # New-Item -Path 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace' 
    Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowWindowsInkWorkspace' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220818 System should attempt to use certificated for authentication
    # New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'DevicePKInitEnabled' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220819 UI not displayed during logon
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220800 No plaintext passwords for wdigest
    # New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' 
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -Name 'UseLogonCredential' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220910 Cannot have blank passwords
    # New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220810 Remote host allows delegation of non-exportable credentials
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220913 Audits using subcategories
    # New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-250318 Auditing for powershell
    # New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220940 Security requirement for NTLM SSP based clients
    # New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinClientSec' -Value 0x20080000 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220941 Security requirement for NTLM SSP based servers
    # New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Value 0x20080000 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220861 Vulnerabilities in preview pane & reading pane so they must be disabled
    Set-RegistryValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoPreviewPane' -Value 1 -Type DWord 
    Set-RegistryValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoReadingPane' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220863 No unecrypted traffic for WinRM
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220723
    # Search all drives for *.p12 and *.pfx files.
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220916 Outgoing traffic signed
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-250319 LOOK INTO FURTHER Hardened UNC paths prevent tampering and spoofing https://www.tenable.com/audits/items/CIS_Microsoft_Windows_10_Stand-alone_v3.0.0_L1.audit:88fd3a1bcb9e05eec18b18d11a09cff0 Require Privacy
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Value 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1' -Type String 
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Value 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1' -Type String 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220955 Saving zone information is good for windows to determine risk
    Set-RegistryValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'SaveZoneInformation' -Value 2 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220951 User Account Control must virtualize file and registry write failures to per-user locations
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220950 Enabled UAC
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220814 Make group policy objects reprocessed even if they have not been changed
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoGPOListChanges' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220815 No printer driver packages over http
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220816 Web publishing and online ordering wizards must be prevented from downloading a list of providers. - Whatever that means
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWebServices' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220817 No printing over http
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220813 Prevent bad boot drivers
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Value 3 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220868 WinRM should not be using digest
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220946 idk
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220947 UAC must deny standard users when they want to elevate
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220944 Allows built-in admin to have admin rights
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220945 Prompt consent for admins for elevated use
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220860 Powershell auditing
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220948 UAC can detect installations
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Value 1 -Type DWord 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220698 idk if we should should do this by scripting or event at all
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220699 same as above
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220942 Use FIPS for hashing
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Value 1 -Type "DWord" 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220949 Only elevate UIaccess in secure locations
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1 -Type DWORD 
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220809 Keep record of command line data
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWORD
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220808 Disable Wifi-Sense
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWORD
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220807 Non domain networks can't connect to domain networks
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value 1 -Type DWORD
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220806 Simultaneous connections limited
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 1 -Type DWORD
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220805 EEC curves prioritize longer keys
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -Value @("NistP384", "NistP256") -Type MultiString
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220803 Disable ICS, might be required service though
    # Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220802 No insecure logons to SMB
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220801 Run as a different user should not be on context menus
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser" -Name "SuppressionPolicy" -Value 4096 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser" -Name "SuppressionPolicy" -Value 4096 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser" -Name "SuppressionPolicy" -Value 4096 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser" -Name "SuppressionPolicy" -Value 4096 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220920 Have an inactivity timeout
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220924 SC removal should log out user
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Value "2" -Type String
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220925 SMB must do packet signing
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220867 Disable RunAs because it can store credentials
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220831 Can't have windows recommend random installations
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220700 Don't think I can script this
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220835 Is cypat domain joined or standalone im confused
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220838 Prevents stuff from happening when file explorer becomes corrupt
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220825 Have modern stuff ig
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220918 Maximum age of machine passwords to 30
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value 30 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220797 just trust this idk
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220798 Ignore NetBIOS name release
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220826 No collecting data and sending it
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220872 No third part suggestions
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220917 Passwords should be able to be changes
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220811 idek
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220954 who made smth called a toast notification like what are we doing? making bread
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220922 no me doing this
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220923 Limit password caching
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "10" -Type String
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220943 Default mode is protection
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220865 No clear text passwords for WINRM
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/microsoft_windows_11/2024-06-10/finding/V-253418 Same as above for 
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220929 No anonymous SAM
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2019-09-25/finding/V-94719  App and voice shouldn't be connected
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Value 2 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2019-09-25/finding/V-82145 Limit diagnostic (not needed bc i set another registry but just in case)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/microsoft_windows_11/2024-06-10/finding/V-253371 prob dont need says hardware stuff needed
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/microsoft_windows_11/2024-06-10/finding/V-253408 Over http no basic authentication
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63817 Approval mode for built in admin 
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/microsoft_windows_11/2024-06-10/finding/V-253394 Can't get updates from internet from other PCs
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 1 -Type DWord
    # https://answers.microsoft.com/en-us/windows/forum/all/smartscreen-can-not-be-changed-to-warn-or-off/62b50abc-db05-4ae2-9196-d11681c9fc38 More smartscreen
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Warn" -Type String
    # https://www.stigviewer.com/stig/internet_explorer_8/2015-06-30/finding/V-15494
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security Criteria" -Name "DisableSecuritySettingsCheck" -Value 0 -Type DWord
}

function Set-STIGS7 {
    # https://www.stigviewer.com/stig/windows_7/2015-09-02/finding/V-32282
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26576
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" -Name "IPHTTPS_ClientState" -Value 3 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26577
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "ISATAP_State" -Value "Disabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26575
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "6to4_State" -Value "Disabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15725
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffSidebar" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15724
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffUnsignedGadgets" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15726
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffUserInstalledGadgets" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15722
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-16008
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-36705
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings" -Name "DEP" -Value 2 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-36706
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings" -Name "SEHOP" -Value 2 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-36701
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings" -Name "ASLR" -Value 3 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14261
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14269
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "HideZoneInfoOnProperties" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26578
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Teredo_State" -Value "Disabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-1171
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -Value "0" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15674
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14228
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-3480
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "DisableAutoupdate" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2014-04-02/finding/V-14229 Disable auditing idk?
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "FullPrivilegeAuditing" -Value 0 -Type Binary
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21975
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Homegroup" -Name "DisableHomeGroup" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15700
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllowRemoteRPC" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-16048
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoExplicitFeedback" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-1075
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-3375
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15701
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSystemRestore" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-1084
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15686
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableLUAPatching" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15687
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "GroupPrivacyAcceptance" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15672
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\EventViewer" -Name "MicrosoftEventVwrDisableLinks" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15680
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LogonType" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21974
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\GameUX" -Name "GameUpdateOptions" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21978
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU" -Name "Disabled" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21965
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21969
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "EnableQueryRemoteServer" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21960
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21961
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Force_Tunneling" -Value "Enabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15703
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15702
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15707
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "LoggingEnabled" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15704 Ofc we must prevent handwriting error reports free vuln
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15709
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\GameUX" -Name "DownloadGameInfo" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-56421
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletTip\1.7" -Name "PasswordSecurityState" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletTip\1.7" -Name "PasswordSecurity" -Value 5 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-17373
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value "0" -Type String
    # https://www.stigviewer.com/stig/windows_7/2012-08-22/finding/V-1085
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Allocatefloppies" -Value "0" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14231
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name "Hidden" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14232
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\IPSEC" -Name "NoDefaultExempt" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15712
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "PreventIndexingUncachedExchangeFolders" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2015-09-02/finding/V-32282
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26576
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" -Name "IPHTTPS_ClientState" -Value 3 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26577
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "ISATAP_State" -Value "Disabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26575
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "6to4_State" -Value "Disabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15725
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffSidebar" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15724
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffUnsignedGadgets" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15726
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -Name "TurnOffUserInstalledGadgets" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15722
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-16008
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-36705
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings" -Name "DEP" -Value 2 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-36706
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings" -Name "SEHOP" -Value 2 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-36701
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings" -Name "ASLR" -Value 3 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14261
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14269
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "HideZoneInfoOnProperties" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-26578
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Teredo_State" -Value "Disabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-1171
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -Value "0" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15674
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14228
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-3480
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "DisableAutoupdate" -Value 1 -Type DWord
    # Disable auditing idk?
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "FullPrivilegeAuditing" -Value 0 -Type Binary
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21975
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Homegroup" -Name "DisableHomeGroup" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15700
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllowRemoteRPC" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-16048
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoExplicitFeedback" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-1075
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-3375
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15701
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSystemRestore" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-1084
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15686
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableLUAPatching" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15687
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "GroupPrivacyAcceptance" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15672
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\EventViewer" -Name "MicrosoftEventVwrDisableLinks" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15680
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LogonType" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21974
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\GameUX" -Name "GameUpdateOptions" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21978
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU" -Name "Disabled" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21965
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21969
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "EnableQueryRemoteServer" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21960
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-21961
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Force_Tunneling" -Value "Enabled" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15703
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15702
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15707
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "LoggingEnabled" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15704 Ofc we must prevent handwriting error reports free vuln
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15709
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\GameUX" -Name "DownloadGameInfo" -Value 0 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-56421
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletTip\1.7" -Name "PasswordSecurityState" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletTip\1.7" -Name "PasswordSecurity" -Value 5 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-17373
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value "0" -Type String
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14231
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name "Hidden" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-14232
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\IPSEC" -Name "NoDefaultExempt" -Value 1 -Type DWord
    # https://www.stigviewer.com/stig/windows_7/2016-12-19/finding/V-15712
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "PreventIndexingUncachedExchangeFolders" -Value 1 -Type DWord
}
function Main {
    $outputDir = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("MyDocuments"), "Downloads\SecurityAudit")
    if (!(Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir
    }

    function Write-Log {
        param($Message, $ForegroundColor = 'White')
    
        Add-Content -Path "$outputDir\Main_log.txt" -Value $Message
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    
    Write-Log "Starting Security Policy Configuration..." 'Cyan'
    
    if (-not (Test-AdminPrivileges)) {
        Write-Log "This script requires administrator privileges. Please run as administrator." 'Red'
        exit 1
    }

    # Function to display the options
    function Display-Options {
        Clear-Host
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "║                     System Security Menu                       ║" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host
        Write-Host "=== Administrative Privileges & Configuration ===" -ForegroundColor Yellow
        Write-Host "[1] Initialize-UserManagement    [2] Set-SecPol" -ForegroundColor Cyan
        Write-Host
        Write-Host "=== Package & File Management ===" -ForegroundColor Yellow
        Write-Host "[3] Remove-Packages             [4] Repair-Windows" -ForegroundColor Cyan
        Write-Host "[5] Remove-MediaFiles           [6] Search-UnwantedFiles" -ForegroundColor Cyan
        Write-Host
        Write-Host "=== Services & Security Settings ===" -ForegroundColor Yellow
        Write-Host "[7] Set-Services                [8] Set-Defender" -ForegroundColor Cyan
        Write-Host
        Write-Host "=== Configuration Hardening ===" -ForegroundColor Yellow
        Write-Host "[9] Set-CIS10                  [10] Set-Misc-Reg" -ForegroundColor Cyan
        Write-Host "[11] Set-STIGS10                [12] Set-STIGS7" -ForegroundColor Cyan
        Write-Host "`n**************************************************************************************" -ForegroundColor Yellow -BackgroundColor Red

        Write-Host "*                            Take Frequent Snapshots!!                               *" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host "* WARNING: The Registry and Services Configured Do Not Account for Critical Services *" -ForegroundColor White -BackgroundColor Red
        Write-Host "**************************************************************************************" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "║ Enter comma-separated numbers or 'exit' to quit                ║" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "║ Example: 1,3,5 to run multiple functions                       ║" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor White -BackgroundColor DarkBlue
        [console]::beep(800, 750)
            
        
        # Beep sound with frequency 1000Hz for 500ms
    }

    # Function to validate input
    # Function to validate a single number input (between 1 and 14)
    # Function to validate a single number input (between 1 and 14)

    # Function to run selected functions based on input
    function Run-SelectedFunction {
        param (
            $selection
        )

        # Map numbers to function names
        switch ($selection) {
            1 { Write-Host "Running Initialize-UserManagement" -ForegroundColor Green; Initialize-UserManagement }
            2 { Write-Host "Running Set-SecPol" -ForegroundColor Green; Set-SecPol }
            3 { Write-Host "Running Remove-Packages" -ForegroundColor Green; Remove-Packages }
            4 { Write-Host "Running Repair-Windows" -ForegroundColor Green; Repair-Windows }
            5 { Write-Host "Running Remove-MediaFiles" -ForegroundColor Green; Remove-MediaFiles }
            6 { Write-Host "Running Search-UnwantedFiles" -ForegroundColor Green; Search-UnwantedFiles }
            7 { Write-Host "Running Set-Services" -ForegroundColor Green; Set-Services }
            8 { Write-Host "Running Set-Defender" -ForegroundColor Green; Set-Defender }
            9 { Write-Host "Running Set-CIS10" -ForegroundColor Green; Set-CIS10 }
            10 { Write-Host "Running Set-Misc-Reg" -ForegroundColor Green; Set-Misc-Reg }
            11 { Write-Host "Running Set-STIGS10" -ForegroundColor Green; Set-STIGS10 }
            12 { Write-Host "Running Set-STIGS7" -ForegroundColor Green; Set-STIGS7 }
            Default { Write-Host "Invalid selection: $input" -ForegroundColor Red }
        }
    }

    # Main script execution loop
    while ($true) {
        Display-Options
        # Display the options to the user

        # Use an alternative method to capture the input (System.Console.ReadLine)
        $userInput = Read-Host "Please enter a number (1 to 14) to run a function, or type 'exit' to quit:" -ForegroundColor Yellow
        # Debugging: Output the captured user input
        Write-Host "Captured user input: '$userInput'" -ForegroundColor Yellow


        # Trim any extra spaces
        $userInput = $userInput.Trim()

        # Debugging: Output the trimmed input
        Write-Host "Trimmed input: '$userInput'" -ForegroundColor Yellow

        # Check if input is empty after trimming
        if ($input -eq '') {
            Write-Host "Error: No input entered. Please enter a number between 1 and 14." -ForegroundColor Red
            continue
        }

        # Check if the input is a valid number (between 1 and 14)
        if ($input -match '^\d+$' -and [int]$userInput -ge 1 -and [int]$userInput -le 14) {
            Write-Host "Valid number: $userInput" -ForegroundColor Green
            continue
        }

        # Check for exit condition
        if ($userInput.ToLower() -eq "exit") {
            Write-Host "Exiting the script." -ForegroundColor Green
            Start-Sleep -Seconds 10
            break
        }

    
        Run-SelectedFunction -selection $userInput


        # Pause before the next iteration
        Write-Host
        Read-Host -Prompt 'Press Enter to continue...'
    }

    Write-Log "Hardened!" Green
    Write-Log "TODO:" Green

    Write-Log "`nCheck Shares (File Shares in Computer Management)" Green
    Write-Log "Update Programs!" Green
    Write-Log "Configure Programs!" Green


}

Main
