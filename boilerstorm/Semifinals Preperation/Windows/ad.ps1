function ADUserAudit {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "CheckedValue" /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "CheckedValue" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null
    $file = "correctUsers.txt"
    # Read file content and replace newlines with spaces
    try {
        $readmeContent = (Get-Content $file -Raw) -replace "`r`n", ' '
    }
    catch {
        Write-Host "Error reading file: $_"
        Write-Host "Make sure you did the correctUsers.txt"
        exit 1
    }
    
    # Extract Authorized Administrators
    try {
        $adminsResult = ($readmeContent -split 'Authorized Administrators:')[1] -split 'Authorized Users:' | Select-Object -First 1
        $baseAdmins = $adminsResult -split ' ' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        if ($baseAdmins.Count -eq 0) { Write-Host "Add Admins to the File"; exit 1 } else { Write-Host "Authorized Admins: $($baseAdmins -join ', ')" }
    }
    catch {
        Write-Host "Error extracting Authorized Administrators: $_"
        exit 1
    }
    
    # Extract Authorized Users
    try {
        $usersResult = ($readmeContent -split 'Authorized Users:')[1]
        $baseUsers = $usersResult -split ' ' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        if ($baseUsers.Count -eq 0) { Write-Host "Add Users to the File"; exit 1 } else { Write-Host "Authorized Users: $($baseUsers -join ', ')" }
    }
    catch {
        Write-Host "Error extracting Authorized Users: $_"
        exit 1
    }
    
    # Get the current user
    $currentUsername = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
    
    # Add the current user to the admin list if not already present
    if (-not $baseAdmins.Contains($currentUsername)) {
        $baseAdmins += $currentUsername
    }
    
    # Get all AD users
    try {
        $allUsers = Get-ADUser -Filter * | Where-Object { $_.Enabled -eq $true }
    }
    catch {
        Write-Host "Error retrieving AD users: $_"
        exit 1
    }
    
    $usersToExclude = @(
        "$currentUsername"
        "WDAGUtilityAccount",   
        "DefaultAccount",       
        "Guest",                
        "Administrator",        
        "sshd",                 
        "System",               
        "LocalService",         
        "NetworkService",       
        "IUSR",                 
        "IISUSR",               
        "TrustedInstaller",     
        "DWM-*",                
        "TsInternetUser",       
        "SQLServer*"            
        "MSSQL*"                
        "NT AUTHORITY\*"        
        "NT SERVICE\*"          
        "HealthMailbox*"       
        "krbtgt",               
        "Hyper-V Administrators", 
        "Virtual Machine Group",
        "VSS",                 
        "WMSvc"           
    )
    
    # Filter out specific users
    $filteredUsers = $allUsers | Where-Object { $usersToExclude -notcontains $_.SamAccountName }
    
    $allUsers = $filteredUsers
    
    # Remove admin from everyone (will get added back later)
    foreach ($user in $allUsers) {
        $username = $user.SamAccountName
        # Ensure $currentUsername is defined and matches the expected value
        if ($username -ne $currentUsername) {
            # Get members of the Administrators group and filter by username
            $userGroup = Get-ADGroupMember -Identity "Administrators" | Where-Object { $_.SamAccountName -eq $username }
                
            if ($userGroup) {
                # Remove from Administrators group
                Remove-ADGroupMember -Identity "Administrators" -Members $user -Confirm:$false
            }
        }
    }
    
    # Add back the users
    foreach ($user in $baseUsers) {
        try {
            # Attempt to retrieve the user; if they exist, do nothing
            Get-ADUser -Identity $user
        }
        catch {
            # If an error occurs (user doesn't exist), create the user
            New-ADUser -SamAccountName $user -UserPrincipalName "$user@domain.com" -NoPassword
            Write-Output "Added user: $user"
        }
    }
    # Add back the admins as users
    foreach ($user in $baseAdmins) {
        try {
            # Attempt to retrieve the user; if they exist, do nothing
            Get-ADUser -Identity $user
        }
        catch {
            # If an error occurs (user doesn't exist), create the user
            New-ADUser -SamAccountName $user -UserPrincipalName "$user@domain.com" -NoPassword
            Write-Output "Added Admin: $user"
        }
    }
    
    # Add back the admins as admins
    foreach ($admin in $baseAdmins) {
        try {
            Add-ADGroupMember -Identity "Administrators" -Members $admin -Confirm:$false
            Write-Host "$admin has been added to the Administrators group"
        }
        catch {
            Write-Host "An error occurred while trying to add $admin to the Administrators group: $_"
        }
    }
    
    foreach ($user in $baseUsers) {
        Enable-ADAccount -Identity $user
        Set-ADUser -Identity $user -PasswordNeverExpires $false
        Set-ADUser -Identity $user -UserCannotChangePassword $false
    }
    foreach ($user in $baseAdmins) {
        Enable-ADAccount -Identity $user
        Set-ADUser -Identity $user -PasswordNeverExpires $false
        Set-ADUser -Identity $user -UserCannotChangePassword $false
    }
    
    # Start the removal process 
    foreach ($user in $allUsers) {
        $username = $user.SamAccountName
    
        # Remove the user if they're not in base users or base admins and not a protected account
        if (-not ($baseUsers -contains $username) -and -not ($baseAdmins -contains $username) -and 
            -not ($username -in $usersToExclude)) {
                
            Write-Host "---------------------------------------------"
            Write-Host "Processing user: $username"
                
            # Ask for confirmation before removal
            $response = Read-Host "Do you want to remove user $username? (y/n)"
                
            if ($response -eq 'y') {
                try {
                    Remove-ADUser -Identity $username -Confirm:$false
                    Write-Host "Removed user $username"
                }
                catch {
                    Write-Host "Failed to remove user {$username}: $_"
                }
            }
            else {
                Write-Host "Skipped removal of user $username"
            }
                
            # Clear some space for the next prompt
            Write-Host "`n"
        }
    }
    
    Write-Host "What would you like your password to be (Something like CyberPatriot1!#)"
    $password = Read-Host -AsSecureString
    foreach ($user in $baseUsers) {
        try {
            Set-ADUser -Identity $user -AccountPassword $password
        }
        catch {
            Write-Host "Failed to set password for user {$username}: $_"
        }
    }
    foreach ($user in $baseAdmins) {
        try {
            Set-ADUser -Identity $user -AccountPassword $password
        }
        catch {
            Write-Host "Failed to set password for user {$username}: $_"
        }
    }
    
    Write-Host "Set the users."
    Write-Host "Now moving on to groups."
    
    $configureGroups = Read-Host "Are there any groups you would like to configure? (y/n)"
    
    # Start the loop
    while ($configureGroups -eq "y") {
        # Prompt for the group name to configure
        $groupName = Read-Host "Enter the name of the group you would like to configure"
    
        # Check if the group exists
        if (Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue) {
            # List all users currently in the group
            Write-Output "Users currently in the group '$groupName':"
            $currentUsers = Get-ADGroupMember -Identity $groupName
            $currentUsers | ForEach-Object { Write-Output $_.SamAccountName }
    
            # Prompt for users to remove
            $removeUsers = Read-Host "List all users you would like to remove from '$groupName' (separated by a space, or press Enter to skip)"
            if ($removeUsers) {
                # Convert input to an array of usernames
                $removeUsersArray = $removeUsers.Split(" ")
    
                # Attempt to remove each specified user from the group
                foreach ($user in $removeUsersArray) {
                    if ($currentUsers.SamAccountName -contains $user) {
                        Remove-ADGroupMember -Identity $groupName -Members $user -Confirm:$false
                        Write-Host "Removed $user from $groupName"
                    }
                    else {
                        Write-Host "$user is not a member of $groupName"
                    }
                }
            }
    
            # Prompt for users to add
            $addUsers = Read-Host "List all users you would like to add to '$groupName' (separated by a space, or press Enter to skip)"
            if ($addUsers) {
                # Convert input to an array of usernames
                $addUsersArray = $addUsers.Split(" ")
    
                # Attempt to add each specified user to the group
                foreach ($user in $addUsersArray) {
                    Add-ADGroupMember -Identity $groupName -Members $user -Confirm:$false
                    Write-Host "Added $user to $groupName"
                }
            }
        }
        else {
            Write-Host "The group '$groupName' does not exist."
        }
    
        # Ask if user wants to configure another group
        $configureGroups = Read-Host "Would you like to configure another group? (y/n)"
    }
    # Get the list of users from the SAM registry
    $users = Get-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\*" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'Names' }
    
    foreach ($user in $users) {
        # Get the binary data from the 'F' value
        $fValue = $user.F
    
        # Check if the data at the 0030 offset contains the bytes corresponding to F4 01
        # The 0030 offset in PowerShell is 48 in decimal, and we need two bytes from there
        if ($fValue[48] -eq 0xF4 -and $fValue[49] -eq 0x01) {
            Write-Host "Potential RID hijacking detected for user with key: $($user.PSChildName)"
        }
    }
    # Get all user accounts where DES encryption is enabled
    Get-ADUser -Filter { UserAccountControl -band 0x200000 } -Properties UserAccountControl | ForEach-Object {
        # Get the current UserAccountControl value
        $currentUAC = $_.UserAccountControl
    
        # Remove the DES encryption flag (0x200000)
        $newUAC = $currentUAC -band 0xFFFDFFFF
    
        # If the UserAccountControl value was changed, apply the new value and print the result
        if ($currentUAC -ne $newUAC) {
            Set-ADUser -Identity $_ -UserAccountControl $newUAC
            Write-Host "DES encryption disabled for user: $($_.SamAccountName)"
        }
    }
    
    # Get users with 'Does not require pre-authentication' flag
    Get-ADUser -Filter { userAccountControl -band 4194304 } -Properties userAccountControl | ForEach-Object {
        # Check if the user requires pre-authentication (i.e., userAccountControl has the flag 4194304)
        if ($_ .userAccountControl -band 4194304) {
            # Set 'Does not require pre-authentication' to false and print the result
            Set-ADAccountControl -Identity $_.SamAccountName -DoesNotRequirePreAuth $false
            Write-Host "Pre-authentication enabled for user: $($_.SamAccountName)"
        }
    }
    
    # Automatically get the domain's Distinguished Name (DN) based on the computer's domain
    $domainDN = (Get-ADDomain).DistinguishedName
    
    # Get all AD objects in the domain (not just OUs, but computers, users, etc.)
    $ADObjects = Get-ADObject -Filter * -SearchBase "LDAP://$domainDN" -Properties dsHeuristic
    
    # Iterate through each object and set the dsHeuristic attribute
    foreach ($obj in $ADObjects) {
        $objDN = $obj.DistinguishedName
    
        # Check if the object has the dsHeuristic property and modify it
        if ($obj.PSObject.Properties.Match("dsHeuristic")) {
            try {
                # Set the dsHeuristic attribute to 0 (or desired value) for each object
                Set-ADObject -Identity $objDN -Replace @{dsHeuristic = 0 }
    
                # Output the change for verification
                Write-Host "dsHeuristic set to 0 for object: $($obj.Name) [$($objDN)]"
            }
            catch {
                Write-Error "Failed to set dsHeuristic for object: $($obj.Name) [$($objDN)] - $_"
            }
        }
        else {
            Write-Host "Object: $($obj.Name) does not have the dsHeuristic attribute."
        }
    }
    
    # Get all OUs in the domain
    $OUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName
    
    # SID for the "Everyone" group
    $everyoneSID = "S-1-1-0"  # Everyone group SID
    
    # Iterate through each OU
    foreach ($OU in $OUs) {
        $OUdn = $OU.DistinguishedName
        try {
            # Get the current ACL (Access Control List) for the OU
            $acl = Get-Acl "AD:$OUdn"
    
            # Check if the "Everyone" group has "Replicating Directory Changes All" or "Replicating Directory Changes" permissions
            $permissions = $acl.Access | Where-Object { 
                $_.IdentityReference -eq $everyoneSID -and 
                ($_.ActiveDirectoryRights -eq "ReplicatingDirectoryChangesAll" -or $_.ActiveDirectoryRights -eq "ReplicatingDirectoryChanges") 
            }
    
            # If such permissions exist, remove them
            foreach ($permission in $permissions) {
                Write-Host "Removing replicating directory change permission for 'Everyone' on OU: $($OU.Name)"
                $acl.RemoveAccessRule($permission)
            }
    
            # Apply the updated ACL
            Set-Acl "AD:$OUdn" $acl
        }
        catch {
            Write-Error "Failed to process OU: $($OU.Name) - $_"
        }
    }
    
    
    # Secure default groups
    $group = "Pre-Windows 2000 Compatible Access"
    $groupObject = Get-ADGroup -Identity $group
    
    # Get all current members of the group
    $members = Get-ADGroupMember -Identity $groupObject
    
    # Check group permissions for "Authenticated Users"
    $acl = Get-Acl "AD:\$group"
    $authenticatedUsersPermission = $acl.Access | Where-Object { $_.IdentityReference -eq "Authenticated Users" }
    
    # If "Authenticated Users" has Full Control, change it to Read-Only
    if ($authenticatedUsersPermission.AccessControlType -eq "Allow" -and $authenticatedUsersPermission.ActiveDirectoryRights -eq "GenericAll") {
        # Remove Full Control and set Read-Only
        $acl.RemoveAccessRule($authenticatedUsersPermission)
        $readOnlyPermission = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute", "Allow")
        $acl.AddAccessRule($readOnlyPermission)
        Set-Acl "AD:\$group" $acl
        Write-Host "Updated 'Authenticated Users' to Read-Only access."
    }
    else {
        Write-Host "'Authenticated Users' already have Read-Only access."
    }
    
    # Loop through the members and remove them, excluding "Authenticated Users"
    foreach ($member in $members) {
        if ($member.Name -ne "Authenticated Users") {
            $confirmation = Read-Host "Are you sure you want to remove $($member.Name) from $group? (Y/N)"
            if ($confirmation.ToLower() -eq "y") {
                Remove-ADGroupMember -Identity $groupObject -Members $member -Confirm:$false
                Write-Host "Removed $($member.Name) from $group"
            }
            else {
                Write-Host "Skipped removing $($member.Name)"
            }
        }
    }
    # Get all members of the Backup Operators group in AD
    $members = Get-ADGroupMember -Identity "Backup Operators"
    
    # Iterate through each member
    foreach ($member in $members) {
        $confirmation = Read-Host "Do you want to remove '$($member.SamAccountName)' from the Backup Operators group? (yes/no)"
        if ($confirmation -eq "yes") {
            Remove-ADGroupMember -Identity "Backup Operators" -Members $member.SamAccountName -Confirm:$false
            Write-Host "Removed $($member.SamAccountName) from Backup Operators."
        }
        else {
            Write-Host "Skipped removing $($member.SamAccountName)."
        }
    }
    Get-ADGroup | ForEach-Object { Set-ADGroup $_ -Clear ManagedBy }
    
    # Starting search in users' home directories
    Write-Host "--------------------All-home-dirs----------------------"
    # Get all directories inside C:\Users
    $usersDirs = Get-ChildItem -Path C:\Users -Directory
    
    # Loop through each directory and generate a tree for it
    foreach ($dir in $usersDirs) {
        Write-Host "Tree for $($dir.FullName)"
        Write-Host "-------------------------------------------------------------"
        tree $dir.FullName /F /A
        Write-Host "-------------------------------------------------------------"
        Write-Host ""
    }
}




















function ADconfig {
    # Update various user properties
    Get-ADUser -Filter 'Name -like "*"' -Properties DisplayName | ForEach-Object {
        Set-ADUser $_ -TrustedForDelegation $false -PasswordNeverExpires $false -PasswordNotRequired $false -CannotChangePassword $true -AllowReversiblePasswordEncryption $false
    }
    Get-ADUser -Filter 'Name -like "*"' -Properties DisplayName | ForEach-Object {
        Set-ADAccountControl $_ -DoesNotRequirePreAuth $false -AllowReversiblePasswordEncryption $false -TrustedForDelegation $false -TrustedToAuthForDelegation $false -UseDESKeyOnly $false -AccountNotDelegated $true
    }
    
    # Adjust encryption types for users
    Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -band 0x4' -Properties msDS-SupportedEncryptionTypes |
    ForEach-Object {
        $NewEncTyp = $_.'msDS-SupportedEncryptionTypes' - 0x4
        Set-ADUser -Identity $_ -replace @{'msDS-SupportedEncryptionTypes' = $NewEncTyp }
    }
    
    # Remove sidhistory from users
    Get-ADUser -Filter { sidhistory -like '*' } -properties sidhistory | ForEach-Object {
        Set-ADUser $_ -remove @{sidhistory = $_.sidhistory.value }
    }
    
    # Variable to hold all group names
    $groups = Get-ADGroup -Filter *
    
    # Remove sidhistory from groups
    $groups | ForEach-Object {
        $group = Get-ADGroup $_ -Properties sidhistory
        if ($group.sidhistory) {
            Set-ADGroup $group -Remove @{sidhistory = $group.sidhistory.value }
        }
    }
    
    
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
function Check-RegistryPerms {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,
    
        [Parameter(Mandatory = $true)]
        [hashtable]$Permissions
    )
    
    # Check if the registry path exists
    if (-not (Test-Path $RegistryPath)) {
        Write-Output "Finding: The registry key '$RegistryPath' does not exist."
        return
    }
    
    # Get the Access Control List (ACL) for the registry key
    $acl = Get-Acl -Path $RegistryPath
    $findings = @()
    
    # Check for unexpected groups with permissions
    $expectedGroups = $Permissions.Keys
    $actualGroups = $acl.Access | Select-Object -ExpandProperty IdentityReference | Select-Object -Unique
    $unexpectedGroups = $actualGroups | Where-Object { $_ -notin $expectedGroups }
    
    if ($unexpectedGroups) {
        foreach ($group in $unexpectedGroups) {
            $findings += "Warning: Unexpected permissions found for $group."
        }
    }
    
    # Loop through each entry in the permissions hashtable
    foreach ($group in $Permissions.Keys) {
        $requiredPermission = $Permissions[$group]
            
        # Check if the group has the required permissions
        $groupAccess = $acl.Access | Where-Object {
            $_.IdentityReference -eq $group -and $_.FileSystemRights -contains $requiredPermission
        }
    
        if (-not $groupAccess) {
            $findings += "$group does not have $requiredPermission permissions."
        }
    }
    
    # Output findings
    if ($findings.Count -eq 0) {
        Write-Output "Permissions for '$RegistryPath' are as required."
    }
    else {
        Write-Output "Findings for '$RegistryPath':"
        $findings | ForEach-Object { Write-Output $_ }
    }
}