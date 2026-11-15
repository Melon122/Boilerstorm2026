$file = "currentUsers.txt", "Users.txt"
$ErrorActionPreference = "Stop"

# Get the current user's profile folders
$searchFolders = @(
    [Environment]::GetFolderPath("Downloads"),
    [Environment]::GetFolderPath("Documents"),
    [Environment]::GetFolderPath("Desktop")
)

$fileFound = $false
foreach ($searchFile in $file) {
    foreach ($folder in $searchFolders) {
        $filePath = Join-Path $folder $searchFile
        if (Test-Path $filePath -PathType Leaf) {
            $file = $filePath
            $fileFound = $true
            break
        }
    }
    if ($fileFound) {
        break
    }
}

if (-not $fileFound) {
    Write-Host "Error: 'currentUsers.txt' or 'Users.txt' not found in the current user's Downloads, Documents, or Desktop folders."
    Write-Host "File format should be with the name: currentUsers.txt or Users.txt`nIn this format:`n`nStart Here(Not in acutal file):`nAuthorized Administrators:`nAdmin1`nAdmin2`netc.`nAuthorized Users:`nUser1`nUser2`nUser3`netc.`nEnd Here (Not in actual file)"
    exit 1
}

# Read file content and replace newlines with spaces
try {
    $readmeContent = (Get-Content $file -Raw) -replace "`r`n", ' '
} catch {
    Write-Host "Error reading file: $_"
    exit 1
}

# Extract Authorized Administrators
try {
    $adminsResult = ($readmeContent -split 'Authorized Administrators:')[1] -split 'Authorized Users:' | Select-Object -First 1
    $baseAdmins = $adminsResult -split ' ' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    if ($baseAdmins.Count -eq 0) { Write-Host "Add Admins to the File"; exit 1 } else { Write-Host "Authorized Administrators: $($baseAdmins -join ', ')" }
} catch {
    Write-Host "Error extracting Authorized Administrators: $_"
    exit 1
}

# Extract Authorized Users
try {
    $usersResult = ($readmeContent -split 'Authorized Users:')[1]
    $baseUsers = $usersResult -split ' ' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    if ($baseUsers.Count -eq 0) { Write-Host "Add Users to the File"; exit 1 } else { Write-Host "Authorized Users: $($baseUsers -join ', ')" }
} catch {
    Write-Host "Error extracting Authorized Users: $_"
    exit 1
}

# Get the current user
$currentUsername = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]

# Add the current user to the admin list if not already present
if (-not $baseAdmins.Contains($currentUsername)) {
    $baseAdmins += $currentUsername
}

# Get all local users
try {
    $allUsers = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
} catch {
    Write-Host "Error retrieving local users: $_"
    exit 1
}

# Step 1: Remove admin rights from everyone except the current user and protected accounts
$usersToExclude = @(
    "$currentUsername"
    "WDAGUtilityAccount", "DefaultAccount", "Guest", "Administrator", "sshd", "System", "LocalService", "NetworkService", "IUSR", "IISUSR", "TrustedInstaller", "DWM-*", "TsInternetUser", "SQLServer*", "MSSQL*", "NT AUTHORITY\*", "NT SERVICE\*", "HealthMailbox*", "krbtgt", "Hyper-V Administrators", "Virtual Machine Group", "VSS", "WMSvc"
)

$filteredUsers = $allUsers | Where-Object { $usersToExclude -notcontains $_.Name }
Write-Host "Removing admin rights from users not in the exclusion list:"
foreach ($user in $filteredUsers) {
    $username = $user.Name
    Write-Host "Processing user: $username"
    
    # Get members of the Administrators group and filter by username
    $userGroup = Get-LocalGroupMember -Group "Administrators" | Where-Object {
        $localUsername = ($_).Name.Split('\')[-1]
        $localUsername -eq $username
    }
    
    if ($userGroup) {
        Write-Host "User found in Administrators group: $username"
        # Remove from Administrators group
        Remove-LocalGroupMember -Group "Administrators" -Member $username -Confirm
    }
    else {
        Write-Host "User not found in Administrators group or failed to query group for user: $username"
    }
}

# Step 2: Re-admin the base admins (including current user)
Write-Host "Re-adding authorized administrators to the Administrators group:"
foreach ($admin in $baseAdmins) {
    # Check if the user exists before adding them to the admin group
    if (Get-LocalUser -Name $admin) {
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction Stop
            Write-Host "$admin has been added to the Administrators group"
        } catch {
            # Check if the error message indicates the user is already a member
            if ($_.Exception.Message -match "already a member") {
                Write-Host "$admin is already an admin"
            } else {
                Write-Host "An error occurred while trying to add $admin to the Administrators group: $_"
            }
        }
    }
}

# Step 3: Disable users not in the base users or base admins list, with confirmation
Write-Host "Disabling unauthorized users:"
foreach ($user in $filteredUsers) {
    $username = $user.Name

    # Disable the user if they're not in base users or base admins and not a protected account
    if (-not ($baseUsers -contains $username) -and -not ($baseAdmins -contains $username)) {
        
        # Provide clear visual separation for the prompt
        Write-Host "---------------------------------------------"
        Write-Host "Processing user: $username"
        
        # Ask for confirmation before disabling
        $response = Read-Host "Do you want to disable user $username? (y/n)"
        
        if ($response -eq 'y') {
            try {
                Disable-LocalUser -Name $username
                Write-Host "Disabled user $username"
            } catch {
                Write-Host "Failed to disable user {$username}: $_"
            }
        } else {
            Write-Host "Skipped disabling user $username"
        }
        
        # Clear some space for the next prompt
        Write-Host "`n"
    }
}

# Step 4: Set the password for all accounts to a secure value
$password = ConvertTo-SecureString "CyberPatriot101!#" -AsPlainText -Force
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$gpoPath = "Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy"

Write-Host "Setting the password for all accounts to 'CyberPatriot101!#' and updating password policies..."

# Set the password for all local users
foreach ($user in $allUsers) {
    $username = $user.Name
    try {
        Set-LocalUser -Name $username -Password $password
        Write-Host "Password set for user $username"
    } catch {
        Write-Host "Failed to set password for user {$username}: $_"
    }
}

# Update registry settings to make the password difficult to change
Set-ItemProperty -Path $regKeyPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
Set-ItemProperty -Path $regKeyPath -Name "RestrictAnonymous" -Value 1 -Type DWord

# Update Group Policy settings to enforce password requirements
& gpupdate /force
Write-Host "Password policies have been updated to make the password difficult to change."

Write-Host "User management complete."
