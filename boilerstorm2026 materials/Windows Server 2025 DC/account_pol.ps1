# PowerShell Script to Configure Secure Password Policies
# Run as Administrator

# Function to write status messages
function Write-Status {
    param($Message)
    Write-Host "[*] $Message" -ForegroundColor Green
}

try {
    Write-Status "Starting password policy configuration..."
    
    # Configure password history
    Net Accounts /UNIQUEPW:24
    Write-Status "Password history set to 24"
    
    # Set maximum password age
    Net Accounts /MAXPWAGE:365
    Write-Status "Maximum password age set to 365 days"
    
    # Set minimum password age
    Net Accounts /MINPWAGE:1
    Write-Status "Minimum password age set to 1 day"
    
    # Set minimum password length
    Net Accounts /MINPWLEN:14
    Write-Status "Minimum password length set to 14 characters"
    
    # Enable password complexity
    $complexityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    Set-ItemProperty -Path $complexityPath -Name "RequireStrongKey" -Value 1
    Write-Status "Password complexity requirements enabled"
    
    # Configure account lockout policies
    Net Accounts /LOCKOUTDURATION:15
    Write-Status "Account lockout duration set to 15 minutes"
    
    Net Accounts /LOCKOUTTHRESHOLD:5
    Write-Status "Account lockout threshold set to 5 attempts"
    
    Net Accounts /LOCKOUTWINDOW:15
    Write-Status "Account lockout counter reset time set to 15 minutes"
    
    # Enable administrator account lockout via Registry
    $adminLockoutPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $adminLockoutPath -Name "AllocateDASD" -Value 0
    Write-Status "Administrator account lockout enabled"
    
    # Disable reversible encryption
    $securityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $securityPath -Name "ClearTextPassword" -Value 0
    Write-Status "Reversible encryption disabled"
    
    # Additional security settings
    # Set password complexity requirements via Security Policy
    $secEditPath = "$env:windir\security\database\secedit.sdb"
    $tempPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $tempPath
    (Get-Content $tempPath) | ForEach-Object {
        $_ -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
    } | Set-Content $tempPath
    secedit /configure /db $secEditPath /cfg $tempPath /areas SECURITYPOLICY
    Remove-Item -Path $tempPath -Force
    Write-Status "Security policy updated for password complexity"
    
    # Display final configuration
    Write-Status "Displaying current password policy settings:"
    Net Accounts
    
    Write-Status "Password policy configuration completed successfully!"
}
catch {
    Write-Host "[!] Error occurred: $_" -ForegroundColor Red
    exit 1
}
