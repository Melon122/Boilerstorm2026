# Requires -RunAsAdministrator

# Password Policy Configuration
function Set-PasswordPolicy {
    Write-Host "Configuring Password Policy..." -ForegroundColor Green
    
    # Set password policies using net accounts
    net accounts /MINPWLEN:14
    net accounts /MAXPWAGE:60
    net accounts /MINPWAGE:1
    net accounts /UNIQUEPW:24
    
    # Set password complexity using secedit
    $securityPolicy = @"
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0
"@
    $securityPolicy | Out-File "$env:TEMP\secpol.cfg"
    secedit /configure /db $env:windir\security\new.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY
    Remove-Item "$env:TEMP\secpol.cfg" -Force
}

# Account Lockout Policy Configuration
function Set-LockoutPolicy {
    Write-Host "Configuring Lockout Policy..." -ForegroundColor Green
    net accounts /lockoutduration:30
    net accounts /lockoutthreshold:10
    net accounts /lockoutwindow:30
}

# User Settings Configuration
function Set-UserSettings {
    Write-Host "Configuring User Settings..." -ForegroundColor Green
    $users = Get-LocalUser
    foreach ($user in $users) {
        # Force password change at next logon
        Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
        Set-LocalUser -Name $user.Name -UserMayChangePassword $true
        
        # Check if user is authorized (you'll need to modify this list)
        $authorizedUsers = @("Administrator", "AuthorizedUser1", "AuthorizedUser2")
        if ($user.Name -notin $authorizedUsers) {
            Disable-LocalUser -Name $user.Name
        }
    }
}

# Windows Services Configuration
function Set-WindowsServices {
    Write-Host "Configuring Windows Services..." -ForegroundColor Green
    $services = @{
        "upnphost" = @("Stopped", "Disabled")
        "TlntSvr" = @("Stopped", "Disabled")
        "SNMPTRAP" = @("Stopped", "Disabled")
        "Wecsvc" = @("Running", "Automatic")
        "RemoteRegistry" = @("Stopped", "Disabled")
    }
    
    foreach ($service in $services.Keys) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            if ($services[$service][0] -eq "Stopped") {
                Stop-Service -Name $service -Force
            } else {
                Start-Service -Name $service
            }
            Set-Service -Name $service -StartupType $services[$service][1]
        }
    }
}

# Screen Saver Configuration
function Set-ScreenSaver {
    Write-Host "Configuring Screen Saver..." -ForegroundColor Green
    $RegPath = "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path $RegPath -Name "ScreenSaveActive" -Value 1
    Set-ItemProperty -Path $RegPath -Name "ScreenSaverIsSecure" -Value 1
    Set-ItemProperty -Path $RegPath -Name "ScreenSaveTimeOut" -Value 600
    Set-ItemProperty -Path $RegPath -Name "SCRNSAVE.EXE" -Value "C:\Windows\System32\scrnsave.scr"
}

# Audit Policy Configuration
function Set-AuditPolicy {
    Write-Host "Configuring Audit Policy..." -ForegroundColor Green
    $auditCategories = @(
        "Account Logon",
        "Account Management",
        "Detailed Tracking",
        "DS Access",
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System"
    )
    
    foreach ($category in $auditCategories) {
        auditpol /set /category:"$category" /success:enable /failure:enable
    }
}

# Main execution
function Main {
    Write-Host "Starting Security Configuration Script..." -ForegroundColor Cyan
    
    # Check for administrator privileges
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Administrator privileges required. Please run this script as Administrator."
        exit 1
    }
    
    # Execute all configurations
    Set-PasswordPolicy
    Set-LockoutPolicy
    Set-UserSettings
    Set-WindowsServices
    Set-ScreenSaver
    Set-AuditPolicy
    
    Write-Host "Security Configuration Complete!" -ForegroundColor Green
}

# Run the script
Main
