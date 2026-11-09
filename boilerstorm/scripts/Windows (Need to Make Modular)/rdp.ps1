# only used for GroupPolicy
function Set-RegistryKeyValue {
    param (
        [string]$Path,
        [string]$Key,
        [string]$ValueName,
        $Type,
        $Data
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    $keyPath = Join-Path -Path $Path -ChildPath $Key

    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }

    Set-ItemProperty -Path $keyPath -Name $ValueName -Value $Data -Type $Type
}

function groupPolicy(){
 $userInput = Read-Host -Prompt "Do you want to execute Remote Desktop Group Policy? (y/n)"
    if ($userInput -eq "y") {
        try {
        # # Restrict Remote Registry Access
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg" -ValueName \ -Type String -Data "O:BAG:SYD:(D;;0xf0007;;;SY)(D;;0xf0007;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)"
        # # Disable Remote Assistance
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fAllowToGetHelp -Type DWord -Data 0
        # Disable Remote Desktop Clipboard
        Set-RegistryKeyValue-Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableClip -Type DWord -Data 1

        # Disable Remote Desktop Clipboard Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableClip -Type DWord -Data 1

        # Disable Remote Desktop Printer Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableCpm -Type DWord -Data 1

        # Disable Remote Desktop Drive Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableCdm -Type DWord -Data 1

        # Disable Remote Desktop COM Port Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableCcm -Type DWord -Data 1

        # Disable Remote Desktop LPT Port Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableLPT -Type DWord -Data 1

        # Disable Remote Desktop PnP Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisablePNPRedir -Type DWord -Data 1

        # Disable Remote Desktop Audio Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableAudioCapture -Type DWord -Data 1

        # Disable Remote Desktop Audio Playback
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableAudio -Type DWord -Data 1

        # Disable Remote Desktop Smart Card Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisableSmartCard -Type DWord -Data 1

        # Disable Remote Desktop Plug and Play Device Redirection
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fDisablePNPRedir -Type DWord -Data 1

        # Restrict Remote Registry Access
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg" -ValueName \ -Type String -Data "O:BAG:SYD:(D;;0xf0007;;;SY)(D;;0xf0007;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)"

        # Disable Remote Assistance
        Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName fAllowToGetHelp -Type DWord -Data 0

        Write-Host "Group Policies have been successfully set." -ForegroundColor Green
        }
        catch {
            Write-Host "An error occurred while executing the command: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "You did not enter y"
    }
}

function hostFirewall(){
 $userInput = Read-Host -Prompt "Do you want to execute Remote Desktop Firewall? (y/n)"
    if ($userInput -eq "y") {
        try {
       netsh advfirewall firewall add rule name="Block RDP" dir=in action=block protocol=TCP localport=3389
        Write-Host "Firewall have been successfully set." -ForegroundColor Green
        }
        catch {
            Write-Host "An error occurred while executing the command: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "You did not enter y"
    }
}

function massReg() {
 reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f
}
# more stuff

massReg
groupPolicy
hostFirewall


