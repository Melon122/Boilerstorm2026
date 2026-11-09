$user =  $env:USERNAME

function globalAudit(){
    Write-Host "Adding global audit policies..." -ForegroundColor Gray
    $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version
    $OSName = $OSWMI.Caption
    if ($LASTEXITCODE -eq 0){
        try {
            auditpol /resourceSACL /set /type:File /user:Administrator /success /failure /access:FW
            auditpol /resourceSACL /set /type:Key /user:Administrator /success /failure /access:FW

      	    auditpol /resourceSACL /set /type:File /user:Domain Admins /success /failure /access:FW
            auditpol /resourceSACL /set /type:Key /user:Domain Admins /success /failure /access:FW
        }
        catch {
            Write-Host "$user GLOBAL AUDIT POLICY FAILURE : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "User $user does not exist" -ForegroundColor Red
    }
}



function smbShare() {
    try {
        $OSWMI = Get-CimInstance Win32_OperatingSystem -Property Caption,Version
        $OSVer = [version]$OSWMI.Version
        $OSName = $OSWMI.Caption
        # SMBv1 server
        # Windows v6.2 and later (client & server OS)
        If ($OSVer -ge [version]"6.2") { If ((Get-SmbServerConfiguration).EnableSMB1Protocol) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } }
        # Windows v6.0 & 6.1 (client & server OS)
        ElseIf ($OSVer -ge [version]"6.0" -and $OSVer -lt [version]"6.2") { Set-ItemProperty  }
        # SMBv1 client
        # Windows v6.3 and later (server OS only)
        If ($OSVer -ge [version]"6.3" -and $OSName -match "\bserver\b") { If ((Get-WindowsFeature FS-SMB1).Installed) { Remove-WindowsFeature FS-SMB1 } }
        # Windows v6.3 and later (client OS)
        ElseIf ($OSVer -ge [version]"6.3" -and $OSName -notmatch "\bserver\b") {
            If ((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State -eq "Enabled") { Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol }
            If ((Get-WindowsOptionalFeature -Online -FeatureName smb2protocol).State -eq "Enabled") { Disable-WindowsOptionalFeature -Online -FeatureName smb2protocol }
        }
        # Windows v6.2, v6.1 and v6.0 (client and server OS)
        ElseIf ($OSVer -ge [version]"6.0" -and $OSVer -lt [version]"6.3") {
            $svcLMWDependsOn = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\).DependOnService
            If ($svcLMWDependsOn -contains "MRxSmb10") {
                $svcLMWDependsOn = $svcLMWDependsOn | Where-Object{$_ -ne "MRxSmb10"}
                Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\ -Name DependOnService -Value $svcLMWDependsOn -Type MultiString
            }
            Set-Service mrxsmb10 -StartupType Disabled
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)"
    }
}


function smbGood() {
    try {
        If ($PSVersionTable.PSVersion -ge [version]"3.0") { $OSWMI = Get-CimInstance Win32_OperatingSystem -Property Caption,Version }
        Else { $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version }
        $OSVer = [version]$OSWMI.Version
        $OSName = $OSWMI.Caption
        # Windows v6.2 and later (client & server OS)
        If ($OSVer -ge [version]"6.2") { Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force }
        # Windows v6.0 & 6.1 (client & server OS)
        ElseIf ($OSVer -ge [version]"6.0" -and $OSVer -lt [version]"6.2") { Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters SMB2 -Type DWORD -Value 1 -Force}
        # Windows v6.3 and later (server OS only)
        If ($OSVer -ge [version]"6.3" -and $OSName -match "\bserver\b") { If ((Get-WindowsFeature FS-SMB3).Installed) { Install-WindowsFeature FS-SMB3 } }
        # Windows v6.3 and later (client OS)
        ElseIf ($OSVer -ge [version]"6.3" -and $OSName -notmatch "\bserver\b") {
            If ((Get-WindowsOptionalFeature -Online -FeatureName smb2protocol).State -eq "Disabled") { Enable-WindowsOptionalFeature -Online -FeatureName smb2protocol }
        }
    }
    catch {
        Write-Host "An error occurred while configuring SMBv3: $($_.Exception.Message)" -ForegroundColor Red 
    }
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force
    }
    catch {
        Write-Host "An error occurred while configuring second SMB3: $($_.Exception.Message)" -ForegroundColor Red 
    }
}

# only used for GroupPolicy
# function Set-RegistryKeyValue {
#     param (
#         [string]$Path,
#         [string]$Key,
#         [string]$ValueName,
#         $Type,
#         $Data
#     )

#     if (-not (Test-Path $Path)) {
#         New-Item -Path $Path -Force | Out-Null
#     }

#     $keyPath = Join-Path -Path $Path -ChildPath $Key

#     if (-not (Test-Path $keyPath)) {
#         New-Item -Path $keyPath -Force | Out-Null
#     }

#     Set-ItemProperty -Path $keyPath -Name $ValueName -Value $Data -Type $Type
# }

# function GroupPolicy {
#     Write-Host "Setting Group Policies..." -ForegroundColor Gray
#     try {
	#  Set-RegistryKeyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Key "PreventAutoRun" -ValueName "PreventAutoRun" -Type DWord -Data 1
        # Disable Content File Updates for Search Companion
        #  Set-RegistryKeyValue -Path  "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Key "DisableContentFileUpdates" -ValueName "DisableContentFileUpdates" -Type DWord -Data 1
        # Disable AutoRun for Microsoft Messenger
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName PreventAutoRun -Type DWord -Data 1

        # Disable Content File Updates for Search Companion
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName DisableContentFileUpdates -Type DWord -Data 1
	 # Prevent IIS Install
        # Set-RegistryKeyValue -Path "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -Key "PreventIISInstall" -ValueName "PreventIISInstall" -Type DWord -Data 1

        # Enable Auto Update for Windows Update
        # Set-RegistryKeyValue -Path "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoUpdate" -ValueName "NoAutoUpdate" -Type DWord -Data 0
        # Set Account Lockout Policies
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\AccountLockout" -ValueName LockoutBadCount -Type DWord -Data 5
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\AccountLockout" -ValueName ResetLockoutCount -Type DWord -Data 15

        # Enable Windows Firewall
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\WindowsFirewall" -ValueName DisableFirewall -Type DWord -Data 0

        # Set Audit Policies
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName AuditLogonEvents -Type DWord -Data 2
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName AuditObjectAccess -Type DWord -Data 1

        # Disable Autorun for USB devices
        #Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName NoAutorun -Type DWord -Data 1

        # Disable Windows Script Host
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows Script Host\Settings" -ValueName Enabled -Type DWord -Data 0

        # # Restrict Remote Registry Access
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg" -ValueName \ -Type String -Data "O:BAG:SYD:(D;;0xf0007;;;SY)(D;;0xf0007;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)"

        # Disable LM and NTLMv1 authentication protocols
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName LmCompatibilityLevel -Type DWord -Data 5
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName LMCompatibilityLevel -Type DWord -Data 5

        # Disable Windows Error Reporting
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName Disabled -Type DWord -Data 1
      
        # Disable SMBv1
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName SMB1 -Type DWord -Data 0

        # Disable LM and NTLMv1 authentication protocols
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName LmCompatibilityLevel -Type DWord -Data 5
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName LMCompatibilityLevel -Type DWord -Data 5

        # Disable Windows Error Reporting
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName Disabled -Type DWord -Data 1
      
        # Disable SMBv1
        # Set-RegistryKeyValue -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName SMB1 -Type DWord -Data 0
#         Write-Host "Group Policies have been successfully set." -ForegroundColor Green
#     }
#     catch {
#         Write-Host "Failed to set Default Group Policies: $($_.Exception.Message)" -ForegroundColor Red
#     }
# }

function hostFirewall() {
    Write-Host "Configuring firewall rules..." -ForegroundColor Gray
    try {
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any

        # Block ICMP (ping) requests
        netsh advfirewall firewall add rule name="Block ICMP" dir=in action=block protocol=ICMPv4
        # Block File and Printer Sharing (SMB) traffic
        netsh advfirewall firewall add rule name="Block SMB" dir=in action=block protocol=TCP localport=139
        netsh advfirewall firewall add rule name="Block SMB" dir=in action=block protocol=TCP localport=445
        # Block DNS traffic (TCP and UDP)
        netsh advfirewall firewall add rule name="Block DNS" dir=in action=block protocol=UDP localport=53
        netsh advfirewall firewall add rule name="Block DNS" dir=in action=block protocol=TCP localport=53
        # Block outgoing HTTP and HTTPS traffic
        netsh advfirewall firewall add rule name="Block Outgoing HTTP" dir=out action=block protocol=TCP remoteport=80
        netsh advfirewall firewall add rule name="Block Outgoing HTTPS" dir=out action=block protocol=TCP remoteport=443
        # Block outgoing SMTP traffic
        netsh advfirewall firewall add rule name="Block Outgoing SMTP" dir=out action=block protocol=TCP remoteport=25
        # Block incoming FTP traffic
        netsh advfirewall firewall add rule name="Block Incoming FTP" dir=in action=block protocol=TCP localport=21
        # Block NetBIOS traffic
        netsh advfirewall firewall add rule name="Block NetBIOS" dir=in action=block protocol=UDP localport=137
        netsh advfirewall firewall add rule name="Block NetBIOS" dir=in action=block protocol=UDP localport=138
        netsh advfirewall firewall add rule name="Block NetBIOS" dir=in action=block protocol=TCP localport=139
        # Block outgoing DNS traffic
        netsh advfirewall firewall add rule name="Block Outgoing DNS" dir=out action=block protocol=UDP remoteport=53
        # Block ICMPv6 traffic
        netsh advfirewall firewall add rule name="Block ICMPv6" dir=in action=block protocol=ICMPv6
        # Block incoming SSH traffic (if SSH service is installed)
        netsh advfirewall firewall add rule name="Block Incoming SSH" dir=in action=block protocol=TCP localport=22
        # Block outgoing NTP traffic
        netsh advfirewall firewall add rule name="Block Outgoing NTP" dir=out action=block protocol=UDP remoteport=123
        # Block SNMP traffic
        netsh advfirewall firewall add rule name="Block SNMP" dir=in action=block protocol=UDP localport=161
        # Block incoming IMAP traffic
        netsh advfirewall firewall add rule name="Block Incoming IMAP" dir=in action=block protocol=TCP localport=143
        # Block Apple Bonjour traffic
        netsh advfirewall firewall add rule name="Block Bonjour" dir=in action=block protocol=UDP localport=5353
        # Block outgoing LDAP traffic
        netsh advfirewall firewall add rule name="Block Outgoing LDAP" dir=out action=block protocol=TCP remoteport=389
        # Block outgoing SSH traffic
        netsh advfirewall firewall add rule name="Block Outgoing SSH" dir=out action=block protocol=TCP remoteport=22
        # Block outgoing DNS over HTTPS (DoH) traffic
        netsh advfirewall firewall add rule name="Block Outgoing DoH" dir=out action=block protocol=TCP remoteport=443
        # Block outgoing SNMP Trap traffic
        netsh advfirewall firewall add rule name="Block Outgoing SNMP Trap" dir=out action=block protocol=UDP remoteport=162

         netsh advfirewall firewall add rule name="Block Incoming MySQL" dir=in action=block protocol=TCP localport=3306
	  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
	Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
	    netsh advfirewall import "C:\Users\$user\Desktop\Win10Firewall.wfw"
	    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
	    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
	    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
	    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
	    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
	    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
	    netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
	    netsh advfirewall firewall set rule name="netcat" new enable=no

  #disable network discovery 
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    #disable file and printer sharing 
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes
    
    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block #ssh
    New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block #ftp
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block #telnet
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block #SMTP
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block #POP3
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block #SNMP
    New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block #RDP

    #network profile to public 
    Set-NetConnectionProfile -NetworkCategory Public
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue

	#make sure firewall service is running and configurable
    Set-Service -name MpsSvc -StartupType Automatic -Status Running

    #Enable the entire firewall
    Set-NetFirewallProfile -Name Domain, Public, Private -Enabled True

    #Set direction defaults
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

    #Settings for profiles
    Set-NetFirewallProfile -Name Domain, Private, Public -NotifyOnListen False

    #Unique Settings for Public
    Set-NetFirewallProfile -Name Public -AllowLocalFirewallRules False -AllowLocalIPsecRules False

    #Logging for Domain, Private, and Public
    Set-NetFirewallProfile -Name Domain, Private, Public -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

    }
    catch {
        Write-host "FIREWALL RULE FAIL" -ForegroundColor Red
    }
}

function disableWinRM() {
    Write-Host "Disabling WinRm..." -ForegroundColor Gray
    try {
        # Disable PowerShell Remoting
        Disable-PSRemoting -Force
        Write-Host "WinRM disabled successfully.1" -ForegroundColor Green

        # Clear Trusted Hosts
        Set-Item wsman:\localhost\client\trustedhosts * -Force
        Write-Host "WinRM disabled successfully2." -ForegroundColor Green

        # Set Session Configuration
        Set-PSSessionConfiguration -Name "Microsoft.PowerShell" -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
        Write-Host "WinRM disabled successfully3." -ForegroundColor Green

        # Stop and disable the WinRM service
        Stop-Service WinRM -PassThru
        Set-Service WinRM -StartupType Disabled -PassThru
        Write-Host "WinRM disabled successfully.4" -ForegroundColor Green

        # Disable WinRM on the Network
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0
        Write-Host "WinRM disabled successfully5." -ForegroundColor Green

        # Disable Basic Authentication
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
        Write-Host "WinRM disabled successfully6." -ForegroundColor Green

        Write-Host "WinRM disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to disable WinRM. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function disableAnonLdap() {
    Write-Host "Disabling anonymous LDAP..." -ForegroundColor Gray
    try {
        # Get OS Name
        $OSWMI = (Get-WmiObject Win32_OperatingSystem).Caption
        # Construct Object Path manually based on the domain
        $ObjectPath = "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-WmiObject Win32_ComputerSystem).Domain)"

        switch -wildcard ($OSWMI) {
            '*Windows 10*' {
                Write-Warning "Localhost is not a Windows Server. Moving on to the next function."
            }
            '*Windows Server*' {
                try {
                    # Disable Anonymous LDAP Binding
                    $result = Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1' }
                    if ($result -eq $null) {
                        Write-Host "Anonymous LDAP binding disabled successfully." -ForegroundColor Green
                    } else {
                        Write-Host "Failed to disable anonymous LDAP binding. Error: $result" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Failed to disable anonymous LDAP binding. Error: $($_.Exception.Message)" -ForegroundColor Red        
                }
            }
            default {
                Write-Output "Unknown OS: $OSWMI"
            }
        }
    } catch {
        Write-Host "An error occurred while disabling anonymous LDAP binding: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function defenderConfig() {
    Write-Host "Configuring Windows Defender" -ForegroundColor Gray
    try {
        # Enable Real-time Monitoring
        $DefenderPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

        if (-not (Test-Path $DefenderPolicyKey)) {
            New-Item -Path $DefenderPolicyKey -Force | Out-Null
        }
    
        Set-ItemProperty -Path $DefenderPolicyKey -Name "DisableRealtimeMonitoring" -Value 0 -Type DWORD

        # Enable Attack Surface Reduction Rules
        $ASRIds = @(
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
            "3B576869-A4EC-4529-8536-B80A7769E899",
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
            "D3E037E1-3EB8-44C8-A917-57927947596D"
        )
        $ASRValues = @('Enabled', 'Enabled', 'Enabled', 'Enabled')
        Set-ItemProperty -Path $DefenderPolicyKey -Name "ASR" -Value $ASRIds -Type MultiString
        Set-ItemProperty -Path $DefenderPolicyKey -Name "ASRPaths" -Value $ASRValues -Type MultiString

        # Enable Network Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord

        # Enable Controlled Folder Access
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Value 1 -Type DWord

        # Enable Potentially Unwanted Application (PUA) Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1 -Type DWord

        # Enable Cloud-delivered Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "HighThreatDefaultAction" -Value 6 -Type DWord

        # Enable Behavior Monitoring
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "BehaviorMonitor" -Value 1 -Type DWord

        # Enable Antivirus Early Launch
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\ELAM" -Name "EnableELAMDriver" -Value 1 -Type DWord

        # Enable Block at First Sight
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2 -Type DWord

        # Enable Cloud-based Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2 -Type DWord

        # Enable Automatic Sample Submission
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 1 -Type DWord

        # Enable Intrusion Prevention System (IPS)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\IPS" -Name "Enable" -Value 1 -Type DWord

        # Enable Advanced Real-time Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "AdvancedProtectionBefore" -Value 1 -Type DWord

        # Enable Automatic Behavior Monitoring
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 3 -Type DWord

        # Enable Advanced Scanning of Encrypted Connections
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan" -Name "ScanFilesWithEncryption" -Value 1 -Type DWord
	
	# HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -PropertyType DWord -Value 1 -Force
	
	# HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -PropertyType DWord -Value 0 -Force
	
	# HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "CheckForSignaturesBeforeRunningScan" -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableHeuristics" -PropertyType DWord -Value 0 -Force
	
	# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -PropertyType DWord -Value 3 -Force


	# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
 #    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
 #    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
 #    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
 #    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
 #    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
 #    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

        Write-Host "Windows Defender configuration completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "An error occurred while configuring Windows Defender: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Stage 2 - Deep Protection

function stage2setup() {
 New-Item -Path C:\Users\$user\Desktop\newfile -ItemType directory
    'no files are safe [.][.]'
    New-Item -Path C:\Users\$user\Desktop\newfile\userfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\newfile\programfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\newfile\programfilesx86 -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\newfile\documents -ItemType directory
	New-Item -Path C:\Users\$user\Desktop\newfile\OS_search_engine -ItemType directory
    Write-Warning "grabbing user files"
    Get-ChildItem -Path "C:\Users\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\newfile\userfiles
    Write-Warning "grabbing program files"
    Get-ChildItem -Path "C:\Program Files\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\newfile\programfiles
    Get-ChildItem -Path "C:\Program Files (x86)\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\newfile\programfilesx86
    Write-Warning "grabbing Documents"
    Get-ChildItem -Path "C:\Users\$user\Documents\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\newfile\documentsandsettings
    Write-Warning "catching them special media files"
    Get-ChildItem -Path C:\Users -Include .jpg,.png,.jpeg,.avi,.mp4,.mp3,*.wav -Exclude .dll,.doc,*.docx,  -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\Users\$user\Desktop\newfile\Mediafiles.txt
	'Proceed to search baby ;) keep in mind these are only copies of the originals'

    net user > newfile\users.txt
    net localgroup > newfile\groups.txt

     #grabbing network shares check if irregular
    Write-Warning "grabbing smb shares bb"
    net share > newfile\shares.txt
    	
    #flush DNS
    Write-Warning "flushing dns cache"
    ipconfig /flushdns
    
    #Grabbing hosts file
    Write-Warning "grabbing hosts file"	
    New-Item -Path C:\Users\$user\Desktop\newfile\hosts -ItemType directory
    Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Copy-Item -Destination C:\Users\$user\Desktop\newfile\hosts
}

function upgradeNetstat() {
	$proclist = (get-nettcpconnection | ? {$_.State -eq 'Listen'}).OwningProcess

	$tcpcon = @()
	$i = 1
	foreach ($proc in $proclist) {
    	Write-Progress -Activity "TcpConnection" -Status "Filling New Object tcpcon" -PercentComplete (($i / $proclist.Count) * 100)
    	$procname = (Get-Process -PID $proc).ProcessName
        $procpath = (Get-Process -PID $proc).Path
    	$port = (Get-NetTCPConnection | ? {$_.OwningProcess -eq $proc}).LocalPort
    	$tcpcon += [PSCustomObject]@{
        	'Name' = $procname
        	'ProcessId' = $proc
        	'Port' = $port
            'Path to bin' = $procpath
    	}
        $i++
    }
    $tcpcon | sort Name | ft -AutoSize
}

function fixAccounts() {
#disabling guest/admin and renaming them
    Get-LocalUser Guest | Disable-LocalUser
    Write-Warning "setting passwords to CyberPatriot101!#"
    Get-WmiObject win32_useraccount | Foreach-object {
    ([adsi]("WinNT://"+$_.caption).replace("\","/")).SetPassword("CyberPatriot101!#")
    }
}

function accPol() {
    net accounts /UNIQUEPW:24 /MAXPWAGE:60 /MINPWAGE:1 /MINPWLEN:12 /lockoutthreshold:5
}

function featureWipe() {
dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI 
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn
	dism /online /disable-feature /featurename:IIS-FTPServer
	dism /online /disable-feature /featurename:IIS-FTPSvc
	dism /online /disable-feature /featurename:IIS-FTPExtensibility
	dism /online /disable-feature /featurename:TFTP
    	dism /online /disable-feature /featurename:"SMB1Protocol"
   	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Write-Warning "investigating suspicious processes"
   	Get-Process | Where-Object {$_.WorkingSet -gt 20000000} > newfile\interestingprocess.txt
}

function updates() {
   reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
}

function regSafe() {
#Restrict CD ROM drive
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

    #disable remote access to floppy disk
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

    #disable auto admin login
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

    #clear page file
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

    #no printer drivers
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

    #auditing to LSASS.exe
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

    #Enable LSA protection
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

    #Limit use of blank passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
    
    #Auditing access of Global System Objects
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
    
    #Auditing Backup and Restore
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
    
    #Restrict Anonymous Enumeration #1
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
    
    #Restrict Anonymous Enumeration #2
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
    
    #Disable storage of domain passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
    
    #Take away Anonymous user Everyone permissions
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
    
    #Allow Machine ID for NTLM
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
    
    #Do not display last user on logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
    
    #Enable UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

    #UAC set high
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
    
    #UAC setting (Prompt on Secure Desktop)
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    
    #Enable Installer Detection
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
    
    #Disable undocking without logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
    
    #Enable CTRL+ALT+DEL
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
    
    #Max password age
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f

    #Disable machine account password changes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
    
    #Require strong session key
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
    
    #Require Sign/Seal
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
    
    #Sign Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
    
    #Seal Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
    
    #Set idle time to 45 minutes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
    
    #Require Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
    
    #Enable Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
    
    #Clear null session pipes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
    
    #Restict Anonymous user access to named pipes and shares
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
    
    #Encrypt SMB Passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
    
    #Clear remote registry paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
    #Clear remote registry paths and sub-paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
    #Enable smart screen for IE8
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
    
    #Enable smart screen for IE9 and up
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    
    #Disable IE password caching
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    
    #Warn users if website has a bad certificate
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
    
    #Warn users if website redirects
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
    
    #Enable Do Not Track
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

    #Show hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
    
    #Disable sticky keys
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
    
    #Show super hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
    
    #Disable dump file creation
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
    
    #Disable autoruns
    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    #enable internet explorer phishing filter
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
}

function macroBlock() {
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
}

function endService() {
cmd.exe /c 'sc stop tlntsvr'
	cmd.exe /c 'sc config tlntsvr start= disabled'
	cmd.exe /c 'sc stop msftpsvc'
	cmd.exe /c 'sc config msftpsvc start= disabled'
	cmd.exe /c 'sc stop snmptrap'
	cmd.exe /c 'sc config snmptrap start= disabled'
	cmd.exe /c 'sc stop ssdpsrv'
	cmd.exe /c 'sc config ssdpsrv start= disabled'
	cmd.exe /c 'sc stop termservice'
	cmd.exe /c 'sc config termservice start= disabled'
	cmd.exe /c 'sc stop sessionenv'
	cmd.exe /c 'sc config sessionenv start= disabled'
	cmd.exe /c 'sc stop remoteregistry'
	cmd.exe /c 'sc config remoteregistry start= disabled'
	cmd.exe /c 'sc stop Messenger'
	cmd.exe /c 'sc config Messenger start= disabled'
	cmd.exe /c 'sc stop upnphos'
	cmd.exe /c 'sc config upnphos start= disabled'
	cmd.exe /c 'sc stop WAS'
	cmd.exe /c 'sc config WAS start= disabled'
	cmd.exe /c 'sc stop RemoteAccess'
	cmd.exe /c 'sc config RemoteAccess start= disabled'
	cmd.exe /c 'sc stop mnmsrvc'
	cmd.exe /c 'sc config mnmsrvc start= disabled'
	cmd.exe /c 'sc stop NetTcpPortSharing'
	cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
	cmd.exe /c 'sc stop RasMan'
	cmd.exe /c 'sc config RasMan start= disabled'
	cmd.exe /c 'sc stop TabletInputService'
	cmd.exe /c 'sc config TabletInputService start= disabled'
	cmd.exe /c 'sc stop RpcSs'
	cmd.exe /c 'sc config RpcSs start= disabled'
	cmd.exe /c 'sc stop SENS'
	cmd.exe /c 'sc config SENS start= disabled'
	cmd.exe /c 'sc stop EventSystem'
	cmd.exe /c 'sc config EventSystem start= disabled'
	cmd.exe /c 'sc stop XblAuthManager'
	cmd.exe /c 'sc config XblAuthManager start= disabled'
	cmd.exe /c 'sc stop XblGameSave'
	cmd.exe /c 'sc config XblGameSave start= disabled'
	cmd.exe /c 'sc stop XboxGipSvc'
	cmd.exe /c 'sc config XboxGipSvc start= disabled'
	cmd.exe /c 'sc stop xboxgip'
	cmd.exe /c 'sc config xboxgip start= disabled'
	cmd.exe /c 'sc stop xbgm'
	cmd.exe /c 'sc config xbgm start= disabled'
	cmd.exe /c 'sc stop SysMain'
	cmd.exe /c 'sc config SysMain start= disabled'
    cmd.exe /c 'sc stop seclogon'
    cmd.exe /c 'sc config seclogon start= disabled'
    cmd.exe /c 'sc stop TapiSrv'
    cmd.exe /c 'sc config TapiSrv start= disabled'
    cmd.exe /c 'sc stop p2pimsvc'
    cmd.exe /c 'sc config p2pimsvc start= disabled'
    cmd.exe /c 'sc stop simptcp'
    cmd.exe /c 'sc config simptcp start= disabled'
    cmd.exe /c 'sc stop fax'
    cmd.exe /c 'sc config fax start= disabled'
    cmd.exe /c 'sc stop Msftpsvc'
    cmd.exe /c 'sc config Msftpsvc start= disabled'
    cmd.exe /c 'sc stop iprip'
    cmd.exe /c 'sc config iprip start= disabled'
    cmd.exe /c 'sc stop ftpsvc'
    cmd.exe /c 'sc config ftpsvc start= disabled'
    cmd.exe /c 'sc stop RasAuto'
    cmd.exe /c 'sc config RasAuto start= disabled'
    cmd.exe /c 'sc stop W3svc'
    cmd.exe /c 'sc config W3svc start= disabled'
    cmd.exe /c 'sc stop Smtpsvc'
    cmd.exe /c 'sc config Smtpsvc start= disabled'
    cmd.exe /c 'sc stop Dfs'
    cmd.exe /c 'sc config Dfs start= disabled'
    cmd.exe /c 'sc stop TrkWks'
    cmd.exe /c 'sc config TrkWks start= disabled'
    cmd.exe /c 'sc stop MSDTC'
    cmd.exe /c 'sc config MSDTC start= disabled'
    cmd.exe /c 'sc stop ERSvc'
    cmd.exe /c 'sc config ERSvc start= disabled'
    cmd.exe /c 'sc stop NtFrs'
    cmd.exe /c 'sc config NtFrs start= disabled'
    cmd.exe /c 'sc stop Iisadmin'
    cmd.exe /c 'sc config Iisadmin start= disabled'
    cmd.exe /c 'sc stop IsmServ'
    cmd.exe /c 'sc config IsmServ start= disabled'
    cmd.exe /c 'sc stop WmdmPmSN'
    cmd.exe /c 'sc config WmdmPmSN start= disabled'
    cmd.exe /c 'sc stop helpsvc'
    cmd.exe /c 'sc config helpsvc start= disabled'
    cmd.exe /c 'sc stop Spooler'
    cmd.exe /c 'sc config Spooler start= disabled'
    cmd.exe /c 'sc stop RDSessMgr'
    cmd.exe /c 'sc config RDSessMgr start= disabled'
    cmd.exe /c 'sc stop RSoPProv'
    cmd.exe /c 'sc config RSoPProv start= disabled'
    cmd.exe /c 'sc stop SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= disabled'
    cmd.exe /c 'sc stop lanmanserver'
    cmd.exe /c 'sc config lanmanserver start= disabled'
    cmd.exe /c 'sc stop Sacsvr'
    cmd.exe /c 'sc config Sacsvr start= disabled'
    cmd.exe /c 'sc stop TermService'
    cmd.exe /c 'sc config TermService start= disabled'
    cmd.exe /c 'sc stop uploadmgr'
    cmd.exe /c 'sc config uploadmgr start= disabled'
    cmd.exe /c 'sc stop VDS'
    cmd.exe /c 'sc config VDS start= disabled'
    cmd.exe /c 'sc stop VSS'
    cmd.exe /c 'sc config VSS start= disabled'
    cmd.exe /c 'sc stop WINS'
    cmd.exe /c 'sc config WINS start= disabled'
    cmd.exe /c 'sc stop CscService'
    cmd.exe /c 'sc config CscService start= disabled'
    cmd.exe /c 'sc stop hidserv'
    cmd.exe /c 'sc config hidserv start= disabled'
    cmd.exe /c 'sc stop IPBusEnum'
    cmd.exe /c 'sc config IPBusEnum start= disabled'
    cmd.exe /c 'sc stop PolicyAgent'
    cmd.exe /c 'sc config PolicyAgent start= disabled'
    cmd.exe /c 'sc stop SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop SSDPSRV'
    cmd.exe /c 'sc config SSDPSRV start= disabled'
    cmd.exe /c 'sc stop Themes'
    cmd.exe /c 'sc config Themes start= disabled'
    cmd.exe /c 'sc stop upnphost'
    cmd.exe /c 'sc config upnphost start= disabled'
    cmd.exe /c 'sc stop nfssvc'
    cmd.exe /c 'sc config nfssvc start= disabled'
    cmd.exe /c 'sc stop nfsclnt'
    cmd.exe /c 'sc config nfsclnt start= disabled'
    cmd.exe /c 'sc stop MSSQLServerADHelper'
    cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
    cmd.exe /c 'sc stop SharedAccess'
    cmd.exe /c 'sc config SharedAccess start= disabled'
    cmd.exe /c 'sc stop UmRdpService'
    cmd.exe /c 'sc config UmRdpService start= disabled'
    cmd.exe /c 'sc stop SessionEnv'
    cmd.exe /c 'sc config SessionEnv start= disabled'
    cmd.exe /c 'sc stop Server'
    cmd.exe /c 'sc config Server start= disabled'
    cmd.exe /c 'sc stop TeamViewer'
    cmd.exe /c 'sc config TeamViewer start= disabled'
    cmd.exe /c 'sc stop TeamViewer7'
    cmd.exe /c 'sc config start= disabled'
    cmd.exe /c 'sc stop HomeGroupListener'
    cmd.exe /c 'sc config HomeGroupListener start= disabled'
    cmd.exe /c 'sc stop HomeGroupProvider'
    cmd.exe /c 'sc config HomeGroupProvider start= disabled'
    cmd.exe /c 'sc stop AxInstSV'
    cmd.exe /c 'sc config AXInstSV start= disabled'
    cmd.exe /c 'sc stop Netlogon'
    cmd.exe /c 'sc config Netlogon start= disabled'
    cmd.exe /c 'sc stop lltdsvc'
    cmd.exe /c 'sc config lltdsvc start= disabled'
    cmd.exe /c 'sc stop iphlpsvc'
    cmd.exe /c 'sc config iphlpsvc start= disabled'
    cmd.exe /c 'sc stop AdobeARMservice'
    cmd.exe /c 'sc config AdobeARMservice start= disabled'
}

function startService() {
cmd.exe /c 'sc start wuauserv'
cmd.exe /c 'sc config wuauserv start= auto'
cmd.exe /c 'sc start EventLog'
cmd.exe /c 'sc config EventLog start= auto'
cmd.exe /c 'sc start MpsSvc'
cmd.exe /c 'sc config MpsSvc start= auto'
cmd.exe /c 'sc start WinDefend'
cmd.exe /c 'sc config WinDefend start= auto'
cmd.exe /c 'sc start WdNisSvc'
cmd.exe /c 'sc config WdNisSvc start= auto'
cmd.exe /c 'sc start Sense'
cmd.exe /c 'sc config Sense start= auto'
cmd.exe /c 'sc start Schedule'
cmd.exe /c 'sc config Schedule start= auto'
cmd.exe /c 'sc start SCardSvr'
cmd.exe /c 'sc config SCardSvr start= auto'
cmd.exe /c 'sc start ScDeviceEnum'
cmd.exe /c 'sc config ScDeviceEnum start= auto'
cmd.exe /c 'sc start SCPolicySvc'
cmd.exe /c 'sc config SCPolicySvc start= auto'
cmd.exe /c 'sc start wscsvc'
cmd.exe /c 'sc config wscsvc start= auto'
}

#Stage 3
function endMisc() {
Set-NetFirewallRule * -Enabled False -Action NotConfigured

#Block multiple Windows features by pre-existing rules
Set-NetFirewallRule -DisplayGroup "AllJoyn Router","*BranchCache*","Cast to Device functionality","Connect","Cortana","Delivery Optimization","DIAL protocol server","Feedback Hub","File and Printer Sharing","Get Office","Groove Music","HomeGroup","iSCSI Service","mDNS","Media Center Extenders","Microsoft Edge","Microsoft Photos","Microsoft Solitaire Collection","Movies & TV","MSN Weather","Network Discovery","OneNote","*Wi-Fi*","Paint 3D","Proximity Sharing","*Remote*","Secure Socket Tunneling Protocol","*Skype*","SNMP Trap","Store","*Smart Card*","Virtual Machine Monitoring","Windows Collaboration Computer Name Registration Service","*Windows Media Player*","Windows Peer to Peer Collaboration Foundation","Windows View 3D Preview","*Wireless*","*WFD*","*Xbox*","3D Builder","Captive Portal Flow","Take a Test","Wallet" -Action Block -Enabled True -Profile Any

#Block multiple insecure protocols by pre-existing rules
Set-NetFirewallRule -DisplayName "*IPv6*","*ICMP*","*SMB*","*UPnP*","*FTP*","*Telnet*" -Action Block -Enabled True -Profile Any

New-NetFireWallRule -DisplayName "OpenSSH" -Protocol TCP -LocalPort 22 -Action Allow -Enabled True -Direction Inbound
New-NetFireWallRule -DisplayName "OpenSSH" -Protocol TCP -LocalPort 22 -Action Allow -Enabled True -Direction Outbound
#Block multiple ports with new rule
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 20-21 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 22 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 23 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "HTTP" -LocalPort 80 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TorPark onion routing" -LocalPort 81 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TorPark control" -LocalPort 82 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Flash" -LocalPort 843 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WASTE" -LocalPort 1337 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Civ" -LocalPort 1492 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSketch" -LocalPort 1626-1627 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Defunct RADIUS Ports" -LocalPort 1645-1646 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "America's Army" -LocalPort 1716 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SSDP" -LocalPort 1900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Warzone 2100" -LocalPort 2100 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apple Notifs" -LocalPort 2195 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apple Notifs Feedback" -LocalPort 2196 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "ArmA/Halo" -LocalPort 2302-2305 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "AIM/Ghost" -LocalPort 2351-2368 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSync" -LocalPort 3004 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BF4" -LocalPort 3659 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Warframe" -LocalPort 3960 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Warframe again" -LocalPort 3962 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Ants" -LocalPort 4001 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Remote Web Workplace admin" -LocalPort 4125 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apprentice" -LocalPort 4747 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "LoL" -LocalPort 5000-5500 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Neverwinter Nights" -LocalPort 5121 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apple Notif 2" -LocalPort 5223 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Outlaws" -LocalPort 5310 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "PostgreSQL" -LocalPort 5432 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "B.net/Club penguin 3" -LocalPort 6113 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent tracker" -LocalPort 6969 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "HTTP Bittorrent" -LocalPort 7000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Enemy Territory: Quake Wars" -LocalPort 7133 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Tibia" -LocalPort 7171 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Rise: The Vieneo Province" -LocalPort 7473 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7707-7708 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7717 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 8075 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "MapleStory" -LocalPort 8484 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "QBittorrent" -LocalPort 9000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9030 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9050-9051 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Clash of Clans" -LocalPort 9339 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Club Penguin" -LocalPort 9875 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Touhou" -LocalPort 10080 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Farming Simulator 2011" -LocalPort 10823 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenRCT2" -LocalPort 11753 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12035 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12043 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12046 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 13000-13050 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Battlefield 1942" -LocalPort 14567 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Battlefield Vietnam" -LocalPort 15567 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Battlefield 2" -LocalPort 16567 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Worms" -LocalPort 17011 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Monero P2P" -LocalPort 18080 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Bitcoin" -LocalPort 18333 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft: Bedrock Edition" -LocalPort 19132-19133 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "0 A.D. Empires Ascendant" -LocalPort 20595 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25575 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "EVE Online" -LocalPort 26900-26901 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27000-27006 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27000-27015 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Unturned" -LocalPort 27015-27018 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27031 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27500-27900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Quake II" -LocalPort 27901-27910 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenArena" -LocalPort 27950 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Enemy Territoy, Quake III, Quake Live" -LocalPort 27960-27969 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Rust" -LocalPort 28015 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "AssaultCube Reloaded" -LocalPort 28770-28771 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cube 2: Sauerbraten" -LocalPort 28785-28786 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TetriNET" -LocalPort 31457 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ace of Spades" -LocalPort 32887 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Infestation: Survivor Stories" -LocalPort 34000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Factorio" -LocalPort 34197 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Mu Online" -LocalPort 44405 -Protocol TCP -Action Block -Enabled True -Direction Inbound

New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 20-21 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 22 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 23 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "HTTP" -LocalPort 80 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TorPark onion routing" -LocalPort 81 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TorPark control" -LocalPort 82 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Flash" -LocalPort 843 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WASTE" -LocalPort 1337 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Civ" -LocalPort 1492 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSketch" -LocalPort 1626-1627 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Defunct RADIUS Ports" -LocalPort 1645-1646 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "America's Army" -LocalPort 1716 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "SSDP" -LocalPort 1900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Warzone 2100" -LocalPort 2100 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apple Notifs" -LocalPort 2195 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apple Notifs Feedback" -LocalPort 2196 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "ArmA/Halo" -LocalPort 2302-2305 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "AIM/Ghost" -LocalPort 2351-2368 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSync" -LocalPort 3004 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BF4" -LocalPort 3659 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Warframe" -LocalPort 3960 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Warframe again" -LocalPort 3962 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Ants" -LocalPort 4001 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Remote Web Workplace admin" -LocalPort 4125 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apprentice" -LocalPort 4747 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "LoL" -LocalPort 5000-5500 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Neverwinter Nights" -LocalPort 5121 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apple Notif 2" -LocalPort 5223 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Outlaws" -LocalPort 5310 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "PostgreSQL" -LocalPort 5432 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "B.net/Club penguin 3" -LocalPort 6113 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent tracker" -LocalPort 6969 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "HTTP Bittorrent" -LocalPort 7000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Enemy Territory: Quake Wars" -LocalPort 7133 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Tibia" -LocalPort 7171 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Rise: The Vieneo Province" -LocalPort 7473 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7707-7708 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7717 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 8075 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "MapleStory" -LocalPort 8484 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "QBittorrent" -LocalPort 9000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9030 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9050-9051 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Clash of Clans" -LocalPort 9339 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Club Penguin" -LocalPort 9875 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Touhou" -LocalPort 10080 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Farming Simulator 2011" -LocalPort 10823 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenRCT2" -LocalPort 11753 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12035 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12043 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12046 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 13000-13050 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Battlefield 1942" -LocalPort 14567 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Battlefield Vietnam" -LocalPort 15567 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Battlefield 2" -LocalPort 16567 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Worms" -LocalPort 17011 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Monero P2P" -LocalPort 18080 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Bitcoin" -LocalPort 18333 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft: Bedrock Edition" -LocalPort 19132-19133 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "0 A.D. Empires Ascendant" -LocalPort 20595 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25575 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "EVE Online" -LocalPort 26900-26901 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27000-27006 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27000-27015 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Unturned" -LocalPort 27015-27018 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27031 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27500-27900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Quake II" -LocalPort 27901-27910 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenArena" -LocalPort 27950 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Enemy Territoy, Quake III, Quake Live" -LocalPort 27960-27969 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Rust" -LocalPort 28015 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "AssaultCube Reloaded" -LocalPort 28770-28771 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cube 2: Sauerbraten" -LocalPort 28785-28786 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TetriNET" -LocalPort 31457 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ace of Spades" -LocalPort 32887 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Infestation: Survivor Stories" -LocalPort 34000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Factorio" -LocalPort 34197 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Mu Online" -LocalPort 44405 -Protocol TCP -Action Block -Enabled True -Direction Outbound

#Block multiple protocols with new rule
New-NetFirewallRule -DisplayName "ICMPv4" -Protocol ICMPv4 -Action Block -Enabled True -Direction Inbound -Profile Any
New-NetFirewallRule -DisplayName "ICMPv4" -Protocol ICMPv4 -Action Block -Enabled True -Direction Outbound -Profile Any
New-NetFirewallRule -DisplayName "ICMPv6" -Protocol ICMPv6 -Action Block -Enabled True -Direction Inbound -Profile Any
New-NetFirewallRule -DisplayName "ICMPv6" -Protocol ICMPv6 -Action Block -Enabled True -Direction Outbound -Profile Any

#Allow multiple ports with new rule
New-NetFirewallRule -DisplayName "HTTPS" -LocalPort 443 -Protocol TCP -Action Allow -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "NTP" -LocalPort 123 -Protocol UDP -Action Allow -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "NTP" -LocalPort 123 -Protocol UDP -Action Allow -Enabled True -Direction Inbound

#Allow multiple features with pre-existing rules
Set-NetFirewallRule -DisplayName "*Defender*" -Enabled True -Action Allow -Profile Any
}

function restoreDefender(){
    Write-Host "Restoring Defender..." -ForegroundColor Gray
    try {
        $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version
        $OSName = $OSWMI.Caption

        $OSWMI = (Get-WmiObject Win32_OperatingSystem).Caption

        if ($OSWMI -like '*Windows 10*') {
            DISM /Online /Cleanup-Image /RestoreHealth
            Get-AppxPackage Microsoft.Windows.SecHealthUI | Reset-AppxPackage
        } else {
            Dism /Online /Enable-Feature /FeatureName:Windows-Defender
            DISM /Online /Cleanup-Image /RestoreHealth
        }

        $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version
        Dism /Online /Enable-Feature /FeatureName:Windows-Defender


        DISM /Online /Cleanup-Image /RestoreHealth

        Get-AppxPackage Microsoft.Windows.SecHealthUI | Reset-AppxPackage
    }
    catch {
        Write-Host "Writing error to file: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

globalAudit
smbShare
smbGood
# GroupPolicy
hostFirewall
disableWinRM
disableAnonLdap
defenderConfig

#stage 2
stage2setup
upgradeNetstat
fixAccounts
accPol
featureWipe
updates
regSafe
macroBlock
endService
startService

#stage 3 - Longest 
endMisc
restoreDefender
