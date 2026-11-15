# Check and ensure RPC service is running and set to Automatic
$rpcService = Get-Service -Name "RpcSs"
if ($rpcService.Status -ne 'Running') {
    Start-Service -Name "RpcSs"
    # Wait for the service to start
    while ((Get-Service -Name "RpcSs").Status -ne 'Running') {
        Start-Sleep -Seconds 1
    }
}
if ($rpcService.StartType -ne 'Automatic') {
    Set-Service -Name "RpcSs" -StartupType Automatic
}

# Set Windows Firewall Private Profile settings
Set-NetFirewallProfile -Profile Private -Enabled True
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Private -NotifyOnListen False
Set-NetFirewallProfile -Profile Private -LogFileName "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
Set-NetFirewallProfile -Profile Private -LogMaxSizeKilobytes 16384

# Set Windows Firewall Public Profile settings
Set-NetFirewallProfile -Profile Public -Enabled True
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Public -NotifyOnListen False
Set-NetFirewallProfile -Profile Public -AllowLocalFirewallRules False
Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False
Set-NetFirewallProfile -Profile Public -LogFileName "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384
