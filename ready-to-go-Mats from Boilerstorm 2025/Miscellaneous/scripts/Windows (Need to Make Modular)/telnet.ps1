# Block Telnet traffic
netsh advfirewall firewall add rule name="Block Telnet" dir=in action=block protocol=TCP localport=23


function disableTelnet() {
    $OSName = (Get-WmiObject Win32_OperatingSystem -Property Caption,Version).Caption
    Write-Host "Disabling telnet..." -ForegroundColor Gray
	dism /online /disable-feature /featurename:TelnetClient
	dism /online /disable-feature /featurename:TelnetServer
    try {
        # Disable Telnet Client
        $telnetClient = dism /online /Disable-feature /featurename:TelnetClient /NoRestart
        netsh advfirewall firewall add rule name="BlockTelNet23" protocol=TCP dir=in localport=23 action=block >nul
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Telnet Client disabled successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Failed to disable Telnet Client. Error: $telnetClient" -ForegroundColor Red
        }

        # Get OS Name
        $OSName = (Get-WmiObject -Class Win32_OperatingSystem).Caption

        if ($OSName -like "*Server*"){
            # Disable Telnet Server
            $telnetServer = dism /online /Disable-feature /featurename:TelnetServer /NoRestart
            netsh advfirewall firewall add rule name="BlockTelNet23" protocol=TCP dir=in localport=23 action=block >nul
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Telnet Server disabled successfully." -ForegroundColor Green
            }
            else {
                Write-Host "Failed to disable Telnet Server. Error: $telnetServer" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "An error occurred while disabling telnet: $($_.Exception.Message)" -ForegroundColor Red
    }
}
