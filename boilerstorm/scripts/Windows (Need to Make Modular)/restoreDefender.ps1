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

restoreDefender
