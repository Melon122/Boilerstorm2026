#Requires -RunAsAdministrator

$logPath = "C:\SecurityHardening\Logs"
if (-not (Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory | Out-Null }
$logFile = "$logPath\DefenderHardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logFile

function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$Level] $timestamp - $Message"
    Write-Host $Message
}

function Configure-DefenderBaseSettings {
    Write-SecurityLog "Configuring Core Windows Defender Settings"

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -EnableNetworkProtection Enabled
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent Always
        Set-MpPreference -PUAProtection Enabled
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableScriptScanning $false
        
        Write-SecurityLog "Core Defender Settings Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Core Settings Configuration Failed: $_" -Level "ERROR"
    }
}

function Remove-DefenderExclusions {
    Write-SecurityLog "Removing All Defender Exclusions"

    try {
        $exclusionTypes = @(
            "ExclusionPath",
            "ExclusionExtension", 
            "ExclusionProcess",
            "ExclusionIpAddress"
        )

        foreach ($type in $exclusionTypes) {
            $exclusions = (Get-MpPreference).$type
            if ($exclusions) {
                foreach ($exclusion in $exclusions) {
                    try {
                        switch ($type) {
                            "ExclusionPath" { Remove-MpPreference -ExclusionPath $exclusion }
                            "ExclusionExtension" { Remove-MpPreference -ExclusionExtension $exclusion }
                            "ExclusionProcess" { Remove-MpPreference -ExclusionProcess $exclusion }
                            "ExclusionIpAddress" { Remove-MpPreference -ExclusionIpAddress $exclusion }
                        }
                        Write-SecurityLog "Removed Exclusion: $exclusion from $type" -Level "INFO"
                    } catch {
                        Write-SecurityLog "Failed to remove exclusion $exclusion" -Level "WARNING"
                    }
                }
            }
        }

        Write-SecurityLog "All Defender Exclusions Removed" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Exclusions Removal Failed: $_" -Level "ERROR"
    }
}

function Configure-AdvancedDefenderScan {
    Write-SecurityLog "Configuring Advanced Defender Scanning"

    try {
        Set-MpPreference -ScanScheduleDay Everyday
        Set-MpPreference -ScanScheduleTime "03:00"
        Set-MpPreference -RandomizeScheduleTaskTimes $true
        
        Set-MpPreference -ScanParameters 2
        Set-MpPreference -DisableCatchupFullScan $false
        Set-MpPreference -DisableCatchupQuickScan $false
        
        Set-MpPreference -LowCpuPriority $false
        Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
        
        Write-SecurityLog "Advanced Scanning Configurations Applied" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Advanced Scan Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-CloudProtection {
    Write-SecurityLog "Configuring Cloud-Powered Protection"

    try {
        Set-MpPreference -CloudBlockLevel High
        Set-MpPreference -CloudExtendedTimeout 50
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -SignatureAuditDisabled $false
        
        Write-SecurityLog "Cloud Protection Enhanced" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Cloud Protection Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-ThreatProtection {
    Write-SecurityLog "Configuring Advanced Threat Protection"

    try {
        Set-MpPreference -DisableEmailScanning $false
        Set-MpPreference -DisableRemovableDriveScanning $false
        Set-MpPreference -DisableArchiveScanning $false
        Set-MpPreference -DisableScriptScanning $false
        
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 1 -PropertyType DWORD -Force
        
        Write-SecurityLog "Threat Protection Mechanisms Maximized" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Threat Protection Configuration Failed: $_" -Level "ERROR"
    }
}

function Update-DefenderSignatures {
    Write-SecurityLog "Updating Defender Signatures"

    try {
        Update-MpSignature
        Start-MpScan -ScanType FullScan
        
        Write-SecurityLog "Signatures Updated and Full Scan Initiated" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Signature Update Failed: $_" -Level "ERROR"
    }
}

function Execute-DefenderHardening {
    Write-SecurityLog "Starting Comprehensive Defender Hardening"

    Configure-DefenderBaseSettings
    Remove-DefenderExclusions
    Configure-AdvancedDefenderScan
    Configure-CloudProtection
    Configure-ThreatProtection
    Update-DefenderSignatures

    Write-SecurityLog "Defender Hardening Complete" -Level "SUCCESS"
}

Execute-DefenderHardening

Stop-Transcript
