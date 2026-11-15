#Requires -RunAsAdministrator

$logPath = "C:\SecurityHardening\Logs"
if (-not (Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory | Out-Null }
$logFile = "$logPath\WebServerHardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logFile

function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$Level] $timestamp - $Message"
    Write-Host $Message
}

function Install-WebServerSecurityFeatures {
    Write-SecurityLog "Installing Web Server Security Components"

    try {
        Install-WindowsFeature -Name Web-Server, Web-Asp-Net45, Web-Basic-Auth, Web-Windows-Auth, Web-Filtering, Web-Url-Auth, Web-Cert-Auth -IncludeManagementTools
        
        Install-WindowsFeature -Name NET-Framework-Features -IncludeManagementTools
        
        Write-SecurityLog "Web Server Security Features Installed" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Web Server Feature Installation Failed: $_" -Level "ERROR"
    }
}

function Configure-IISSecuritySettings {
    Write-SecurityLog "Configuring Advanced IIS Security"

    try {
        Import-Module WebAdministration
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "requestLimits" -value @{maxAllowedContentLength=30000000}
        
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "." -value @{fileExtensions=@{applyToWebDAV='True'}}
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "denyUrlSequences" -value @{sequence='..'}
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "denyUrlSequences" -value @{sequence='./'}
        
        Write-SecurityLog "IIS Request Filtering Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "IIS Security Configuration Failed: $_" -Level "ERROR"
    }
}

function Disable-UnnecessaryWebProtocols {
    Write-SecurityLog "Disabling Unnecessary Web Protocols"

    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -NoRestart
        
        $websiteBindings = Get-WebBinding
        foreach ($binding in $websiteBindings) {
            if ($binding.protocol -eq "http") {
                Remove-WebBinding -Name $binding.name -Protocol "http"
            }
        }
        
        Write-SecurityLog "Unnecessary Web Protocols Disabled" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Protocol Disabling Failed: $_" -Level "ERROR"
    }
}

function Configure-SSLCertificateSettings {
    Write-SecurityLog "Configuring SSL/TLS Security"

    try {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
        
        $protocols = @(
            "SSL 2.0",
            "SSL 3.0",
            "TLS 1.0",
            "TLS 1.1"
        )
        
        foreach ($protocol in $protocols) {
            $keyPath = "$registryPath\$protocol\Server"
            if (!(Test-Path $keyPath)) {
                New-Item -Path $keyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $keyPath -Name "Enabled" -Value 0
            Set-ItemProperty -Path $keyPath -Name "DisabledByDefault" -Value 1
        }
        
        Write-SecurityLog "SSL/TLS Protocols Secured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "SSL/TLS Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-WebServerAuthentication {
    Write-SecurityLog "Configuring Web Authentication"

    try {
        $sitePath = "IIS:\Sites\Default Web Site"
        
        Set-WebConfigurationProperty -pspath $sitePath -filter "system.webServer/security/authentication/anonymousAuthentication" -name "enabled" -value "False"
        Set-WebConfigurationProperty -pspath $sitePath -filter "system.webServer/security/authentication/windowsAuthentication" -name "enabled" -value "True"
        
        Add-WebConfiguration -pspath $sitePath -filter "system.webServer/security/authentication" -value @{mode='Windows'}
        
        Write-SecurityLog "Web Authentication Secured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Web Authentication Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-WebServerLogging {
    Write-SecurityLog "Configuring Advanced Web Logging"

    try {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpLogging" -name "dontLog" -value "False"
        
        $logPath = "C:\Logs\WebServer"
        if (!(Test-Path $logPath)) {
            New-Item -Path $logPath -ItemType Directory | Out-Null
        }
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpLogging" -name "directory" -value $logPath
        
        Write-SecurityLog "Web Server Logging Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Web Logging Configuration Failed: $_" -Level "ERROR"
    }
}

function Secure-WebDirectoryPermissions {
    Write-SecurityLog "Securing Web Directory Permissions"

    try {
        $webRoot = "C:\inetpub\wwwroot"
        $acl = Get-Acl $webRoot
        
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "IUSR", 
            "ReadAndExecute", 
            "ContainerInherit,ObjectInherit", 
            "None", 
            "Allow"
        )
        
        $acl.SetAccessRule($rule)
        Set-Acl $webRoot $acl
        
        Write-SecurityLog "Web Directory Permissions Secured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "Directory Permissions Configuration Failed: $_" -Level "ERROR"
    }
}

function Configure-WebApplicationFirewall {
    Write-SecurityLog "Configuring Web Application Firewall"

    try {
        Install-WindowsFeature -Name Web-Filtering
        
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "." -value @{hiddenSegments='web.config'}
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "verbs" -value @{applyToWebDAV='True'}
        
        Write-SecurityLog "Web Application Firewall Configured" -Level "SUCCESS"
    } catch {
        Write-SecurityLog "WAF Configuration Failed: $_" -Level "ERROR"
    }
}

function Execute-WebServerHardening {
    Write-SecurityLog "Starting Comprehensive Web Server Hardening"

    Install-WebServerSecurityFeatures
    Configure-IISSecuritySettings
    Disable-UnnecessaryWebProtocols
    Configure-SSLCertificateSettings
    Configure-WebServerAuthentication
    Configure-WebServerLogging
    Secure-WebDirectoryPermissions
    Configure-WebApplicationFirewall

    Write-SecurityLog "Web Server Hardening Complete" -Level "SUCCESS"
}

Execute-WebServerHardening

Stop-Transcript
