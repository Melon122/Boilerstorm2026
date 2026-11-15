# Requires elevation - check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrative privileges. Please run as Administrator."
    exit
}

# Function to enable audit policy
function Set-AuditPolicy {
    param (
        [string]$SubCategory,
        [string]$Setting
    )
    
    try {
        # Parse the setting string to determine success and failure flags
        $success = if ($Setting -like "*Success*") { "enable" } else { "disable" }
        $failure = if ($Setting -like "*Failure*") { "enable" } else { "disable" }
        
        $result = auditpol /set /subcategory:"$SubCategory" /success:$success /failure:$failure 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully configured audit policy for: $SubCategory" -ForegroundColor Green
        } else {
            Write-Warning "Failed to set audit policy for: $SubCategory. Error: $result"
        }
    }
    catch {
        Write-Error "Error configuring audit policy for $SubCategory : $_"
    }
}

# Define the audit policies and their settings
$auditPolicies = @(
    @{ Name = "Credential Validation"; Setting = "Success and Failure" },
    @{ Name = "Application Group Management"; Setting = "Success and Failure" },
    @{ Name = "Security Group Management"; Setting = "Success and Failure" },
    @{ Name = "User Account Management"; Setting = "Success and Failure" },
    @{ Name = "PNP Activity"; Setting = "Success and Failure" },
    @{ Name = "Process Creation"; Setting = "Success and Failure" },
    @{ Name = "Account Lockout"; Setting = "Success and Failure" },
    @{ Name = "Group Membership"; Setting = "Success and Failure" },
    @{ Name = "Logoff"; Setting = "Success and Failure" },
    @{ Name = "Logon"; Setting = "Success and Failure" },
    @{ Name = "Other Logon/Logoff Events"; Setting = "Success and Failure" },
    @{ Name = "Special Logon"; Setting = "Success and Failure" },
    @{ Name = "Detailed File Share"; Setting = "Success and Failure" },
    @{ Name = "File Share"; Setting = "Success and Failure" },
    @{ Name = "Other Object Access Events"; Setting = "Success and Failure" },
    @{ Name = "Removable Storage"; Setting = "Success and Failure" },
    @{ Name = "Audit Policy Change"; Setting = "Success and Failure" },
    @{ Name = "Authentication Policy Change"; Setting = "Success and Failure" },
    @{ Name = "Authorization Policy Change"; Setting = "Success and Failure" },
    @{ Name = "MPSSVC Rule-Level Policy Change"; Setting = "Success and Failure" },
    @{ Name = "Other Policy Change Events"; Setting = "Success and Failure" },
    @{ Name = "Sensitive Privilege Use"; Setting = "Success and Failure" },
    @{ Name = "IPsec Driver"; Setting = "Success and Failure" },
    @{ Name = "Other System Events"; Setting = "Success and Failure" },
    @{ Name = "Security State Change"; Setting = "Success and Failure" },
    @{ Name = "Security System Extension"; Setting = "Success and Failure" },
    @{ Name = "System Integrity"; Setting = "Success and Failure" }
)

Write-Host "Starting audit policy configuration..." -ForegroundColor Cyan

# Verify current audit policy status
Write-Host "`nVerifying current audit policy settings..." -ForegroundColor Yellow
$currentSettings = auditpol /get /category:* | Out-String

# Apply the audit policies
foreach ($policy in $auditPolicies) {
    # Check if the subcategory exists before attempting to set it
    if ($currentSettings -match $policy.Name) {
        Set-AuditPolicy -SubCategory $policy.Name -Setting $policy.Setting
    } else {
        Write-Warning "Subcategory not found: $($policy.Name)"
    }
}

# Verify the changes
Write-Host "`nVerifying final audit policy configuration..." -ForegroundColor Yellow
Write-Host "To see the current settings, run: auditpol /get /category:*" -ForegroundColor Cyan

# Export the settings to a CSV file for documentation
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$exportPath = ".\AuditPolicy_$timestamp.csv"
try {
    auditpol /backup /file:"$exportPath" | Out-Null
    if (Test-Path $exportPath) {
        Write-Host "`nAudit policy settings have been exported to: $exportPath" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to export audit policy settings: $_"
}

Write-Host "`nAudit policy configuration complete." -ForegroundColor Green
