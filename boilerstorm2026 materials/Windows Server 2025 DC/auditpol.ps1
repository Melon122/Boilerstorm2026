if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrative privileges. Please run as Administrator."
    exit
}
auditpol /set /category:* /success:enable /failure:enable | Out-Null

# List all subcategories and store them in an array, excluding categories
$subcategories = auditpol /list /subcategory:* | Select-String -Pattern "^\s{2}(.*)\s*$" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }

# Set all subcategories to "Success and Failure"
foreach ($subcategory in $subcategories) {
    auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable | Out-Null
}

# Get and display the settings for all subcategories
foreach ($subcategory in $subcategories) {
    $result = auditpol /get /subcategory:"$subcategory"
    Write-Output $result
}

Write-Host "`nAudit policy configuration complete. To verify settings, look through the printed out results" -ForegroundColor Cyan
