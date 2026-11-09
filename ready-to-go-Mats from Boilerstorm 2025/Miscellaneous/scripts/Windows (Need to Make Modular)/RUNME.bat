@echo off
:: Elevate to administrator
cd /d %~dp0
powershell.exe -Command "Start-Process -FilePath '%comspec%' -ArgumentList '/c %~0' -Verb RunAs"
exit /b

:: Run batch files
:RunBatchFiles
start "" "Bat1.bat"
start "" "Other.bat"

:: Run PowerShell scripts
:RunPowerShellScripts
powershell.exe -ExecutionPolicy Bypass -File "Script1.ps1"
powershell.exe -ExecutionPolicy Bypass -File "Script2.ps1"
powershell.exe -ExecutionPolicy Bypass -File "WindowsSecurity.ps1"
powershell.exe -ExecutionPolicy Bypass -File "CyberPatriotPowerShellScript.ps1"
powershell.exe -ExecutionPolicy Bypass -File "Script3.ps1"
powershell.exe -ExecutionPolicy Bypass -File "Script4.ps1"
powershell.exe -ExecutionPolicy Bypass -File "Script4v2.ps1"
powershell.exe -ExecutionPolicy Bypass -File "Script5.ps1"

:: Run Registry files
:RunRegistryFiles
regedit /s "Reg1.reg"
regedit /s "Reg2.reg"
regedit /s "Reg3.reg"

:: Run other batch files
:RunOtherBatchFiles
start "" "Windows.bat"
start "" "WindowsStigs.bat"

:: Run PowerShell modules
:RunPowerShellModules
powershell.exe -ExecutionPolicy Bypass -Command "Import-Module .\Script6.psm1"
powershell.exe -ExecutionPolicy Bypass -Command "Import-Module .\Script7.psm1"
powershell.exe -ExecutionPolicy Bypass -Command "Import-Module .\Script8.psm1"

:: Exit the batch file
exit /b