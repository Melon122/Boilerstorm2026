@echo off
setlocal
set "psScriptPath1=C:\Users\%username%\Downloads\mainscript.ps1"
set "psScriptPath2=C:\Users\%username%\Downloads\defenderhard.ps1"
set "psScriptPath3=C:\Users\%username%\Downloads\restoreDefender.ps1"
set "psScriptPath4=C:\Users\%username%\Downloads\script2.ps1"
set "psScriptPath5=C:\Users\%username%\Downloads\script4.ps1"
set "psScriptPath6=C:\Users\%username%\Downloads\WindowsSecurity.ps1"
set "psScriptPath7=C:\Users\%username%\Downloads\CyberPatriotPowerShellScript.ps1"

:Start
echo.
echo 1. Run mainscript.ps1
echo 2. Run defenderhard.ps1
echo 3. Run restoreDefender.ps1
echo 4. Run script2.ps1
echo 5. Run script4.ps1
echo 6. Run WindowsSecurity.ps1
echo 7. Run CyberPatriotPowerShellScript.ps1
set /p "choice=Enter your choice (1-3): "

if "%choice%"=="1" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath1%""' -Verb RunAs"
) else if "%choice%"=="2" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath2%""' -Verb RunAs"
) else if "%choice%"=="3" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath3%""' -Verb RunAs"
) else if "%choice%"=="4" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath4%""' -Verb RunAs"
) else if "%choice%"=="5" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath5%""' -Verb RunAs"
) else if "%choice%"=="6" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath6%""' -Verb RunAs"
) else if "%choice%"=="7" (
    powershell -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%psScriptPath7%""' -Verb RunAs"
) else (
    echo Invalid choice, please choose valid.
    goto Start
)

goto Start

:End
endlocal
