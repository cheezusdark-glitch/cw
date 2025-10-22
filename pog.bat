@echo off
rem ------------------------------------------------------------------
rem CyberPatriot — Max Points Interactive Script
rem - Modular, generalized, aims to cover most CyberPatriot scoring areas
rem - Place authorizedusers.txt and admins.txt (one username per line) in same folder if desired
rem ------------------------------------------------------------------
color 0b
title CyberPatriot Max-Points Script
setlocal ENABLEDELAYEDEXPANSION

rem -------------------------
rem Logging
rem -------------------------
set LOGFILE=%~dp0cyberpatriot_script_log_%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.txt
echo Script run at %DATE% %TIME% > "%LOGFILE%"
echo Script path: %~f0 >> "%LOGFILE%"
echo. >> "%LOGFILE%"

rem -------------------------
rem Admin check
rem -------------------------
echo Checking for Administrator privileges... | tee "%LOGFILE%"
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Script must be run as Administrator. Right-click -> Run as administrator. >> "%LOGFILE%"
    echo Press any key to exit...
    pause>nul
    goto :eof
)
echo Administrator privileges confirmed. >> "%LOGFILE%"
cls

rem -------------------------
rem Helper: safe run of commands and logging
rem -------------------------
:run
rem %1 is the command to run (use call :run cmd)
echo Running: %* >> "%LOGFILE%"
%*
if %ERRORLEVEL% equ 0 (
    echo SUCCESS: %* >> "%LOGFILE%"
) else (
    echo FAIL (exit %ERRORLEVEL%): %* >> "%LOGFILE%"
)
goto :eof

rem -------------------------
rem Prompt helpers
rem -------------------------
:askYN
rem returns ERRORLEVEL 1=yes 2=no 3=cancel
choice /c ync /m "%~1"
goto :eof

:askAMC
rem returns ERRORLEVEL 1=a 2=m 3=c
choice /c amc /m "%~1"
goto :eof

rem -------------------------
rem MAIN MENU
rem -------------------------
:menu
cls
echo ============================================================
echo CyberPatriot — Max Points Interactive Script
echo ============================================================
echo 1. Quick apply (recommended: runs standard set)
echo 2. Step through sections interactively (recommended for competition)
echo 3. Exit
echo.
choice /c 123 /m "Choose an option"
if %ERRORLEVEL% equ 1 goto :quick
if %ERRORLEVEL% equ 2 goto :interactive
if %ERRORLEVEL% equ 3 goto :end

rem -------------------------
rem QUICK (runs main sections, prompts for destructive ones)
rem -------------------------
:quick
echo Running quick (safe default) profile... >> "%LOGFILE%"
call :section_firewall
call :section_remote_assist_rdp
call :section_registry_hardening
call :section_password_policies
call :section_audit_policies
call :section_restrict_anonymous
call :section_user_admin_audit
call :section_services --auto
call :section_remove_unauth_software
call :section_disallowed_media --prompt
call :section_gpo_import
call :section_updates
call :final_report
goto :end

rem -------------------------
rem INTERACTIVE (step through each)
rem -------------------------
:interactive
echo Interactive mode selected. >> "%LOGFILE%"
call :section_firewall
call :section_remote_assist_rdp
call :section_registry_hardening
call :section_password_policies
call :section_audit_policies
call :section_restrict_anonymous
call :section_user_admin_audit
call :section_services --manual
call :section_remove_unauth_software
call :section_disallowed_media --manual
call :section_gpo_import
call :section_forensics_cleanup
call :section_updates
call :final_report
goto :end

rem =========================
rem Sections
rem =========================

rem -------------------------
rem Firewall
rem -------------------------
:section_firewall
echo.
call :askYN "Enable Windows Firewall for all profiles? (y=yes n=no c=cancel)"
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping firewall. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 2 (
    echo Skipping firewall. >> "%LOGFILE%"
    goto :eof
)
echo Enabling Windows Firewall... | tee "%LOGFILE%"
call :run netsh advfirewall set allprofiles state on
echo.
goto :eof

rem -------------------------
rem Remote Assistance / RDP
rem -------------------------
:section_remote_assist_rdp
echo.
call :askYN "Disable Remote Assistance AND Remote Desktop and related services? (recommended)"
if %ERRORLEVEL% equ 2 (
    echo Skipping remote assist/rdp. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
echo Disabling Remote Assistance and RDP... >> "%LOGFILE%"
call :run sc stop "TermService" 2>nul
call :run sc config "TermService" start=disabled
call :run sc stop "SessionEnv" 2>nul
call :run sc config "SessionEnv" start=disabled
call :run sc stop "UmRdpService" 2>nul
call :run sc config "UmRdpService" start=disabled
call :run sc stop "RemoteRegistry" 2>nul
call :run sc config "RemoteRegistry" start=disabled
call :run reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
call :run reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
echo Done. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Registry hardening (large set from training key)
rem -------------------------
:section_registry_hardening
echo.
call :askYN "Apply registry hardening (UAC, LSA protections, show hidden files, disable autoruns, various security options)?"
if %ERRORLEVEL% equ 2 (
    echo Skipping registry hardening. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
echo Applying registry hardening... >> "%LOGFILE%"

rem Windows Update policy tweaks (leave updates enabled)
call :run reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
call :run reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
call :run reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f

rem Winlogon, clear pagefile at shutdown, disable AutoAdminLogon
call :run reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
call :run reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
call :run reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
call :run reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

rem LSA protections
call :run reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
call :run reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

rem User logon display, UAC, secure desktop
call :run reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
call :run reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
call :run reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

rem SMB/Netlogon hardening
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f

rem Explorer/hidden files/autoplay
call :run reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
call :run reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
call :run reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f

rem Internet Explorer protections (where applicable)
call :run reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
call :run reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
call :run reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
call :run reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
call :run reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f

echo Registry hardening completed. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Password policies & lockout
rem -------------------------
:section_password_policies
echo.
call :askYN "Enforce password policies (min length 10, max age 90, lockout threshold 10)?"
if %ERRORLEVEL% equ 2 (
    echo Skipping password policy changes. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
echo Applying password policies... >> "%LOGFILE%"
call :run net accounts /minpwlen:10
call :run net accounts /maxpwage:90
call :run net accounts /uniquepw:5
call :run net accounts /lockoutthreshold:10
call :run net accounts /lockoutduration:15
call :run net accounts /lockoutwindow:15
echo Password policy applied. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Audit policies
rem -------------------------
:section_audit_policies
echo.
call :askYN "Enable basic auditing (Account Logon, Logon/Logoff, Credential Validation failures)?"
if %ERRORLEVEL% equ 2 (
    echo Skipping audit policy changes. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
echo Setting audit policies... >> "%LOGFILE%"
call :run auditpol /set /subcategory:"Credential Validation" /failure:enable
call :run auditpol /set /category:"Account Logon" /success:enable /failure:enable
call :run auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
echo Audit policies set. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Restrict anonymous
rem -------------------------
:section_restrict_anonymous
echo.
call :askYN "Enable 'Do not allow anonymous enumeration of SAM accounts' and related LSA restrictions?"
if %ERRORLEVEL% equ 2 (
    echo Skipping anonymous restrictions. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
call :run reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
echo Anonymous enumeration restricted. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem User/Admin audit (reads authorizedusers.txt and admins.txt if present)
rem -------------------------
:section_user_admin_audit
echo.
call :askYN "Perform user/admin audit (reads authorizedusers.txt and admins.txt if present)?"
if %ERRORLEVEL% equ 2 (
    echo Skipping user/admin audit. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)

rem Users file
set USERSFILE=%~dp0authorizedusers.txt
if exist "%USERSFILE%" (
    echo Found authorized users file: %USERSFILE% >> "%LOGFILE%"
) else (
    echo No authorizedusers.txt found. You will be prompted to manually add/remove users. >> "%LOGFILE%"
)

rem Admins file
set ADMINSFILE=%~dp0admins.txt
if exist "%ADMINSFILE%" (
    echo Found admins file: %ADMINSFILE% >> "%LOGFILE%"
) else (
    echo No admins.txt found. Will prompt for manual admin fixes. >> "%LOGFILE%"
)

call :askYN "Automatically remove users NOT listed in authorizedusers.txt and add missing listed users? (Destructive)"
if %ERRORLEVEL% equ 1 (
    if exist "%USERSFILE%" (
        echo Processing authorized users... >> "%LOGFILE%"
        rem build list of authorized users into variables
        for /f "usebackq tokens=*" %%A in ("%USERSFILE%") do (
            set auth_%%A=1
            echo Authorized: %%A >> "%LOGFILE%"
        )
        rem enumerate current local users via net user
        for /f "skip=1 tokens=1" %%U in ('net user') do (
            rem "net user" output includes blank lines and headers; skip empty and 'The command completed...' lines
            if not "%%U"=="" (
                rem check if system built-in accounts; skip Administrator, Guest, DefaultAccount, WDAGUtilityAccount, etc.
                set skip=0
                for %%B in (Administrator Guest DefaultAccount WDAGUtilityAccount) do (
                    if /I "%%U"=="%%B" set skip=1
                )
                if !skip! equ 1 (
                    rem skip
                ) else (
                    set found=0
                    for /f "usebackq tokens=*" %%A in ("%USERSFILE%") do (
                        if /I "%%U"=="%%A" set found=1
                    )
                    if !found! equ 0 (
                        echo Deleting unauthorized user %%U ... >> "%LOGFILE%"
                        net user "%%U" /delete >> "%LOGFILE%" 2>&1
                    ) else (
                        echo Keeping authorized user %%U >> "%LOGFILE%"
                    )
                )
            )
        )
        rem Add missing users
        for /f "usebackq tokens=*" %%A in ("%USERSFILE%") do (
            call :isLocalUser "%%A"
            if !ISLOCAL! equ 0 (
                echo Adding missing user %%A ... >> "%LOGFILE%"
                net user "%%A" q1W@e3R$t5Y^u7I*o9 /add >> "%LOGFILE%" 2>&1
            )
        )
    ) else (
        echo Authorized file not found; skipping automatic user removal. >> "%LOGFILE%"
    )
) else (
    echo Skipping automatic user add/remove. >> "%LOGFILE%"
)

rem Admins enforcement
call :askYN "Automatically enforce admins list from admins.txt (remove admins not listed, add listed)?"
if %ERRORLEVEL% equ 1 (
    if exist "%ADMINSFILE%" (
        echo Enforcing Administrators group... >> "%LOGFILE%"
        rem remove anyone not in list
        rem get current admins via 'net localgroup Administrators'
        for /f "skip=6 tokens=*" %%A in ('net localgroup Administrators') do (
            if "%%A"=="" goto :afterAdminsEnum
            set CURADMIN=%%A
            rem trim spaces
            for /f "tokens=* delims= " %%T in ("%%A") do set CURADMIN=%%T
            set KEEP=0
            for /f "usebackq tokens=*" %%L in ("%ADMINSFILE%") do (
                if /I "%%L"=="!CURADMIN!" set KEEP=1
            )
            if !KEEP! equ 0 (
                if /I "!CURADMIN!" NEQ "%USERNAME%" (
                    echo Removing admin rights from !CURADMIN! >> "%LOGFILE%"
                    net localgroup Administrators "!CURADMIN!" /delete >> "%LOGFILE%" 2>&1
                ) else (
                    echo Skipping removal of current user from Administrators >> "%LOGFILE%"
                )
            ) else (
                echo Keeping admin !CURADMIN! >> "%LOGFILE%"
            )
        )
        :afterAdminsEnum
        rem Add missing admins
        for /f "usebackq tokens=*" %%L in ("%ADMINSFILE%") do (
            net localgroup Administrators "%%L" /add >> "%LOGFILE%" 2>&1
        )
    ) else (
        echo admins.txt not found; skipping automatic admin enforcement. >> "%LOGFILE%"
    )
) else (
    echo Skipping automatic admins enforcement. >> "%LOGFILE%"
)

goto :eof

rem helper to check if user exists
:isLocalUser
set ISLOCAL=0
for /f "skip=1 tokens=1" %%U in ('net user') do (
    if /I "%%U"=="%~1" set ISLOCAL=1
)
goto :eof

rem -------------------------
rem Services management (manual/automatic)
rem -------------------------
:section_services
rem optional parameter --auto or --manual passed in via %1 when called
set mode=manual
if /I "%~1"=="--auto" set mode=auto
if /I "%~1"=="--manual" set mode=manual

echo.
if /I "%mode%"=="auto" (
    echo Auto mode selected for service hardening. >> "%LOGFILE%"
    call :askYN "Proceed to disable a common set of unnecessary services automatically?"
    if %ERRORLEVEL% equ 2 (
        echo Skipping service changes. >> "%LOGFILE%"
        goto :eof
    )
) else (
    call :askAMC "Service mode: (a=automatic disable a pre-selected list, m=manual step-through each, c=cancel)"
    if %ERRORLEVEL% equ 3 (
        echo Cancel requested; skipping services. >> "%LOGFILE%"
        goto :eof
    )
    if %ERRORLEVEL% equ 1 set mode=auto
    if %ERRORLEVEL% equ 2 set mode=manual
)

rem Services list - general suspicious/unneeded services in many images
set services=Telnet TapiSrv Tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RasMan RasAuto seclogon W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv ShellHWDetection ScardSvr Sacsvr Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper

if /I "%mode%"=="auto" (
    for %%S in (%services%) do (
        echo Disabling %%S ... >> "%LOGFILE%"
        sc stop "%%S" >nul 2>&1
        sc config "%%S" start=disabled >nul 2>&1
    )
    echo Services auto-disabled (where present). >> "%LOGFILE%"
    goto :eof
) else (
    for %%S in (%services%) do (
        call :askYN "Disable service %%S if present? (y=yes n=no c=cancel)"
        if %ERRORLEVEL% equ 3 (
            echo User cancelled service step. >> "%LOGFILE%"
            goto :eof
        )
        if %ERRORLEVEL% equ 1 (
            echo Disabling %%S ... >> "%LOGFILE%"
            sc stop "%%S" >nul 2>&1
            sc config "%%S" start=disabled >nul 2>&1
        ) else (
            echo Skipping %%S >> "%LOGFILE%"
        )
    )
)
goto :eof

rem -------------------------
rem Remove unauthorized software (Wireshark, NetStumbler, PCCleaner, etc.)
rem -------------------------
:section_remove_unauth_software
echo.
call :askYN "Attempt to remove commonly-prohibited tools (Wireshark, NetStumbler, PC Cleaner, etc.)? (uses WMI/PowerShell uninstall if available)"
if %ERRORLEVEL% equ 2 (
    echo Skipping software removal. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)

echo Removing known prohibited programs... >> "%LOGFILE%"
rem Try WMIC uninstall (may not show everything); also try to remove specific folders if present
for %%P in ("Wireshark" "NetStumbler" "PC Cleaner" "PCCleaner" "PC-Cleaner") do (
    echo Attempting to uninstall %%~P >> "%LOGFILE%"
    wmic product where "Name like '%%~P%%'" call uninstall /nointeractive >> "%LOGFILE%" 2>&1
)

rem Attempt to remove common install locations (best-effort, non-recursive)
if exist "C:\Program Files\Wireshark" (
    echo Deleting C:\Program Files\Wireshark >> "%LOGFILE%"
    rmdir /s /q "C:\Program Files\Wireshark" >> "%LOGFILE%" 2>&1
)
if exist "C:\Program Files (x86)\Wireshark" (
    echo Deleting C:\Program Files (x86)\Wireshark >> "%LOGFILE%"
    rmdir /s /q "C:\Program Files (x86)\Wireshark" >> "%LOGFILE%" 2>&1
)
echo Software removal attempted. Review log for details. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Disallowed media file removal (manual or automatic)
rem -------------------------
:section_disallowed_media
rem caller can pass --prompt/--manual/--auto in %1
set DMODE=prompt
if /I "%~1"=="--manual" set DMODE=manual
if /I "%~1"=="--auto" set DMODE=auto

echo.
if /I "%DMODE%"=="auto" (
    call :askYN "Automatically delete common media filetypes (.mp3 .mp4 .jpg .png .gif etc.) across user profiles? (Destructive)"
    if %ERRORLEVEL% equ 2 (
        echo Skipping media deletion. >> "%LOGFILE%"
        goto :eof
    )
    if %ERRORLEVEL% equ 3 (
        echo Cancel requested; skipping. >> "%LOGFILE%"
        goto :eof
    )
    set filetypes=mp3 mov mp4 avi mpg mpeg flac m4a flv ogg gif png jpg jpeg
    echo Auto-deleting media files (this may remove legitimate files). >> "%LOGFILE%"
    for %%E in (%filetypes%) do (
        for /f "delims=" %%F in ('dir /s /b C:\Users\*.*.%%E 2^>nul') do (
            echo Deleting "%%F" >> "%LOGFILE%"
            del /f /q "%%F" >> "%LOGFILE%" 2>&1
        )
    )
    goto :eof
)

rem Prompt/manual mode
call :askAMC "Media deletion mode: (a=automatic delete, m=manual inspect each, c=cancel)"
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 1 set DMODE=auto
if %ERRORLEVEL% equ 2 set DMODE=manual

set filetypes=mp3 mov mp4 avi mpg mpeg flac m4a flv ogg gif png jpg jpeg
if /I "%DMODE%"=="auto" (
    for %%E in (%filetypes%) do (
        for /f "delims=" %%F in ('dir /s /b C:\Users\*.*.%%E 2^>nul') do (
            echo Deleting "%%F" >> "%LOGFILE%"
            del /f /q "%%F" >> "%LOGFILE%" 2>&1
        )
    )
) else (
    for %%E in (%filetypes%) do (
        for /f "delims=" %%F in ('dir /s /b C:\Users\*.*.%%E 2^>nul') do (
            choice /c yn /m "Delete %%F ? (y=yes n=no)"
            if %ERRORLEVEL% equ 1 (
                echo Deleting "%%F" >> "%LOGFILE%"
                del /f /q "%%F" >> "%LOGFILE%" 2>&1
            ) else (
                echo Skipping "%%F" >> "%LOGFILE%"
            )
        )
    )
)
goto :eof

rem -------------------------
rem LGPO import if LGPO.exe present
rem -------------------------
:section_gpo_import
echo.
call :askYN "Import local GPO folder using LGPO.exe if present in script folder? (requires LGPO.exe and Policies folder)"
if %ERRORLEVEL% equ 2 (
    echo Skipping GPO import. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)

rem Search for LGPO.exe in current folder and subfolders
set LGPOFOUND=
for /f "delims=" %%L in ('dir /s /b LGPO.exe 2^>nul') do (
    set LGPOFOUND=%%L
    goto :foundLGPO
)
:foundLGPO
if not defined LGPOFOUND (
    echo LGPO.exe not found on system. Please add LGPO.exe and a Policies folder to the script folder to import. >> "%LOGFILE%"
    goto :eof
)
set LGPOPATH=%~dp0
if exist ".\Policies" (
    echo Importing policies from .\Policies using LGPO.exe >> "%LOGFILE%"
    call :run ".\LGPO.exe" /g .\Policies /v
) else (
    echo No .\Policies folder present to import. >> "%LOGFILE%"
)
goto :eof

rem -------------------------
rem Forensics-safe cleanup (e.g., prohibited forensic artifact files)
rem -------------------------
:section_forensics_cleanup
echo.
call :askYN "Remove specific prohibited forensic files if found (e.g., thisisaffinecode.txt)?"
if %ERRORLEVEL% equ 2 (
    echo Skipping forensic cleanup. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)
rem Example: delete known forensic clue file if present
if exist "C:\Users\Public\Public Downloads\thisisaffinecode.txt" (
    echo Deleting C:\Users\Public\Public Downloads\thisisaffinecode.txt >> "%LOGFILE%"
    del /f /q "C:\Users\Public\Public Downloads\thisisaffinecode.txt" >> "%LOGFILE%" 2>&1
)
echo Forensics cleanup complete. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Windows and Firefox updates (best-effort)
rem -------------------------
:section_updates
echo.
call :askYN "Attempt to install Windows Updates and update Firefox (best-effort; may require network and modules)?"
if %ERRORLEVEL% equ 2 (
    echo Skipping updates. >> "%LOGFILE%"
    goto :eof
)
if %ERRORLEVEL% equ 3 (
    echo Cancel requested; skipping. >> "%LOGFILE%"
    goto :eof
)

rem Attempt PSWindowsUpdate usage (best-effort)
echo Attempting Windows Update via PSWindowsUpdate module... >> "%LOGFILE%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Try { if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue; Install-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue } Import-Module PSWindowsUpdate; Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot } Catch { Write-Output 'PSWindowsUpdate not available or failed' }" >> "%LOGFILE%" 2>&1

rem Update Firefox (if installed) by checking path and launching update UI
if exist "C:\Program Files\Mozilla Firefox\firefox.exe" (
    echo Attempting to trigger Firefox update UI... >> "%LOGFILE%"
    start "" "C:\Program Files\Mozilla Firefox\firefox.exe" -Update >> "%LOGFILE%" 2>&1
) else (
    echo Firefox not installed. >> "%LOGFILE%"
)
echo Update attempts logged. >> "%LOGFILE%"
goto :eof

rem -------------------------
rem Final report and summary
rem -------------------------
:final_report
echo.
echo ============================================================
echo Final Report
echo ============================================================
echo Actions logged to: %LOGFILE%
echo.
echo Quick checklist (verify in UI or logs):
echo - Firewall enabled
echo - Remote Assistance / RDP disabled
echo - Registry hardening applied (UAC / LSA / SMB / Explorer)
echo - Password & lockout policies set (min length 10, lockout 10)
echo - Auditing for credential validation and logons enabled
echo - Anonymous SAM enumeration restricted
echo - User/admin audit attempted (if authorizedusers.txt/admins.txt present)
echo - Services disabled per chosen mode
echo - Known prohibited software removal attempted
echo - Media removal depending on chosen mode
echo - LGPO import attempted (if Policies folder & LGPO.exe present)
echo - Windows/Firefox update attempts
echo.
echo IMPORTANT: Review the log file above and verify each change in the image UI before submitting.
echo ============================================================
echo.
pause
goto :eof

rem -------------------------
rem End
rem -------------------------
:end
echo Exiting. Log saved to %LOGFILE%
endlocal
exit /b
