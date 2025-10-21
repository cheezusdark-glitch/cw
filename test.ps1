<#
All-in-one CyberPatriot Beginner Script (Windows 10 practice)
- Audit system
- Apply easy fixes (password policy, lockout, firewall, Windows Update policy, Defender, SMBv1, UAC, disable risky services, disable Guest, AutoPlay off, OneDrive policy)
- Log all actions and results
- Save audit folder on Desktop and final report to C:\CyberPatriot_Report.txt

Run as Administrator. Designed for practice images.
#>

# --- Initialization ---
$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$desktopAudit = Join-Path $env:USERPROFILE "Desktop\CP_Audit_$timestamp"
New-Item -Path $desktopAudit -ItemType Directory -Force | Out-Null

$reportPath = "C:\CyberPatriot_Report.txt"
"CyberPatriot All-in-One Beginner Report - $timestamp" | Out-File -FilePath $reportPath -Encoding utf8

function LogWrite {
    param([string]$line)
    $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $out = "[$time] $line"
    $out | Out-File -FilePath $reportPath -Append -Encoding utf8
    $out
}

function Save-Text($name, $content) {
    $f = Join-Path $desktopAudit ($name + ".txt")
    if ($null -eq $content) { $content = "No output / not available" }
    $content | Out-File -FilePath $f -Encoding utf8
}

LogWrite "Script started. Audit directory: $desktopAudit"

# Keep lists of changes & issues for final summary
$changes = @()
$failures = @()
$auditFindings = @()

# --- 1) Basic audit collection (non-destructive) ---
try {
    LogWrite "Collecting audit data..."
    # Local users
    $localUsers = Get-LocalUser | Select Name,Enabled,LastLogon
    Save-Text "LocalUsers" ($localUsers | Format-Table -AutoSize | Out-String)
    $auditFindings += "LocalUsers collected"
    # Local groups
    $localGroups = Get-LocalGroup | Select Name
    Save-Text "LocalGroups" ($localGroups | Format-Table -AutoSize | Out-String)
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Save-Text "Administrators_Group" -content { param($x) $x | Format-Table -AutoSize | Out-String }
} catch {
    LogWrite "ERROR - collecting local users/groups: $_"
    $failures += "Audit LocalUsers/Groups: $_"
}

try {
    # Firewall summary
    $fw = Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    Save-Text "Firewall_Profile_Summary" ($fw | Format-Table -AutoSize | Out-String)
    # Firewall rules snapshot (limit size)
    Get-NetFirewallRule -PolicyStore ActiveStore | Select DisplayName,Direction,Action,Enabled,Profile | Save-Text "Firewall_Rules" -content { param($x) $x | Format-Table -AutoSize | Out-String }
    $auditFindings += "Firewall snapshot"
} catch {
    LogWrite "ERROR - firewall audit: $_"
    $failures += "Firewall audit: $_"
}

try {
    # Windows Update service and policies
    Get-Service -Name wuauserv -ErrorAction SilentlyContinue | Save-Text "WindowsUpdate_Service" -content { param($x) $x | Format-List | Out-String }
    Try { Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Save-Text "WU_Policies" -content { param($y) $y | Out-String } } catch {}
    $auditFindings += "Windows Update info"
} catch {
    LogWrite "ERROR - Windows Update audit: $_"
    $failures += "Windows Update audit: $_"
}

try {
    # Defender / AV
    Try { $def = Get-MpComputerStatus -ErrorAction Stop; Save-Text "WindowsDefender_Status" ($def | Out-String) ; $auditFindings += "Defender status" } catch { Save-Text "WindowsDefender_Status" "Get-MpComputerStatus not available or Defender not installed" }
} catch {
    LogWrite "ERROR - Defender audit: $_"
    $failures += "Defender audit: $_"
}

try {
    # SMBv1 check
    Try { $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue; Save-Text "SMB1_Feature" ($smb1 | Out-String) } catch {}
    Try { $smbReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue; Save-Text "SMB1_Registry" ($smbReg | Out-String) } catch {}
    $auditFindings += "SMBv1 check"
} catch {
    LogWrite "ERROR - SMBv1 audit: $_"
    $failures += "SMBv1 audit: $_"
}

try {
    # RDP status
    $rdp = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    Save-Text "RDP_fDenyTSConnections" ("fDenyTSConnections = $rdp")
    $auditFindings += "RDP check"
} catch {
    LogWrite "ERROR - RDP audit: $_"
    $failures += "RDP audit: $_"
}

try {
    # UAC settings
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,EnableLUA
    Save-Text "UAC_Settings" ($uac | Out-String)
    $auditFindings += "UAC settings"
} catch {
    LogWrite "ERROR - UAC audit: $_"
    $failures += "UAC audit: $_"
}

try {
    # Event log top errors (small sample)
    Get-EventLog -LogName System -Newest 100 | Where-Object {$_.EntryType -in @("Error","Warning")} | Save-Text "System_Recent_Errors" -content { param($x) $x | Out-String }
    $auditFindings += "Event log sample"
} catch {
    LogWrite "ERROR - EventLog audit: $_"
    $failures += "EventLog audit: $_"
}

# --- 2) Apply safe fixes (do changes, log each success/failure) ---
LogWrite "Applying changes (begin). Actions will be logged."

# 2.1 Disable Guest account
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        Disable-LocalUser -Name "Guest" -ErrorAction Stop
        LogWrite "Disabled Guest account"
        $changes += "Disabled Guest account"
    } else {
        LogWrite "Guest account not present or already disabled"
    }
} catch {
    LogWrite "FAILED to disable Guest: $_"
    $failures += "Disable Guest: $_"
}

# 2.2 Password & lockout policy (net accounts) - set to checklist values
try {
    LogWrite "Setting password policy: min length=10, max age=60, min age=1, history=24"
    $out1 = net accounts /minpwlen:10 /uniquepw:24 /maxpwage:60 /minpwage:1 2>&1
    LogWrite ("net accounts output: " + ($out1 -join " | "))
    $changes += "Password policy via net accounts set (minlen=10, maxage=60, minage=1, history=24)"
} catch {
    LogWrite "FAILED to set password policy: $_"
    $failures += "PasswordPolicy: $_"
}

try {
    LogWrite "Setting account lockout: threshold=10, window=30, duration=30"
    $out2 = net accounts /lockoutthreshold:10 /lockoutwindow:30 /lockoutduration:30 2>&1
    LogWrite ("net accounts lockout output: " + ($out2 -join " | "))
    $changes += "Account lockout set (threshold 10, window 30, duration 30)"
} catch {
    LogWrite "FAILED to set lockout policy: $_"
    $failures += "LockoutPolicy: $_"
}

# 2.3 Enable Windows Firewall for all profiles
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    LogWrite "Enabled Windows Firewall for Domain, Public, Private"
    $changes += "Enabled Windows Firewall (all profiles)"
} catch {
    LogWrite "FAILED to enable Windows Firewall: $_"
    $failures += "Enable Firewall: $_"
}

# 2.4 Configure Windows Update to automatic via policy registry (AUOptions=4)
try {
    $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    New-Item -Path $wuKey -Force | Out-Null
    Set-ItemProperty -Path $wuKey -Name "AUOptions" -Value 4 -Type DWord -ErrorAction Stop
    # Prevent forced reboot when a user is logged on (best-effort)
    Set-ItemProperty -Path $wuKey -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    LogWrite "Set Windows Update policy (AUOptions=4: Auto download & schedule install)"
    $changes += "Windows Update policy set (AUOptions=4)"
} catch {
    LogWrite "FAILED to set Windows Update policy: $_"
    $failures += "WindowsUpdatePolicy: $_"
}

# 2.5 Enable Windows Defender real-time & update signatures (if Defender present)
try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Update-MpSignature -ErrorAction SilentlyContinue
        $mp = Get-MpComputerStatus
        Save-Text "Defender_PostChange" ($mp | Out-String)
        LogWrite "Windows Defender: ensured real-time monitoring on and attempted signature update"
        $changes += "Enabled/ensured Windows Defender real-time and attempted signature update"
    } else {
        LogWrite "Windows Defender cmdlets not available on this image"
    }
} catch {
    LogWrite "FAILED Defender actions: $_"
    $failures += "DefenderActions: $_"
}

# 2.6 Disable SMBv1 (client & server) - best-effort; requires restart to fully remove in some cases
try {
    # Disable optional feature
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    # also attempt to set server config
    Try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    LogWrite "Attempted to disable SMBv1 (feature and server config). May require restart."
    $changes += "Attempted to disable SMBv1 (feature + server config)"
} catch {
    LogWrite "FAILED to disable SMBv1: $_"
    $failures += "SMBv1 disable: $_"
}

# 2.7 Set UAC to secure values (ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1, EnableLUA=1)
try {
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
    LogWrite "Set UAC: ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1, EnableLUA=1"
    $changes += "UAC settings hardened"
} catch {
    LogWrite "FAILED to set UAC registry values: $_"
    $failures += "UACSettings: $_"
}

# 2.8 Disable AutoPlay / AutoRun for all drives
try {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction Stop
    LogWrite "Disabled AutoPlay/AutoRun for all drive types (NoDriveTypeAutoRun=255)"
    $changes += "Disabled AutoPlay/AutoRun"
} catch {
    LogWrite "FAILED to disable AutoPlay: $_"
    $failures += "DisableAutoPlay: $_"
}

# 2.9 Disable a selected list of risky services (stop + disable) - safe defaults
$servicesToDisable = @(
    "Telnet",         # Telnet (Telnet)
    "RemoteRegistry", # Remote Registry
    "SSDPSRV",        # SSDP Discovery
    "UPnPHost",       # UPnP Device Host
    "SNMP",           # SNMP (SNMP may have different service name; best-effort)
    "Tftpd"           # TFTP (may not exist)
)
foreach ($s in $servicesToDisable) {
    try {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Stopped") { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
            LogWrite "Stopped & disabled service (if present): $s"
            $changes += "Stopped & disabled service: $s"
        } else {
            LogWrite "Service not present (skipped): $s"
        }
    } catch {
        LogWrite "FAILED to stop/disable $s: $_"
        $failures += "Service change $s: $_"
    }
}

# 2.10 Disable OneDrive auto-start via policy (best-effort)
try {
    $oneDriveExe = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    if (Test-Path $oneDriveExe) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        # try to stop running OneDrive process
        Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        LogWrite "Applied OneDrive disable policy (DisableFileSyncNGSC=1) and stopped running OneDrive (if present)"
        $changes += "Applied OneDrive policy to disable sync/auto-start"
    } else {
        LogWrite "OneDrive not found; skipping OneDrive disable"
    }
} catch {
    LogWrite "FAILED OneDrive policy change: $_"
    $failures += "OneDrivePolicy: $_"
}

# 2.11 Check shares and warn if extra shares exist (non-destructive)
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    if ($null -ne $shares) {
        Save-Text "SmbShares" ($shares | Format-Table -AutoSize | Out-String)
        $nonStd = $shares | Where-Object { $_.Name -notin @("ADMIN$","C$","IPC$") }
        if ($nonStd) {
            LogWrite "WARNING: Found non-standard SMB shares: " + ($nonStd.Name -join ", ")
            $failures += "Non-standard SMB shares found: " + ($nonStd.Name -join ", ")
        } else {
            LogWrite "Only ADMIN$, C$, IPC$ shares present (expected)"
        }
    } else {
        LogWrite "Get-SmbShare not available or no shares present"
    }
} catch {
    LogWrite "ERROR checking SMB shares: $_"
    $failures += "SmbSharesCheck: $_"
}

# 2.12 Snapshot of Admins & Users exported (evidence)
try {
    Get-LocalUser | Select Name,Enabled,LastLogon | Export-Csv -Path (Join-Path $desktopAudit "LocalUsers.csv") -NoTypeInformation -Force
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select @{n='Group';e={'Administrators'}},Name | Export-Csv -Path (Join-Path $desktopAudit "Administrators_Members.csv") -NoTypeInformation -Force
    LogWrite "Exported LocalUsers and Administrators members to audit folder"
    $auditFindings += "Exported LocalUsers and Admins CSV"
} catch {
    LogWrite "FAILED export of users/groups: $_"
    $failures += "ExportUsers: $_"
}

# --- 3) Re-run a few quick checks to capture post-change state for report ---
try {
    # Firewall final
    $fwFinal = Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    Save-Text "Firewall_Profile_Summary_PostChange" ($fwFinal | Format-Table -AutoSize | Out-String)
} catch {}

try {
    # Net accounts post-check
    $netAccountsPost = net accounts 2>&1
    Save-Text "NetAccounts_PostChange" ($netAccountsPost -join "`n")
} catch {}

try {
    # SMB1 feature status post-change
    Try { $smb1Post = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue; Save-Text "SMB1_Feature_PostChange" ($smb1Post | Out-String) } catch {}
} catch {}

try {
    # UAC post
    $uacPost = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,EnableLUA
    Save-Text "UAC_Settings_PostChange" ($uacPost | Out-String)
} catch {}

# --- 4) Final summary & report printing to C:\CyberPatriot_Report.txt ---
LogWrite "------------------ FINAL SUMMARY ------------------"
LogWrite ("Audit files saved to: " + $desktopAudit)
if ($changes.Count -gt 0) {
    LogWrite "CHANGES APPLIED:"
    foreach ($c in $changes) { LogWrite " - $c" }
} else {
    LogWrite "No changes were applied."
}

if ($failures.Count -gt 0) {
    LogWrite "ACTIONS THAT FAILED / WARNINGS:"
    foreach ($f in $failures) { LogWrite " - $f" }
} else {
    LogWrite "No failures detected during automation."
}

LogWrite "ADDITIONAL AUDIT FINDINGS:"
foreach ($a in $auditFindings) { LogWrite " - $a" }

LogWrite "A small selection of important files created in audit folder:"
Get-ChildItem -Path $desktopAudit -File | Select-Object Name,Length | ForEach-Object { LogWrite (" - " + $_.Name + " (" + $_.Length + " bytes)") }

LogWrite "Script finished at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
LogWrite "Please review C:\CyberPatriot_Report.txt and files in $desktopAudit for evidence to include in your README and forensic answers."

# End of script
