#Designed by Pavel Mirochnitchenko MVP, 10-2025 together with ChatGTP & Github Copilot.
# AddTempAdminRights_v1.1.ps1
# Temporarily grants the currently signed-in user local admin rights and automatically revokes them after $DurationMin minutes.
# Designed for Intune/Company Portal deployments. Event Viewer logs only grant/removal and errors under source "AddTempAdminRights";
# all other informational messages are written to C:\ProgramData\Microsoft\Windows\Temp\Scan.log.
# The script generates Scan.ps1 (removal) and CleanupScan.ps1 (cleanup) in the work folder and schedules a hidden SYSTEM task to run once.
# Note: UI pop-ups may not appear when run under SYSTEM (e.g., via Intune). Adjust $DurationMin to change the elevation duration.

# --- CONFIGURATION ---
$EventSource = "AddTempAdminRights"
$WorkFolder = "C:\ProgramData\Microsoft\Windows\Temp"
$ScanScript = "Scan.ps1"
$CleanupScript = "CleanupScan.ps1"
$LogFile = Join-Path $WorkFolder "Scan.log"
$TaskName = "Scan"
$TaskPath = "\Microsoft\Windows\Chkdsk"
$DurationMin = 5
$IntuneFlag = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AddTempAdminRights.flag"

# --- Ensure event source ---
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName Application -Source $EventSource
}

# --- Ensure working folder ---
if (-not (Test-Path $WorkFolder)) {
    New-Item -ItemType Directory -Path $WorkFolder -Force | Out-Null
}

# --- Logging function (Event Viewer logs only for admin actions/errors, file log for everything else) ---
function Write-Log {
    param(
        [string]$msg,
        [string]$type = "Information",
        [bool]$logToEventViewer = $false
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts [$type] $msg" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($logToEventViewer) {
        try {
            Write-EventLog -LogName Application -Source $EventSource -EventId 1005 -EntryType $type -Message $msg
        } catch {}
    }
}

Write-Log "=== Start AddTempAdminRights_CopilotHybrid ===" # only file log

# --- Detect interactive user ---
try {
    $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $currentUser) { throw "No interactive user detected." }
    Write-Log "Interactive user: $currentUser"
} catch {
    Write-Log "ERROR: Could not detect user: $_" "Error" $true
    exit 1
}

# --- Create Intune detection flag ---
try { New-Item -Path $IntuneFlag -ItemType File -Force | Out-Null } catch {}
Write-Log "Intune flag created: $IntuneFlag" # only file log

# --- Grant admin rights using net localgroup ---
try {
    net localgroup Administrators "$currentUser" /add | Out-Null
    Write-Log "Granted Administrators to $currentUser" "Information" $true
} catch {
    Write-Log "ERROR: Failed to grant admin rights: $_" "Error" $true
    exit 1
}

# --- Create Scan.ps1 for removal ---
$ScanScriptPath = Join-Path $WorkFolder $ScanScript
$scanTemplate = @"
# Scan.ps1 - temporary admin removal
try {
    # Ensure Event Source exists
    if (-not [System.Diagnostics.EventLog]::SourceExists('$EventSource')) {
        New-EventLog -LogName Application -Source '$EventSource'
    }
    # Remove admin rights
    net localgroup Administrators '$currentUser' /delete | Out-Null
    # Log success
    try {
        Write-EventLog -LogName Application -Source '$EventSource' -EventId 1006 -EntryType Information -Message "Temporary admin rights removed from $currentUser."
    } catch {
        Add-Content -Path '$LogFile' -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - WARNING: Failed to write EventLog: $($_.Exception.Message)"
    }
    # Remove Intune flag
    if (Test-Path '$IntuneFlag') { Remove-Item -Force '$IntuneFlag' }
} catch {
    Add-Content -Path '$LogFile' -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: Failed to remove admin rights: $($_.Exception.Message)"
}
# Launch CleanupScan.ps1 to remove Scan.ps1 and Scan.log
Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "$WorkFolder\$CleanupScript"' -WindowStyle Hidden
"@
$scanTemplate | Out-File -FilePath $ScanScriptPath -Encoding UTF8 -Force
Write-Log "Scan.ps1 created at $ScanScriptPath" # only file log

# --- Create CleanupScan.ps1 for file cleanup ---
$CleanupScriptPath = Join-Path $WorkFolder $CleanupScript
$cleanupTemplate = @"
# CleanupScan.ps1 - deletes Scan.ps1 and Scan.log
Start-Sleep -Seconds 5
try {
    Remove-Item -Force '$ScanScriptPath' -ErrorAction SilentlyContinue
    Remove-Item -Force '$LogFile' -ErrorAction SilentlyContinue
} catch {}
"@
$cleanupTemplate | Out-File -FilePath $CleanupScriptPath -Encoding UTF8 -Force
Write-Log "CleanupScan.ps1 created at $CleanupScriptPath" # only file log

# --- Schedule Scan.ps1 (SYSTEM principal, hidden, robust registration) ---
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScanScriptPath`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($DurationMin)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Compatibility Win8 -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -WakeToRun
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -InputObject $task -Force | Out-Null
    # Hide task
    for ($i=0; $i -lt 10; $i++) {
        try {
            $taskObj = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
            if ($taskObj) {
                $taskObj.Settings.Hidden = $true; Set-ScheduledTask -InputObject $taskObj; break
            }
        } catch { Start-Sleep -Seconds 1 }
    }
    Write-Log "Scheduled task '$TaskName' created and hidden. Admin rights will be removed in $DurationMin minutes." # only file log
} catch {
    Write-Log "ERROR: Failed to create scheduled task: $_" "Error" $true
}

# --- Notify user ---
$expires = (Get-Date).AddMinutes($DurationMin).ToString("HH:mm")
try {
    $shell = New-Object -ComObject WScript.Shell
    $shell.Popup("Temporary admin rights granted until $expires", 5, "Temporary Admin Granted", 64)
} catch {}
Write-Log "=== End AddTempAdminRights_CopilotHybrid ===" # only file log