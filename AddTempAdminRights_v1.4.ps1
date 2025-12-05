# Designed by Pavel Mirochnitchenko MVP, 12-2025 together with ChatGTP & GitHub Copilot.
# AddTempAdminRights_v1.4.ps1
# Description:
# - Grants the current interactive user temporary local admin rights, then schedules removal.
# - Resolves the localized name of the Administrators group from the well-known SID S-1-5-32-544 for language independence.
# - Writes key events to the Application log (grant: EventId 1005, removal verified: EventId 1006) and detailed logs to C:\ProgramData\Microsoft\Windows\Temp\Scan.log.
# - Schedules hidden removal and retry tasks under \Microsoft\Windows\Chkdsk.
# - Schedules additional removal triggers: on user logoff (event-based) and on system startup (ensures clean state after reboot).
# - Important: Existing processes keep their admin token until sign-out; removal prevents NEW elevations.

# Configuration:
# EventSource        = "AddTempAdminRights"
# WorkFolder         = "C:\ProgramData\Microsoft\Windows\Temp"
# ScanScript         = "Scan.ps1"
# CleanupScript      = "CleanupScan.ps1"
# TaskName           = "Scan"
# TaskPath           = "\Microsoft\Windows\Chkdsk"
# RetryTaskName      = "Scan_Retry"
# LogoffTaskName     = "Scan_Logoff"
# StartupTaskName    = "Scan_Startup"
# AdminGroupSID      = "S-1-5-32-544"
# IntuneFlag         = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AddTempAdminRights.flag"
# LogFile            = Join-Path $WorkFolder "Scan.log"
# PowerShellExe      = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

param(
    [int]$DurationMin = 5
)

# Relaunch in 64-bit PowerShell if currently in 32-bit (Intune IME/Win32 apps typical)
if (-not [Environment]::Is64BitProcess) {
    $ps64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

# --- CONFIGURATION VARIABLES ---
$EventSource        = "AddTempAdminRights"
$WorkFolder         = "C:\ProgramData\Microsoft\Windows\Temp"
$ScanScript         = "Scan.ps1"
$CleanupScript      = "CleanupScan.ps1"
$TaskName           = "Scan"
$TaskPath           = "\Microsoft\Windows\Chkdsk"
$RetryTaskName      = "Scan_Retry"
$LogoffTaskName     = "Scan_Logoff"
$StartupTaskName    = "Scan_Startup"
$LogoffScript       = "LogoffRemove.ps1"
$StartupScript      = "StartupRemove.ps1"
$AdminGroupSID      = "S-1-5-32-544"
$IntuneFlag         = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AddTempAdminRights.flag"
$LogFile            = Join-Path $WorkFolder "Scan.log"
$PowerShellExe      = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

# --- Ensure event source (may fail without elevation) ---
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        New-EventLog -LogName Application -Source $EventSource
    }
} catch {}

# --- Working folder ---
if (-not (Test-Path $WorkFolder)) { New-Item -ItemType Directory -Path $WorkFolder -Force | Out-Null }

# Helper: choose a safe, existing Application log source if our custom source isn't available
function Get-AppEventSource {
    param([string]$Preferred)
    try {
        if ($Preferred -and [System.Diagnostics.EventLog]::SourceExists($Preferred)) { return $Preferred }
        $candidates = @('EventLog','MsiInstaller','Application Error','Windows Error Reporting','Windows PowerShell')
        foreach ($s in $candidates) { if ([System.Diagnostics.EventLog]::SourceExists($s)) { return $s } }
    } catch {}
    return $null
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Information','Warning','Error')] [string]$Type = 'Information',
        [int]$EventId = 0,
        [bool]$EV = $false
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($EV) {
        try {
            $src = Get-AppEventSource -Preferred $EventSource
            if ($null -ne $src) {
                $id  = if ($EventId -gt 0) { $EventId } else { if ($Type -eq 'Error') {1005} else {1005} }
                Write-EventLog -LogName Application -Source $src -EventId $id -EntryType $Type -Message $Message
            } else {
                "$ts [Warning] No Application log source available to write event." | Out-File -FilePath $LogFile -Append -Encoding UTF8
            }
        } catch {
            "$ts [Warning] Failed to write to Event Viewer: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append -Encoding UTF8
        }
    }
}

Write-Log "=== Start AddTempAdminRights_v1.4 ==="

# --- Detect interactive user ---
try {
    $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $currentUser) { throw "No interactive user detected." }
    Write-Log "Interactive user: $currentUser"
} catch {
    Write-Log "ERROR: $($_.Exception.Message)" "Error" 1005 $true
    exit 1
}

# --- Resolve localized group name ---
function Resolve-AdminsGroupName {
    param([string]$Sid)
    $si      = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $account = $si.Translate([System.Security.Principal.NTAccount])
    ($account.Value -replace '^[^\\]+\\','')
}
try {
    $AdminsGroupName = Resolve-AdminsGroupName $AdminGroupSID
    Write-Log "Resolved Administrators group name: $AdminsGroupName"
} catch {
    Write-Log "ERROR: Failed to resolve group name from SID ${AdminGroupSID}. Details: $($_.Exception.Message)" "Error" 1005 $true
    exit 1
}

# --- Flag file ---
try { New-Item -Path $IntuneFlag -ItemType File -Force | Out-Null } catch {}
Write-Log "Flag created: $IntuneFlag"

# --- Check if already a member ---
$alreadyMember = $false
try {
    $alreadyMember = (Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $currentUser }) -ne $null
} catch {}

if ($alreadyMember) {
    Write-Log "User $currentUser already in $AdminsGroupName; will still schedule removal." "Warning" 1010 $false  # file only
} else {
    # --- Grant admin rights ---
    try {
        net localgroup "$AdminsGroupName" "$currentUser" /add | Out-Null
        $addExit = $LASTEXITCODE
        Write-Log "net localgroup add exit code: $addExit"  # file only
        if ($addExit -ne 0) { throw "net localgroup returned $addExit" }

        # Verify membership
        $memberNow = (Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $currentUser }) -ne $null
        if ($memberNow) {
            # Event Viewer visible: grant
            Write-Log "Granted '$AdminsGroupName' to $currentUser (verified membership)." "Information" 1005 $true
        } else {
            Write-Log "WARNING: Add command succeeded but membership not verified; will still proceed." "Warning" 1010 $false
        }
    } catch {
        Write-Log "ERROR: Failed to grant admin rights: $($_.Exception.Message)" "Error" 1005 $true
        exit 1
    }
}

# Suppressed in Event Viewer (file log only)
Write-Log "Important: Existing processes keep original admin token until user signs out and back in." "Warning" 1010 $false

# --- Helper: Ensure Task Scheduler folder exists (safe if it already exists) ---
function Ensure-TaskFolderExists {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $root = $svc.GetFolder("\")
        $rel = $Path.Trim("\")
        if ([string]::IsNullOrWhiteSpace($rel)) { return }
        $segments = $rel -split '\\'
        $current = "\"
        foreach ($seg in $segments) {
            if ([string]::IsNullOrWhiteSpace($seg)) { continue }
            $current = if ($current -eq "\") { "\" + $seg } else { $current + "\" + $seg }
            try { $null = $svc.GetFolder($current) } catch { $null = $root.CreateFolder($current.TrimStart("\")) }
        }
    } catch {
        Write-Log "WARNING: Could not verify/create task folder '$Path': $($_.Exception.Message)"
    }
}

# --- Build removal script (Scan.ps1) ---
$ScanScriptPath = Join-Path $WorkFolder $ScanScript
$scanTemplate = @'
# Relaunch in 64-bit PowerShell if currently in 32-bit
if (-not [Environment]::Is64BitProcess) {
    $ps64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

# Scan.ps1 - removal for temporary admin rights
$EventSource      = '__EVENT_SOURCE__'
$LogFile          = '__LOG_FILE__'
$IntuneFlag       = '__INTUNE_FLAG__'
$AdminGroupSID    = '__ADMIN_SID__'
$currentUser      = '__CURRENT_USER__'
$PowerShellExe    = '__POWERSHELL_EXE__'
$TaskPath         = '__TASK_PATH__'
$RetryTaskName    = '__RETRY_TASK_NAME__'
$AdminsGroupName  = (New-Object System.Security.Principal.SecurityIdentifier $AdminGroupSID).Translate([System.Security.Principal.NTAccount]).Value -replace '^[^\\]+\\',''

function Get-AppEventSource {
    param([string]$Preferred)
    try {
        if ($Preferred -and [System.Diagnostics.EventLog]::SourceExists($Preferred)) { return $Preferred }
        $candidates = @('EventLog','MsiInstaller','Application Error','Windows Error Reporting','Windows PowerShell')
        foreach ($s in $candidates) { if ([System.Diagnostics.EventLog]::SourceExists($s)) { return $s } }
    } catch {}
    return $null
}

function Write-Log {
    param([string]$Message,[ValidateSet('Information','Warning','Error')] [string]$Type='Information',[int]$EventId=1006,[bool]$EV=$true)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($EV) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
                New-EventLog -LogName Application -Source $EventSource
            }
        } catch {}
        $src = Get-AppEventSource -Preferred $EventSource
        if ($null -ne $src) {
            try { Write-EventLog -LogName Application -Source $src -EventId $EventId -EntryType $Type -Message $Message } catch {}
        } else {
            try { "$ts [Warning] No Application log source available to write event." | Out-File -FilePath $LogFile -Append -Encoding UTF8 } catch {}
        }
    }
}

# Suppressed banner in Event Viewer
Write-Log "=== Removal start ===" "Information" 1006 $false

function Test-Membership {
    (Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $currentUser }) -ne $null
}

$before = Test-Membership
# Suppressed state log in Event Viewer
Write-Log "Membership before removal: $before" "Information" 1006 $false

$removed = $false
try {
    net localgroup "$AdminsGroupName" "$currentUser" /delete | Out-Null
    $delExit = $LASTEXITCODE
    # Suppressed exit code log in Event Viewer
    Write-Log "net localgroup delete exit code: $delExit" "Information" 1006 $false
    if ($delExit -eq 0) {
        $removed = -not (Test-Membership)
    }
    if (-not $removed) {
        # Fallback PowerShell cmdlet if still member
        try {
            Remove-LocalGroupMember -Group $AdminsGroupName -Member $currentUser -ErrorAction Stop
            $removed = -not (Test-Membership)
            Write-Log "Fallback Remove-LocalGroupMember executed. Removed=$removed" "Information" 1006 $false
        } catch {
            Write-Log "ERROR: Fallback Remove-LocalGroupMember failed: $($_.Exception.Message)" "Error" 1006 $true
        }
    }

    if ($removed) {
        # Visible in Event Viewer: removal verified
        Write-Log "Temporary admin rights removed from $currentUser (verified)." "Information" 1006 $true
    } else {
        Write-Log "WARNING: User still appears in $AdminsGroupName after removal attempts." "Warning" 1010 $true

        # --- Build retry script next to this script ---
        try {
            $retryScript = Join-Path (Split-Path $PSCommandPath) "RetryRemove.ps1"
@"
# Relaunch in 64-bit PowerShell if currently in 32-bit
if (-not [Environment]::Is64BitProcess) {
    `$ps64 = "`$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path `$ps64) {
        & `$ps64 -NoProfile -ExecutionPolicy Bypass -File `$PSCommandPath @args
        exit `$LASTEXITCODE
    }
}
`$EventSource     = '$EventSource'
`$AdminsGroupName = '$AdminsGroupName'
`$currentUser     = '$currentUser'
function Get-AppEventSource {
    param([string]`$Preferred)
    try {
        if (`$Preferred -and [System.Diagnostics.EventLog]::SourceExists(`$Preferred)) { return `$Preferred }
        `$candidates = @('EventLog','MsiInstaller','Application Error','Windows Error Reporting','Windows PowerShell')
        foreach (`$s in `$candidates) { if ([System.Diagnostics.EventLog]::SourceExists(`$s)) { return `$s } }
    } catch {}
    return `$null
}
`$src = Get-AppEventSource -Preferred `$EventSource
try {
  net localgroup "`$AdminsGroupName" "`$currentUser" /delete | Out-Null
  Remove-LocalGroupMember -Group "`$AdminsGroupName" -Member "`$currentUser" -ErrorAction SilentlyContinue
  `$stillMember = (Get-LocalGroupMember -Group "`$AdminsGroupName" -ErrorAction SilentlyContinue | Where-Object { `$_.Name -eq "`$currentUser" }) -ne `$null
  if (-not `$stillMember) {
    if (`$null -ne `$src) { Write-EventLog -LogName Application -Source `$src -EventId 1006 -EntryType Information -Message "Retry removal succeeded for `$currentUser." }
  } else {
    if (`$null -ne `$src) { Write-EventLog -LogName Application -Source `$src -EventId 1010 -EntryType Warning -Message "Retry removal still shows membership for `$currentUser." }
  }
} catch {}
"@ | Out-File -FilePath $retryScript -Encoding UTF8 -Force

            $startAt   = (Get-Date).AddMinutes(2)
            $action    = New-ScheduledTaskAction -Execute $PowerShellExe -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$retryScript`""
            $trigger   = New-ScheduledTaskTrigger -Once -At $startAt
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -Compatibility Win8
            Register-ScheduledTask -TaskName $RetryTaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

            try {
                $rt = Get-ScheduledTask -TaskPath $TaskPath -TaskName $RetryTaskName -ErrorAction Stop
                if ($rt) { $rt.Settings.Hidden = $true; Set-ScheduledTask -InputObject $rt | Out-Null }
            } catch {}
        } catch {}
    }

} catch {
    Write-Log "ERROR: Exception during removal: $($_.Exception.Message)" "Error" 1006 $true
}

# Clean up Intune flag
try { if (Test-Path $IntuneFlag) { Remove-Item -Force $IntuneFlag } } catch {}

# Start cleanup script
Start-Process -FilePath "$PowerShellExe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File '__WORK_FOLDER__\__CLEANUP_SCRIPT__'" -WindowStyle Hidden

# Suppressed banner in Event Viewer
Write-Log "=== Removal end ===" "Information" 1006 $false
'@

# Placeholder replacements
$scanTemplate = $scanTemplate.Replace('__EVENT_SOURCE__', $EventSource)
$scanTemplate = $scanTemplate.Replace('__LOG_FILE__', $LogFile)
$scanTemplate = $scanTemplate.Replace('__INTUNE_FLAG__', $IntuneFlag)
$scanTemplate = $scanTemplate.Replace('__ADMIN_SID__', $AdminGroupSID)
$scanTemplate = $scanTemplate.Replace('__CURRENT_USER__', $currentUser)
$scanTemplate = $scanTemplate.Replace('__WORK_FOLDER__', $WorkFolder)
$scanTemplate = $scanTemplate.Replace('__CLEANUP_SCRIPT__', $CleanupScript)
$scanTemplate = $scanTemplate.Replace('__POWERSHELL_EXE__', $PowerShellExe)
$scanTemplate = $scanTemplate.Replace('__TASK_PATH__', $TaskPath)
$scanTemplate = $scanTemplate.Replace('__RETRY_TASK_NAME__', $RetryTaskName)

$scanTemplate | Out-File -FilePath $ScanScriptPath -Encoding UTF8 -Force
Write-Log "Created $ScanScriptPath"

# --- Build logoff removal script (LogoffRemove.ps1) ---
$LogoffScriptPath = Join-Path $WorkFolder $LogoffScript
$logoffTemplate = @'
# Relaunch in 64-bit PowerShell if currently in 32-bit
if (-not [Environment]::Is64BitProcess) {
    $ps64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

# LogoffRemove.ps1 - removal on user logoff
$EventSource      = '__EVENT_SOURCE__'
$LogFile          = '__LOG_FILE__'
$IntuneFlag       = '__INTUNE_FLAG__'
$AdminGroupSID    = '__ADMIN_SID__'
$currentUser      = '__CURRENT_USER__'
$AdminsGroupName  = (New-Object System.Security.Principal.SecurityIdentifier $AdminGroupSID).Translate([System.Security.Principal.NTAccount]).Value -replace '^[^\\]+\\',''

function Get-AppEventSource {
    param([string]$Preferred)
    try {
        if ($Preferred -and [System.Diagnostics.EventLog]::SourceExists($Preferred)) { return $Preferred }
        $candidates = @('EventLog','MsiInstaller','Application Error','Windows Error Reporting','Windows PowerShell')
        foreach ($s in $candidates) { if ([System.Diagnostics.EventLog]::SourceExists($s)) { return $s } }
    } catch {}
    return $null
}

function Write-Log {
    param([string]$Message,[ValidateSet('Information','Warning','Error')] [string]$Type='Information',[int]$EventId=1006,[bool]$EV=$true)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($EV) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
                New-EventLog -LogName Application -Source $EventSource
            }
        } catch {}
        $src = Get-AppEventSource -Preferred $EventSource
        if ($null -ne $src) {
            try { Write-EventLog -LogName Application -Source $src -EventId $EventId -EntryType $Type -Message $Message } catch {}
        }
    }
}

Write-Log "=== Logoff removal start ===" "Information" 1006 $false

function Test-Membership {
    (Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $currentUser }) -ne $null
}

$isMember = Test-Membership
if (-not $isMember) {
    Write-Log "User $currentUser not in $AdminsGroupName, no removal needed (logoff trigger)." "Information" 1006 $false
    exit 0
}

try {
    net localgroup "$AdminsGroupName" "$currentUser" /delete | Out-Null
    $removed = -not (Test-Membership)
    if (-not $removed) {
        Remove-LocalGroupMember -Group $AdminsGroupName -Member $currentUser -ErrorAction SilentlyContinue
        $removed = -not (Test-Membership)
    }
    if ($removed) {
        Write-Log "Temporary admin rights removed from $currentUser on logoff (verified)." "Information" 1006 $true
    } else {
        Write-Log "WARNING: User still in $AdminsGroupName after logoff removal attempts." "Warning" 1010 $true
    }
} catch {
    Write-Log "ERROR: Exception during logoff removal: $($_.Exception.Message)" "Error" 1006 $true
}

# Clean up Intune flag
try { if (Test-Path $IntuneFlag) { Remove-Item -Force $IntuneFlag } } catch {}

Write-Log "=== Logoff removal end ===" "Information" 1006 $false
'@

$logoffTemplate = $logoffTemplate.Replace('__EVENT_SOURCE__', $EventSource)
$logoffTemplate = $logoffTemplate.Replace('__LOG_FILE__', $LogFile)
$logoffTemplate = $logoffTemplate.Replace('__INTUNE_FLAG__', $IntuneFlag)
$logoffTemplate = $logoffTemplate.Replace('__ADMIN_SID__', $AdminGroupSID)
$logoffTemplate = $logoffTemplate.Replace('__CURRENT_USER__', $currentUser)

$logoffTemplate | Out-File -FilePath $LogoffScriptPath -Encoding UTF8 -Force
Write-Log "Created $LogoffScriptPath"

# --- Build startup removal script (StartupRemove.ps1) ---
$StartupScriptPath = Join-Path $WorkFolder $StartupScript
$startupTemplate = @'
# Relaunch in 64-bit PowerShell if currently in 32-bit
if (-not [Environment]::Is64BitProcess) {
    $ps64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

# StartupRemove.ps1 - removal on system startup
$EventSource      = '__EVENT_SOURCE__'
$LogFile          = '__LOG_FILE__'
$IntuneFlag       = '__INTUNE_FLAG__'
$AdminGroupSID    = '__ADMIN_SID__'
$currentUser      = '__CURRENT_USER__'
$AdminsGroupName  = (New-Object System.Security.Principal.SecurityIdentifier $AdminGroupSID).Translate([System.Security.Principal.NTAccount]).Value -replace '^[^\\]+\\',''

function Get-AppEventSource {
    param([string]$Preferred)
    try {
        if ($Preferred -and [System.Diagnostics.EventLog]::SourceExists($Preferred)) { return $Preferred }
        $candidates = @('EventLog','MsiInstaller','Application Error','Windows Error Reporting','Windows PowerShell')
        foreach ($s in $candidates) { if ([System.Diagnostics.EventLog]::SourceExists($s)) { return $s } }
    } catch {}
    return $null
}

function Write-Log {
    param([string]$Message,[ValidateSet('Information','Warning','Error')] [string]$Type='Information',[int]$EventId=1006,[bool]$EV=$true)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    if ($EV) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
                New-EventLog -LogName Application -Source $EventSource
            }
        } catch {}
        $src = Get-AppEventSource -Preferred $EventSource
        if ($null -ne $src) {
            try { Write-EventLog -LogName Application -Source $src -EventId $EventId -EntryType $Type -Message $Message } catch {}
        }
    }
}

Write-Log "=== Startup removal start ===" "Information" 1006 $false

function Test-Membership {
    (Get-LocalGroupMember -Group $AdminsGroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $currentUser }) -ne $null
}

$isMember = Test-Membership
if (-not $isMember) {
    Write-Log "User $currentUser not in $AdminsGroupName, no removal needed (startup trigger)." "Information" 1006 $false
    exit 0
}

try {
    net localgroup "$AdminsGroupName" "$currentUser" /delete | Out-Null
    $removed = -not (Test-Membership)
    if (-not $removed) {
        Remove-LocalGroupMember -Group $AdminsGroupName -Member $currentUser -ErrorAction SilentlyContinue
        $removed = -not (Test-Membership)
    }
    if ($removed) {
        Write-Log "Temporary admin rights removed from $currentUser on startup (verified)." "Information" 1006 $true
    } else {
        Write-Log "WARNING: User still in $AdminsGroupName after startup removal attempts." "Warning" 1010 $true
    }
} catch {
    Write-Log "ERROR: Exception during startup removal: $($_.Exception.Message)" "Error" 1006 $true
}

# Clean up Intune flag
try { if (Test-Path $IntuneFlag) { Remove-Item -Force $IntuneFlag } } catch {}

Write-Log "=== Startup removal end ===" "Information" 1006 $false
'@

$startupTemplate = $startupTemplate.Replace('__EVENT_SOURCE__', $EventSource)
$startupTemplate = $startupTemplate.Replace('__LOG_FILE__', $LogFile)
$startupTemplate = $startupTemplate.Replace('__INTUNE_FLAG__', $IntuneFlag)
$startupTemplate = $startupTemplate.Replace('__ADMIN_SID__', $AdminGroupSID)
$startupTemplate = $startupTemplate.Replace('__CURRENT_USER__', $currentUser)

$startupTemplate | Out-File -FilePath $StartupScriptPath -Encoding UTF8 -Force
Write-Log "Created $StartupScriptPath"

# --- Cleanup script ---
$CleanupScriptPath = Join-Path $WorkFolder $CleanupScript
@'
Start-Sleep -Seconds 7
try {
  Remove-Item -Force "__SCAN_SCRIPT__" -ErrorAction SilentlyContinue
  Remove-Item -Force "__LOG_FILE__" -ErrorAction SilentlyContinue
} catch {}
'@.Replace('__SCAN_SCRIPT__', $ScanScriptPath).Replace('__LOG_FILE__', $LogFile) |
    Out-File -FilePath $CleanupScriptPath -Encoding UTF8 -Force
Write-Log "Created $CleanupScriptPath"

# --- Ensure Scheduler folder then schedule removal under \Microsoft\Windows\Chkdsk and hide it ---
Ensure-TaskFolderExists -Path $TaskPath

try {
    $startAt  = (Get-Date).AddMinutes($DurationMin)
    $action   = New-ScheduledTaskAction -Execute $PowerShellExe -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScanScriptPath`""
    $trigger  = New-ScheduledTaskTrigger -Once -At $startAt
    $principal= New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -Compatibility Win8 -AllowStartIfOnBatteries
    $task     = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings

    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -InputObject $task -Force | Out-Null

    # Hide the main task (best-effort)
    try {
        $taskObj = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        if ($taskObj) {
            $taskObj.Settings.Hidden = $true
            Set-ScheduledTask -InputObject $taskObj | Out-Null
        }
    } catch {
        Write-Log "WARNING: Could not set task hidden flag: $($_.Exception.Message)"
    }

    # Suppressed scheduling entry in Event Viewer by request (file log only)
    Write-Log "Scheduled removal task '$TaskName' under '$TaskPath'. Next run: $($startAt.ToString('yyyy-MM-dd HH:mm:ss'))." "Information" 1005 $false
} catch {
    Write-Log "ERROR: Failed to schedule removal task: $($_.Exception.Message)" "Error" 1005 $true
}

# --- Schedule logoff trigger task (using COM object for event-based trigger) ---
try {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()

    # Get or create the task folder
    try {
        $folder = $svc.GetFolder($TaskPath)
    } catch {
        $rootFolder = $svc.GetFolder("\")
        $folder = $rootFolder.CreateFolder($TaskPath.TrimStart("\"))
    }

    # Create task definition
    $taskDef = $svc.NewTask(0)
    $taskDef.RegistrationInfo.Description = "Remove temporary admin rights on user logoff"
    $taskDef.Settings.Enabled = $true
    $taskDef.Settings.Hidden = $true
    $taskDef.Settings.AllowDemandStart = $true
    $taskDef.Settings.StartWhenAvailable = $true
    $taskDef.Settings.DisallowStartIfOnBatteries = $false
    $taskDef.Settings.StopIfGoingOnBatteries = $false

    # Event trigger for logoff (Security log, Event ID 4634 for logoff, or use System log Event ID 7002 for user logoff notification)
    # Using Microsoft-Windows-Winlogon/Operational with event ID 7002 (user logoff notification)
    $trigger = $taskDef.Triggers.Create(0)  # 0 = TASK_TRIGGER_EVENT
    $trigger.Enabled = $true
    # Event subscription for logoff - using System log's User32 source with EventID 1074 or Winlogon
    # More reliable: use Microsoft-Windows-Security-Auditing for logoff events
    $trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Winlogon'] and (EventID=7002)]]</Select>
  </Query>
</QueryList>
"@

    # Action
    $action = $taskDef.Actions.Create(0)  # 0 = TASK_ACTION_EXEC
    $action.Path = $PowerShellExe
    $action.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$LogoffScriptPath`""

    # Principal (run as SYSTEM with highest privileges)
    $taskDef.Principal.UserId = "S-1-5-18"  # SYSTEM SID
    $taskDef.Principal.RunLevel = 1  # 1 = TASK_RUNLEVEL_HIGHEST

    # Register the task (6 = TASK_CREATE_OR_UPDATE)
    $folder.RegisterTaskDefinition($LogoffTaskName, $taskDef, 6, $null, $null, 5) | Out-Null  # 5 = TASK_LOGON_SERVICE_ACCOUNT

    Write-Log "Scheduled logoff removal task '$LogoffTaskName' under '$TaskPath'." "Information" 1005 $false
} catch {
    Write-Log "WARNING: Failed to schedule logoff trigger task: $($_.Exception.Message)" "Warning" 1010 $false
}

# --- Schedule startup trigger task ---
try {
    $startupAction   = New-ScheduledTaskAction -Execute $PowerShellExe -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$StartupScriptPath`""
    $startupTrigger  = New-ScheduledTaskTrigger -AtStartup
    $startupPrincipal= New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $startupSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -Compatibility Win8 -AllowStartIfOnBatteries
    $startupTask     = New-ScheduledTask -Action $startupAction -Principal $startupPrincipal -Trigger $startupTrigger -Settings $startupSettings

    Register-ScheduledTask -TaskName $StartupTaskName -TaskPath $TaskPath -InputObject $startupTask -Force | Out-Null

    # Hide the startup task (best-effort)
    try {
        $startupTaskObj = Get-ScheduledTask -TaskPath $TaskPath -TaskName $StartupTaskName -ErrorAction Stop
        if ($startupTaskObj) {
            $startupTaskObj.Settings.Hidden = $true
            Set-ScheduledTask -InputObject $startupTaskObj | Out-Null
        }
    } catch {
        Write-Log "WARNING: Could not set startup task hidden flag: $($_.Exception.Message)"
    }

    Write-Log "Scheduled startup removal task '$StartupTaskName' under '$TaskPath'." "Information" 1005 $false
} catch {
    Write-Log "WARNING: Failed to schedule startup trigger task: $($_.Exception.Message)" "Warning" 1010 $false
}

# --- User notification (best-effort) ---
$expires = (Get-Date).AddMinutes($DurationMin).ToString('HH:mm')
try {
    $shell = New-Object -ComObject WScript.Shell
    $shell.Popup("Temporary admin rights granted until $expires (sign-out needed to drop existing token).", 7, "Temporary Admin Granted", 64)
} catch {}

Write-Log "=== End AddTempAdminRights_v1.4 ==="