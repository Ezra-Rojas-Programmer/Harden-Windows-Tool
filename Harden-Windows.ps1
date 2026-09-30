# Harden-Windows.ps1
# IS2083 Advanced Scripting - Lab 2: Windows Hardening Tool
#
# Audits a Windows 11 machine against a slice of the Microsoft Security Baseline,
# plus a group of "Advanced hardening" controls that go beyond the baseline.
#
#   .\Harden-Windows.ps1                # Audit only: reads settings, changes nothing
#   .\Harden-Windows.ps1 -Mode Apply    # Audit, fix what is failing, audit again (practice VM only)
#
# Each control is one New-Check call with four parts, in this order:
#   1. category and name
#   2. TEST block        (first  { } ) reads the setting, returns @{ Pass = ...; Detail = ... }
#   3. REMEDIATE block   (second { } ) fixes the setting; $null means audit only
#   4. weight            (points toward the security score)
#
# Portions of this script were assisted with AI ( Claude & Microsoft Copilot )

param(
    [ValidateSet('Audit','Apply')]
    [string]$Mode = 'Audit'
)

# ======================= SET YOUR TOOL NAME HERE =======================
$ToolName = 'WinGuard'
# =======================================================================

# Category labels used in the code and the report.
$BASELINE = 'Microsoft Security Baseline'
$ADVANCED = 'Advanced hardening'

# The list every New-Check call registers into.
$script:Checks = @()

# ---------- Helper: are we running as Administrator? (done for you) ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- Helper: show a pop-up, fall back to the console (done for you) ----------
function Show-Popup {
    param([string]$Message, [string]$Title)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title)
    } catch {
        Write-Host ('[' + $Title + '] ' + $Message) -ForegroundColor Magenta
    }
}

# ---------- Helper: rate a score (done for you) ----------
function Get-Rating {
    param([int]$Score)
    if ($Score -ge 85)      { return 'STRONG' }
    elseif ($Score -ge 60)  { return 'MODERATE' }
    else                    { return 'NEEDS WORK' }
}

# ---------- Register one control (done for you) ----------
# Usage:  New-Check <Category> '<Name>' { Test returns @{Pass=..;Detail=..} } { Remediate } <Weight>
# Pass $null for the Remediate block to make a control audit only.
function New-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Remediate,
        [int]$Weight = 10
    )
    $script:Checks += [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Test      = $Test
        Remediate = $Remediate
        Weight    = $Weight
    }
}

# ---------- Helper: read one number from "net accounts" ----------
# net accounts prints lines like "Minimum password length:      14".
# This finds the line that contains $Label and returns the last word on it as a number.
# "Never" (used for lockout threshold 0) is returned as 0. Returns $null if not found.
function Get-NetAccountsNumber {
    param([string]$Label)
    $line = net accounts | Where-Object { $_ -match $Label } | Select-Object -First 1
    if (-not $line) { return $null }
    $last = ($line.Trim() -split '\s+')[-1]
    if ($last -eq 'Never') { return 0 }
    $n = 0
    if ([int]::TryParse($last, [ref]$n)) { return $n }
    return $null
}

# =======================================================================
#  Microsoft Security Baseline controls  (category: $BASELINE)
# =======================================================================

# SMBv1 disabled  (DONE: finished example, copy this shape)
New-Check $BASELINE 'SMBv1 disabled' {                 # TEST block starts here
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool](-not $c.EnableSMB1Protocol); Detail = "EnableSMB1Protocol=$($c.EnableSMB1Protocol)" }
} {                                                    # TEST ends, REMEDIATE starts
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
} 10                                                   # REMEDIATE ends, weight 10

# SMB server signing required  (DONE: the worked example in handout Part B)
New-Check $BASELINE 'SMB server signing required' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
} {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
} 10

# NTLM hardened: refuse LM and NTLMv1 (LmCompatibilityLevel 5 = NTLMv2 only)
New-Check $BASELINE 'NTLM hardened (LmCompatibilityLevel = 5)' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = [bool]($v -eq 5); Detail = "LmCompatibilityLevel=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
} 10

# UAC enabled
New-Check $BASELINE 'User Account Control (UAC) enabled' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = [bool]($v -eq 1); Detail = "EnableLUA=$shown" }
} {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord
} 10

# Minimum password length 14 or more
New-Check $BASELINE 'Minimum password length 14 or more' {
    $n = Get-NetAccountsNumber 'Minimum password length'
    @{ Pass = [bool]($null -ne $n -and $n -ge 14); Detail = "MinimumPasswordLength=$n" }
} {
    net accounts /minpwlen:14 | Out-Null
} 10

# Account lockout threshold 1 to 10 (0 / Never fails)
New-Check $BASELINE 'Account lockout threshold 1 to 10' {
    $n = Get-NetAccountsNumber 'Lockout threshold'
    @{ Pass = [bool]($null -ne $n -and $n -ge 1 -and $n -le 10); Detail = "LockoutThreshold=$n (0 means Never)" }
} {
    net accounts /lockoutthreshold:10 | Out-Null
} 10

# Firewall enabled on Domain, Private and Public profiles
New-Check $BASELINE 'Firewall enabled on all profiles' {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' })
    $detail = ($profiles | ForEach-Object { $_.Name + '=' + $_.Enabled }) -join ', '
    @{ Pass = [bool]($off.Count -eq 0); Detail = $detail }
} {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
} 10

# Defender real-time protection on
New-Check $BASELINE 'Defender real-time protection on' {
    $p = Get-MpPreference -ErrorAction Stop
    @{ Pass = [bool]($p.DisableRealtimeMonitoring -eq $false); Detail = "DisableRealtimeMonitoring=$($p.DisableRealtimeMonitoring)" }
} {
    Set-MpPreference -DisableRealtimeMonitoring $false
} 10

# Guest account disabled
New-Check $BASELINE 'Guest account disabled' {
    $g = Get-LocalUser -Name Guest -ErrorAction Stop
    @{ Pass = [bool](-not $g.Enabled); Detail = "Guest Enabled=$($g.Enabled)" }
} {
    Disable-LocalUser -Name Guest
} 10

# RDP requires Network Level Authentication
New-Check $BASELINE 'RDP requires Network Level Authentication' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = [bool]($v -eq 1); Detail = "UserAuthentication=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord
} 10

# =======================================================================
#  Advanced controls (beyond the baseline)  (category: $ADVANCED)
# =======================================================================

# Defender PUA (potentially unwanted application) protection
New-Check $ADVANCED 'Defender PUA protection on' {
    $p = Get-MpPreference -ErrorAction Stop
    @{ Pass = [bool]($p.PUAProtection -eq 1); Detail = "PUAProtection=$($p.PUAProtection)" }
} {
    Set-MpPreference -PUAProtection 1
} 8

# ASR rule: block Office applications from creating child processes
# Get-MpPreference gives two matching lists: rule ids and rule actions. The action
# at the same position as our id is what we want (1 = Block).
New-Check $ADVANCED 'ASR: block Office child processes' {
    $ruleId = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
    $p = Get-MpPreference -ErrorAction Stop
    $ids = @($p.AttackSurfaceReductionRules_Ids)
    $actions = @($p.AttackSurfaceReductionRules_Actions)
    $pos = -1
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i] -eq $ruleId) { $pos = $i; break }
    }
    if ($pos -ge 0) { $action = $actions[$pos] } else { $action = 'rule not configured' }
    @{ Pass = [bool]($pos -ge 0 -and $action -eq 1); Detail = "ASR action=$action" }
} {
    Add-MpPreference -AttackSurfaceReductionRules_Ids 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' -AttackSurfaceReductionRules_Actions Enabled
} 8

# PowerShell script block logging
New-Check $ADVANCED 'PowerShell script block logging on' {
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $v = (Get-ItemProperty $path -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = [bool]($v -eq 1); Detail = "EnableScriptBlockLogging=$shown" }
} {
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name EnableScriptBlockLogging -Value 1 -Type DWord
} 8

# LSA protection (RunAsPPL) - takes effect after a reboot
New-Check $ADVANCED 'LSA protection (RunAsPPL) on' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    if ($null -eq $v) { $shown = 'not set' } else { $shown = $v }
    @{ Pass = [bool]($v -eq 1); Detail = "RunAsPPL=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
} 8

# BitLocker on the system drive - AUDIT ONLY (no remediate block, on purpose)
# Turn it on yourself with:  manage-bde -on $env:SystemDrive
New-Check $ADVANCED 'BitLocker on system drive' {
    $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    @{ Pass = [bool]([string]$v.ProtectionStatus -eq 'On'); Detail = "ProtectionStatus=$($v.ProtectionStatus)" }
} $null 6

# =======================================================================
#  Engine (done for you): audit, apply, report
# =======================================================================

# Run every check, print a grouped report, compute the weighted score.
function Invoke-Audit {
    param([string]$Label = '')

    $results = @()
    foreach ($c in $script:Checks) {
        try {
            $r = & $c.Test
        } catch {
            $r = @{ Pass = $false; Detail = ('error: ' + $_.Exception.Message) }
        }
        $results += [pscustomobject]@{
            Category = $c.Category
            Name     = $c.Name
            Pass     = [bool]$r.Pass
            Detail   = [string]$r.Detail
            Weight   = [int]$c.Weight
        }
    }

    $total  = ($script:Checks | Measure-Object -Property Weight -Sum).Sum
    $earned = (@($results | Where-Object { $_.Pass }) | Measure-Object -Property Weight -Sum).Sum
    if (-not $total)  { $total  = 1 }
    if (-not $earned) { $earned = 0 }
    $score  = [math]::Round(($earned / $total) * 100)
    $rating = Get-Rating -Score $score

    $header = '=== Windows Security Audit ==='
    if ($Label) { $header = $header + '  [' + $Label + ']' }
    Write-Host ''
    Write-Host $header -ForegroundColor Cyan

    foreach ($cat in @($BASELINE, $ADVANCED)) {
        $catResults = @($results | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }
        $catPass = @($catResults | Where-Object { $_.Pass }).Count
        Write-Host ''
        Write-Host ('-- ' + $cat + '  (' + $catPass + ' of ' + $catResults.Count + ' passing) --') -ForegroundColor White
        foreach ($x in $catResults) {
            if ($x.Pass) {
                Write-Host ('  [PASS] ' + $x.Name) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] ' + $x.Name + '  ->  ' + $x.Detail) -ForegroundColor Red
            }
        }
    }

    Write-Host ''
    Write-Host ('Security score: ' + $score + ' / 100   (' + $rating + ')') -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]@{
        Label   = $Label
        Results = $results
        Earned  = $earned
        Total   = $total
        Score   = $score
        Rating  = $rating
    }
}

# Make a restore point, then remediate every failing control that has a fix.
function Invoke-Apply {
    $actions = @()

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description ('Before ' + $ToolName + ' hardening') -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $actions += 'Created a System Restore Point (your undo button).'
    } catch {
        $actions += 'Could not create a restore point (it may be off or rate limited). Continuing.'
    }

    foreach ($c in $script:Checks) {
        if ($null -eq $c.Remediate) { continue }        # audit-only control
        try { $r = & $c.Test } catch { $r = @{ Pass = $false } }
        if ([bool]$r.Pass) { continue }                 # already passing
        try {
            & $c.Remediate
            $note = 'Remediated: ' + $c.Name
            if ($c.Name -match 'UAC' -or $c.Name -match 'LSA') {
                $note = $note + '   (reboot required to take effect)'
            }
            $actions += $note
        } catch {
            $actions += ('Remediation failed: ' + $c.Name + '  ->  ' + $_.Exception.Message)
        }
    }

    return $actions
}

# Write a timestamped, grouped report and return its path.
function Write-Report {
    param([array]$Summaries, [array]$Actions)

    $dir = Join-Path $env:USERPROFILE ($ToolName + '_reports')
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path  = Join-Path $dir ($ToolName + '_report_' + $stamp + '.txt')

    $lines = @()
    $lines += ($ToolName + ' Security Report')
    $lines += ('Generated: ' + (Get-Date))
    $lines += ('Computer:  ' + $env:COMPUTERNAME)
    $lines += ''

    foreach ($s in $Summaries) {
        $title = 'AUDIT'
        if ($s.Label) { $title = $s.Label }
        $lines += ('===== ' + $title + ' =====')
        foreach ($cat in @($BASELINE, $ADVANCED)) {
            $cr = @($s.Results | Where-Object { $_.Category -eq $cat })
            if ($cr.Count -eq 0) { continue }
            $cp = @($cr | Where-Object { $_.Pass }).Count
            $lines += ''
            $lines += ('-- ' + $cat + '  (' + $cp + ' of ' + $cr.Count + ' passing) --')
            foreach ($x in $cr) {
                $flag = '[FAIL]'
                if ($x.Pass) { $flag = '[PASS]' }
                $lines += ('  ' + $flag + ' ' + $x.Name + '  ->  ' + $x.Detail)
            }
        }
        $lines += ''
        $lines += ('Security score: ' + $s.Score + ' / 100  (' + $s.Rating + ')')
        $lines += ''
    }

    if ($Actions -and $Actions.Count -gt 0) {
        $lines += '===== Applying hardening ====='
        foreach ($a in $Actions) { $lines += ('  ' + $a) }
        $lines += ''
    }

    $lines | Out-File -FilePath $path -Encoding UTF8
    return $path
}

# =======================================================================
#  Main (done for you)
# =======================================================================

Write-Host ($ToolName + ' Windows Hardening Toolkit') -ForegroundColor Cyan
Show-Popup ($ToolName + ' is starting a security ' + $Mode + '.') ($ToolName + ' starting')

$elevated = Test-Admin
if (-not $elevated) {
    Write-Host 'Note: you are NOT running as Administrator.' -ForegroundColor Yellow
    Write-Host 'Audit will run, but some checks and all fixes need Administrator.' -ForegroundColor Yellow
}

if ($Mode -eq 'Apply') {
    if (-not $elevated) {
        Write-Host 'Apply mode needs Administrator. Re-open PowerShell as administrator and run again with -Mode Apply.' -ForegroundColor Red
        Show-Popup 'Apply mode needs Administrator. Re-run in an elevated PowerShell.' ($ToolName + ' stopped')
        return
    }

    $before = Invoke-Audit -Label 'BEFORE'

    Write-Host '=== Applying safe hardening fixes ===' -ForegroundColor Cyan
    $actions = Invoke-Apply
    foreach ($a in $actions) { Write-Host ('  ' + $a) -ForegroundColor Green }

    $after = Invoke-Audit -Label 'AFTER'

    $report = Write-Report -Summaries @($before, $after) -Actions $actions
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' apply complete.  Before ' + $before.Score + ' / 100,  After ' + $after.Score + ' / 100  (' + $after.Rating + ')') ($ToolName + ' complete')
}
else {
    $audit = Invoke-Audit

    $report = Write-Report -Summaries @($audit) -Actions @()
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' audit complete.  Score ' + $audit.Score + ' / 100  (' + $audit.Rating + ')') ($ToolName + ' complete')
}
