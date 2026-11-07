# psnet benchmark: drives the real binary in a private psmux server and
# measures what a user feels.
#
#   startup_ms    launch until the first frame shows the tab bar
#   key_ms        Tab press until the screen changes (median of 5 per run)
#   idle_cpu_pct  CPU over 10 s of idle, as a percent of one core
#   ws_mb / priv_mb  working set and private bytes after the idle window
#   quit_ms       'q' until the process is gone (issue #12; 10000 = hung)
#
# Usage:
#   pwsh bench/bench.ps1 -Exe target\release\psnet.exe -Label after -Runs 5
# Results are appended as CSV to $HOME\psmux-bench\psnet\<date>\results.csv.
# Run it elevated to include the packet sniffer, which is where #12 lived.
param(
    [Parameter(Mandatory)] [string]$Exe,
    [string]$Label = "run",
    [int]$Runs = 5,
    [string]$OutDir = (Join-Path $HOME "psmux-bench\psnet\$(Get-Date -Format yyyy-MM-dd)")
)

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
$server = "test-psnet-bench"
$session = "bench"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$csv = Join-Path $OutDir "results.csv"

function Mux { psmux -L $server @args }
function Screen { (Mux capture-pane -t $session -p) -join "`n" }

function Wait-Until([scriptblock]$cond, [int]$timeoutMs) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        if (& $cond) { return $sw.ElapsedMilliseconds }
        Start-Sleep -Milliseconds 15
    }
    return -1
}

function Get-Psnet {
    Get-Process psnet -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe }
}

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

Mux new-session -d -s $session -x 200 -y 50
try {
    for ($i = 1; $i -le $Runs; $i++) {
        Mux send-keys -t $session "cls" Enter
        Start-Sleep -Milliseconds 500

        # Startup: the tab bar ("Alerts" and "Networks" tabs) is in the first frame.
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Mux send-keys -t $session "& '$Exe'" Enter
        $null = Wait-Until { $s = Screen; $s -match 'Alerts' -and $s -match 'Networks' } 15000
        $startup = $sw.ElapsedMilliseconds
        $proc = $null
        $null = Wait-Until { $script:proc = Get-Psnet; $null -ne $script:proc } 5000

        # Let the deferred init settle, then measure idle CPU.
        Start-Sleep -Seconds 5
        $proc.Refresh(); $cpu0 = $proc.TotalProcessorTime.TotalMilliseconds
        $t0 = [Diagnostics.Stopwatch]::StartNew()
        Start-Sleep -Seconds 10
        $proc.Refresh(); $cpu1 = $proc.TotalProcessorTime.TotalMilliseconds
        $idleCpu = [math]::Round(100 * ($cpu1 - $cpu0) / $t0.ElapsedMilliseconds, 2)
        $ws = [math]::Round($proc.WorkingSet64 / 1MB, 1)
        $priv = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)

        # Keystroke to screen: Tab switches tabs, so the frame must change.
        $keys = @()
        for ($k = 0; $k -lt 5; $k++) {
            $before = Screen
            $sw = [Diagnostics.Stopwatch]::StartNew()
            Mux send-keys -t $session Tab
            $null = Wait-Until { (Screen) -ne $before } 5000
            $keys += $sw.ElapsedMilliseconds
            Start-Sleep -Milliseconds 400
        }
        $keyMs = ($keys | Sort-Object)[2]

        # Quit: 'q' until the process has exited.
        Mux send-keys -t $session Escape
        Start-Sleep -Milliseconds 200
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Mux send-keys -t $session q
        $gone = Wait-Until { $proc.Refresh(); $proc.HasExited } 10000
        $quitMs = if ($gone -lt 0) { 10000 } else { $sw.ElapsedMilliseconds }
        if (-not $proc.HasExited) {
            Write-Warning "psnet did not exit within 10 s (the #12 hang); killing it"
            Stop-Process -Id $proc.Id -Force
        }

        $row = [pscustomobject]@{
            timestamp    = (Get-Date -Format o)
            label        = $Label
            exe          = $Exe
            elevated     = $elevated
            run          = $i
            startup_ms   = $startup
            key_ms       = $keyMs
            idle_cpu_pct = $idleCpu
            ws_mb        = $ws
            priv_mb      = $priv
            quit_ms      = $quitMs
        }
        $row | Export-Csv -Path $csv -Append -NoTypeInformation
        $row | Format-Table -AutoSize | Out-String | Write-Host
        Start-Sleep -Seconds 1
    }
}
finally {
    Get-Psnet | Stop-Process -Force -ErrorAction SilentlyContinue
    Mux kill-server
}
Write-Host "results: $csv"
