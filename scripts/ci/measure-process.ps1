[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Command
)

$ErrorActionPreference = 'Stop'
$metricsDirectory = Join-Path (Get-Location) 'target\ci-metrics'
New-Item -ItemType Directory -Force -Path $metricsDirectory | Out-Null
$runnerTemp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$batchPath = Join-Path $runnerTemp ("akrat-measured-{0}.cmd" -f [guid]::NewGuid().ToString('N'))
try {
    # Passing a long command containing nested quotes through Start-Process and
    # cmd /c loses its quoting. Put it in a batch file so && and quoted paths
    # reach cmd unchanged, and propagate the real command exit code.
    $batchContents = "@echo off`r`n$Command`r`nexit /b %errorlevel%`r`n"
    [IO.File]::WriteAllText($batchPath, $batchContents, [Text.Encoding]::ASCII)
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $env:ComSpec
    $startInfo.Arguments = '/d /c call "' + $batchPath + '"'
    $startInfo.UseShellExecute = $false
    $buildProcess = [Diagnostics.Process]::Start($startInfo)
} catch {
    Remove-Item -LiteralPath $batchPath -Force -ErrorAction SilentlyContinue
    throw
}
$rootProcessId = [int]$buildProcess.Id
$started = [Diagnostics.Stopwatch]::StartNew()
$peakTreeWorkingSet = [int64]0
$minimumAvailableBytes = [int64]::MaxValue
$cpu100nsByPid = @{}
$readBytesByPid = @{}
$writeBytesByPid = @{}

while (-not $buildProcess.HasExited) {
    $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, WorkingSetSize, KernelModeTime, UserModeTime, ReadTransferCount, WriteTransferCount)
    $byParent = @{}
    foreach ($item in $all) {
        $parent = [string]$item.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = [System.Collections.Generic.List[object]]::new() }
        $byParent[$parent].Add($item)
    }

    $pids = [System.Collections.Generic.HashSet[int]]::new()
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $pending.Enqueue($rootProcessId)
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        if (-not $pids.Add($current)) { continue }
        $children = $byParent[[string]$current]
        foreach ($child in $children) { $pending.Enqueue([int]$child.ProcessId) }
    }

    $treeWorkingSet = [int64]0
    foreach ($item in $all) {
        $processId = [int]$item.ProcessId
        if (-not $pids.Contains($processId)) { continue }
        $treeWorkingSet += [int64]$item.WorkingSetSize
        $cpu100nsByPid[$processId] = [Math]::Max([int64]$cpu100nsByPid[$processId], [int64]$item.KernelModeTime + [int64]$item.UserModeTime)
        $readBytesByPid[$processId] = [Math]::Max([int64]$readBytesByPid[$processId], [int64]$item.ReadTransferCount)
        $writeBytesByPid[$processId] = [Math]::Max([int64]$writeBytesByPid[$processId], [int64]$item.WriteTransferCount)
    }
    $peakTreeWorkingSet = [Math]::Max($peakTreeWorkingSet, $treeWorkingSet)

    $os = Get-CimInstance Win32_OperatingSystem -Property FreePhysicalMemory
    $availableBytes = [int64]$os.FreePhysicalMemory * 1024
    $minimumAvailableBytes = [Math]::Min($minimumAvailableBytes, $availableBytes)
    Start-Sleep -Milliseconds 1000
    $buildProcess.Refresh()
}

$buildProcess.WaitForExit()
$buildProcess.Refresh()
$exitCode = [int]$buildProcess.ExitCode
$started.Stop()
$metrics = [ordered]@{
    name = $Name
    platform = 'windows'
    exit_code = $exitCode
    duration_seconds = [Math]::Round($started.Elapsed.TotalSeconds, 3)
    peak_process_tree_working_set_bytes = $peakTreeWorkingSet
    minimum_host_available_memory_bytes = $minimumAvailableBytes
    process_tree_cpu_seconds = [Math]::Round((($cpu100nsByPid.Values | Measure-Object -Sum).Sum / 10000000), 3)
    process_tree_read_bytes = ($readBytesByPid.Values | Measure-Object -Sum).Sum
    process_tree_write_bytes = ($writeBytesByPid.Values | Measure-Object -Sum).Sum
    sample_interval_seconds = 1
    metric_scope = 'descendants of launched command; 1-second sampling'
}
$output = Join-Path $metricsDirectory "$Name.json"
$metrics | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $output -Encoding utf8
$metrics | ConvertTo-Json -Depth 4 | Write-Output
Remove-Item -LiteralPath $batchPath -Force -ErrorAction SilentlyContinue
if ($exitCode -ne 0) { throw "Measured build command failed with exit code $exitCode." }
