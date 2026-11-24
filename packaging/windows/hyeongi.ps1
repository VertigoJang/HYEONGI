<#
    hyeongi.ps1 — HYEONGI launcher for Windows (banner, menu, commands).
    Usually started from the Start Menu shortcut or .\hyeongi.cmd in the repo.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Data = Join-Path $env:ProgramData 'HYEONGI'
Set-Location $Root

function Get-Python {
    $saved = Join-Path $Data 'python.txt'
    if (Test-Path $saved) { return (Get-Content $saved -TotalCount 1).Trim() }
    if (Get-Command py.exe -ErrorAction SilentlyContinue) { return 'py.exe' }
    return 'python.exe'
}
$Py = Get-Python

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Need-Admin {
    if (-not (Test-Admin)) {
        Write-Host '! this command changes the firewall or HYEONGI data; run PowerShell as administrator.' -ForegroundColor Red
        exit 1
    }
}

function Show-Banner {
    $ver = (Select-String -Path (Join-Path $Root 'hyeongi\__init__.py') -Pattern '__version__ = "(.*)"').Matches[0].Groups[1].Value
    $lines = @(
        '██╗  ██╗██╗   ██╗███████╗ ██████╗ ███╗   ██╗ ██████╗ ██╗',
        '██║  ██║╚██╗ ██╔╝██╔════╝██╔═══██╗████╗  ██║██╔════╝ ██║',
        '███████║ ╚████╔╝ █████╗  ██║   ██║██╔██╗ ██║██║  ███╗██║',
        '██╔══██║  ╚██╔╝  ██╔══╝  ██║   ██║██║╚██╗██║██║   ██║██║',
        '██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║╚██████╔╝██║',
        '╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝'
    )
    Write-Host ''
    foreach ($l in $lines) {
        Write-Host (' ' + $l) -ForegroundColor White
    }
    Write-Host ' Host-based, Your-network-gated Enforcement' -ForegroundColor Red
    Write-Host ' with On-device Network Guard & Inspection' -ForegroundColor Red
    Write-Host ''
    $left = "   v$ver"; $right = "by VertigoJang · github.com/VertigoJang"
    Write-Host ($left + (' ' * [Math]::Max(2, 57 - $left.Length - $right.Length)) + $right) -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Menu {
    Show-Banner
    Write-Host '  USAGE   hyeongi <command> [options]' -ForegroundColor White
    Write-Host ''
    Write-Host '  ENFORCEMENT  (Windows Defender Firewall, group "HYEONGI")' -ForegroundColor White
    Write-Host '    status            show the live blocklist'
    Write-Host '    block <ip>        block an IP  (--timeout 1h)            (admin)'
    Write-Host '    unblock <ip>      remove a block                         (admin)'
    Write-Host '    flush             remove all blocks                      (admin)'
    Write-Host ''
    Write-Host '  DAEMON (hyeongid)' -ForegroundColor White
    Write-Host '    services          hyeongid / Suricata task state, enforce, backend'
    Write-Host '    logs              follow the hyeongid log (Ctrl+C to quit)'
    Write-Host '    restart           restart hyeongid (after editing the config) (admin)'
    Write-Host '    report            run the LLM triage now and show it     (admin)'
    Write-Host '    pause / resume    stop / restart training-data logging  (admin)'
    Write-Host '    gui               open the desktop app                   (asks for admin)'
    Write-Host '    stats             collection and detection summary'
    Write-Host '    config            print the effective config'
    Write-Host ''
    Write-Host '  MODEL' -ForegroundColor White
    Write-Host '    dataset ...       ml.make_dataset  (e.g. --flows "C:/ProgramData/HYEONGI/flows/*.csv" --label 0)'
    Write-Host '    train ...         ml.train'
    Write-Host '    eval ...          ml.eval'
    Write-Host ''
    Write-Host '  Detectors default to dry-run (enforce: false). Enforcement is never automatic.' -ForegroundColor DarkGray
    Write-Host ''
}

switch ($Command.ToLower()) {
    { $_ -in 'help', '-h', '--help' } { Show-Menu }
    { $_ -in 'version', '-v', '--version' } { Show-Banner }
    'status'   { & $Py -m hyeongi.blocklist list @Rest }
    'block'    { Need-Admin; & $Py -m hyeongi.blocklist add @Rest }
    'unblock'  { Need-Admin; & $Py -m hyeongi.blocklist remove @Rest }
    'flush'    { Need-Admin; & $Py -m hyeongi.blocklist flush }
    'services' {
        foreach ($t in 'hyeongid', 'hyeongi-suricata') {
            $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            $state = if ($task) { $task.State } else { 'not installed' }
            '  {0,-18} {1}' -f $t, $state
        }
        $cfg = & $Py -m hyeongi.service show 2>$null
        '  {0,-18} {1}' -f 'enforce', (($cfg | Select-String '^enforce: (.*)').Matches.Groups[1].Value)
        '  {0,-18} {1}' -f 'backend', (($cfg | Select-String '^backend: (.*)').Matches.Groups[1].Value)
        '  {0,-18} {1}' -f 'firewall rules', @(Get-NetFirewallRule -Group 'HYEONGI' -ErrorAction SilentlyContinue).Count
    }
    'logs'     { Get-Content (Join-Path $Data 'logs\hyeongid.log') -Tail 30 -Wait }
    'restart'  {
        Need-Admin
        $all = Get-CimInstance Win32_Process
        $daemon = $all | Where-Object { $_.CommandLine -match 'hyeongi\.daemon' }
        foreach ($a in $daemon) {
            $all | Where-Object { $_.ParentProcessId -eq $a.ProcessId } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        }
        Stop-ScheduledTask -TaskName 'hyeongid' -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName 'hyeongid'
        Write-Host 'hyeongid restarted' -ForegroundColor Green
    }
    'report'   {
        Need-Admin
        & $Py -m hyeongi.service triage
        $out = Join-Path $Data 'triage\report.txt'
        if (Test-Path $out) { Get-Content $out -Encoding UTF8 }
    }
    'gui'      {
        $pyw = Join-Path (Split-Path $Py) 'pythonw.exe'
        if (-not (Test-Path $pyw)) { $pyw = $Py }
        Start-Process -FilePath $pyw -ArgumentList '-m', 'hyeongi.gui' -WorkingDirectory $Root -Verb RunAs
    }
    'stats'    { & $Py -m hyeongi.status @Rest }
    'pause'    { Need-Admin; & $Py -m hyeongi.collect pause @Rest }
    'resume'   { Need-Admin; & $Py -m hyeongi.collect resume }
    'config'   { & $Py -m hyeongi.service show }
    'dataset'  { & $Py -m ml.make_dataset @Rest }
    'train'    { & $Py -m ml.train @Rest }
    'eval'     { & $Py -m ml.eval @Rest }
    default    {
        Write-Host "unknown command: $Command" -ForegroundColor Red
        Show-Menu
        exit 2
    }
}
