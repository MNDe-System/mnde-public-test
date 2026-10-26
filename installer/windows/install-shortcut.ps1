# Creates the "MNDe" desktop shortcut. Safe to re-run: it only rewrites MNDe.lnk.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File installer\windows\install-shortcut.ps1
#
# The shortcut runs node.exe on installer\windows\mnde-launch.mjs (minimized), with the
# repo as its working directory. Paths are resolved to absolute locations now, so it works
# from any directory. If you move the repo or upgrade/relocate Node, re-run this script.
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$launcher = Join-Path $repo 'installer\windows\mnde-launch.mjs'
$icon = Join-Path $repo 'installer\windows\mnde.ico'
foreach ($p in @($launcher, $icon)) { if (-not (Test-Path $p)) { throw "Missing $p" } }

$node = (Get-Command node.exe -ErrorAction Stop).Source
$major = [int](& $node -p 'process.versions.node.split(".")[0]')
if ($major -lt 24) { throw "Node.js 24 or later is required (found $major). Install it, then re-run." }

# Resolves the real Desktop, including a OneDrive-redirected one.
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop 'MNDe.lnk'

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($lnkPath)
$lnk.TargetPath = $node
$lnk.Arguments = '"' + $launcher + '"'
$lnk.WorkingDirectory = $repo
$lnk.IconLocation = $icon
$lnk.WindowStyle = 7   # minimized
$lnk.Description = 'Start MNDe (if needed) and open the dashboard'
$lnk.Save()

Write-Host "Created $lnkPath"
Write-Host "  target : $node `"$launcher`""
Write-Host "  icon   : $icon"
