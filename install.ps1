#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the runner Windows Tier-3 binary (no admin required).
.EXAMPLE
  irm https://raw.githubusercontent.com/runnerhq/runner/main/install.ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$repo = 'runnerhq/runner'
$tag = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
$dir = Join-Path $env:LOCALAPPDATA 'runner'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'runner.exe'
Invoke-WebRequest "https://github.com/$repo/releases/download/$tag/runner-windows-x86_64.exe" -OutFile $exe
# Fetch the sidecar to a file: `.Content` is a byte array (not a
# string) when the response content-type isn't text, and `[byte]`
# has no `.Split` (PowerShell 7 member enumeration fails loudly).
$shaFile = Join-Path $dir 'runner.exe.sha256'
Invoke-WebRequest "https://github.com/$repo/releases/download/$tag/runner-windows-x86_64.exe.sha256" -OutFile $shaFile
$want = (Get-Content $shaFile -Raw).Split()[0]
$got = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($got -ne $want.ToLower()) { throw "SHA-256 mismatch for runner.exe" }
$path = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($path -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable('PATH', "$path;$dir", 'User')
}
Write-Output 'runner installed. Please restart your terminal.'
