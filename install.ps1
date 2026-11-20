#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the runner Windows Tier-3 binary (no admin required).
.EXAMPLE
  irm https://raw.githubusercontent.com/kirthi-sagar/runner/main/install.ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$repo = 'kirthi-sagar/runner'
$tag = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
$dir = Join-Path $env:LOCALAPPDATA 'runner'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'runner.exe'
Invoke-WebRequest "https://github.com/$repo/releases/download/$tag/runner-windows-x86_64.exe" -OutFile $exe
$want = (Invoke-WebRequest "https://github.com/$repo/releases/download/$tag/runner-windows-x86_64.exe.sha256").Content.Split()[0]
$got = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($got -ne $want.ToLower()) { throw "SHA-256 mismatch for runner.exe" }
$path = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($path -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable('PATH', "$path;$dir", 'User')
}
Write-Output 'runner installed. Please restart your terminal.'
