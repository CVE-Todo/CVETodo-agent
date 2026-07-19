<#
.SYNOPSIS
    CVETodo Agent installer for Windows.

.DESCRIPTION
    Downloads the latest CVETodo Agent release from GitHub, installs it to
    Program Files, writes the configuration, and registers the agent as a
    Windows service that scans the system once a day.

    Run from an elevated PowerShell prompt:

        irm https://raw.githubusercontent.com/CVE-Todo/CVETodo-agent/main/install.ps1 | iex

    Non-interactive install:

        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/CVE-Todo/CVETodo-agent/main/install.ps1))) -ApiKey "your-key" -TeamId "your-team"

.NOTES
    To disable the agent later:
      - cvetodo-agent service stop        (or 'service uninstall')
      - set 'agent.enabled: false' in C:\ProgramData\cvetodo-agent\.cvetodo-agent.yaml
      - stop/disable the 'CVETodo Agent' service in services.msc
#>
param(
    [string]$ApiKey,
    [string]$TeamId,
    [string]$InstallDir = "$env:ProgramFiles\CVETodo Agent"
)

$ErrorActionPreference = 'Stop'

$Repo = 'CVE-Todo/CVETodo-agent'
$ConfigDir = "$env:ProgramData\cvetodo-agent"
$ConfigFile = "$ConfigDir\.cvetodo-agent.yaml"

# --- Preconditions -----------------------------------------------------------

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This installer must be run from an elevated (Administrator) PowerShell prompt."
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- Download latest release -------------------------------------------------

Write-Host "Looking up the latest CVETodo Agent release..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'cvetodo-agent-installer' }
$tag = $release.tag_name
$zipName = "cvetodo-agent-$tag-windows-amd64.zip"
$asset = $release.assets | Where-Object { $_.name -eq $zipName }
if (-not $asset) {
    Write-Error "Could not find asset '$zipName' in release $tag."
}

$tempDir = Join-Path $env:TEMP "cvetodo-agent-install-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$zipPath = Join-Path $tempDir $zipName

Write-Host "Downloading $zipName ($tag)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -Headers @{ 'User-Agent' = 'cvetodo-agent-installer' }

# Verify the artifact against the published checksums before unpacking
$checksumAsset = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS' }
if ($checksumAsset) {
    Write-Host "Verifying checksum..."
    $checksumPath = Join-Path $tempDir 'SHA256SUMS'
    Invoke-WebRequest -Uri $checksumAsset.browser_download_url -OutFile $checksumPath -Headers @{ 'User-Agent' = 'cvetodo-agent-installer' }
    $expectedLine = Get-Content $checksumPath | Where-Object { $_ -match [regex]::Escape($zipName) } | Select-Object -First 1
    if (-not $expectedLine) {
        Write-Error "No checksum entry found for '$zipName' in SHA256SUMS. Aborting."
    }
    $expectedHash = ($expectedLine -split '\s+')[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Write-Error "Checksum verification failed for '$zipName' (expected $expectedHash, got $actualHash). Aborting."
    }
} else {
    Write-Warning "No SHA256SUMS published for release $tag; skipping checksum verification."
}

Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

# --- Install binary ----------------------------------------------------------

# Stop an existing service before replacing the binary (upgrade path)
$existing = Get-Service -Name 'cvetodo-agent' -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -eq 'Running') {
    Write-Host "Stopping existing CVETodo Agent service..."
    Stop-Service -Name 'cvetodo-agent' -Force
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path (Join-Path $tempDir 'cvetodo-agent.exe') -Destination (Join-Path $InstallDir 'cvetodo-agent.exe') -Force
Remove-Item -Path $tempDir -Recurse -Force

# Add to the system PATH if not already present
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($machinePath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$InstallDir", 'Machine')
    Write-Host "Added '$InstallDir' to the system PATH (open a new terminal to pick it up)."
}

Write-Host "Installed cvetodo-agent.exe to '$InstallDir'."

# --- Configuration -----------------------------------------------------------

if (Test-Path $ConfigFile) {
    Write-Host "Existing configuration found at '$ConfigFile' - keeping it."
} else {
    if (-not $ApiKey) {
        Write-Host ""
        Write-Host "To obtain your API key and team ID: log into https://cvetodo.com,"
        Write-Host "open your team settings and generate a key under 'Agent Keys'."
        Write-Host ""
        $ApiKey = Read-Host "Enter your CVETodo team API key"
    }
    if (-not $TeamId) {
        $TeamId = Read-Host "Enter your CVETodo team ID"
    }
    if (-not $ApiKey -or -not $TeamId) {
        Write-Error "An API key and team ID are required."
    }

    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null

    $dataDir = ($ConfigDir -replace '\\', '/') + '/data'
    @"
# CVETodo Agent Configuration
api:
  base_url: "https://cvetodo.com"
  api_key: "$ApiKey"
  team_id: "$TeamId"
  timeout: "30s"

agent:
  enabled: true       # set to false to disable all scanning without uninstalling
  name: "$env:COMPUTERNAME"
  scan_interval: "24h"
  report_interval: "24h"
  data_dir: "$dataDir"

log_level: "info"
log_format: "text"

scanner:
  enabled_scanners:
    - "windows"
"@ | Set-Content -Path $ConfigFile -Encoding UTF8

    # Restrict the config (contains the API key) to SYSTEM and Administrators
    $acl = Get-Acl $ConfigFile
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $ConfigFile -AclObject $acl

    Write-Host "Configuration written to '$ConfigFile'."
}

# --- Service -----------------------------------------------------------------

Write-Host "Registering the CVETodo Agent service..."
& (Join-Path $InstallDir 'cvetodo-agent.exe') service install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Service installation failed (exit code $LASTEXITCODE)."
}

Write-Host ""
Write-Host "CVETodo Agent installed successfully." -ForegroundColor Green
Write-Host "It runs as a Windows service and scans this system once a day."
Write-Host ""
Write-Host "To turn it off:"
Write-Host "  - cvetodo-agent service stop        (until next boot)"
Write-Host "  - cvetodo-agent service uninstall   (remove entirely)"
Write-Host "  - set 'agent.enabled: false' in $ConfigFile"
Write-Host "  - stop/disable the 'CVETodo Agent' service in services.msc"
