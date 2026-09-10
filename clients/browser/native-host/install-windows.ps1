[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BinaryPath,
    [ValidateSet('Chrome', 'Edge', 'Both')]
    [string]$Browser = 'Both'
)

$ErrorActionPreference = 'Stop'
$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if ([IO.Path]::GetFileName($resolvedBinary) -ne 'secret-broker-browser-host.exe') {
    throw 'BinaryPath must point to secret-broker-browser-host.exe'
}

$manifestDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'SecretBroker\NativeMessagingHosts'
New-Item -ItemType Directory -Force -Path $manifestDirectory | Out-Null
$manifestPath = Join-Path $manifestDirectory 'com.secretbroker.browser.json'
@{
    name = 'com.secretbroker.browser'
    description = 'Secret Broker one-time fill bridge'
    path = $resolvedBinary
    type = 'stdio'
    allowed_origins = @('chrome-extension://fcllkkhicfhknnbapgheklkaccjdbeln/')
} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

$targets = if ($Browser -eq 'Both') { @('Chrome', 'Edge') } else { @($Browser) }
foreach ($target in $targets) {
    $vendor = if ($target -eq 'Chrome') { 'Google\Chrome' } else { 'Microsoft\Edge' }
    $registryPath = "HKCU:\Software\$vendor\NativeMessagingHosts\com.secretbroker.browser"
    New-Item -Force -Path $registryPath | Out-Null
    Set-Item -LiteralPath $registryPath -Value $manifestPath
}

Write-Host "Registered com.secretbroker.browser for $($targets -join ', ')."
