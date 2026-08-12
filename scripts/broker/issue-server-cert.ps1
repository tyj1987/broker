# issue-server-cert.ps1
# 签发 broker 服务端证书 / Issue broker server certificate
# 用 CA 私钥签发，结果存到 pki/server/

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Domain,                    # 例如 broker.example.com
  [string[]]$AltNames = @("localhost","127.0.0.1"),
  [int]$Days = 365
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$CaDir    = Join-Path $RepoRoot "pki\ca"
$OutDir   = Join-Path $RepoRoot "pki\server"
$CaKey    = Join-Path $CaDir "ca.key"
$CaCrt    = Join-Path $CaDir "ca.crt"

if (-not (Test-Path $CaKey)) {
  Write-Error "Root CA not found. Run .\scripts\broker\init-ca.ps1 first."
  exit 1
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$KeyFile = Join-Path $OutDir "server.key"
$CrtFile = Join-Path $OutDir "server.crt"
$CsrFile = Join-Path $OutDir "server.csr"
$ExtFile = Join-Path $OutDir "server.ext"

Write-Host "==> Generating server certificate for $Domain ..." -ForegroundColor Cyan

# 1. 私钥
openssl genrsa -out $KeyFile 2048 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to generate private key" }

# 2. CSR
$Subject = "/CN=$Domain"
openssl req -new -key $KeyFile -out $CsrFile -subj $Subject 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to generate CSR" }

# 3. SAN 扩展
$Sans = @($Domain) + $AltNames
$SanLines = ($Sans | ForEach-Object {
  if ($_ -match '^\d+\.\d+\.\d+\.\d+$') { "IP:$_" } else { "DNS:$_" }
}) -join ","
@"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SanLines
"@ | Out-File -FilePath $ExtFile -Encoding ASCII

# 4. 用 CA 签名
openssl x509 -req -in $CsrFile -CA $CaCrt -CAkey $CaKey -CAcreateserial `
  -out $CrtFile -days $Days -sha256 -extfile $ExtFile 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to sign server certificate" }

# 5. 清理
Remove-Item $CsrFile, $ExtFile -ErrorAction SilentlyContinue

# 6. 显示指纹
$Fp = openssl x509 -in $CrtFile -noout -fingerprint -sha256 | Select-String -Pattern 'SHA256 Fingerprint=' | ForEach-Object { $_.ToString().Replace('SHA256 Fingerprint=','').Trim() }
Write-Host ""
Write-Host "OK! Server certificate issued." -ForegroundColor Green
Write-Host "  Certificate: $CrtFile"
Write-Host "  Private key: $KeyFile"
Write-Host "  Domain:      $Domain"
Write-Host "  Alt names:   $($AltNames -join ', ')"
Write-Host "  SHA-256:     $Fp"
Write-Host ""
Write-Host "Next: copy the cert+key to your broker server, then start it with:" -ForegroundColor Cyan
Write-Host "  docker compose up -d broker" -ForegroundColor Cyan
