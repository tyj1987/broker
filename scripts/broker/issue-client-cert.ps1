# issue-client-cert.ps1
# 签发客户端证书（每台设备一张）/ Issue a client certificate
# 结果存到 pki/clients/<cn>.{crt,key}，并把指纹注册到 broker.yaml

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$CN,                     # 客户端通用名，例如 client.tyj-laptop
  [string]$Role = "developer",     # developer | ci | admin
  [int]$Days = 365,
  [string]$OutDir,                 # 自定义输出目录（可选）
  [switch]$RegisterToConfig        # 自动追加到 broker.yaml
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$CaDir    = Join-Path $RepoRoot "pki\ca"
$CaKey    = Join-Path $CaDir "ca.key"
$CaCrt    = Join-Path $CaDir "ca.crt"
$ConfigFile = Join-Path $RepoRoot "secrets\broker.yaml"

if (-not (Test-Path $CaKey)) {
  Write-Error "Root CA not found. Run .\scripts\broker\init-ca.ps1 first."
  exit 1
}

if (-not $OutDir) {
  $OutDir = Join-Path $RepoRoot "pki\clients"
}
if (-not (Test-Path $OutDir)) { New-Item -Item-Type Directory -Path $OutDir -Force | Out-Null }

$SafeName = ($CN -replace '[^a-zA-Z0-9._-]','_')
$KeyFile  = Join-Path $OutDir "$SafeName.key"
$CrtFile  = Join-Path $OutDir "$SafeName.crt"
$CsrFile  = Join-Path $OutDir "$SafeName.csr"
$ExtFile  = Join-Path $OutDir "$SafeName.ext"

if (Test-Path $CrtFile) {
  Write-Error "Certificate for $CN already exists at $CrtFile. Delete it first or use a different CN."
  exit 1
}

Write-Host "==> Issuing client certificate for $CN (role=$Role, valid $Days days)..." -ForegroundColor Cyan

# 1. 私钥
openssl genrsa -out $KeyFile 2048 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to generate private key" }

# 2. CSR
$Subject = "/CN=$CN"
openssl req -new -key $KeyFile -out $CsrFile -subj $Subject 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to generate CSR" }

# 3. ext 文件
@"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"@ | Out-File -FilePath $ExtFile -Encoding ASCII

# 4. CA 签名
openssl x509 -req -in $CsrFile -CA $CaCrt -CAkey $CaKey -CAcreateserial `
  -out $CrtFile -days $Days -sha256 -extfile $ExtFile 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to sign client certificate" }

# 5. 清理
Remove-Item $CsrFile, $ExtFile -ErrorAction SilentlyContinue
# 私钥权限
icacls $KeyFile /inheritance:r /grant:r "$env:USERNAME:R" | Out-Null

# 6. 显示指纹
$Fp = openssl x509 -in $CrtFile -noout -fingerprint -sha256 | Select-String -Pattern 'SHA256 Fingerprint=' | ForEach-Object { $_.ToString().Replace('SHA256 Fingerprint=','').Trim() }
$Serial = openssl x509 -in $CrtFile -noout -serial | Select-String -Pattern 'serial=' | ForEach-Object { $_.ToString().Replace('serial=','').Trim() }

Write-Host ""
Write-Host "OK! Client certificate issued." -ForegroundColor Green
Write-Host "  Certificate: $CrtFile"
Write-Host "  Private key: $KeyFile"
Write-Host "  CN:          $CN"
Write-Host "  Role:        $Role"
Write-Host "  SHA-256:     $Fp"
Write-Host "  Serial:      $Serial"
Write-Host ""
Write-Host "==> Distribute the .crt + .key + ca.crt to the target device." -ForegroundColor Cyan
Write-Host "    Recommended: keep the .key on the device only, never commit it." -ForegroundColor Cyan

# 7. 可选：自动注册到 broker.yaml
if ($RegisterToConfig -and (Test-Path $ConfigFile)) {
  $FpEscaped = $Fp
  $RoleEscaped = $Role
  $CNEscaped = $CN
  $Yaml = @"

  # auto-registered $(Get-Date -Format 'yyyy-MM-dd HH:mm')
  "$CNEscaped":
    cert_fingerprint_sha256: "$FpEscaped"
    role: "$RoleEscaped"
    allowed_resolve: []
    allowed_proxy:
      - service: github
        paths: ["^/.*"]
    rate_limit: "100/hour"
"@
  Add-Content -Path $ConfigFile -Value $Yaml -Encoding UTF8
  Write-Host "==> Appended to broker.yaml. Remember to re-encrypt with sops." -ForegroundColor Cyan
}
