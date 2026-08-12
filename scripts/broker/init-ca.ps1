# init-ca.ps1
# 初始化根 CA / Initialize root Certificate Authority
# 运行一次即可，生成 pki/ca/ca.crt + ca.key
# Generates pki/ca/ca.crt + ca.key (run once)

[CmdletBinding()]
param(
  [string]$Org = "Personal Secret Broker",
  [int]$Days = 3650  # 10 年
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$CaDir = Join-Path $PSScriptRoot "..\..\pki\ca"
$CaKey = Join-Path $CaDir "ca.key"
$CaCrt = Join-Path $CaDir "ca.crt"

if (-not (Test-Path $CaDir)) { New-Item -ItemType Directory -Path $CaDir -Force | Out-Null }

if (Test-Path $CaKey) {
  Write-Host "CA already exists at $CaCrt" -ForegroundColor Yellow
  Write-Host "Delete the file manually if you want to regenerate." -ForegroundColor Yellow
  exit 0
}

Write-Host "==> Generating root CA (valid for $Days days)..." -ForegroundColor Cyan

# 生成 CA 私钥 (RSA 4096)
openssl genrsa -out $CaKey 4096 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to generate CA private key" }

# 生成自签证书
$Subject = "/O=$Org/CN=Secret Broker Root CA"
openssl req -new -x509 -days $Days -key $CaKey -out $CaCrt -subj $Subject 2>$null
if ($LASTEXITCODE -ne 0) { throw "Failed to generate CA certificate" }

# 初始化 CRL
$CrlPem = Join-Path $CaDir "crl.pem"
$IndexTxt = Join-Path $CaDir "index.txt"
$Serial = Join-Path $CaDir "serial"
"" | Out-File -FilePath $CrlPem -Encoding ASCII
"00" | Out-File -FilePath $Serial -Encoding ASCII -NoNewline
"" | Out-File -FilePath $IndexTxt -Encoding ASCII -NoNewline
"unique_subject = no" | Out-File -FilePath (Join-Path $CaDir "index.txt.attr") -Encoding ASCII

# 显示指纹供用户记录
$Fp = openssl x509 -in $CaCrt -noout -fingerprint -sha256 | Select-String -Pattern 'SHA256 Fingerprint=' | ForEach-Object { $_.ToString().Replace('SHA256 Fingerprint=','').Trim() }
$SubjectAlt = openssl x509 -in $CaCrt -noout -subject | Select-String -Pattern 'subject=' | ForEach-Object { $_.ToString() }

Write-Host ""
Write-Host "OK! Root CA created." -ForegroundColor Green
Write-Host "  Certificate: $CaCrt"
Write-Host "  Private key: $CaKey (KEEP SAFE!)"
Write-Host "  SHA-256:     $Fp"
Write-Host "  Subject:     $SubjectAlt"
Write-Host ""
Write-Host "IMPORTANT: The private key ca.key must NEVER leave the broker server." -ForegroundColor Red
Write-Host "            Anyone with this key can sign trusted client certificates." -ForegroundColor Red
Write-Host ""
Write-Host "Next step: .\scripts\broker\issue-server-cert.ps1" -ForegroundColor Cyan
