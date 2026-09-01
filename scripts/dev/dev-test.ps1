# dev-test.ps1 - PowerShell-native mTLS test for the local broker.
# Uses Git for Windows' curl (OpenSSL backend) because Windows
# built-in curl (Schannel) doesn't accept PEM client certs.
#
# Usage: .\dev-test.ps1 [me|secrets|resolve|health]
#   default: me

param(
    [ValidateSet('', 'me', 'secrets', 'resolve', 'health', 'help')]
    [string]$Endpoint = 'me'
)

$CERT    = 'E:\broker\pki\clients\dev-client.crt'
$KEY     = 'E:\broker\pki\clients\dev-client.key'
$CA      = 'E:\broker\pki\ca\ca.crt'
$URL     = 'https://127.0.0.1:8443'
$CURL    = 'C:\Program Files\Git\usr\bin\curl.exe'

if ($Endpoint -eq 'help' -or $Endpoint -eq '') {
    Write-Host "Usage: .\dev-test.ps1 [me|secrets|resolve|health]"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\dev-test.ps1 me       # GET /api/v1/me (mTLS)"
    Write-Host "  .\dev-test.ps1 secrets  # GET /api/v1/secrets"
    Write-Host "  .\dev-test.ps1 resolve  # POST /api/v1/secrets/resolve github.pat"
    Write-Host "  .\dev-test.ps1 health   # GET /health (public, no mTLS)"
    Write-Host ""
    Write-Host "Or just run the Python smoke test:"
    Write-Host "  python E:\broker\audit\smoke-test.py"
    return
}

if ($false) {  # Test-Path gate disabled - some PowerShell hosts block stat on C:\Program Files
}

function Run-Curl {
    & $CURL -k @args 2>&1
}

function Run-Curl {
    & $CURL -k @args 2>&1
}

switch ($Endpoint) {
    'me' {
        Write-Host "=== GET $URL/api/v1/me ===" -ForegroundColor Cyan
        Run-Curl --cert $CERT --key $KEY --cacert $CA "$URL/api/v1/me"
    }
    'secrets' {
        Write-Host "=== GET $URL/api/v1/secrets ===" -ForegroundColor Cyan
        Run-Curl --cert $CERT --key $KEY --cacert $CA "$URL/api/v1/secrets"
    }
    'resolve' {
        Write-Host "=== POST $URL/api/v1/secrets/resolve github.pat ===" -ForegroundColor Cyan
        Run-Curl --cert $CERT --key $KEY --cacert $CA -H "Content-Type: application/json" -X POST -d '{"name":"github.pat"}' "$URL/api/v1/secrets/resolve"
    }
    'health' {
        Write-Host "=== GET $URL/health (public) ===" -ForegroundColor Cyan
        Run-Curl "$URL/health"
    }
}

Write-Host ""
Write-Host "(broker PID: $((Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue).OwningProcess))" -ForegroundColor DarkGray
