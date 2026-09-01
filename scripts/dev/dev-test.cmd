@echo off
REM dev-test.cmd — easy mTLS test for the local broker
REM Usage: dev-test.cmd [me^|secrets^|resolve^|health]
REM   default: me
REM
REM Uses Git for Windows' curl (OpenSSL backend) because Windows
REM built-in curl (Schannel) doesn't accept PEM client certs.

set "CERT=E:\broker\pki\clients\dev-client.crt"
set "KEY=E:\broker\pki\clients\dev-client.key"
set "CA=E:\broker\pki\ca\ca.crt"
set "URL=https://127.0.0.1:8443"
set "CURL=C:\Program Files\Git\usr\bin\curl.exe"
set "ENDPOINT=%~1"

if "%ENDPOINT%"=="" set "ENDPOINT=me"

if /I "%ENDPOINT%"=="me" goto :me
if /I "%ENDPOINT%"=="secrets" goto :secrets
if /I "%ENDPOINT%"=="resolve" goto :resolve
if /I "%ENDPOINT%"=="health" goto :health
if /I "%ENDPOINT%"=="help" goto :help

:help
echo Usage: dev-test.cmd [me^|secrets^|resolve^|health]
echo.
echo Examples:
echo   dev-test.cmd me       REM GET /api/v1/me (mTLS)
echo   dev-test.cmd secrets  REM GET /api/v1/secrets
echo   dev-test.cmd resolve  REM POST /api/v1/secrets/resolve github.pat
echo   dev-test.cmd health   REM GET /health (public, no mTLS)
echo.
echo Or just run the Python smoke test:
echo   python E:\broker\audit\smoke-test.py
exit /b 0

:me
echo === GET %URL%/api/v1/me ===
"%CURL%" -k --cert "%CERT%" --key "%KEY%" --cacert "%CA%" "%URL%/api/v1/me"
echo.
exit /b 0

:secrets
echo === GET %URL%/api/v1/secrets ===
"%CURL%" -k --cert "%CERT%" --key "%KEY%" --cacert "%CA%" "%URL%/api/v1/secrets"
echo.
exit /b 0

:resolve
echo === POST %URL%/api/v1/secrets/resolve github.pat ===
"%CURL%" -k --cert "%CERT%" --key "%KEY%" --cacert "%CA%" -H "Content-Type: application/json" -X POST -d "{\"name\":\"github.pat\"}" "%URL%/api/v1/secrets/resolve"
echo.
exit /b 0

:health
echo === GET %URL%/health (public) ===
"%CURL%" -k "%URL%/health"
echo.
exit /b 0
