$ErrorActionPreference = 'Stop'
try {
    $inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($inputData.thumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid thumbprint' }
    $uri = [Uri]$inputData.url
    if ($uri.Scheme -ne 'https') { throw 'HTTPS required' }
    $cert = Get-Item -LiteralPath "Cert:/CurrentUser/My/$($inputData.thumbprint)"
    if (-not $cert.HasPrivateKey) { throw 'Certificate private key unavailable' }
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $null = $handler.ClientCertificates.Add($cert)
    # Default Windows server-certificate validation remains enabled.
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($inputData.method), $uri)
    # Staged PoP: sign the canonical request message with the certificate's
    # private key (used in-place, never exported) and add it as X-Broker-PoP.
    # If signing is unavailable, continue without the header so legacy/off
    # brokers still work. stdout contract is unchanged.
    try {
        $popTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $popMessage = "v1`n$($inputData.method.ToUpperInvariant())`n$($uri.PathAndQuery)`n$popTs"
        $popBytes = [Text.Encoding]::UTF8.GetBytes($popMessage)
        $popSig = $null
        $rsaKey = $cert.GetRSAPrivateKey()
        if ($null -ne $rsaKey) {
            $popSig = $rsaKey.SignData($popBytes, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $rsaKey.Dispose()
        } else {
            $ecdsaKey = $cert.GetECDsaPrivateKey()
            if ($null -eq $ecdsaKey) { throw 'No RSA or ECDSA private key' }
            $popSig = $ecdsaKey.SignData($popBytes, [Security.Cryptography.HashAlgorithmName]::SHA256)
            $ecdsaKey.Dispose()
        }
        $popValue = "v1:$popTs`:$([Convert]::ToBase64String($popSig))"
        $inputData.headers | Add-Member -NotePropertyName 'X-Broker-PoP' -NotePropertyValue $popValue -Force
    } catch { }
    if ($null -ne $inputData.body) {
        $request.Content = [System.Net.Http.StringContent]::new([string]$inputData.body, [Text.Encoding]::UTF8, 'application/json')
    }
    foreach ($h in $inputData.headers.PSObject.Properties) {
        if (-not $request.Headers.TryAddWithoutValidation($h.Name, [string]$h.Value) -and $null -ne $request.Content) {
            $null = $request.Content.Headers.Remove($h.Name)
            $null = $request.Content.Headers.TryAddWithoutValidation($h.Name, [string]$h.Value)
        }
    }
    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    $headers = @{}
    foreach ($h in $response.Headers) { $headers[$h.Key.ToLowerInvariant()] = $h.Value -join ', ' }
    foreach ($h in $response.Content.Headers) { $headers[$h.Key.ToLowerInvariant()] = $h.Value -join ', ' }
    [Console]::Out.Write((@{ status = [int]$response.StatusCode; headers = $headers; raw = [Convert]::ToBase64String($bytes) } | ConvertTo-Json -Compress -Depth 5))
    $response.Dispose()
    $request.Dispose()
    $client.Dispose()
} catch {
    [Console]::Error.WriteLine('Windows certificate request failed.')
    exit 1
}
