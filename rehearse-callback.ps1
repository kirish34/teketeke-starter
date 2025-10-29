param(
  [string]$BASE = $env:BASE,
  [string]$CALLBACK_SECRET = $env:CALLBACK_SECRET,
  [string]$MATATU_ID = $env:MATATU_ID,
  [string]$RECEIPT = $env:RECEIPT
)

if (-not $BASE) { throw "BASE not set" }
if (-not $CALLBACK_SECRET) { throw "CALLBACK_SECRET not set" }
if (-not $MATATU_ID) { throw "MATATU_ID not set" }
if (-not $RECEIPT) { $RECEIPT = "TEST123456" }

# If you get HTTP 400 on Valid case, set this to $true and run again.
$SendAsBytes = $false

function Get-Utf8NoBomBytes([string]$s) {
  return [System.Text.UTF8Encoding]::new($false).GetBytes($s)
}

function Get-HmacHex([string]$raw, [string]$secret) {
  $hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret))
  $hash = $hmac.ComputeHash((Get-Utf8NoBomBytes $raw))
  return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Post-Callback([string]$raw, [string]$sig) {
  $uri = ($BASE.TrimEnd('/') + "/api/mpesa/callback")
  $headers = @{
    "x-callback-signature" = $sig
    "Accept"               = "application/json"
  }
  $contentType = 'application/json; charset=utf-8'

  # PS5-compatible conditional (no ternary)
  if ($SendAsBytes) {
    $bodyToSend = Get-Utf8NoBomBytes $raw
  } else {
    $bodyToSend = $raw
  }

  # Debug
  Write-Host "POST $uri" -ForegroundColor DarkGray
  Write-Host "Content-Type: $contentType" -ForegroundColor DarkGray
  Write-Host "x-callback-signature: $sig" -ForegroundColor DarkGray
  if ($SendAsBytes) {
    Write-Host ("Body length: {0} bytes" -f $bodyToSend.Length) -ForegroundColor DarkGray
  } else {
    Write-Host ("Body length: {0} chars" -f $raw.Length) -ForegroundColor DarkGray
  }

  try {
    $res = Invoke-WebRequest -Uri $uri -Method Post -ContentType $contentType -Headers $headers -Body $bodyToSend -ErrorAction Stop
    return @{ status = $res.StatusCode; body = $res.Content }
  } catch {
    if ($_.Exception.Response) {
      $resp = $_.Exception.Response
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
      $content = $sr.ReadToEnd()
      return @{ status = [int]$resp.StatusCode; body = $content }
    } else {
      throw
    }
  }
}

function New-ValidBody([string]$receipt) {
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  return '{"matatu_id":"'+$MATATU_ID+'","amount":150,"msisdn":"254712345678","status":"success","mpesa_receipt":"'+$receipt+'","gateway_ref":"SIM-'+$ts+'","raw":{"note":"webhook rehearsal"}}'
}
function New-TamperedBody() {
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  return '{"matatu_id":"'+$MATATU_ID+'","amount":151,"msisdn":"254712345678","status":"success","mpesa_receipt":"'+$RECEIPT+'","gateway_ref":"SIM-'+$ts+'","raw":{"note":"webhook rehearsal"}}'
}
function New-FailedBody() {
  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  return '{"matatu_id":"'+$MATATU_ID+'","amount":150,"msisdn":"254712345678","status":"failed","mpesa_receipt":"TESTFAIL-'+$ts+'","gateway_ref":"SIM-'+$ts+'","raw":{"note":"webhook rehearsal"}}'
}

Write-Host "=== A) Valid success ===" -ForegroundColor Cyan
$valid = New-ValidBody -receipt $RECEIPT
$sigA  = Get-HmacHex -raw $valid -secret $CALLBACK_SECRET
$rA    = Post-Callback -raw $valid -sig $sigA
$rA | Format-List

Write-Host "`n=== B) Invalid signature (tampered) ===" -ForegroundColor Cyan
$tampered = New-TamperedBody
$rB = Post-Callback -raw $tampered -sig $sigA  # reuse old sig -> mismatch
$rB | Format-List

Write-Host "`n=== C) Duplicate receipt ===" -ForegroundColor Cyan
$sigC = Get-HmacHex -raw $valid -secret $CALLBACK_SECRET
$rC   = Post-Callback -raw $valid -sig $sigC
$rC | Format-List

Write-Host "`n=== D) Non-success (ignored) ===" -ForegroundColor Cyan
$failed = New-FailedBody
$sigD   = Get-HmacHex -raw $failed -secret $CALLBACK_SECRET
$rD     = Post-Callback -raw $failed -sig $sigD
$rD | Format-List

Write-Host "`nDone."
