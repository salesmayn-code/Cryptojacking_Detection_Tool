<#
.SYNOPSIS
    Windows Authenticode Code Signing Utility for CryptoDetect Endpoint Security Agent.

.DESCRIPTION
    Signs the CryptoDetect Agent Windows binary (dist\CryptoDetect-Agent-v1.exe) using Microsoft
    Authenticode and SHA-256 with RFC 3161 timestamping. This guarantees binary integrity,
    authenticates the publisher, and mitigates Windows Defender SmartScreen untrusted binary warnings.

    Supports:
      1. Default / Self-Signed mode: Locates or generates a dedicated code signing certificate in
         Cert:\CurrentUser\My with Subject "CN=CryptoDetect Endpoint Security".
      2. Enterprise EV/OV Thumbprint: Signs with an existing hardware token or cert store certificate.
      3. Enterprise PFX File: Signs with a specified .pfx / .p12 certificate file.

.PARAMETER CertThumbprint
    SHA-1 thumbprint of an existing code signing certificate in CurrentUser\My or LocalMachine\My.

.PARAMETER PfxPath
    Path to a PKCS#12 (.pfx / .p12) code signing certificate file.

.PARAMETER PfxPassword
    Password for the .pfx file (optional if unencrypted or pre-authenticated).

.PARAMETER SelfSigned
    Explicit switch to use or create a local self-signed code signing certificate.
    This is the default if neither -CertThumbprint nor -PfxPath is specified.

.PARAMETER ExePath
    Target executable path to sign. Defaults to "dist\CryptoDetect-Agent-v1.exe" relative to this script.

.PARAMETER TimestampServer
    RFC 3161 Timestamp Authority URL. Defaults to DigiCert's public timestamp server:
    http://timestamp.digicert.com

.PARAMETER HashAlgorithm
    Hash digest algorithm for the Authenticode signature. Defaults to SHA256.

.EXAMPLE
    .\sign_exe.ps1
    Signs dist\CryptoDetect-Agent-v1.exe with a self-signed "CN=CryptoDetect Endpoint Security" cert.

.EXAMPLE
    .\sign_exe.ps1 -CertThumbprint "A1B2C3D4E5F6..."
    Signs with an enterprise OV/EV certificate identified by thumbprint.

.EXAMPLE
    .\sign_exe.ps1 -PfxPath "C:\Certs\CryptoDetect_EV.pfx"
    Signs with an exported enterprise PFX file.
#>

[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $false, ParameterSetName = "Thumbprint")]
    [string]$CertThumbprint,

    [Parameter(Mandatory = $false, ParameterSetName = "Pfx")]
    [string]$PfxPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Pfx")]
    [string]$PfxPassword = "",

    [Parameter(Mandatory = $false, ParameterSetName = "SelfSigned")]
    [switch]$SelfSigned,

    [Parameter(Mandatory = $false)]
    [string]$ExePath = "",

    [Parameter(Mandatory = $false)]
    [string]$TimestampServer = "http://timestamp.digicert.com",

    [Parameter(Mandatory = $false)]
    [string]$HashAlgorithm = "SHA256"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CryptoDetect Endpoint Agent - Authenticode Code Signer   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Resolve Target Executable
if ([string]::IsNullOrWhiteSpace($ExePath)) {
    $targetPath = Join-Path $PSScriptRoot "dist\CryptoDetect-Agent-v1.exe"
} else {
    $targetPath = $ExePath
}

if (-not (Test-Path $targetPath)) {
    Write-Error "Target executable not found: $targetPath`nPlease run 'python build_exe.py' first to build the executable."
    exit 1
}

$fullExePath = (Resolve-Path $targetPath).Path
Write-Host "[*] Target Binary : $fullExePath" -ForegroundColor Gray

# 2. Acquire Signing Certificate
$cert = $null

if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
    if (-not (Test-Path $PfxPath)) {
        Write-Error "Specified PFX file not found: $PfxPath"
        exit 1
    }
    Write-Host "[*] Loading certificate from PFX: $PfxPath" -ForegroundColor Yellow
    if ([string]::IsNullOrEmpty($PfxPassword)) {
        $cert = Get-PfxCertificate -FilePath $PfxPath
    } else {
        $secPass = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $PfxPath).Path, $secPass)
    }
}
elseif (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
    $cleanThumb = $CertThumbprint.Replace(" ", "").Trim().ToUpper()
    Write-Host "[*] Searching certificate store for Thumbprint: $cleanThumb" -ForegroundColor Yellow
    
    $storeCerts = @(
        Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint.ToUpper() -eq $cleanThumb }
        Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint.ToUpper() -eq $cleanThumb }
    )
    if ($storeCerts.Count -eq 0) {
        Write-Error "No certificate matching thumbprint '$cleanThumb' was found in CurrentUser\My or LocalMachine\My."
        exit 1
    }
    $cert = $storeCerts[0]
}
else {
    # Default or -SelfSigned: locate or create "CN=CryptoDetect Endpoint Security"
    $subjectName = "CN=CryptoDetect Endpoint Security"
    Write-Host "[*] Mode: Self-Signed / Internal Dev Certificate ($subjectName)" -ForegroundColor Yellow

    $existing = @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match "CryptoDetect Endpoint Security" -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object -Property NotAfter -Descending)

    if ($existing.Count -gt 0) {
        $cert = $existing[0]
        Write-Host "[+] Found valid existing certificate in CurrentUser\My: $($cert.Thumbprint)" -ForegroundColor Green
    } else {
        Write-Host "[*] No active certificate found. Creating new self-signed Code Signing Certificate..." -ForegroundColor Cyan
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $subjectName `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(5) `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256

        Write-Host "[+] Generated new certificate:" -ForegroundColor Green
        Write-Host "    Subject    : $($cert.Subject)" -ForegroundColor Gray
        Write-Host "    Thumbprint : $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "    Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
        Write-Host "`n[i] Note for Operators: For zero SmartScreen prompts on managed workstations," -ForegroundColor DarkYellow
        Write-Host "    export this cert and deploy it into 'Trusted Root Certification Authorities'." -ForegroundColor DarkYellow
    }
}

if ($null -eq $cert) {
    Write-Error "Failed to obtain a valid code signing certificate."
    exit 1
}

# 3. Apply Authenticode Signature
Write-Host "`n[*] Signing executable with $HashAlgorithm..." -ForegroundColor Cyan
$signResult = $null

try {
    if (-not [string]::IsNullOrWhiteSpace($TimestampServer)) {
        Write-Host "    Using Timestamp Authority: $TimestampServer" -ForegroundColor Gray
        $signResult = Set-AuthenticodeSignature `
            -FilePath $fullExePath `
            -Certificate $cert `
            -HashAlgorithm $HashAlgorithm `
            -TimestampServer $TimestampServer `
            -ErrorAction Stop
    } else {
        $signResult = Set-AuthenticodeSignature `
            -FilePath $fullExePath `
            -Certificate $cert `
            -HashAlgorithm $HashAlgorithm `
            -ErrorAction Stop
    }
}
catch {
    Write-Warning "Timestamping failed or timed out ($($_.Exception.Message)). Falling back to un-timestamped signature..."
    $signResult = Set-AuthenticodeSignature `
        -FilePath $fullExePath `
        -Certificate $cert `
        -HashAlgorithm $HashAlgorithm `
        -ErrorAction Stop
}

# 4. Verification and Summary
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "                  SIGNING VERIFICATION                      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$verifySig = Get-AuthenticodeSignature -FilePath $fullExePath

Write-Host "File        : $(Split-Path $fullExePath -Leaf)"
Write-Host "Status      : $($verifySig.Status)" -ForegroundColor $(if ($verifySig.Status -eq "Valid") { "Green" } else { "Yellow" })
Write-Host "StatusMessage: $($verifySig.StatusMessage)"
if ($verifySig.SignerCertificate) {
    Write-Host "Signer      : $($verifySig.SignerCertificate.Subject)"
    Write-Host "Thumbprint  : $($verifySig.SignerCertificate.Thumbprint)"
    Write-Host "Algorithm   : $($HashAlgorithm)"
}
if ($verifySig.TimeStamperCertificate) {
    Write-Host "Timestamp   : $($verifySig.TimeStamperCertificate.Subject)"
}

Write-Host "============================================================`n" -ForegroundColor Cyan

if ($verifySig.Status -in @("Valid", "UnknownError")) {
    # Note: "UnknownError" in Authenticode typically means valid signature from untrusted root (expected for self-signed)
    if ($verifySig.Status -eq "Valid") {
        Write-Host "[SUCCESS] Executable successfully signed with trusted certificate!" -ForegroundColor Green
    } else {
        Write-Host "[SUCCESS] Executable successfully signed! (Untrusted root is normal for self-signed dev certs)" -ForegroundColor Green
    }
    exit 0
} else {
    Write-Error "[FAIL] Authenticode signature verification reported: $($verifySig.Status)"
    exit 1
}
