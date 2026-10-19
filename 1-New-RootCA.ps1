<#
.SYNOPSIS
    Step 1 of 3: creates a root CA certificate and imports it as a trusted root.

.DESCRIPTION
    Creates a root certification authority with strong settings:
    - RSA 4096 key, SHA-384 signature;
    - CA certificate with path length 0 (it can only issue end-entity certificates),
      key usage "Certificate Signing" and "CRL Signing" only;
    - validity of -ValidityYears years.

    Then:
    - exports the public certificate to RootCA.cer;
    - exports the private key to RootCA.pfx, encrypted with AES-256 / SHA-256 and protected by a
      password (at least 12 characters);
    - deletes the private key from this computer: the PFX file is the only copy of the key.
      Keep it offline, with its password. Without it no certificate can be issued any more;
    - imports RootCA.cer in the "Trusted Root Certification Authorities" store of the computer
      (use -SkipImport to skip this step).

    The script must be run as administrator: it stops at once with an error otherwise.

    Steps 2 (2-New-EncryptedPassword.ps1) and 3 (3-Get-DecryptedPassword.ps1) use these files.
    Every step is written to "1-New-RootCA.log" next to the script (CMTrace format).

.PARAMETER Subject
    Subject of the root certificate. Default: "CN=Lab Root CA".

.PARAMETER ValidityYears
    Validity of the root certificate, in years. Default: 10.

.PARAMETER KeyLength
    RSA key length: 3072 or 4096. Default: 4096.

.PARAMETER OutputFolder
    Folder of RootCA.cer and RootCA.pfx. Default: "Certificates" next to the script.

.PARAMETER PfxPassword
    Password protecting RootCA.pfx (SecureString). Asked twice if not given.

.PARAMETER SkipImport
    Does not import the certificate in the trusted root store. Administrator rights are still required.

.PARAMETER Force
    Overwrites an existing RootCA.cer / RootCA.pfx.

.EXAMPLE
    .\1-New-RootCA.ps1

    Creates the root CA with the default settings and asks for the PFX password.

.EXAMPLE
    .\1-New-RootCA.ps1 -Subject "CN=Contoso Root CA" -ValidityYears 15 -OutputFolder "D:\PKI"

    Creates a root CA valid for 15 years in D:\PKI.

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Must be run as administrator.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $Subject = "CN=Lab Root CA",
    [ValidateRange(1, 30)] [int] $ValidityYears = 10,
    [ValidateSet(3072, 4096)] [int] $KeyLength = 4096,
    [string] $OutputFolder = (Join-Path $PSScriptRoot "Certificates"),
    [SecureString] $PfxPassword,
    [switch] $SkipImport,
    [switch] $Force
)

$ErrorActionPreference = "Stop"

# ============================================================================
# HELPERS
# ============================================================================
$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$LogFile    = Join-Path $PSScriptRoot "$ScriptName.log"

# Writes a CMTrace log line (a log failure never stops the script)
function Write-Log([string] $Message, [ValidateSet("Info", "Warning", "Error")] [string] $Severity = "Info") {
    $type = @{ Info = 1; Warning = 2; Error = 3 }[$Severity]
    $line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="{5}" file="">' -f
        $Message, (Get-Date -Format "HH:mm:ss.ffffff"), (Get-Date -Format "MM-dd-yyyy"), $ScriptName, $type, $PID
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}

# Writes a message to the console and to the log
function Write-Status([string] $Message, [string] $Color = "Cyan", [string] $Severity = "Info") {
    Write-Host $Message -ForegroundColor $Color
    Write-Log -Message $Message -Severity $Severity
}

# Bytes (UTF-8) of a SecureString; the caller clears them
function ConvertTo-PlainBytes([SecureString] $Secure) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# Compares two SecureStrings without leaking where they differ
function Test-SecureStringEqual([SecureString] $A, [SecureString] $B) {
    $x = ConvertTo-PlainBytes $A
    $y = ConvertTo-PlainBytes $B
    try {
        $diff = $x.Length -bxor $y.Length
        for ($i = 0; $i -lt [Math]::Min($x.Length, $y.Length); $i++) { $diff = $diff -bor ($x[$i] -bxor $y[$i]) }
        $diff -eq 0
    }
    finally { [Array]::Clear($x, 0, $x.Length); [Array]::Clear($y, 0, $y.Length) }
}

# Asks for a new password twice
function Read-NewPassword([string] $Prompt, [int] $MinLength = 12) {
    while ($true) {
        $first = Read-Host -Prompt $Prompt -AsSecureString
        if ($first.Length -lt $MinLength) {
            Write-Host "   The password must have at least $MinLength characters." -ForegroundColor Yellow
            continue
        }
        $second = Read-Host -Prompt "Confirm the password" -AsSecureString
        if (Test-SecureStringEqual $first $second) { return $first }
        Write-Host "   The two passwords do not match." -ForegroundColor Yellow
    }
}

# Writes the error to the log and the console, then stops the script
function Stop-Script([string] $Message) {
    Write-Log -Message $Message -Severity Error
    Write-Log -Message "===== $ScriptName stopped with an error =====" -Severity Error
    throw $Message
}

# ============================================================================
# CHECKS
# ============================================================================
Write-Log -Message "===== $ScriptName started ====="
Write-Log -Message "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) on $env:COMPUTERNAME, PowerShell $($PSVersionTable.PSVersion)"

# --- Run as administrator ---
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Script "This script must be run as administrator (right-click > Run as administrator, or an elevated PowerShell)."
}
Write-Log -Message "Running as administrator: OK"

$CerPath = Join-Path $OutputFolder "RootCA.cer"
$PfxPath = Join-Path $OutputFolder "RootCA.pfx"
foreach ($file in $CerPath, $PfxPath) {
    if ((Test-Path -LiteralPath $file) -and -not $Force) {
        Stop-Script "'$file' already exists. Use -Force to replace it (the previous root CA and everything it issued would no longer match)."
    }
}

if ($PfxPassword) {
    if ($PfxPassword.Length -lt 12) { Stop-Script "The PFX password must have at least 12 characters." }
} else {
    $PfxPassword = Read-NewPassword "Password protecting RootCA.pfx (12 characters minimum)"
}

if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

# ============================================================================
# ROOT CA
# ============================================================================
# The certificate is created in the store of the current user, only to export it: it is removed
# (with its private key) at the end, even if something fails.
$Root = $null
try {
    Write-Status "Creating the root CA '$Subject' (RSA $KeyLength, SHA-384, $ValidityYears year(s))..."
    $Root = New-SelfSignedCertificate -Type Custom -Subject $Subject `
        -KeyAlgorithm RSA -KeyLength $KeyLength -HashAlgorithm SHA384 `
        -KeyExportPolicy ExportableEncrypted `
        -KeyUsage CertSign, CRLSign `
        -TextExtension @("2.5.29.19={critical}{text}CA=true&pathlength=0") `
        -NotBefore (Get-Date).AddMinutes(-10) -NotAfter (Get-Date).AddYears($ValidityYears) `
        -CertStoreLocation "Cert:\CurrentUser\My"
    Write-Log -Message "Root CA created, thumbprint $($Root.Thumbprint)"

    Export-Certificate -Cert $Root -FilePath $CerPath -Type CERT -Force | Out-Null
    Export-PfxCertificate -Cert $Root -FilePath $PfxPath -Password $PfxPassword `
        -CryptoAlgorithmOption AES256_SHA256 -ChainOption EndEntityCertOnly -Force | Out-Null

    # The PFX must open with the password and contain this certificate
    $check = Get-PfxData -FilePath $PfxPath -Password $PfxPassword
    if (@($check.EndEntityCertificates)[0].Thumbprint -ne $Root.Thumbprint) {
        Stop-Script "The exported PFX does not contain the expected certificate."
    }
    Write-Status "Exported '$CerPath' (public certificate) and '$PfxPath' (private key, AES-256)." "Green"
}
finally {
    if ($Root) {
        Remove-Item -Path "Cert:\CurrentUser\My\$($Root.Thumbprint)" -DeleteKey -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Temporary certificate and private key removed from this computer."
    }
}

# ============================================================================
# IMPORT IN THE TRUSTED ROOT STORE
# ============================================================================
$Imported = $false
if ($SkipImport) {
    Write-Status "Import skipped (-SkipImport): import '$CerPath' later in the trusted root store." "Yellow" "Warning"
} else {
    $trusted = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $Root.Thumbprint })
    if ($trusted.Count -gt 0) {
        Write-Status "The root CA is already in the trusted root store." "Yellow"
    } else {
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $Root.Thumbprint })) {
            Stop-Script "The root CA was not found in the trusted root store after the import."
        }
        Write-Status "Root CA imported in Cert:\LocalMachine\Root." "Green"
    }
    $Imported = $true
}

# ============================================================================
# END
# ============================================================================
Write-Status "Thumbprint : $($Root.Thumbprint)"
Write-Status "Valid until: $($Root.NotAfter.ToString('yyyy-MM-dd'))"
Write-Status "Keep '$PfxPath' offline with its password: it is the only copy of the root private key." "Yellow"
Write-Log -Message "===== $ScriptName completed ====="

[PSCustomObject]@{
    Subject    = $Root.Subject
    Thumbprint = $Root.Thumbprint
    NotAfter   = $Root.NotAfter
    CerPath    = $CerPath
    PfxPath    = $PfxPath
    Imported   = $Imported
}
