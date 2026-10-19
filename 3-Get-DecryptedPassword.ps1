<#
.SYNOPSIS
    Step 3 of 3: decrypts a password with the root CA certificate and the decryption certificate.

.DESCRIPTION
    1. Opens the decryption certificate with its private key: from a PFX file (-PfxPath and its
       password), or from a certificate store (-Thumbprint).
    2. Checks that this certificate was issued by the root CA given in -RootCertificatePath: the
       certification chain must end on that exact root certificate, the signatures and the
       validity dates must be correct, and the certificate must not be a CA. Revocation is not
       checked (the certificates have no revocation list).
    3. Checks that the encrypted password was made for this certificate and this root CA.
    4. Decrypts the AES key with the private key (RSA-OAEP, SHA-256), checks the HMAC-SHA256 of the
       envelope (any change is refused), then decrypts the password (AES-256-CBC).

    The script must be run as administrator: it stops at once with an error otherwise.

    By default the password is returned as a SecureString. Use -AsPlainText to get a string.
    The password is never written to the log.
    Every step is written to "3-Get-DecryptedPassword.log" next to the script (CMTrace format);
    if that folder is not writable, nothing is logged.

.PARAMETER EncryptedPasswordPath
    Encrypted password file created by step 2. Default: Certificates\PasswordDecryption.json.

.PARAMETER RootCertificatePath
    Public certificate of the root CA (created by step 1). Default: Certificates\RootCA.cer.

.PARAMETER PfxPath
    Decryption certificate with its private key. Default: Certificates\PasswordDecryption.pfx.

.PARAMETER PfxPassword
    Password of the PFX (SecureString). Asked if not given.

.PARAMETER Thumbprint
    Thumbprint of a decryption certificate installed with its private key in the LocalMachine or
    CurrentUser "My" store (use it instead of -PfxPath).

.PARAMETER AsPlainText
    Returns the password as a plain text string instead of a SecureString.

.EXAMPLE
    $secure = .\3-Get-DecryptedPassword.ps1

    Decrypts with the default files (the PFX password is asked) and returns a SecureString.

.EXAMPLE
    .\3-Get-DecryptedPassword.ps1 -EncryptedPasswordPath D:\PKI\LocalAdmin.json -PfxPath D:\PKI\LocalAdmin.pfx -RootCertificatePath D:\PKI\RootCA.cer -AsPlainText

    Decrypts the password of another set of files and returns it as plain text.

.EXAMPLE
    .\3-Get-DecryptedPassword.ps1 -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567

    Uses a decryption certificate installed in a certificate store (no PFX password needed).

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Must be run as administrator.
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = "Pfx")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "EncryptedPasswordPath", Justification = "This is the path of a file, not a password.")]
param(
    [string] $EncryptedPasswordPath = (Join-Path $PSScriptRoot "Certificates\PasswordDecryption.json"),
    [string] $RootCertificatePath   = (Join-Path $PSScriptRoot "Certificates\RootCA.cer"),
    [Parameter(ParameterSetName = "Pfx")]   [string] $PfxPath = (Join-Path $PSScriptRoot "Certificates\PasswordDecryption.pfx"),
    [Parameter(ParameterSetName = "Pfx")]   [SecureString] $PfxPassword,
    [Parameter(Mandatory, ParameterSetName = "Store")] [string] $Thumbprint,
    [switch] $AsPlainText
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

# Writes the error to the log, then stops the script
function Stop-Script([string] $Message) {
    Write-Log -Message $Message -Severity Error
    Write-Log -Message "===== $ScriptName stopped with an error =====" -Severity Error
    throw $Message
}

# Compares two byte arrays without leaking where they differ
function Test-FixedTimeEqual([byte[]] $A, [byte[]] $B) {
    $diff = $A.Length -bxor $B.Length
    for ($i = 0; $i -lt [Math]::Min($A.Length, $B.Length); $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
    $diff -eq 0
}

# Input of the HMAC: the same one as step 2
function Get-MacInput([string] $CertificateThumbprint, [string] $RootThumbprint, [byte[]] $Iv, [byte[]] $CipherText) {
    $header = [System.Text.Encoding]::UTF8.GetBytes("PKI-PASSWORD-ENVELOPE|1|$CertificateThumbprint|$RootThumbprint|")
    $stream = New-Object System.IO.MemoryStream
    foreach ($part in $header, $Iv, $CipherText) { $stream.Write($part, 0, $part.Length) }
    , $stream.ToArray()
}

# Loads a PFX without keeping its private key on the disk of this computer
function Open-Pfx([string] $Path, [SecureString] $Secret) {
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    try { $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet } catch { }
    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path, $Secret, $flags)
}

# ============================================================================
# DECRYPTION
# ============================================================================
Write-Log -Message "===== $ScriptName started ====="
Write-Log -Message "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) on $env:COMPUTERNAME, PowerShell $($PSVersionTable.PSVersion)"

# --- Run as administrator ---
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Script "This script must be run as administrator (right-click > Run as administrator, or an elevated PowerShell)."
}
Write-Log -Message "Running as administrator: OK"

$Leaf = $null; $Root = $null
$keyMaterial = $null; $plain = $null
try {
    # --- Files ---
    foreach ($file in $EncryptedPasswordPath, $RootCertificatePath) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Stop-Script "File not found: '$file'." }
    }
    try {
        $envelope = Get-Content -LiteralPath $EncryptedPasswordPath -Raw | ConvertFrom-Json
    }
    catch { Stop-Script "'$EncryptedPasswordPath' is not a valid encrypted password file." }

    $expected = [ordered]@{ format = "PKI-PASSWORD-ENVELOPE"; version = 1; keyTransport = "RSA-OAEP-SHA256"; encryption = "AES-256-CBC"; authentication = "HMAC-SHA256" }
    foreach ($key in $expected.Keys) {
        if ($envelope.$key -ne $expected[$key]) { Stop-Script "Unsupported encrypted password file: '$key' must be '$($expected[$key])'." }
    }

    # --- Root CA certificate ---
    $Root = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($RootCertificatePath)
    $basic = $Root.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
    if ($Root.Subject -ne $Root.Issuer -or -not $basic -or -not $basic.CertificateAuthority) {
        Stop-Script "'$RootCertificatePath' is not a self-signed root CA certificate."
    }
    Write-Log -Message "Root CA: $($Root.Subject), thumbprint $($Root.Thumbprint)"

    # --- Decryption certificate with its private key ---
    if ($PSCmdlet.ParameterSetName -eq "Store") {
        $wanted = ($Thumbprint -replace "\s", "").ToUpperInvariant()
        $Leaf = foreach ($location in "Cert:\LocalMachine\My", "Cert:\CurrentUser\My") {
            Get-ChildItem $location | Where-Object { $_.Thumbprint -eq $wanted -and $_.HasPrivateKey } | Select-Object -First 1
        }
        $Leaf = @($Leaf)[0]
        if (-not $Leaf) { Stop-Script "No certificate with a private key and thumbprint $wanted in the 'My' stores." }
    } else {
        if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) { Stop-Script "File not found: '$PfxPath'." }
        if (-not $PfxPassword) { $PfxPassword = Read-Host -Prompt "Password of '$(Split-Path $PfxPath -Leaf)'" -AsSecureString }
        try { $Leaf = Open-Pfx $PfxPath $PfxPassword }
        catch { Stop-Script "Unable to open '$PfxPath': wrong password or invalid file." }
        if (-not $Leaf.HasPrivateKey) { Stop-Script "'$PfxPath' does not contain a private key." }
    }
    Write-Log -Message "Decryption certificate: $($Leaf.Subject), thumbprint $($Leaf.Thumbprint)"

    # --- The decryption certificate must come from this root CA ---
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    [void]$chain.ChainPolicy.ExtraStore.Add($Root)
    $null = $chain.Build($Leaf)
    $top = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    if ($top.Thumbprint -ne $Root.Thumbprint) {
        Stop-Script "The decryption certificate was not issued by the root CA '$($Root.Subject)' ($($Root.Thumbprint))."
    }
    # UntrustedRoot is accepted: the root CA is the file given by the caller (it is pinned above)
    $problems = @($chain.ChainStatus | Where-Object { $_.Status -notin "NoError", "UntrustedRoot" })
    if ($problems.Count -gt 0) {
        Stop-Script "The certification chain is not valid: $(($problems | ForEach-Object { $_.StatusInformation.Trim() }) -join '; ')"
    }
    $basicLeaf = $Leaf.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
    $usage     = $Leaf.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] }
    if (($basicLeaf -and $basicLeaf.CertificateAuthority) -or -not $usage -or
        -not ($usage.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment)) {
        Stop-Script "The certificate is not a decryption certificate (CA, or no 'Key Encipherment' usage)."
    }
    Write-Log -Message "Certification chain valid, root CA $($Root.Thumbprint)."

    # --- The password must have been encrypted for these two certificates ---
    if ($envelope.certificateThumbprint -ne $Leaf.Thumbprint) {
        Stop-Script "This password was encrypted for another certificate ($($envelope.certificateThumbprint))."
    }
    if ($envelope.rootThumbprint -ne $Root.Thumbprint) {
        Stop-Script "This password belongs to another root CA ($($envelope.rootThumbprint))."
    }

    # --- Keys: RSA-OAEP unwrapping with the private key ---
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Leaf)
    try {
        $keyMaterial = $rsa.Decrypt([Convert]::FromBase64String($envelope.encryptedKey), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }
    catch { Stop-Script "The key of the encrypted password cannot be decrypted with this certificate." }
    finally { if ($rsa) { $rsa.Dispose() } }
    if ($keyMaterial.Length -ne 64) { Stop-Script "Invalid encrypted password file (key size)." }
    $encKey = New-Object byte[] 32; [Array]::Copy($keyMaterial, 0, $encKey, 0, 32)
    $macKey = New-Object byte[] 32; [Array]::Copy($keyMaterial, 32, $macKey, 0, 32)

    # --- Integrity: HMAC-SHA256, checked before any decryption ---
    $iv         = [Convert]::FromBase64String($envelope.iv)
    $cipherText = [Convert]::FromBase64String($envelope.ciphertext)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$macKey)
    try { $mac = $hmac.ComputeHash((Get-MacInput $envelope.certificateThumbprint $envelope.rootThumbprint $iv $cipherText)) }
    finally { $hmac.Dispose() }
    if (-not (Test-FixedTimeEqual $mac ([Convert]::FromBase64String($envelope.mac)))) {
        Stop-Script "Integrity check failed: the encrypted password was modified."
    }

    # --- Decryption: AES-256-CBC ---
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256; $aes.Mode = "CBC"; $aes.Padding = "PKCS7"; $aes.Key = $encKey; $aes.IV = $iv
        $plain = $aes.CreateDecryptor().TransformFinalBlock($cipherText, 0, $cipherText.Length)
    }
    finally { $aes.Dispose() }
    $text = [System.Text.Encoding]::UTF8.GetString($plain)
    Write-Log -Message "Password decrypted (the value is not logged)."

    if ($AsPlainText) { $output = $text } else { $output = ConvertTo-SecureString -String $text -AsPlainText -Force }
}
finally {
    foreach ($secret in $keyMaterial, $encKey, $macKey, $plain) { if ($secret) { [Array]::Clear($secret, 0, $secret.Length) } }
    foreach ($cert in $Leaf, $Root) { if ($cert -and $PSCmdlet.ParameterSetName -eq "Pfx") { $cert.Dispose() } }
}

Write-Log -Message "===== $ScriptName completed ====="
$output
