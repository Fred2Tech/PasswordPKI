<#
.SYNOPSIS
    Step 2 of 3: encrypts a password and creates the certificate that decrypts it.

.DESCRIPTION
    1. Opens the root CA (RootCA.pfx, created by step 1) in a temporary way.
    2. Issues a decryption certificate signed by the root CA: RSA 4096, SHA-384, key usage
       "Key Encipherment" + "Data Encipherment", "Document Encryption" purpose, not a CA.
    3. Encrypts the password for this certificate with a hybrid envelope:
       - the data is encrypted with AES-256 (CBC) using a random key;
       - the AES key is encrypted with the RSA public key of the certificate (RSA-OAEP, SHA-256);
       - an HMAC-SHA256 (with another random key) protects the whole envelope, so any change is
         detected before decryption (encrypt-then-MAC).
    4. Writes three files in -OutputFolder:
       <Name>.json  the encrypted password;
       <Name>.cer   the public certificate;
       <Name>.pfx   the certificate with its private key (AES-256 / SHA-256, protected by a
                    password): it is what decrypts the password, protect it.
    5. Deletes the root key and the decryption key from this computer.

    The script must be run as administrator: it stops at once with an error otherwise.

    Step 3 (3-Get-DecryptedPassword.ps1) decrypts the password with the root CA certificate and
    the decryption certificate. The password is never written to the log.
    Every step is written to "2-New-EncryptedPassword.log" next to the script (CMTrace format).

.PARAMETER Password
    Password to encrypt (SecureString). Asked twice if not given.

.PARAMETER RootPfxPath
    Root CA with its private key. Default: RootCA.pfx in -OutputFolder (where step 1 wrote it).

.PARAMETER RootPfxPassword
    Password of the root PFX (SecureString). Asked if not given.

.PARAMETER Subject
    Subject of the decryption certificate. Default: "CN=Password Decryption".

.PARAMETER ValidityYears
    Validity of the decryption certificate, in years (never longer than the root CA). Default: 2.

.PARAMETER KeyLength
    RSA key length: 3072 or 4096. Default: 4096.

.PARAMETER OutputFolder
    Folder of the three files. Default: "Certificates" next to the script.

.PARAMETER Name
    Base name of the three files. Default: "PasswordDecryption".

.PARAMETER PfxPassword
    Password protecting <Name>.pfx (SecureString, 12 characters minimum). Asked twice if not given.

.PARAMETER Force
    Overwrites existing files.

.EXAMPLE
    .\2-New-EncryptedPassword.ps1

    Asks for the password to encrypt and the two PFX passwords.

.EXAMPLE
    .\2-New-EncryptedPassword.ps1 -Name "LocalAdmin" -ValidityYears 1 -OutputFolder "D:\PKI"

    Creates D:\PKI\LocalAdmin.json, LocalAdmin.cer and LocalAdmin.pfx (valid for 1 year).

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Must be run as administrator.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [SecureString] $Password,
    [string] $RootPfxPath,
    [SecureString] $RootPfxPassword,
    [string] $Subject = "CN=Password Decryption",
    [ValidateRange(1, 30)] [int] $ValidityYears = 2,
    [ValidateSet(3072, 4096)] [int] $KeyLength = 4096,
    [string] $OutputFolder = (Join-Path $PSScriptRoot "Certificates"),
    [ValidatePattern('^[\w\-. ]+$')] [string] $Name = "PasswordDecryption",
    [SecureString] $PfxPassword,
    [switch] $Force
)

$ErrorActionPreference = "Stop"

# The root CA is looked for in the output folder, like step 1 wrote it
if (-not $RootPfxPath) { $RootPfxPath = Join-Path $OutputFolder "RootCA.pfx" }

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
function Read-NewPassword([string] $Prompt, [int] $MinLength = 1) {
    while ($true) {
        $first = Read-Host -Prompt $Prompt -AsSecureString
        if ($first.Length -lt $MinLength) {
            Write-Host "   The password must have at least $MinLength character(s)." -ForegroundColor Yellow
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

# Random bytes from the operating system generator
function New-RandomBytes([int] $Count) {
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    , $bytes
}

# Input of the HMAC: format, version, both thumbprints, IV and ciphertext. Step 3 builds the same one.
function Get-MacInput([string] $CertificateThumbprint, [string] $RootThumbprint, [byte[]] $Iv, [byte[]] $CipherText) {
    $header = [System.Text.Encoding]::UTF8.GetBytes("PKI-PASSWORD-ENVELOPE|1|$CertificateThumbprint|$RootThumbprint|")
    $stream = New-Object System.IO.MemoryStream
    foreach ($part in $header, $Iv, $CipherText) { $stream.Write($part, 0, $part.Length) }
    , $stream.ToArray()
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

if (-not (Test-Path -LiteralPath $RootPfxPath -PathType Leaf)) {
    Stop-Script "Root CA file not found: '$RootPfxPath'. Run 1-New-RootCA.ps1 first, or use -RootPfxPath."
}

$CerPath  = Join-Path $OutputFolder "$Name.cer"
$PfxPath  = Join-Path $OutputFolder "$Name.pfx"
$JsonPath = Join-Path $OutputFolder "$Name.json"
foreach ($file in $CerPath, $PfxPath, $JsonPath) {
    if ((Test-Path -LiteralPath $file) -and -not $Force) {
        Stop-Script "'$file' already exists. Use -Force to replace it, or another -Name."
    }
}

if (-not $RootPfxPassword) { $RootPfxPassword = Read-Host -Prompt "Password of '$(Split-Path $RootPfxPath -Leaf)'" -AsSecureString }
if (-not $Password)        { $Password = Read-NewPassword "Password to encrypt" }
if ($PfxPassword) {
    if ($PfxPassword.Length -lt 12) { Stop-Script "The PFX password must have at least 12 characters." }
} else {
    $PfxPassword = Read-NewPassword "Password protecting $Name.pfx (12 characters minimum)" 12
}

if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

# ============================================================================
# CERTIFICATE AND ENCRYPTION
# ============================================================================
# The root and the decryption certificate live in the store of the current user only during this
# step: both are removed with their private keys at the end, even if something fails.
$Root = $null
$Leaf = $null
$plain = $null; $encKey = $null; $macKey = $null; $keyMaterial = $null
try {
    # --- Root CA ---
    Write-Status "Opening the root CA..."
    try {
        $Root = Import-PfxCertificate -FilePath $RootPfxPath -Password $RootPfxPassword -CertStoreLocation "Cert:\CurrentUser\My"
    }
    catch {
        Stop-Script "Unable to open '$RootPfxPath' (wrong password?): $($_.Exception.Message)"
    }
    $Root = @($Root)[0]
    $basic = $Root.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
    if (-not $Root.HasPrivateKey -or -not $basic -or -not $basic.CertificateAuthority) {
        Stop-Script "'$RootPfxPath' is not a root CA with its private key."
    }
    if ($Root.NotAfter -lt (Get-Date).AddDays(2)) {
        Stop-Script "The root CA '$($Root.Subject)' expires on $($Root.NotAfter.ToString('yyyy-MM-dd')): create a new one."
    }
    Write-Log -Message "Root CA: $($Root.Subject), thumbprint $($Root.Thumbprint)"

    # --- Decryption certificate, signed by the root CA ---
    $notAfter = (Get-Date).AddYears($ValidityYears)
    if ($notAfter -gt $Root.NotAfter.AddDays(-1)) {
        $notAfter = $Root.NotAfter.AddDays(-1)
        Write-Status "The root CA ends on $($Root.NotAfter.ToString('yyyy-MM-dd')): the certificate is limited to $($notAfter.ToString('yyyy-MM-dd'))." "Yellow" "Warning"
    }
    Write-Status "Creating the decryption certificate '$Subject' (RSA $KeyLength, SHA-384, until $($notAfter.ToString('yyyy-MM-dd')))..."
    $Leaf = New-SelfSignedCertificate -Type Custom -Subject $Subject -Signer $Root `
        -KeyAlgorithm RSA -KeyLength $KeyLength -HashAlgorithm SHA384 `
        -KeyExportPolicy ExportableEncrypted `
        -KeyUsage KeyEncipherment, DataEncipherment `
        -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.80.1", "2.5.29.19={critical}{text}CA=false") `
        -NotBefore (Get-Date).AddMinutes(-5) -NotAfter $notAfter `
        -CertStoreLocation "Cert:\CurrentUser\My"
    Write-Log -Message "Decryption certificate created, thumbprint $($Leaf.Thumbprint)"

    Export-Certificate -Cert $Leaf -FilePath $CerPath -Type CERT -Force | Out-Null
    Export-PfxCertificate -Cert $Leaf -FilePath $PfxPath -Password $PfxPassword `
        -CryptoAlgorithmOption AES256_SHA256 -ChainOption EndEntityCertOnly -Force | Out-Null

    # --- Encryption: AES-256-CBC + HMAC-SHA256, keys wrapped with RSA-OAEP-SHA256 ---
    Write-Status "Encrypting the password..."
    $plain       = ConvertTo-PlainBytes $Password
    $encKey      = New-RandomBytes 32
    $macKey      = New-RandomBytes 32
    $iv          = New-RandomBytes 16

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256; $aes.Mode = "CBC"; $aes.Padding = "PKCS7"; $aes.Key = $encKey; $aes.IV = $iv
        $encryptor  = $aes.CreateEncryptor()
        $cipherText = $encryptor.TransformFinalBlock($plain, 0, $plain.Length)
    }
    finally { $aes.Dispose() }

    $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$macKey)
    try { $mac = $hmac.ComputeHash((Get-MacInput $Leaf.Thumbprint $Root.Thumbprint $iv $cipherText)) }
    finally { $hmac.Dispose() }

    $keyMaterial = New-Object byte[] 64
    [Array]::Copy($encKey, 0, $keyMaterial, 0, 32)
    [Array]::Copy($macKey, 0, $keyMaterial, 32, 32)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Leaf)
    try { $wrappedKey = $rsa.Encrypt($keyMaterial, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256) }
    finally { $rsa.Dispose() }

    $envelope = [ordered]@{
        format                = "PKI-PASSWORD-ENVELOPE"
        version               = 1
        keyTransport          = "RSA-OAEP-SHA256"
        encryption            = "AES-256-CBC"
        authentication        = "HMAC-SHA256"
        certificateThumbprint = $Leaf.Thumbprint
        rootThumbprint        = $Root.Thumbprint
        created               = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        encryptedKey          = [Convert]::ToBase64String($wrappedKey)
        iv                    = [Convert]::ToBase64String($iv)
        ciphertext            = [Convert]::ToBase64String($cipherText)
        mac                   = [Convert]::ToBase64String($mac)
    }
    [System.IO.File]::WriteAllText($JsonPath, ($envelope | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

    $result = [PSCustomObject]@{
        Subject               = $Leaf.Subject
        CertificateThumbprint = $Leaf.Thumbprint
        RootThumbprint        = $Root.Thumbprint
        NotAfter              = $Leaf.NotAfter
        JsonPath              = $JsonPath
        CerPath               = $CerPath
        PfxPath               = $PfxPath
    }
}
finally {
    # Secrets are cleared from memory, certificates and keys are removed from this computer
    foreach ($secret in $plain, $encKey, $macKey, $keyMaterial) { if ($secret) { [Array]::Clear($secret, 0, $secret.Length) } }
    foreach ($cert in $Leaf, $Root) {
        if ($cert) { Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -Force -ErrorAction SilentlyContinue }
    }
    Write-Log -Message "Temporary certificates and private keys removed from this computer."
}

# ============================================================================
# END
# ============================================================================
Write-Status "Encrypted password : $JsonPath" "Green"
Write-Status "Public certificate : $CerPath" "Green"
Write-Status "Decryption key     : $PfxPath (protect it and its password)" "Green"
Write-Status "Decrypt it with 3-Get-DecryptedPassword.ps1 and the root CA certificate (RootCA.cer)." "Yellow"
Write-Log -Message "===== $ScriptName completed ====="

$result
