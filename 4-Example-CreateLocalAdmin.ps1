<#
.SYNOPSIS
    Example: runs the 3 PKI scripts, then creates a local administrator with the decrypted password.
    Automatic, but it first shows the decrypted password and waits for your confirmation before
    creating the account (use -NoPause for a fully automatic run).

.DESCRIPTION
    1. 1-New-RootCA.ps1            creates the root CA (RootCA.cer / RootCA.pfx);
    2. 2-New-EncryptedPassword.ps1 creates the decryption certificate, signed by the root CA, and
                                   encrypts the password of the administrator;
    3. 3-Get-DecryptedPassword.ps1 decrypts the password with the root CA and the decryption
                                   certificate, and the result is compared with the original.
                                   The decrypted password is then displayed in clear and the script
                                   waits for a Y/N answer (skipped with -NoPause);
    4. creates the local user and adds it to the Administrators group (found by its SID, so it
       works whatever the language of Windows).

    Every password that is not given as a parameter is generated (24 characters for the account,
    32 for the PFX files, with upper and lower case letters, digits and symbols) and displayed once
    at the end, on the screen only: it is never written to a log. Passwords given as parameters are
    never displayed.

    This is an example: it works in its own folder (-OutputFolder, "Demo" by default), with its own
    root CA, and it does not touch the trusted root store unless -ImportRoot is used. The account
    it creates is marked in its description, so that -Cleanup removes only what this script made:
    the account, the root CA from the trusted root store (if it was imported) and the files.
    It refuses to run again while its files or its account exist: use -Cleanup first.

    The steps are logged in "4-Example-CreateLocalAdmin.log" (and in the log of each script).

.PARAMETER UserName
    Name of the local administrator to create (20 characters maximum). Default: "DemoAdmin".

.PARAMETER AdminPassword
    Password of the account (SecureString). Generated if not given.

.PARAMETER RootPfxPassword
    Password protecting RootCA.pfx (SecureString). Generated if not given.

.PARAMETER PfxPassword
    Password protecting the decryption certificate PFX (SecureString). Generated if not given.

.PARAMETER OutputFolder
    Folder of the certificates and of the encrypted password. Default: "Demo" next to the script.

.PARAMETER ImportRoot
    Also imports the root CA in the trusted root store of the computer (step 1 without -SkipImport).

.PARAMETER NoPause
    Does not show the decrypted password and does not wait for a confirmation before creating the
    account (fully automatic run).

.PARAMETER Cleanup
    Removes what this example created (account, root CA of the trusted root store, files) and stops.

.EXAMPLE
    .\4-Example-CreateLocalAdmin.ps1

    Creates the local administrator "DemoAdmin" with a generated password, shown at the end.

.EXAMPLE
    .\4-Example-CreateLocalAdmin.ps1 -UserName "LocalAdmin" -AdminPassword (Read-Host -AsSecureString)

    Creates "LocalAdmin" with the password you type; no password is displayed at the end.

.EXAMPLE
    .\4-Example-CreateLocalAdmin.ps1 -UserName LocalAdmin -NoPause

    Fully automatic: no confirmation is asked.

.EXAMPLE
    .\4-Example-CreateLocalAdmin.ps1 -Cleanup

    Removes everything the example created.

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Must be run as administrator.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$')] [string] $UserName = "DemoAdmin",
    [SecureString] $AdminPassword,
    [SecureString] $RootPfxPassword,
    [SecureString] $PfxPassword,
    [string] $OutputFolder = (Join-Path $PSScriptRoot "Demo"),
    [switch] $ImportRoot,
    [switch] $NoPause,
    [switch] $Cleanup
)

$ErrorActionPreference = "Stop"

# ============================================================================
# HELPERS
# ============================================================================
$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$LogFile    = Join-Path $PSScriptRoot "$ScriptName.log"
$Marker     = "Created by 4-Example-CreateLocalAdmin.ps1"   # description of the account (48 characters maximum)

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

# Writes the error to the log and the console, then stops the script
function Stop-Script([string] $Message) {
    Write-Log -Message $Message -Severity Error
    Write-Log -Message "===== $ScriptName stopped with an error =====" -Severity Error
    throw $Message
}

# Bytes (UTF-8) of a SecureString; the caller clears them
function ConvertTo-PlainBytes([SecureString] $Secure) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# Plain text of a SecureString (for display only)
function ConvertTo-PlainText([SecureString] $Secure) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
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

# Random number in [0, Max) from the operating system generator, without modulo bias
function Get-RandomNumber([System.Security.Cryptography.RandomNumberGenerator] $Rng, [int] $Max) {
    $buffer = New-Object byte[] 4
    $limit  = [uint64]4294967296 - ([uint64]4294967296 % [uint64]$Max)
    do { $Rng.GetBytes($buffer); $value = [uint64][BitConverter]::ToUInt32($buffer, 0) } while ($value -ge $limit)
    [int]($value % [uint64]$Max)
}

# Random password with at least one upper case letter, lower case letter, digit and symbol
function New-RandomPassword([int] $Length = 24) {
    $sets = @("ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnpqrstuvwxyz", "23456789", "!#%&*+-=?@^_")
    $all  = $sets -join ""
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $chars = New-Object System.Collections.Generic.List[char]
        foreach ($set in $sets) { $chars.Add($set[(Get-RandomNumber $rng $set.Length)]) }
        while ($chars.Count -lt $Length) { $chars.Add($all[(Get-RandomNumber $rng $all.Length)]) }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {   # Fisher-Yates shuffle
            $j = Get-RandomNumber $rng ($i + 1)
            $temp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $temp
        }
        -join $chars
    }
    finally { $rng.Dispose() }
}

# Draws a box on the console
function Show-Box([string[]] $Lines, [string] $Color = "Green") {
    $width  = ($Lines | Measure-Object -Property Length -Maximum).Maximum + 4
    $border = "+" + ("-" * $width) + "+"
    Write-Host ""
    Write-Host $border -ForegroundColor $Color
    foreach ($line in $Lines) { Write-Host ("|  " + $line.PadRight($width - 2) + "|") -ForegroundColor $Color }
    Write-Host $border -ForegroundColor $Color
    Write-Host ""
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

$Step1 = Join-Path $PSScriptRoot "1-New-RootCA.ps1"
$Step2 = Join-Path $PSScriptRoot "2-New-EncryptedPassword.ps1"
$Step3 = Join-Path $PSScriptRoot "3-Get-DecryptedPassword.ps1"
foreach ($script in $Step1, $Step2, $Step3) {
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { Stop-Script "Script not found: '$script'." }
}

$Name    = "$UserName-Password"   # base name of the files of step 2
$RootCer = Join-Path $OutputFolder "RootCA.cer"
$RootPfx = Join-Path $OutputFolder "RootCA.pfx"
$Json    = Join-Path $OutputFolder "$Name.json"
$LeafCer = Join-Path $OutputFolder "$Name.cer"
$LeafPfx = Join-Path $OutputFolder "$Name.pfx"
$Files   = $RootCer, $RootPfx, $Json, $LeafCer, $LeafPfx

# ============================================================================
# CLEANUP
# ============================================================================
if ($Cleanup) {
    Write-Status "Removing what the example created..."

    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Status "   Local user '$UserName': not found."
    } elseif ($user.Description -ne $Marker) {
        Write-Status "   Local user '$UserName' was not created by this example: it is not removed." "Yellow" "Warning"
    } else {
        Remove-LocalUser -Name $UserName
        Write-Status "   Local user '$UserName' removed." "Green"
    }

    if (Test-Path -LiteralPath $RootCer) {
        $thumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($RootCer)).Thumbprint
        if (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $thumbprint }) {
            Remove-Item -Path "Cert:\LocalMachine\Root\$thumbprint" -Force
            Write-Status "   Root CA $thumbprint removed from the trusted root store." "Green"
        }
    }

    foreach ($file in $Files) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force; Write-Status "   File removed: $file" "Green" }
    }
    if ((Test-Path -LiteralPath $OutputFolder) -and -not (Get-ChildItem -LiteralPath $OutputFolder -Force)) {
        Remove-Item -LiteralPath $OutputFolder -Force
        Write-Status "   Empty folder removed: $OutputFolder" "Green"
    }

    Write-Status "Cleanup done." "Green"
    Write-Log -Message "===== $ScriptName completed ====="
    return
}

# ============================================================================
# CHECKS BEFORE CREATING ANYTHING
# ============================================================================
$existingFiles = @($Files | Where-Object { Test-Path -LiteralPath $_ })
if ($existingFiles.Count -gt 0) {
    Stop-Script "The example already ran here ($($existingFiles.Count) file(s) exist in '$OutputFolder'). Run it with -Cleanup first."
}
if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
    Stop-Script "The local user '$UserName' already exists. Choose another -UserName, or run -Cleanup if this example created it."
}

# ============================================================================
# PASSWORDS: given as parameters, or generated
# ============================================================================
$generated = [ordered]@{}   # what is displayed at the end (only what was generated)
if (-not $AdminPassword) {
    $plain = New-RandomPassword 24
    $AdminPassword = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $generated["Password of $UserName"] = $plain
}
if (-not $RootPfxPassword) {
    $plain = New-RandomPassword 32
    $RootPfxPassword = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $generated["Password of RootCA.pfx"] = $plain
}
if (-not $PfxPassword) {
    $plain = New-RandomPassword 32
    $PfxPassword = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $generated["Password of $Name.pfx"] = $plain
}
$plain = $null
Write-Log -Message "Passwords: $($generated.Count) generated, $(3 - $generated.Count) given (the values are never logged)."

# ============================================================================
# THE 3 SCRIPTS, THEN THE LOCAL ADMINISTRATOR
# ============================================================================
try {
    Write-Status "[1/4] Root CA..."
    $root = & $Step1 -OutputFolder $OutputFolder -Subject "CN=Demo Root CA ($env:COMPUTERNAME)" -PfxPassword $RootPfxPassword -SkipImport:(-not $ImportRoot) 6>$null
    Write-Status "      Root CA $($root.Thumbprint)$(if ($root.Imported) { ', imported in the trusted root store' } else { ', not imported in the trusted root store' })." "Green"

    Write-Status "[2/4] Decryption certificate and encrypted password..."
    $leaf = & $Step2 -OutputFolder $OutputFolder -Name $Name -Subject "CN=Password Decryption - $UserName" `
                     -Password $AdminPassword -RootPfxPassword $RootPfxPassword -PfxPassword $PfxPassword 6>$null
    Write-Status "      Certificate $($leaf.CertificateThumbprint), password encrypted in '$Json'." "Green"

    Write-Status "[3/4] Decryption with the root CA and the certificate..."
    $decrypted = & $Step3 -EncryptedPasswordPath $Json -RootCertificatePath $RootCer -PfxPath $LeafPfx -PfxPassword $PfxPassword
    if ($decrypted -isnot [System.Security.SecureString]) { Stop-Script "Step 3 did not return the decrypted password." }
    if (-not (Test-SecureStringEqual $decrypted $AdminPassword)) { Stop-Script "The decrypted password is not the original one." }
    Write-Status "      Password decrypted, identical to the original." "Green"

    # --- Pause: shows the decrypted password in clear, to check that it is the starting password ---
    if (-not $NoPause) {
        $shown = ConvertTo-PlainText $decrypted
        Show-Box @("Password decrypted by step 3 (this is the one the account will get):", "", "  $shown", "",
                   "Length: $($shown.Length) characters. Check that it is the password you gave.") "Yellow"
        $shown = $null
        Write-Log -Message "Decrypted password displayed on screen for confirmation (the value is not logged)."
        do { $answer = (Read-Host -Prompt "Create the local administrator '$UserName' with this password? [Y/N]").Trim() } until ($answer -match '^[YyNnOo]')
        if ($answer -match '^[Nn]') { Stop-Script "Cancelled before creating the account." }
    }

    Write-Status "[4/4] Local administrator '$UserName'..."
    New-LocalUser -Name $UserName -Password $decrypted -FullName "$UserName (example)" -Description $Marker `
                  -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -SID "S-1-5-32-544" -Member $UserName
    $administrators = (Get-LocalGroup -SID "S-1-5-32-544").Name
    $isMember = $false; $checked = $true
    try   { $isMember = [bool](Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | Where-Object { $_.Name -like "*\$UserName" }) }
    catch { $checked = $false; Write-Status "      Membership not checked: $($_.Exception.Message)" "Yellow" "Warning" }
    if ($checked -and -not $isMember) { Stop-Script "'$UserName' is not a member of the group '$administrators'." }
    Write-Status "      '$UserName' created and member of '$administrators'." "Green"
}
catch {
    Write-Log -Message "Failed: $($_.Exception.Message)" -Severity Error
    Write-Host "The example stopped: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Run .\$([System.IO.Path]::GetFileName($PSCommandPath)) -UserName $UserName -Cleanup to remove what was created." -ForegroundColor Yellow
    throw
}

# ============================================================================
# END
# ============================================================================
$lines = @("Local administrator created", "", "User name : $UserName", "Folder    : $OutputFolder")
if ($generated.Count -gt 0) {
    $lines += ""
    $lines += "Generated passwords (shown once, keep them safely):"
    foreach ($key in $generated.Keys) { $lines += "  $key = $($generated[$key])" }
}
Show-Box $lines
Write-Host "To get the password again (the PFX password is asked):" -ForegroundColor Cyan
Write-Host "  .\3-Get-DecryptedPassword.ps1 -EncryptedPasswordPath '$Json' ``" -ForegroundColor Gray
Write-Host "      -RootCertificatePath '$RootCer' -PfxPath '$LeafPfx'" -ForegroundColor Gray
Write-Host "To remove everything:" -ForegroundColor Cyan
Write-Host "  .\$([System.IO.Path]::GetFileName($PSCommandPath)) -UserName $UserName -Cleanup" -ForegroundColor Gray
Write-Host ""
Write-Log -Message "Local administrator '$UserName' created (the passwords are not logged)."
Write-Log -Message "===== $ScriptName completed ====="
