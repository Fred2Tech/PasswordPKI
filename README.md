# Password PKI

Four PowerShell scripts that protect a password with a **private PKI** (a small certification authority of your own), so that it can be stored or shipped in a file and decrypted only by someone who holds the right certificate.

Typical use: provision a local administrator during a deployment without ever writing its password in clear text in a script or a task sequence.

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [The scripts](#the-scripts)
- [What goes where](#what-goes-where)
- [Encrypted file format](#encrypted-file-format)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## How it works

```
Step 1                         Step 2                                Step 3
1-New-RootCA.ps1               2-New-EncryptedPassword.ps1           3-Get-DecryptedPassword.ps1

 Root CA                        Decryption certificate                RootCA.cer      (who to trust)
 RootCA.pfx  --- signs --->     <Name>.pfx / <Name>.cer               <Name>.pfx      (private key)
 RootCA.cer                          |                                <Name>.json     (encrypted password)
                                     | encrypts the password                 |
                                     v                                       v
                                <Name>.json                            the password
```

1. **A root CA** is created. Its private key lives only in a password-protected file.
2. **A decryption certificate** is issued by that root CA, and the password is encrypted for it.
3. **To decrypt**, the script opens the decryption certificate, checks that it really was issued by *your* root CA, checks that the encrypted file was not modified, and only then decrypts.

A fourth script, `4-Example-CreateLocalAdmin.ps1`, runs the three steps and creates a local administrator with the decrypted password.

### Algorithms

| Purpose | Algorithm |
|---|---|
| Root and decryption keys | RSA 4096 (3072 possible with `-KeyLength`) |
| Certificate signatures | SHA-384 with RSA |
| Encryption of the password | AES-256 in CBC mode, random key and IV for every encryption |
| Protection of the AES key | RSA-OAEP with SHA-256, using the public key of the decryption certificate |
| Integrity (encrypt-then-MAC) | HMAC-SHA256 with a second, independent random key. It is checked **before** any decryption |
| `.pfx` files (private keys) | AES-256 with SHA-256 (PBES2 / PBKDF2), password of 12 characters minimum |
| Random numbers | The operating system generator (`RandomNumberGenerator`) |

The root CA certificate has the CA basic constraint with path length 0 (it can only issue end-entity certificates) and the key usages *Certificate Signing* and *CRL Signing* only. The decryption certificate is not a CA and has the key usages *Key Encipherment* and *Data Encipherment* and the *Document Encryption* purpose.

## Requirements

- Windows, with **Windows PowerShell 5.1** or **PowerShell 7**.
- **Run every script as administrator.** Each script checks it and stops with a clear message otherwise.
- Nothing to install: the scripts use the built-in `PKI` module and the .NET cryptography classes.

Tested on Windows Server 2025 with Windows PowerShell 5.1 and PowerShell 7.6. Files created in one edition can be used in the other.

## Quick start

```powershell
# 1. Create the root CA (a PFX password is asked)
.\1-New-RootCA.ps1

# 2. Create the decryption certificate and encrypt a password (the root PFX password, the password
#    to encrypt and a PFX password for the decryption certificate are asked)
.\2-New-EncryptedPassword.ps1

# 3. Decrypt it (the PFX password of the decryption certificate is asked)
$secure = .\3-Get-DecryptedPassword.ps1
```

Files are written to a `Certificates` folder next to the scripts. Each script also writes a log in the CMTrace format next to itself (for example `1-New-RootCA.log`). **Passwords are never written to a log.**

To try everything at once, with a local account:

```powershell
.\4-Example-CreateLocalAdmin.ps1
```

---

## The scripts

### 1-New-RootCA.ps1

Creates the root CA and makes this computer trust it.

1. Creates the root certificate (`CN=Lab Root CA` by default, 10 years).
2. Exports `RootCA.cer` (public certificate) and `RootCA.pfx` (private key, protected by a password).
3. **Deletes the private key from this computer**: `RootCA.pfx` is the only copy. Keep it offline.
4. Imports `RootCA.cer` in the *Trusted Root Certification Authorities* store of the computer.

| Parameter | Default | Description |
|---|---|---|
| `-Subject` | `CN=Lab Root CA` | Subject of the root certificate |
| `-ValidityYears` | `10` | Validity, 1 to 30 years |
| `-KeyLength` | `4096` | `3072` or `4096` |
| `-OutputFolder` | `Certificates` next to the script | Where `RootCA.cer` and `RootCA.pfx` are written |
| `-PfxPassword` | asked twice | Password of `RootCA.pfx` (`SecureString`, 12 characters minimum) |
| `-SkipImport` | | Does not import the root CA in the trusted root store |
| `-Force` | | Replaces existing files |

```powershell
.\1-New-RootCA.ps1 -Subject "CN=Contoso Root CA" -ValidityYears 15 -OutputFolder "D:\PKI"
.\1-New-RootCA.ps1 -OutputFolder "D:\PKI" -SkipImport      # do not touch the trusted root store
```

### 2-New-EncryptedPassword.ps1

Issues a decryption certificate signed by the root CA, then encrypts a password for it.

1. Opens `RootCA.pfx` temporarily (it never stays on the computer).
2. Issues the decryption certificate. Its validity never goes beyond the root CA.
3. Encrypts the password (see [Algorithms](#algorithms)).
4. Writes `<Name>.json`, `<Name>.cer` and `<Name>.pfx`, then removes both private keys from the computer.

| Parameter | Default | Description |
|---|---|---|
| `-Password` | asked twice | Password to encrypt (`SecureString`) |
| `-RootPfxPath` | `RootCA.pfx` in `-OutputFolder` | Root CA with its private key |
| `-RootPfxPassword` | asked | Password of the root PFX |
| `-Subject` | `CN=Password Decryption` | Subject of the decryption certificate |
| `-ValidityYears` | `2` | Validity, 1 to 30 years (limited by the root CA) |
| `-KeyLength` | `4096` | `3072` or `4096` |
| `-OutputFolder` | `Certificates` next to the script | Where the three files are written |
| `-Name` | `PasswordDecryption` | Base name of the three files |
| `-PfxPassword` | asked twice | Password of `<Name>.pfx` (12 characters minimum) |
| `-Force` | | Replaces existing files |

```powershell
.\2-New-EncryptedPassword.ps1 -Name "LocalAdmin" -ValidityYears 1 -OutputFolder "D:\PKI"
```

Use a different `-Name` for each password you want to encrypt: each one gets its own decryption certificate.

### 3-Get-DecryptedPassword.ps1

Decrypts a password. It returns a `SecureString`, or a plain text string with `-AsPlainText`.

Before decrypting, it checks that:

- the root file is a self-signed CA certificate;
- the decryption certificate chains to **exactly that root certificate**, with valid signatures and dates, and is not a CA;
- the encrypted file was made for this certificate and this root CA;
- the HMAC is correct, so a modified file is refused.

Revocation is not checked: these certificates have no revocation list.

| Parameter | Default | Description |
|---|---|---|
| `-EncryptedPasswordPath` | `Certificates\PasswordDecryption.json` | Encrypted password file |
| `-RootCertificatePath` | `Certificates\RootCA.cer` | Public certificate of the root CA |
| `-PfxPath` | `Certificates\PasswordDecryption.pfx` | Decryption certificate with its private key |
| `-PfxPassword` | asked | Password of the PFX |
| `-Thumbprint` | | Use a decryption certificate installed in the `My` store (LocalMachine or CurrentUser) instead of a PFX |
| `-AsPlainText` | | Returns plain text instead of a `SecureString` |

```powershell
# From files
$secure = .\3-Get-DecryptedPassword.ps1 `
    -EncryptedPasswordPath "D:\PKI\LocalAdmin.json" `
    -RootCertificatePath   "D:\PKI\RootCA.cer" `
    -PfxPath               "D:\PKI\LocalAdmin.pfx"

# From a certificate installed on the machine: no PFX password is needed
.\3-Get-DecryptedPassword.ps1 -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567 `
    -EncryptedPasswordPath "D:\PKI\LocalAdmin.json" -RootCertificatePath "D:\PKI\RootCA.cer"
```

To install the decryption certificate on a machine so that the PFX password is not needed afterwards:

```powershell
Import-PfxCertificate -FilePath "D:\PKI\LocalAdmin.pfx" -CertStoreLocation Cert:\LocalMachine\My `
    -Password (Read-Host -AsSecureString)
```

### 4-Example-CreateLocalAdmin.ps1

An example that runs the three scripts and creates a local administrator with the decrypted password.

1. Creates a root CA (`RootCA.cer`, `RootCA.pfx`).
2. Creates the decryption certificate and encrypts the password of the account.
3. Decrypts it and checks that it is identical to the original.
4. **Displays the decrypted password in clear and asks for confirmation** (`Y` / `N`), so you can check that it is the password you intended.
5. Creates the local user and adds it to the Administrators group (found by its SID, so it works in every language of Windows).

Passwords that are not given as parameters are generated (24 characters for the account, 32 for each PFX, with upper and lower case letters, digits and symbols) and displayed **once** at the end, on screen only. Passwords given as parameters are never displayed.

It is built to be safe to try:

- it works in its own folder (`Demo`) with its own root CA, and does **not** import it in the trusted root store unless you use `-ImportRoot`;
- it never touches an account that already exists;
- the account it creates is marked in its description, so `-Cleanup` removes only what the example created: the account, the root CA from the trusted root store (if imported) and the files;
- it refuses to run again while its files or its account exist.

| Parameter | Default | Description |
|---|---|---|
| `-UserName` | `DemoAdmin` | Local administrator to create (20 characters maximum) |
| `-AdminPassword` | generated | Password of the account (`SecureString`) |
| `-RootPfxPassword` | generated | Password of `RootCA.pfx` |
| `-PfxPassword` | generated | Password of the decryption certificate PFX |
| `-OutputFolder` | `Demo` next to the script | Folder of the certificates and the encrypted password |
| `-ImportRoot` | | Also imports the root CA in the trusted root store |
| `-NoPause` | | Does not display the password and does not ask for confirmation (fully automatic) |
| `-Cleanup` | | Removes what the example created and stops |

```powershell
.\4-Example-CreateLocalAdmin.ps1                                    # DemoAdmin, generated passwords
.\4-Example-CreateLocalAdmin.ps1 -UserName LocalAdmin -AdminPassword (Read-Host -AsSecureString)
.\4-Example-CreateLocalAdmin.ps1 -UserName LocalAdmin -NoPause      # fully automatic
.\4-Example-CreateLocalAdmin.ps1 -UserName LocalAdmin -Cleanup      # remove everything
```

---

## What goes where

| File | Created by | Secret? | Who needs it |
|---|---|---|---|
| `RootCA.pfx` + its password | step 1 | **Yes, the most sensitive** | Only the person who issues certificates (step 2). Keep it **offline** |
| `RootCA.cer` | step 1 | No | Every machine that decrypts (step 3) |
| `<Name>.json` | step 2 | No (it is encrypted) | Every machine that decrypts |
| `<Name>.pfx` + its password | step 2 | **Yes** | Every machine that decrypts |
| `<Name>.cer` | step 2 | No | Optional |

A deployment therefore ships `RootCA.cer`, `<Name>.json` and the decryption certificate (`<Name>.pfx`, or the certificate already installed in the machine store). Never ship `RootCA.pfx`.

## Encrypted file format

`<Name>.json` is a plain JSON file:

```json
{
  "format": "PKI-PASSWORD-ENVELOPE",
  "version": 1,
  "keyTransport": "RSA-OAEP-SHA256",
  "encryption": "AES-256-CBC",
  "authentication": "HMAC-SHA256",
  "certificateThumbprint": "0123456789ABCDEF0123456789ABCDEF01234567",
  "rootThumbprint": "FEDCBA9876543210FEDCBA9876543210FEDCBA98",
  "created": "2026-01-15T09:30:00Z",
  "encryptedKey": "<base64: AES key and HMAC key, encrypted with RSA-OAEP>",
  "iv": "<base64: 16 random bytes>",
  "ciphertext": "<base64: the password, encrypted with AES-256-CBC>",
  "mac": "<base64: HMAC-SHA256>"
}
```

The HMAC covers `PKI-PASSWORD-ENVELOPE|1|<certificate thumbprint>|<root thumbprint>|` followed by the IV and the ciphertext. A file that was modified, or that is presented with another certificate, is refused before anything is decrypted. The script also refuses a file that announces another algorithm than the expected ones.

---

## Security notes

- **The root CA is a real trust anchor.** Step 1 imports it in the trusted root store, so the computer then trusts every certificate it signs, **for any name** (it has no name constraints). Whoever holds `RootCA.pfx` and its password could issue certificates trusted by that computer. Keep the file offline with a long password, and use the root CA only for this purpose.
- **Importing is optional.** Step 3 trusts the root certificate file that you pass to it, so decryption works without the import. Use `-SkipImport` if you do not want the computer to trust the root CA.
- **The decryption key is the weak point.** Anyone who has `<Name>.pfx` and its password can decrypt the password. Distribute the PFX and its password through different channels, or install the certificate on the target machine and use `-Thumbprint`.
- **No revocation.** The certificates have no revocation list. To stop using one, create a new root CA or a new decryption certificate and encrypt again.
- **If `RootCA.pfx` is lost**, no new decryption certificate can be issued. Create a new root CA and encrypt again.
- **Passwords in memory.** Passwords are handled as `SecureString` and the byte arrays holding keys and passwords are cleared after use, but a password is briefly converted to text during encryption and decryption, and `-AsPlainText` returns plain text. This is not a replacement for a password vault.
- **`4-Example-CreateLocalAdmin.ps1` shows a password on screen** (the generated passwords at the end and, unless `-NoPause` is used, the decrypted password before the account is created). Do not run it in a session that is recorded or shared.

## Troubleshooting

| Message or symptom | Cause and solution |
|---|---|
| `This script must be run as administrator` | Open an elevated PowerShell (right-click > *Run as administrator*) |
| `... already exists. Use -Force ...` | Step 1 or 2 would overwrite files. Use `-Force`, or another `-Name` or `-OutputFolder`. For the example, run `-Cleanup` first |
| `Unable to open '...': wrong password` | The password of the root PFX or of the decryption PFX is wrong |
| `Integrity check failed: the encrypted password was modified` | The JSON file was changed or damaged. Encrypt the password again |
| `This password was encrypted for another certificate` | The JSON does not belong to this PFX. Use the PFX created with this JSON (same `-Name`) |
| `The decryption certificate was not issued by the root CA ...` | `RootCA.cer` is not the root that issued this certificate |
| The account exists but the password is refused at sign-in | Compare it with the password displayed by the example (the confirmation step). The sign-in screen often uses a different keyboard layout than your session (for example QWERTY instead of AZERTY): switch the layout on the sign-in screen. After too many failures the account is locked for a while, as set by the account lockout policy |
