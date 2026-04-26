# Litek Secure

A local, offline password manager with military-grade encryption. No cloud, no database, no internet — your data never leaves your device.

## Download

Grab the latest Windows build from the [Releases page](https://github.com/sinanhuskic/litek-secure/releases/latest) — a single `LitekSecure.exe`, no installation required. Just download and run.

If you'd rather run from source or build the executable yourself, see [Building from Source](#building-from-source) below.

## Security Architecture

### Encryption
- **AES-256-GCM** — Authenticated encryption. Same standard used by governments and financial institutions. Provides both confidentiality and integrity verification.
- **PBKDF2-HMAC-SHA256** — Key derivation with **600,000 iterations**. Converts your master password into an encryption key. Each guess takes ~0.15s, making brute-force attacks impractical.
- **Random 32-byte salt** — Generated fresh on every save. Prevents rainbow table attacks.
- **Random 12-byte nonce** — Generated fresh on every save. Ensures identical data produces different ciphertext each time.

### Zero-Knowledge Design
- Master password is **never stored** anywhere — not in the executable, not in vault.dat, not in memory (cleared after lock).
- There is **no recovery mechanism** — no reset email, no security questions, no admin bypass, no backdoor.
- Password verification works by attempting decryption — AES-256-GCM's authentication tag confirms whether the derived key is correct.
- Even with full access to the source code and vault.dat, data cannot be recovered without the master password.

### Additional Protections
- **Brute-force protection** — Exponential delay after failed login attempts (2s, 4s, 8s... up to 5 minutes).
- **Auto-lock** — Vault locks automatically after 5 minutes of inactivity.
- **Clipboard auto-clear** — Copied passwords are wiped from clipboard after 30 seconds.
- **Memory cleanup** — Sensitive data is cleared from RAM on lock/close.
- **Read-only vault** — vault.dat is set to read-only after each save to prevent accidental deletion/overwrite.

## How It Works

```
Master Password
      |
      v
  [PBKDF2-HMAC-SHA256, 600K iterations, random salt]
      |
      v
  256-bit Encryption Key
      |
      v
  [AES-256-GCM, random nonce]
      |
      v
  Encrypted vault.dat = salt(32B) + nonce(12B) + ciphertext + GCM tag(16B)
```

**Decryption:** Enter password → derive key from password + stored salt → attempt AES-GCM decryption → if GCM tag matches, password is correct and data is returned. If not, access denied.

## Features

- Create profiles (e.g., "Google", "Bank", "Work")
- Store key-value pairs within profiles (username, password, email, notes, etc.)
- Show/hide stored values
- Copy to clipboard with auto-clear
- Password generator (20 random characters)
- Password strength indicator
- Search/filter profiles
- Change master password (requires current password)
- Dark theme UI with hex rain animation

## Data Structure

```json
{
  "version": 1,
  "profiles": {
    "uuid": {
      "name": "Profile Name",
      "entries": {
        "uuid": {
          "label": "Entry Label",
          "value": "Secret Value"
        }
      }
    }
  }
}
```

This JSON is encrypted as a single blob — individual entries cannot be read without decrypting the entire vault.

## File Structure

| File | Purpose |
|------|---------|
| `vault_manager.py` | Source code |
| `icon.png` / `icon.ico` / `icon.svg` | Application logo |
| `LitekSecure.exe` | Standalone build — distributed via [Releases](https://github.com/sinanhuskic/litek-secure/releases), not tracked in this repository |
| `vault.dat` | Encrypted data — created automatically next to the executable on first run |

## Building from Source

### Requirements
- Python 3.10+
- `cryptography` library
- `Pillow` library
- `tkinter` (included with Python)

### Run directly
```bash
pip install cryptography pillow
python vault_manager.py
```

### Build standalone executable
```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name "LitekSecure" --icon="icon.ico" --add-data="icon.ico;." --add-data="icon.png;." vault_manager.py
```

The executable will be in the `dist/` folder.

## Security Disclaimer

- **Use a strong master password.** The encryption is only as strong as your password. Use 12+ characters with mixed case, numbers, and symbols.
- **There is no password recovery.** If you forget your master password, your data is permanently inaccessible.
- **Keep backups of vault.dat.** The file is encrypted — it's safe to store copies on USB drives or other locations.
- **This software is open source** so anyone can verify there are no backdoors. Security relies on the strength of AES-256-GCM and your master password, not on secrecy of the code.

## License

MIT
