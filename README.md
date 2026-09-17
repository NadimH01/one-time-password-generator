# One-Time Password Generator

A small, dependency-light implementation of counter-based HOTP (RFC 4226) and time-based TOTP (RFC 6238).

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

```python
from otp_app import TOTP, generate_secret

secret = generate_secret()
totp = TOTP(secret)
print(secret)
print(totp.generate())
```

Secrets use Base32 encoding, as commonly used by authenticator applications. `TOTP.generate(timestamp)` accepts a Unix timestamp, which is useful for reproducible tests. The default time period is 30 seconds and the default output length is 6 digits.

Run the test suite with:

```powershell
$env:PYTHONPATH = "src"
python -m pytest
```
