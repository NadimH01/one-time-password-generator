# One-Time Password Generator

A security-focused Python desktop application for demonstrating **HMAC-Based One-Time Password (HOTP)** and **Time-Based One-Time Password (TOTP)** generation, verification, encrypted secret storage, replay prevention, failed-attempt throttling, and persistent security state.

The project was developed as an individual cryptography implementation project for **CCS2243 — Cryptography Essential**.

> **Important:** This project is an educational local desktop prototype. It is not intended to serve as a production authentication system or to claim full compliance with NIST authentication requirements.

---

## Overview

The application demonstrates how a TOTP system works beyond simply generating a six-digit number.

It includes the complete local workflow:

```text
Demo Account Enrolment
        ↓
Secure Secret Generation
        ↓
Authenticated Secret Encryption
        ↓
SQLite Persistence
        ↓
TOTP Generation
        ↓
OTP Verification
        ↓
Replay Prevention
        ↓
Failed-Attempt Throttling
        ↓
Safe Audit Logging
```

The project separates the graphical interface, cryptographic logic, persistent storage, secret protection, and verification policy into independent Python modules.

---

## Key Features

### OTP Algorithms

* HOTP implementation based on **RFC 4226**
* TOTP implementation based on **RFC 6238**
* HMAC support for:

  * SHA-1
  * SHA-256
  * SHA-512
* Configurable OTP digit length
* Configurable TOTP period
* Base32 secret handling
* Dynamic truncation
* Leading-zero preservation
* Remaining-time calculation

The desktop application uses the project configuration:

```text
Algorithm: HMAC-SHA-256
OTP length: 6 digits
Time step: 30 seconds
Account secret: 32 random bytes
```

---

## Secure Secret Generation

Account secrets are generated using Python's `secrets` module rather than ordinary pseudo-random generation.

Each account receives an independently generated secret.

```python
secrets.token_bytes(32)
```

The account TOTP secret and the storage-encryption key are separate values.

```text
Account TOTP Secret
        ↓
Used for OTP generation

Storage Encryption Key
        ↓
Used only to protect stored account secrets
```

---

## Protected Secret Storage

Account secrets are not stored directly in SQLite.

Before storage, each secret is placed inside a structured payload containing information such as:

* Payload version
* Account identifier
* TOTP algorithm
* OTP digit length
* TOTP period
* Account secret

The payload is then protected using **Fernet authenticated encryption** from the Python `cryptography` library.

```text
Account Secret
     ↓
Structured Payload
     ↓
Fernet Encryption
     ↓
Authenticated Ciphertext
     ↓
SQLite
```

The encrypted payload is bound to its account identifier. Copying encrypted secret data from one account to another therefore causes account-binding validation to fail.

Tests also verify that:

* Correct keys decrypt successfully
* Incorrect keys fail
* Modified ciphertext fails authentication
* Incorrect account binding fails
* Raw account secrets are not stored as plaintext

---

## Storage-Key Separation

The application keeps its SQLite database and storage-encryption key separately.

On Windows, the application uses local application storage similar to:

```text
%LOCALAPPDATA%\CCS2243OTP\
│
├── data\
│   └── otp.sqlite3
│
└── keys\
    └── storage.key
```

The storage key is not embedded in source code and is not stored inside the SQLite database.

If the application detects an inconsistent protected-storage state—for example, a database without its expected key—it refuses normal operation instead of silently replacing the key or resetting stored accounts.

---

## SQLite Persistence

The application uses SQLite for persistent local storage.

The database contains four main logical areas.

### Accounts

Stores:

```text
account_id
account_name
secret_ciphertext
created_at
```

The plaintext account seed is not stored.

### Verification State

Stores:

```text
account_id
last_accepted_counter
failed_attempts
locked_until
```

This allows replay protection and throttling state to survive application restarts.

### Audit Events

Stores security-relevant outcomes such as:

```text
verification / success
verification / replay
verification / no_match
verification / cooldown_started
verification / throttled
```

Audit records do not intentionally store:

* OTP values
* Account secrets
* Storage-encryption keys
* Passwords
* Arbitrary raw user input

### Application Metadata

Supports persistent application-level state and storage validation.

---

## Replay Prevention

A valid TOTP can only be successfully accepted once for an account and time counter.

After successful verification, the accepted counter is stored persistently.

```text
Valid OTP
   +
Unused Time Counter
        ↓
      ACCEPT
        ↓
Store Counter
```

Submitting the same OTP again during the same interval results in rejection.

```text
Same OTP
   +
Already Accepted Counter
        ↓
      REPLAY
        ↓
      REJECT
```

Replay state remains stored after restarting the application.

---

## Failed-Attempt Throttling

The verifier tracks consecutive rejected submissions.

The implemented policy is:

```text
Failure 1 → rejected
Failure 2 → rejected
Failure 3 → rejected
Failure 4 → rejected
Failure 5 → 60-second cooldown
```

During cooldown:

* Verification is blocked
* A correct OTP cannot bypass the cooldown
* Additional submissions do not extend the cooldown
* Failure state remains persistent across application restarts

After the cooldown expires, verification can resume.

Successful verification clears the current failed-attempt state.

---

## Atomic Verification

Verification decisions use SQLite transactions so that persistent security state is updated before a successful result is returned.

Conceptually:

```text
BEGIN IMMEDIATE
      ↓
Read latest state
      ↓
Check cooldown
      ↓
Validate OTP
      ↓
Decrypt secret
      ↓
Generate expected OTP
      ↓
Check replay
      ↓
Update state
      ↓
Record audit event
      ↓
COMMIT
      ↓
Return result
```

This prevents a successful result from being displayed before the corresponding security-state update has been committed.

Concurrent duplicate-verification testing is also used to confirm that two simultaneous submissions of the same account-counter pair cannot both succeed.

---

## Desktop Interface

The application uses **Tkinter** and contains three main tabs.

### Enrolment

Allows creation of local demo accounts.

Features include:

* Account-name validation
* Canonical lowercase account names
* Unique account-name enforcement
* Secure 32-byte secret generation
* Encrypted secret storage
* Automatic verification-state creation

The account secret is not displayed during normal enrolment.

### Generator

Displays:

* Account selector
* Current six-digit TOTP
* Live remaining-time countdown

The countdown is derived from the current clock rather than simply decrementing a local variable.

### Verifier

Allows the user to:

* Select an account
* Enter a six-digit OTP
* Submit the OTP for verification
* View the committed verification result

The GUI does not independently determine whether an OTP is valid. Verification is delegated to the application service layer.

---

## Architecture

The application follows a modular design:

```text
┌───────────────────────┐
│     Tkinter GUI       │
│       gui.py          │
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│ Application Service   │
│      service.py       │
└───────┬─────┬─────────┘
        │     │
        │     ├─────────────────┐
        ▼     ▼                 ▼
┌────────────┐  ┌─────────────┐  ┌──────────────┐
│ TOTP Engine│  │Secret Store │  │ Repository   │
│totp_engine │  │secret_store │  │repository.py │
└────────────┘  └──────┬──────┘  └──────┬───────┘
                       │                │
                       ▼                ▼
                 Fernet Encryption   SQLite
```

This keeps cryptographic logic separate from presentation and persistence logic.

---

## Project Structure

```text
one-time-password-generator/
│
├── src/
│   └── otp_app/
│       ├── __init__.py
│       ├── app_storage.py
│       ├── config.py
│       ├── gui.py
│       ├── main.py
│       ├── repository.py
│       ├── secret_store.py
│       ├── service.py
│       └── totp_engine.py
│
├── tests/
│   ├── test_secret_store.py
│   ├── test_storage_integration.py
│   ├── test_totp_engine.py
│   └── test_verification_service.py
│
├── docs/
│
├── .gitignore
├── pytest.ini
├── README.md
└── requirements.txt
```

---

## Module Responsibilities

| Module            | Responsibility                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `totp_engine.py`  | HOTP/TOTP calculation, counters, HMAC, truncation, Base32 handling                           |
| `secret_store.py` | Secure secret generation support, Fernet encryption/decryption, protected payload validation |
| `repository.py`   | SQLite schema, parameterized queries, transactions, persistent state                         |
| `service.py`      | Enrolment, OTP generation, verification, replay prevention, throttling                       |
| `gui.py`          | Tkinter interface and user interaction                                                       |
| `app_storage.py`  | Application database/key initialization and persistent storage setup                         |
| `config.py`       | Non-secret application and TOTP configuration                                                |
| `main.py`         | Desktop application startup and composition                                                  |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/NadimH01/one-time-password-generator.git
cd one-time-password-generator
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution for the current process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Then activate again:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

---

## Running the Application

From the repository root:

```powershell
python -m src.otp_app.main
```

The Tkinter desktop application should open.

---

## Basic Usage

### Create an Account

1. Open the **Enrolment** tab.
2. Enter a valid demo-account name.
3. Select **Create Account**.
4. The application generates a new account secret.
5. The secret is encrypted before storage.
6. The account becomes available in the Generator and Verifier tabs.

### Generate an OTP

1. Open the **Generator** tab.
2. Select an account.
3. View the current six-digit TOTP.
4. Observe the live countdown.
5. A new OTP is generated when the next 30-second counter begins.

### Verify an OTP

1. Open the **Verifier** tab.
2. Select the corresponding account.
3. Enter the current six-digit OTP.
4. Select **Verify**.

A valid, unused current OTP is accepted.

Submitting the same successfully accepted code again during the same counter is rejected as replay.

---

## Running the Tests

Run the complete test suite with:

```powershell
python -m pytest -v
```

The automated tests cover areas including:

* RFC 4226 HOTP behaviour
* RFC 6238 TOTP vectors
* SHA-1
* SHA-256
* SHA-512
* Base32 secret generation
* Invalid secret handling
* Invalid configuration handling
* Encryption/decryption round trips
* Wrong storage keys
* Ciphertext modification
* Account-binding validation
* Encrypted SQLite storage
* Correct OTP verification
* Incorrect OTP rejection
* Malformed input
* Replay prevention
* Failed-attempt counting
* 60-second cooldown
* Cooldown expiration
* Successful failure-state reset
* Restart persistence
* Concurrent duplicate verification

Tests use temporary databases and test keys rather than the normal application database.

---

## Standards and References

The implementation and evaluation were informed by:

* **RFC 4226** — HOTP: An HMAC-Based One-Time Password Algorithm
* **RFC 6238** — TOTP: Time-Based One-Time Password Algorithm
* **NIST SP 800-63B-4** — Digital Identity Guidelines: Authentication and Authenticator Management
* Python `hmac` documentation
* Python `secrets` documentation
* Python `sqlite3`
* Python `cryptography` / Fernet documentation

PyOTP may be used as an independent comparison implementation during testing. It is not the primary implementation of the project's TOTP algorithm.

---

## Security Properties Demonstrated

The project demonstrates:

* Cryptographically secure account-secret generation
* HMAC-based OTP computation
* Authenticated encryption of stored secrets
* Separation of OTP secrets and storage-encryption keys
* Parameterized SQLite queries
* Persistent replay protection
* Failed-attempt throttling
* Persistent cooldown state
* Atomic verification-state updates
* Concurrent duplicate-verification protection
* Safe audit-event design
* Input validation
* Separation of GUI and security policy

---

## Security Limitations

This project intentionally has a limited scope.

It does **not** claim to protect against complete compromise of the local computer.

Important limitations include:

* Generator and verifier run on the same device.
* The two interfaces therefore do not represent independent authentication factors.
* TOTP is not phishing-resistant.
* Malware running with the same user's privileges may potentially access application memory or local files.
* An administrator may access local protected files.
* The application relies on the local system clock.
* The local database is not a tamper-evident external security store.
* Database rollback or restoration of an older snapshot may restore old security state.
* The project does not provide hardware-backed key storage.
* Account recovery and production identity management are outside scope.
* SMS and email OTP delivery are not implemented.
* Public deployment is outside scope.

The project demonstrates selected cryptographic and security-engineering controls; it does **not** claim production readiness or full NIST compliance.

---

## Project Scope

### Included

* Local demo-account enrolment
* HOTP/TOTP implementation
* Six-digit TOTP application configuration
* 30-second time period
* HMAC-SHA-256 application configuration
* Secure random account secrets
* Encrypted secret storage
* SQLite persistence
* OTP generation
* Live countdown
* OTP verification
* Replay prevention
* Failure throttling
* Persistent security state
* Audit logging
* Tkinter desktop interface
* Automated testing

### Excluded

* SMS delivery
* Email delivery
* Cloud deployment
* Public authentication service
* Account recovery
* Production user identity management
* Hardware security modules
* Phishing-resistant authentication
* Production multi-factor authentication claims

---

## Educational Context

The project builds on cryptography laboratory activities involving:

* Python-based cryptographic implementation
* Key and input handling
* Secure randomness using `secrets`
* Secret-byte generation and encoding
* Symmetric-encryption concepts

HOTP, TOTP, SQLite replay prevention, authenticated secret storage, throttling, and the integrated desktop application were developed as project extensions rather than being presented as functionality already implemented in the laboratory activities.

---

## Development Progress

```text
Project Proposal                       ✅
Cryptographic Foundations              ✅
System Requirements & Security Design  ✅
HOTP/TOTP Engine                       ✅
Encrypted Secret Storage               ✅
SQLite Persistence                     ✅
Replay Prevention                      ✅
Failed-Attempt Throttling              ✅
Tkinter Interface                      ✅
Full System Integration                ✅
Automated Security Testing             ✅
Final Evaluation / Report              ✅
```

---

## Repository

GitHub:

`https://github.com/NadimH01/one-time-password-generator`

---

## Author

**Nadim Hossain**

Computer Science Student
Albukhary International University

Course project for:

**CCS2243 — Cryptography Essential**

---

## Disclaimer

This repository is intended for **educational and academic demonstration purposes**.

Do not use this prototype as a drop-in replacement for a production authentication platform without appropriate security review, hardened key management, trusted deployment infrastructure, operational monitoring, recovery procedures, and additional security controls.
