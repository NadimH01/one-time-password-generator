# One-Time Password Generator — Test Matrix

| Test ID | Requirement | Test / Evidence | Expected Result | Status |
|---|---|---|---|---|
| T01 | FR01 | Create valid demo account | Account created with encrypted secret | PASS |
| T02 | FR01 | Create duplicate account | Duplicate rejected | PASS |
| T03 | FR02 | RFC 6238 SHA-256 vector | Generated TOTP matches expected value | PASS |
| T04 | FR03 | Countdown calculation | Remaining seconds follow 30-second period | PASS |
| T05 | FR04 | Valid OTP verification | Correct current OTP accepted | PASS |
| T06 | FR04 | Incorrect OTP | Incorrect OTP rejected | PASS |
| T07 | FR04 | Malformed OTP | Non-six-digit ASCII input rejected | PASS |
| T08 | FR05 | Replay same OTP | Previously accepted counter rejected | PASS |
| T09 | FR05 | Concurrent same OTP | Exactly one concurrent request succeeds | PASS |
| T10 | FR06 | Five failed attempts | 60-second cooldown begins | PASS |
| T11 | FR06 | OTP during cooldown | Verification remains blocked | PASS |
| T12 | FR06 | Cooldown expiration | Verification resumes after expiry | PASS |
| T13 | FR06 | Restart persistence | Failure/cooldown state survives restart | PASS |
| T14 | FR07 | Encrypted storage | Database stores ciphertext, not raw seed | PASS |
| T15 | FR07 | Wrong encryption key | Protected data cannot be decrypted | PASS |
| T16 | FR07 | Modified ciphertext | Tampered ciphertext rejected | PASS |
| T17 | FR08 | Audit logging | Verification events recorded without credentials | TODO |
| T18 | FR09 | Missing/invalid key | Application refuses normal operation | TODO |
| T19 | FR09 | Database/key mismatch | Application stops rather than resetting storage | TODO |
| T20 | FR09 | Missing verification state | Operation fails safely | TODO |
| T21 | FR10 | Clock rollback | Earlier time is rejected | TODO |
| T22 | NFR01 | Module structure | GUI/service/storage/TOTP responsibilities separated | PASS |
| T23 | NFR04 | Atomic decisions | Success returned only after committed update | PASS |
| T24 | NFR05 | Fresh installation | README/setup procedure succeeds | TODO |
| T25 | NFR06 | Security boundaries | Limitations documented | PASS |
| T26 | NFR07 | Test isolation | Tests use temporary database and test keys | PASS |