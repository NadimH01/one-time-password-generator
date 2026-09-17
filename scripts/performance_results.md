 # Performance Evaluation

## Environment

- Operating system: Windows 11
- Python: 3.13.2
- Test type: Local uncontended verification
- Number of verification attempts: 100
- TOTP configuration: HMAC-SHA-256, 6 digits, 30-second period

## Results

| Metric | Result |
|---|---:|
| Number of attempts | 100 |
| Median verification time | 4.753 ms |
| 95th percentile | 5.650 ms |
| Minimum | 4.173 ms |
| Maximum | 8.031 ms |

## Proposed Targets

| Target | Evaluation |
|---|---|
| Median < 100 ms | PASS |
| 95th percentile < 250 ms | PASS |

The performance test measured the verification service using 100 pre-created accounts and valid OTPs. Account creation and manual user-input time were excluded from the verification timing.
