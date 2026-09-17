import base64
import math
import platform
import secrets
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.otp_app.repository import (
    connect_database,
    create_schema,
    create_account_record,
)
from src.otp_app.secret_store import (
    encrypt_account_secret,
    generate_storage_key,
)
from src.otp_app.service import verify_otp
from src.otp_app.totp_engine import TOTP

NUMBER_OF_ATTEMPTS = 100
FIXED_TIMESTAMP = 1200


def generate_valid_otp(seed: bytes, timestamp: int) -> str:
    base32_secret = base64.b32encode(seed).decode("ascii")
    return TOTP(
        secret=base32_secret,
        digits=6,
        period=30,
        algorithm="sha256",
    ).generate(timestamp)


def percentile_95(values):
    ordered = sorted(values)
    position = math.ceil(0.95 * len(ordered)) - 1
    return ordered[position]


def main():
    timings_ms = []

    with tempfile.TemporaryDirectory() as temp_dir:
        database_path = Path(temp_dir) / "performance.sqlite3"
        connection = connect_database(database_path)
        create_schema(connection)
        storage_key = generate_storage_key()
        test_cases = []

        for index in range(NUMBER_OF_ATTEMPTS):
            account_id = str(uuid.uuid4())
            account_name = f"performance-{index:03d}"
            seed = secrets.token_bytes(32)
            ciphertext = encrypt_account_secret(
                storage_key,
                account_id,
                seed,
            )
            create_account_record(
                connection,
                account_id,
                account_name,
                ciphertext,
                FIXED_TIMESTAMP,
            )
            otp = generate_valid_otp(seed, FIXED_TIMESTAMP)
            test_cases.append((account_id, otp))

        for account_id, otp in test_cases:
            start = time.perf_counter()
            result = verify_otp(
                connection,
                storage_key,
                account_id,
                otp,
                now=FIXED_TIMESTAMP,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            if not result.success:
                connection.close()
                raise RuntimeError("Performance verification failed.")

            timings_ms.append(elapsed_ms)

        connection.close()

    median_ms = statistics.median(timings_ms)
    p95_ms = percentile_95(timings_ms)

    print()
    print("OTP Verification Performance Evaluation")
    print("---------------------------------------")
    print(f"Python version: {platform.python_version()}")
    print(f"Operating system: {platform.system()} {platform.release()}")
    print(f"Number of attempts: {NUMBER_OF_ATTEMPTS}")
    print(f"Median verification: {median_ms:.3f} ms")
    print(f"95th percentile: {p95_ms:.3f} ms")
    print(f"Minimum: {min(timings_ms):.3f} ms")
    print(f"Maximum: {max(timings_ms):.3f} ms")
    print()
    print(
        "Median target (<100 ms): "
        + ("PASS" if median_ms < 100 else "NOT MET")
    )
    print(
        "95th percentile target (<250 ms): "
        + ("PASS" if p95_ms < 250 else "NOT MET")
    )


if __name__ == "__main__":
    main()
