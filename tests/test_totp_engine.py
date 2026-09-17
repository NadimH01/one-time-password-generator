import base64

import pytest

from otp_app import HOTP, TOTP, generate_secret


RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc_6238_sha1_vectors() -> None:
    totp = TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits=8, algorithm="SHA1")
    vectors = {
        59: "94287082",
        1111111109: "07081804",
        1111111111: "14050471",
        1234567890: "89005924",
        2000000000: "69279037",
        20000000000: "65353130",
    }
    assert {timestamp: totp.generate(timestamp) for timestamp in vectors} == vectors


def test_rfc_6238_sha256_and_sha512_vectors() -> None:
    sha256_secret = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
    sha512_secret = base64.b32encode(
        b"1234567890123456789012345678901234567890123456789012345678901234"
    ).decode().rstrip("=")
    assert TOTP(sha256_secret, digits=8, algorithm="SHA256").generate(59) == "46119246"
    assert TOTP(sha512_secret, digits=8, algorithm="SHA512").generate(59) == "90693936"


def test_hotp_counter_vector() -> None:
    hotp = HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    assert hotp.generate(0) == "755224"
    assert hotp.generate(5) == "254676"


def test_time_provider_and_remaining_seconds() -> None:
    totp = TOTP("JBSWY3DPEHPK3PXP", time_provider=lambda: 61.9)
    assert totp.generate() == totp.generate(61)
    assert totp.remaining_seconds() == 29


def test_secret_generation_is_valid_base32() -> None:
    secret = generate_secret()
    assert len(secret) == 32
    assert TOTP(secret).generate(0).isdigit()


@pytest.mark.parametrize(
    ("secret", "message"),
    [("", "secret"), ("not-base32!", "Base32")],
)
def test_invalid_secret(secret: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        TOTP(secret)


def test_invalid_options() -> None:
    with pytest.raises(ValueError, match="digits"):
        TOTP(RFC_SECRET, digits=5)
    with pytest.raises(ValueError, match="period"):
        TOTP(RFC_SECRET, period=0)
    with pytest.raises(ValueError, match="algorithm"):
        TOTP(RFC_SECRET, algorithm="MD5")
