import secrets

import pytest

from src.otp_app.secret_store import (
    decrypt_account_secret,
    encrypt_account_secret,
    generate_storage_key,
)


def test_encrypt_decrypt_round_trip():

    key = generate_storage_key()

    account_id = "test-account-001"

    seed = secrets.token_bytes(32)

    ciphertext = encrypt_account_secret(
        key,
        account_id,
        seed,
    )

    recovered_seed = decrypt_account_secret(
        key,
        account_id,
        ciphertext,
    )

    assert recovered_seed == seed


def test_ciphertext_does_not_contain_seed():

    key = generate_storage_key()

    account_id = "test-account-002"

    seed = secrets.token_bytes(32)

    ciphertext = encrypt_account_secret(
        key,
        account_id,
        seed,
    )

    assert seed not in ciphertext


def test_wrong_key_fails():

    correct_key = generate_storage_key()
    wrong_key = generate_storage_key()

    account_id = "test-account-003"
    seed = secrets.token_bytes(32)

    ciphertext = encrypt_account_secret(
        correct_key,
        account_id,
        seed,
    )

    with pytest.raises(ValueError):

        decrypt_account_secret(
            wrong_key,
            account_id,
            ciphertext,
        )


def test_wrong_account_binding_fails():

    key = generate_storage_key()

    seed = secrets.token_bytes(32)

    ciphertext = encrypt_account_secret(
        key,
        "alice",
        seed,
    )

    with pytest.raises(ValueError):

        decrypt_account_secret(
            key,
            "bob",
            ciphertext,
        )


def test_modified_ciphertext_fails():

    key = generate_storage_key()

    seed = secrets.token_bytes(32)

    ciphertext = encrypt_account_secret(
        key,
        "test-account-004",
        seed,
    )

    modified = bytearray(ciphertext)

    modified[-5] ^= 1

    with pytest.raises(ValueError):

        decrypt_account_secret(
            key,
            "test-account-004",
            bytes(modified),
        )