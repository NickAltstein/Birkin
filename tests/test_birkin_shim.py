"""Tests for birkin backward-compatibility shim."""


def test_birkin_crypto_resolves_to_receiptd_crypto():
    import birkin.crypto
    import receiptd.crypto

    assert birkin.crypto is receiptd.crypto
