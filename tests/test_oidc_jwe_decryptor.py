import base64
import json

import pytest

import oidc_jwe_decryptor as m


def deny(result, expected):
    assert isinstance(result, dict), result
    assert result.get("ok") is False, result
    assert result.get("code") == expected, result
    return result


def allow(result):
    assert isinstance(result, dict), result
    assert result.get("ok") is True, result
    return result


def code(result):
    assert isinstance(result, dict), result
    return result.get("code")


def token(**kw):
    base = {
        "protected": {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "k1"},
        "ciphertext_len": 64,
        "tag_len": 16,
        "auth_ok": True,
        "aad_ok": True,
        "plaintext": {"sub": "u1", "iss": "https://issuer", "aud": "client", "exp": 1000},
        "plaintext_size": 100,
        "recipients": 1,
        "zip": False,
        "nested": False,
        "inner_signature_verified": True,
    }
    base.update(kw)
    return base


def ready(**kw):
    guard = m.OidcJweDecryptor(**kw)
    guard.add_key("k1", b"key-1")
    return guard


def test_alg_none_is_denied():
    guard = ready()
    out = guard.decrypt(token(protected={"alg": "none", "enc": "A256GCM", "kid": "k1"}), 100)
    deny(out, "JWE_ALG_DENIED")


def test_alg_dir_is_denied_by_default_policy():
    guard = ready()
    out = guard.decrypt(token(protected={"alg": "dir", "enc": "A256GCM", "kid": "k1"}), 100)
    deny(out, "JWE_ALG_DENIED")


def test_cbc_content_encryption_is_denied():
    guard = ready()
    out = guard.decrypt(token(protected={"alg": "RSA-OAEP", "enc": "A128CBC-HS256",
                                        "kid": "k1"}), 100)
    deny(out, "JWE_ALG_DENIED")


def test_auth_failure_never_returns_plaintext():
    guard = ready()
    out = guard.decrypt(token(auth_ok=False), 100)
    deny(out, "JWE_AUTH_FAILED")
    assert out["plaintext"] is None


def test_short_tag_and_padding_errors_share_one_code():
    guard = ready()
    short = guard.decrypt(token(tag_len=8), 100)
    padding = guard.decrypt(token(padding_error=True), 100)
    deny(short, "JWE_AUTH_FAILED")
    deny(padding, "JWE_AUTH_FAILED")


def test_unknown_kid_does_not_try_all_keys():
    guard = ready()
    guard.add_key("k2", b"key-2")
    out = guard.decrypt(token(protected={"alg": "RSA-OAEP", "enc": "A256GCM",
                                        "kid": "missing"}), 100)
    deny(out, "JWE_KEY_NOT_FOUND")
    assert out["keys_tried"] == 0


def test_tampered_protected_header_fails_authentication():
    guard = ready()
    out = guard.decrypt(token(aad_ok=False), 100)
    deny(out, "JWE_AUTH_FAILED")


def test_zip_decompression_is_bounded():
    guard = ready(max_plaintext=4096)
    out = guard.decrypt(token(zip=True, plaintext_size=100000), 100)
    deny(out, "JWE_ZIP_LIMIT")


def test_wrong_issuer_is_rejected():
    guard = ready()
    out = guard.validate_claims({"iss": "https://evil", "aud": "client", "exp": 2000},
                                "https://issuer", "client", 1000)
    deny(out, "JWE_CLAIMS_INVALID")


def test_wrong_audience_is_rejected():
    guard = ready()
    out = guard.validate_claims({"iss": "https://issuer", "aud": "other", "exp": 2000},
                                "https://issuer", "client", 1000)
    deny(out, "JWE_CLAIMS_INVALID")


def test_expiry_respects_configured_clock_skew():
    strict = m.OidcJweDecryptor(clock_skew=0)
    lenient = m.OidcJweDecryptor(clock_skew=60)
    claims = {"iss": "https://issuer", "aud": "client", "exp": 1000}
    deny(strict.validate_claims(claims, "https://issuer", "client", 1050),
         "JWE_CLAIMS_INVALID")
    allow(lenient.validate_claims(claims, "https://issuer", "client", 1050))


def test_old_key_decrypts_within_rotation_window_only():
    guard = m.OidcJweDecryptor()
    guard.add_key("k1", b"old-key", retire_at=100)
    within = guard.decrypt(token(), 50)
    after = guard.decrypt(token(), 150)
    allow(within)
    deny(after, "JWE_KEY_NOT_FOUND")


def test_nested_jwt_inner_signature_must_be_verified():
    guard = ready()
    out = guard.decrypt(token(nested=True, inner_signature_verified=False), 100)
    deny(out, "JWE_NESTED_UNVERIFIED")


def test_multiple_recipients_with_shared_key_are_rejected():
    guard = ready()
    out = guard.decrypt(token(recipients=2), 100)
    deny(out, "JWE_RECIPIENT_INVALID")


def test_valid_token_returns_claims():
    guard = ready()
    out = guard.decrypt(token(), 500)
    allow(out)
    assert out["claims"]["sub"] == "u1"
