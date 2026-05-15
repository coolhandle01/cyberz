"""tests/test_jwt.py - unit tests for tools/pentest/jwt.py"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from models import Severity
from tools.pentest.jwt import (
    _ALG_NONE_VARIANTS,
    _KID_PATH_TRAVERSAL,
    _KID_SQLI,
    _WEAK_SECRETS,
    _b64url_decode,
    _b64url_encode,
    _decode_part,
    _forge_hs,
    _forge_unsigned,
    _verify_hs,
    check_jwt,
)

pytestmark = pytest.mark.unit

_ENDPOINT = "https://app.example.com/api/profile"


def _b64(d: dict) -> str:
    raw = json.dumps(d, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_token(header: dict, payload: dict, sig: str = "fakesig") -> str:
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


def _make_hs256_token(header: dict, payload: dict, secret: bytes) -> str:
    h = _b64(header)
    p = _b64(payload)
    sig_bytes = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


def _resp(status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = "{}"
    r.json.return_value = {}
    return r


class TestHelpers:
    def test_b64url_roundtrip(self) -> None:
        original = b"\x00\xff\xfe hello world"
        assert _b64url_decode(_b64url_encode(original)) == original

    def test_decode_part_header(self) -> None:
        header = {"alg": "HS256", "typ": "JWT"}
        token = _make_token(header, {"sub": "1"})
        assert _decode_part(token, 0) == header

    def test_decode_part_payload(self) -> None:
        payload = {"sub": "42", "role": "user"}
        token = _make_token({"alg": "HS256"}, payload)
        assert _decode_part(token, 1) == payload

    def test_forge_unsigned_has_empty_sig(self) -> None:
        forged = _forge_unsigned({"alg": "none"}, {"sub": "1"})
        assert forged.endswith(".")
        assert forged.count(".") == 2

    def test_verify_hs_correct_secret(self) -> None:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1"}
        token = _make_hs256_token(header, payload, b"secret")
        assert _verify_hs(token, b"secret", "HS256") is True

    def test_verify_hs_wrong_secret(self) -> None:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1"}
        token = _make_hs256_token(header, payload, b"secret")
        assert _verify_hs(token, b"wrong", "HS256") is False

    def test_forge_hs_verifies(self) -> None:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1"}
        forged = _forge_hs("HS256", header, payload, b"secret")
        assert _verify_hs(forged, b"secret", "HS256") is True


class TestAlgNone:
    def test_detects_alg_none_bypass(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"})
        with patch("requests.get", return_value=_resp(200)):
            results = check_jwt(token, _ENDPOINT)
        alg_none = [r for r in results if "alg:none" in r.title]
        assert len(alg_none) == 1
        assert alg_none[0].severity_hint == Severity.CRITICAL

    def test_no_finding_when_none_rejected(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
        with patch("requests.get", return_value=_resp(401)):
            results = check_jwt(token, _ENDPOINT)
        assert not any("alg:none" in r.title for r in results)

    def test_stops_after_first_accepted_variant(self) -> None:
        # Only one alg:none finding should be reported even though 4 variants exist.
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})

        with patch("requests.get", return_value=_resp(200)):
            results = check_jwt(token, _ENDPOINT)

        alg_none = [r for r in results if "alg:none" in r.title]
        assert len(alg_none) == 1
        # The first variant tried should appear in the evidence.
        assert _ALG_NONE_VARIANTS[0] in alg_none[0].evidence

    def test_all_four_none_variants_defined(self) -> None:
        variants_lower = [v.lower() for v in _ALG_NONE_VARIANTS]
        assert variants_lower.count("none") == len(_ALG_NONE_VARIANTS)
        assert len(set(_ALG_NONE_VARIANTS)) == len(_ALG_NONE_VARIANTS)


class TestWeakSecret:
    def test_detects_weak_secret(self) -> None:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1", "role": "user"}
        token = _make_hs256_token(header, payload, b"secret")

        with patch("requests.get", return_value=_resp(401)):
            results = check_jwt(token, _ENDPOINT)

        weak = [r for r in results if "weak HMAC" in r.title]
        assert len(weak) == 1
        assert weak[0].severity_hint == Severity.CRITICAL
        assert "secret" in weak[0].evidence

    def test_no_finding_on_strong_secret(self) -> None:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1"}
        token = _make_hs256_token(header, payload, b"v3ryStr0ngS3cr3t!XYZ987")

        with patch("requests.get", return_value=_resp(401)):
            results = check_jwt(token, _ENDPOINT)

        assert not any("weak HMAC" in r.title for r in results)

    def test_weak_secret_reported_even_without_2xx_replay(self) -> None:
        # Cracking the secret offline is proof enough - even if replay returns 403.
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1"}
        token = _make_hs256_token(header, payload, b"secret")

        with patch("requests.get", return_value=_resp(403)):
            results = check_jwt(token, _ENDPOINT)

        weak = [r for r in results if "weak HMAC" in r.title]
        assert len(weak) == 1

    def test_wordlist_includes_common_secrets(self) -> None:
        assert "secret" in _WEAK_SECRETS
        assert "password" in _WEAK_SECRETS
        assert "" in _WEAK_SECRETS

    def test_non_hs_alg_skips_brute_force(self) -> None:
        token = _make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "1"})

        def fake_get(url: str, **kw: Any) -> MagicMock:
            r = _resp(404)
            r.json.return_value = {}
            r.text = "{}"
            return r

        with patch("requests.get", side_effect=fake_get):
            results = check_jwt(token, _ENDPOINT)

        assert not any("weak HMAC" in r.title for r in results)


class TestKidInjection:
    def test_detects_kid_path_traversal(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT", "kid": "key-1"}, {"sub": "1"})

        def fake_get(url: str, **kw: Any) -> MagicMock:
            # Only the path-traversal probe is accepted.
            auth = str(kw.get("headers", {}).get("Authorization", ""))
            t = auth.removeprefix("Bearer ") if "Bearer " in auth else ""
            h = _decode_part(t, 0) if t else {}
            if h.get("kid") == _KID_PATH_TRAVERSAL:
                return _resp(200)
            return _resp(401)

        with patch("requests.get", side_effect=fake_get):
            results = check_jwt(token, _ENDPOINT)

        trav = [r for r in results if "path traversal" in r.title]
        assert len(trav) == 1
        assert trav[0].severity_hint == Severity.CRITICAL
        assert _KID_PATH_TRAVERSAL in trav[0].evidence

    def test_detects_kid_sql_injection(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT", "kid": "key-1"}, {"sub": "1"})

        def fake_get(url: str, **kw: Any) -> MagicMock:
            auth = str(kw.get("headers", {}).get("Authorization", ""))
            t = auth.removeprefix("Bearer ") if "Bearer " in auth else ""
            h = _decode_part(t, 0) if t else {}
            if h.get("kid") == _KID_SQLI:
                return _resp(200)
            return _resp(401)

        with patch("requests.get", side_effect=fake_get):
            results = check_jwt(token, _ENDPOINT)

        sqli = [r for r in results if "SQL injection" in r.title]
        assert len(sqli) == 1
        assert sqli[0].severity_hint == Severity.CRITICAL

    def test_kid_attacks_skipped_when_no_kid(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
        with patch("requests.get", return_value=_resp(401)):
            results = check_jwt(token, _ENDPOINT)
        kid_findings = [r for r in results if "kid" in r.title]
        assert kid_findings == []


class TestClaimsTampering:
    def test_detects_missing_signature_verification(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"})

        def fake_get(url: str, **kw: Any) -> MagicMock:
            # Accept any token with modified payload regardless of signature.
            auth = str(kw.get("headers", {}).get("Authorization", ""))
            if "Bearer " in auth:
                t = auth.removeprefix("Bearer ")
                try:
                    pl = _decode_part(t, 1)
                    if pl.get("role") == "admin":
                        return _resp(200)
                except Exception:
                    pass
            return _resp(401)

        with patch("requests.get", side_effect=fake_get):
            results = check_jwt(token, _ENDPOINT)

        tamper = [r for r in results if "signature not verified" in r.title]
        assert len(tamper) == 1
        assert tamper[0].severity_hint == Severity.CRITICAL
        assert "Original signature retained" in tamper[0].evidence

    def test_no_tamper_finding_when_signature_checked(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"})
        with patch("requests.get", return_value=_resp(401)):
            results = check_jwt(token, _ENDPOINT)
        tamper = [r for r in results if "signature not verified" in r.title]
        assert tamper == []


class TestRS256Confusion:
    def test_detects_rs256_hs256_confusion(self) -> None:
        token = _make_token({"alg": "RS256", "typ": "JWT", "kid": "k1"}, {"sub": "1"})

        # Minimal self-signed RSA public key as a JWK (tiny key, test only).
        # We use a real small RSA key so _jwk_to_pem succeeds.
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        pub = private_key.public_key()
        pub_numbers = pub.public_numbers()

        def _int_to_b64(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        jwks_payload = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "k1",
                    "n": _int_to_b64(pub_numbers.n),
                    "e": _int_to_b64(pub_numbers.e),
                }
            ]
        }
        pem_secret = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        def fake_get(url: str, **kw: Any) -> MagicMock:
            if "jwks" in url:
                r = _resp(200)
                r.json.return_value = jwks_payload
                r.text = json.dumps(jwks_payload)
                return r
            # Accept the HS256-signed token (simulates the confused server).
            auth = str(kw.get("headers", {}).get("Authorization", ""))
            if "Bearer " in auth:
                t = auth.removeprefix("Bearer ")
                try:
                    h_alg = _decode_part(t, 0).get("alg") == "HS256"
                    if h_alg and _verify_hs(t, pem_secret, "HS256"):
                        return _resp(200)
                except Exception:
                    pass
            return _resp(401)

        with patch("requests.get", side_effect=fake_get):
            results = check_jwt(token, _ENDPOINT)

        confusion = [r for r in results if "RS256->HS256" in r.title]
        assert len(confusion) == 1
        assert confusion[0].severity_hint == Severity.CRITICAL

    def test_rs256_skipped_when_no_jwks(self) -> None:
        token = _make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "1"})
        with patch("requests.get", return_value=_resp(404)):
            results = check_jwt(token, _ENDPOINT)
        assert not any("RS256->HS256" in r.title for r in results)


class TestEdgeCases:
    def test_invalid_token_returns_empty(self) -> None:
        with patch("requests.get", return_value=_resp(200)):
            results = check_jwt("not.a.jwt", _ENDPOINT)
        assert results == []

    def test_network_exception_swallowed(self) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
        with patch("requests.get", side_effect=OSError("connection refused")):
            results = check_jwt(token, _ENDPOINT)
        assert isinstance(results, list)

    def test_two_part_token_returns_empty(self) -> None:
        with patch("requests.get", return_value=_resp(200)):
            results = check_jwt("onlytwoparts.here", _ENDPOINT)
        assert results == []
