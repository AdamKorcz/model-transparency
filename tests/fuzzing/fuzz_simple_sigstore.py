#!/usr/bin/env python3
import sys
import json
import base64
import tempfile
import os
import hmac
import hashlib
import time

from utils import any_files
from utils import create_fuzz_files
from model_signing import signing, verifying

from pathlib import Path
from sigstore.models import TrustedRoot  # type: ignore

import atheris

EXPECTED_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/"
    ".github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)
EXPECTED_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# ---------------------------- helpers ----------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _jwt_hs256(payload: dict, secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_json(header)
    payload_b64 = _b64url_json(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def maybe(fdp, p=0.5) -> bool:
    # True ~p% of the time
    return fdp.ConsumeIntInRange(0, 999) < int(p * 1000)

def rand_len(fdp, lo: int, hi: int) -> int:
    return fdp.ConsumeIntInRange(lo, hi)

def rand_unicode(fdp, max_len: int = 64) -> str:
    n = rand_len(fdp, 0, max_len)
    # Surrogate-free = safe for JSON
    try:
        return fdp.ConsumeUnicodeNoSurrogates(n)
    except Exception:
        # Fallback if provider runs out
        return ""

def rand_ascii_token(fdp, max_len: int = 32) -> str:
    # Slightly narrower alphabet to get URL-ish tokens
    n = rand_len(fdp, 0, max_len)
    s = []
    for _ in range(n):
        # letters, digits, dash, underscore
        c = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        s.append(c[fdp.ConsumeIntInRange(0, len(c) - 1)])
    return "".join(s)

def rand_base64(fdp, max_src_len: int = 512) -> str:
    n = rand_len(fdp, 0, max_src_len)
    raw = fdp.ConsumeBytes(n)
    return base64.b64encode(raw).decode("ascii")

def rand_iso8601(fdp) -> str:
    year = fdp.ConsumeIntInRange(1970, 2050)
    month = fdp.ConsumeIntInRange(1, 12)
    # keep it simple to avoid invalid dates
    day = fdp.ConsumeIntInRange(1, 28)
    hour = fdp.ConsumeIntInRange(0, 23)
    minute = fdp.ConsumeIntInRange(0, 59)
    second = fdp.ConsumeIntInRange(0, 59)
    ms = fdp.ConsumeIntInRange(0, 999)
    if maybe(fdp, 0.5):
        return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"
    else:
        return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{ms:03d}Z"

def rand_url(fdp) -> str:
    scheme = "https" if maybe(fdp, 0.8) else "http"
    host = f"{rand_ascii_token(fdp, 8)}.{rand_ascii_token(fdp, 3) or 'dev'}"
    if maybe(fdp, 0.5):
        host = f"{rand_ascii_token(fdp, 5) or 'api'}.{host}"
    path = ""
    for _ in range(fdp.ConsumeIntInRange(0, 3)):
        seg = rand_ascii_token(fdp, 10)
        path += f"/{seg}" if seg else ""
    return f"{scheme}://{host}{path or ''}"

def pick(fdp, options):
    return options[fdp.ConsumeIntInRange(0, len(options) - 1)]

def make_validfor(fdp):
    d = {"start": rand_iso8601(fdp)}
    if maybe(fdp, 0.6):
        d["end"] = rand_iso8601(fdp)
    return d

def make_public_key(fdp):
    key_details_choices = [
        "PKIX_ECDSA_P256_SHA_256",
        "PKIX_ECDSA_P384_SHA_384",
        "PKIX_RSA_PKCS1_2048_SHA_256",
        "UNKNOWN_" + rand_ascii_token(fdp, 8),
    ]
    return {
        "rawBytes": rand_base64(fdp, 200),  # DER-ish, but fuzz
        "keyDetails": pick(fdp, key_details_choices) if maybe(fdp, 0.7) else rand_unicode(fdp, 40),
        "validFor": make_validfor(fdp) if maybe(fdp, 0.8) else {"start": rand_iso8601(fdp)},
    }

def make_log_id(fdp):
    # KeyId is usually a digest; base64 a random 32..64 bytes
    n = fdp.ConsumeIntInRange(16, 64)
    return {"keyId": base64.b64encode(fdp.ConsumeBytes(n)).decode("ascii")}

def make_tlog(fdp):
    hash_alg_choices = ["SHA2_256", "SHA2_512", "SHA1", rand_unicode(fdp, 16)]
    return {
        "baseUrl": rand_url(fdp),
        "hashAlgorithm": pick(fdp, hash_alg_choices),
        "publicKey": make_public_key(fdp),
        "logId": make_log_id(fdp),
    }

def make_certificate(fdp):
    # Just one field in this schema: rawBytes (base64 DER)
    # Use 200..1600 bytes to resemble cert sizes (but fuzzed).
    n = fdp.ConsumeIntInRange(0, 4)
    size = [180, 400, 800, 1400, 0][n] if maybe(fdp, 0.7) else fdp.ConsumeIntInRange(0, 1600)
    return {"rawBytes": base64.b64encode(fdp.ConsumeBytes(size)).decode("ascii")}

def make_cert_chain(fdp):
    count = fdp.ConsumeIntInRange(0, 20)
    return {"certificates": [make_certificate(fdp) for _ in range(count)]}

def make_subject(fdp):
    return {
        "organization": rand_unicode(fdp, 32),
        "commonName": rand_unicode(fdp, 32),
    }

def make_certificate_authority(fdp):
    return {
        "subject": make_subject(fdp),
        "uri": rand_url(fdp),
        "certChain": make_cert_chain(fdp),
        "validFor": make_validfor(fdp),
    }

def make_ctlog(fdp):
    hash_alg_choices = ["SHA2_256", "SHA2_512", rand_unicode(fdp, 10)]
    return {
        "baseUrl": rand_url(fdp),
        "hashAlgorithm": pick(fdp, hash_alg_choices),
        "publicKey": make_public_key(fdp),
        "logId": make_log_id(fdp),
    }

def make_timestamp_authority(fdp):
    return {
        "subject": make_subject(fdp),
        "uri": rand_url(fdp),
        "certChain": make_cert_chain(fdp),
        "validFor": make_validfor(fdp),
    }

def make_trusted_root_json(fdp):
    # Sometimes use the expected mediaType to get "deep" parses
    media_type = (
        "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
        if maybe(fdp, 0.6)
        else rand_unicode(fdp, 60)
    )
    tlogs = [make_tlog(fdp) for _ in range(fdp.ConsumeIntInRange(0, 20))]
    cas = [make_certificate_authority(fdp) for _ in range(fdp.ConsumeIntInRange(0, 20))]
    ctlogs = [make_ctlog(fdp) for _ in range(fdp.ConsumeIntInRange(0, 20))]
    tsas = [make_timestamp_authority(fdp) for _ in range(fdp.ConsumeIntInRange(0, 20))]
    root = {
        "mediaType": media_type,
        "tlogs": tlogs,
        "certificateAuthorities": cas,
        "ctlogs": ctlogs,
        "timestampAuthorities": tsas,
    }
    # Dump compact to keep inputs small; ensure_ascii to stay ASCII-safe.
    return json.dumps(root, separators=(",", ":"), ensure_ascii=True)

def sigstore_oidc_beacon_token() -> str:
    """Offline replacement for the fixture in tests/api_test.py."""
    now = int(time.time())
    payload = {
        "iss": EXPECTED_OIDC_ISSUER,
        "sub": EXPECTED_IDENTITY,
        "aud": "sigstore",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 3600,
        "jti": f"fuzz-{now}",
    }
    secret = b"offline-fuzzing-secret-key"
    return _jwt_hs256(payload, secret)

# ---------------------------- fuzz target ----------------------------

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Build the JSON string from fuzz data.
    try:
        json_text = make_trusted_root_json(fdp)
    except Exception:
        # If we fail to construct JSON (e.g., provider exhausted), bail out quietly.
        return

    # Write ONLY the JSON (no size prefix) and try parsing with sigstore.
    # If the library raises (value error / validation), swallow it so we can keep fuzzing.
    tf = None
    tr = None
    try:
        tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
        tf.write(json_text)
        tf.flush()
        tf.close()

        try:
            tr = TrustedRoot.from_file(tf.name)  # target under test
        except Exception:
            # Validation failures are expected; ignore to keep exploring.
            return

    finally:
        if tf is not None:
            try:
                os.unlink(tf.name)
            except OSError:
                pass

    with (
        tempfile.TemporaryDirectory(prefix="mt_file_fuzz_") as tmpdir,
        tempfile.TemporaryDirectory(prefix="mt_sig_fuzz_") as sigdir,
    ):
        root = Path(tmpdir)
        create_fuzz_files(root, fdp)
        # If there are NO files in root (skip empty directory cases).
        if not any_files(root):
            return

        print("DID IT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        identity_token = sigstore_oidc_beacon_token()
        sc = signing.Config()
        sc.use_sigstore_signer(
            identity_token=identity_token,
            for_fuzzing=True,
            trusted_root_for_fuzzing=tr,
        )
 
        signature_path = os.path.join(tmpdir, "model.sig")
        print("signing")
        try:
            sc.sign(model_path, signature_path)
        except Exception as e:
            print(e)
            return

        '''try:
            print("verifying")
            verifying.Config().use_sigstore_verifier(
                identity=EXPECTED_IDENTITY,
                oidc_issuer=EXPECTED_OIDC_ISSUER,
                use_staging=True,
            ).verify(model_path, signature_path)
        except Exception as e:
            print(e)
            pass'''


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

