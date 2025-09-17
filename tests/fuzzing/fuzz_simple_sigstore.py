# SPDX-License-Identifier: Apache-2.0
# Fuzzer: sign -> verify using Sigstore (TestOneInput API), offline-friendly

from pathlib import Path
import os
import sys
import time
import json
import hmac
import hashlib
import base64
import tempfile
import atheris

from utils import any_files
from utils import create_fuzz_files
from model_signing import signing, verifying


EXPECTED_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/"
    ".github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)
EXPECTED_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


# ---- Offline OIDC beacon token generator ------------------------------------

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


# ---- Atheris harness ---------------------------------------------------------

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    with tempfile.TemporaryDirectory(prefix="fuzz-sigstore-") as tmpdir:
        print("creating files....")
        root = Path(tmpdir)
        files = create_fuzz_files(root, fdp)
        if not any_files(root):
            return
        print("created files")
        model_path = files.get("model_path") if isinstance(files, dict) else files
        if not model_path or not os.path.exists(model_path):
            return

        identity_token = sigstore_oidc_beacon_token()

        sc = signing.Config()
        sc.use_sigstore_signer(
            use_staging=True,
            identity_token=identity_token,
            for_fuzzing=True,
        )
 
        signature_path = os.path.join(tmpdir, "model.sig")
        print("signing")
        try:
            sc.sign(model_path, signature_path)
        except Exception as e:
            print(e)
            return

        try:
            print("verifying")
            verifying.Config().use_sigstore_verifier(
                identity=EXPECTED_IDENTITY,
                oidc_issuer=EXPECTED_OIDC_ISSUER,
                use_staging=True,
            ).verify(model_path, signature_path)
        except Exception:
            print(e)
            pass


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

