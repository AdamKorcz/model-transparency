# fuzz_sigstore_offline_test.py
import atheris  # type: ignore
import sys, os, json, base64, tempfile
from pathlib import Path
from contextlib import contextmanager
from unittest.mock import patch
from id import IdentityError

from model_signing import signing, verifying

# -----------------------
# Helpers to get fuzz strings
# -----------------------
def fuzz_str(fdp, n):
    # Prefer ConsumeString; fall back if not present.
    try:
        return fdp.ConsumeString(n)
    except AttributeError:
        return fdp.ConsumeUnicodeNoSurrogates(n)

# -----------------------
# Fakes (offline)
# -----------------------
def _extract_payload_from_statement(statement) -> bytes:
    for attr in ("payload", "_payload", "content", "data", "body", "bytes"):
        if hasattr(statement, attr):
            v = getattr(statement, attr)
            if isinstance(v, (bytes, bytearray)): return bytes(v)
            if isinstance(v, str):
                try: return base64.b64decode(v, validate=False)
                except Exception: return v.encode("utf-8", "ignore")
    for getter in ("json", "to_json"):
        if hasattr(statement, getter):
            try:
                s = getattr(statement, getter)()
                if isinstance(s, (bytes, bytearray)): s = s.decode("utf-8", "ignore")
                obj = json.loads(s)
                if isinstance(obj.get("payload"), str):
                    try: return base64.b64decode(obj["payload"], validate=False)
                    except Exception: return obj["payload"].encode("utf-8","ignore")
                if isinstance(obj.get("payload_b64"), str):
                    return base64.b64decode(obj["payload_b64"], validate=False)
            except Exception:
                pass
    try:
        s = str(statement)
        if '"payload"' in s:
            try:
                obj = json.loads(s)
                if isinstance(obj.get("payload"), str):
                    return base64.b64decode(obj["payload"], validate=False)
            except Exception:
                pass
        return s.encode("utf-8", "ignore")
    except Exception:
        return b""

def _extract_media_type_from_statement(statement) -> str:
    for attr in ("payload_type","_payload_type","payloadType","type","media_type","mediaType"):
        if hasattr(statement, attr):
            v = getattr(statement, attr)
            if isinstance(v, str) and v: return v
    return "application/vnd.in-toto+json"

class FakeBundle:
    def __init__(self, media_type: str, payload: bytes):
        self.media_type = media_type
        self.payload = payload
    def to_json(self) -> str:
        return json.dumps({
            "mediaType": self.media_type,
            "payloadB64": base64.b64encode(self.payload).decode("utf-8"),
        })
    @classmethod
    def from_json(cls, s: str) -> "FakeBundle":
        obj = json.loads(s)
        mt = obj.get("mediaType", "application/octet-stream")
        p64 = obj.get("payloadB64", "")
        try: payload = base64.b64decode(p64, validate=False)
        except Exception: payload = b""
        return cls(mt, payload)

class _FakeSigner:
    def sign_dsse(self, statement):
        return FakeBundle(
            media_type=_extract_media_type_from_statement(statement),
            payload=_extract_payload_from_statement(statement),
        )

class FakeSigningContext:
    def signer(self, token):
        @contextmanager
        def _cm(): yield _FakeSigner()
        return _cm()

class FakeVerifier:
    def verify_dsse(self, *, bundle, policy):
        return getattr(bundle, "media_type", "application/octet-stream"), getattr(bundle, "payload", b"")

# -----------------------
# Your helpers (replace with real imports if you have them)
# -----------------------
def create_fuzz_files(root: Path, fdp: "atheris.FuzzedDataProvider") -> None:
    n = fdp.ConsumeIntInRange(0, 3)
    for _ in range(n):
        name_len = fdp.ConsumeIntInRange(1, 10)
        fname = "".join(ch for ch in fdp.ConsumeUnicodeNoSurrogates(name_len) if ch.isalnum() or ch in ("_", "-", "."))
        if not fname: fname = "f"
        p = root / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        data_len = fdp.ConsumeIntInRange(0, 4096)
        p.write_bytes(fdp.ConsumeBytes(data_len))

def any_files(root: Path) -> bool:
    return any(root.iterdir())

# -----------------------
# Fuzz iteration
# -----------------------
def _run_once_with_data(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # Fuzzed strings used by mocks
    issuer_token = fuzz_str(fdp, 64)
    ambient_token = fuzz_str(fdp, 64)
    oidc_url_str  = fuzz_str(fdp, 64)
    identity_hint = fuzz_str(fdp, 48)

    # Temp store for read_embedded()
    embedded_store = tempfile.TemporaryDirectory(prefix="sigstore_store_")

    # Stub read_embedded(): return bytes from a temp file; seed with fuzzed bytes
    def fake_read_embedded(name: str, url: str) -> bytes:
        from urllib import parse
        base = Path(embedded_store.name)
        embed_dir = parse.quote(url, safe="")
        path = base / embed_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            size = fdp.ConsumeIntInRange(0, 2048)
            path.write_bytes(fdp.ConsumeBytes(size))
        return path.read_bytes()

    # Fake Issuer factory that returns a fuzzed token
    def make_fake_issuer(token: str):
        class _FakeIssuer:
            def __init__(self, base_url: str) -> None:
                self.base_url = base_url
            def identity_token(self, *, force_oob: bool, client_id: str | None, client_secret: str | None):
                return token  # <-- fuzzed
        return _FakeIssuer

    # ClientTrustConfig stub that returns a fuzzed OIDC URL
    def make_stub_client_trust_config(url_value: str):
        class _StubSigningCfg:
            def get_oidc_url(self) -> str:
                return url_value  # <-- fuzzed
        class _StubClientTrustConfig:
            def __init__(self): self.signing_config = _StubSigningCfg()
        return _StubClientTrustConfig

    # Optionally exercise the ambient credential path
    use_ambient = bool(fdp.ConsumeIntInRange(0, 1))

    # All patches MUST be active before constructing signer/verifier configs
    StubCfg = make_stub_client_trust_config(oidc_url_str)
    patch_specs = [
        ("sigstore._utils.read_embedded", fake_read_embedded),
        ("model_signing._signing.sign_sigstore.sigstore_oidc.Issuer", make_fake_issuer(issuer_token)),
        ("model_signing._signing.sign_sigstore.sigstore_oidc.detect_credential",
         (lambda: ambient_token) if use_ambient else (lambda: None)),
        ("model_signing._signing.sign_sigstore.sigstore_signer.SigningContext.from_trust_config",
         lambda *_a, **_k: FakeSigningContext()),
        ("model_signing._signing.sign_sigstore.sigstore_models.Bundle", FakeBundle),
        ("model_signing._signing.sign_sigstore.sigstore_verifier.Verifier.production", lambda: FakeVerifier()),
        ("model_signing._signing.sign_sigstore.sigstore_verifier.Verifier.staging", lambda: FakeVerifier()),
        ("model_signing._signing.sign_sigstore.sigstore_models.ClientTrustConfig.production", lambda: StubCfg()),
        ("model_signing._signing.sign_sigstore.sigstore_models.ClientTrustConfig.staging", lambda: StubCfg()),
    ]

    ctx_stack = []
    try:
        # Enter all patches first
        for target, repl in patch_specs:
            ctx = patch(target, repl)
            ctx_stack.append(ctx)
            ctx.__enter__()

        # Build fuzzed model/signature paths
        with (
            tempfile.TemporaryDirectory(prefix="mt_file_fuzz_") as tmpdir,
            tempfile.TemporaryDirectory(prefix="mt_sig_fuzz_") as sigdir,
        ):
            root = Path(tmpdir)
            create_fuzz_files(root, fdp)
            if not any_files(root):
                return

            model_path = str(root)
            sig_path = os.path.join(sigdir, "model.sig")

            # Build configs after patches are active
            signer_cfg = signing.Config().use_sigstore_signer(
                oidc_issuer=oidc_url_str,           # fuzzed
                use_staging=False,
                use_ambient_credentials=use_ambient,
                force_oob=True,
            )

            # --- sign ---
            try:
                signer_cfg.sign(model_path, sig_path)
            except json.JSONDecodeError as e:
                print(e)
                # Ignore malformed JSON (e.g., if something wrote garbage to sig_path)
                return
            except ValueError as e:
                print(e)
                # Swallow only the in-toto type mismatch from model-transparency
                if "Expected in-toto" in str(e):
                    return
                raise
            except IdentityError as e:
                print(e)
                return

            try:
                # --- verify ---
                verifier = verifying.Config().use_sigstore_verifier(
                    identity=identity_hint,             # fuzzed
                    oidc_issuer=oidc_url_str,          # fuzzed
                    use_staging=False,
                )
                verifier.verify(model_path, sig_path)
            except json.JSONDecodeError as e:
                print(e)
                # Ignore malformed bundle JSON during verification
                return

    finally:
        for ctx in reversed(ctx_stack):
            try: ctx.__exit__(None, None, None)
            except Exception: pass
        try: embedded_store.cleanup()
        except Exception: pass

def TestOneInput(data: bytes) -> None:
    _run_once_with_data(data)

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
