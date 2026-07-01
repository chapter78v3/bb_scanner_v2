from __future__ import annotations

import base64
import json
import secrets
import string
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class OASTInteraction:
    """A single out-of-band interaction observed by the collaborator."""

    correlation_id: str
    protocol: str
    remote_address: str
    raw: str = ""


class OASTClient:
    """Abstract out-of-band application security testing (OAST) client.

    Detectors ask the client for a unique callback host, embed it in a blind
    payload, and later poll for interactions. Correlation is done via a unique
    token that the client maps back to the probe that generated it.
    """

    enabled = False

    def new_payload_host(self, correlation_id: str) -> Optional[str]:
        """Return a unique callback host for the given correlation id, or None."""
        return None

    def poll(self) -> List[OASTInteraction]:
        """Return any interactions observed since the last poll."""
        return []


class NullOASTClient(OASTClient):
    """No-op client used when OAST is not configured. Never emits hosts."""

    enabled = False


class CallbackDomainOASTClient(OASTClient):
    """Deterministic callback-domain client for a self-hosted listener.

    Given a base domain (e.g. an interactsh/self-hosted DNS+HTTP logger the
    operator controls), this mints unique subdomains of the form
    ``<token>.<base_domain>`` and records the mapping so the operator can
    correlate hits from their own logs. It does not poll automatically; use
    an interactsh deployment plus your log review, or extend ``poll``.
    """

    enabled = True

    def __init__(self, base_domain: str) -> None:
        parsed = urlparse(base_domain)
        # Accept both "example.oast.site" and "https://example.oast.site".
        self.base_domain = (parsed.netloc or parsed.path or base_domain).strip("/").lower()
        self.mappings: Dict[str, str] = {}

    def new_payload_host(self, correlation_id: str) -> Optional[str]:
        if not self.base_domain:
            return None
        token = secrets.token_hex(6)
        host = f"{token}.{self.base_domain}"
        self.mappings[token] = correlation_id
        return host


def build_oast_client(base_domain: Optional[str], use_interactsh: bool = False) -> OASTClient:
    """Factory: return a configured OAST client or a null client."""
    if use_interactsh:
        client = InteractshClient(base_domain or "oast.pro")
        if client.enabled:
            return client
        return NullOASTClient()
    if base_domain and base_domain.strip():
        return CallbackDomainOASTClient(base_domain.strip())
    return NullOASTClient()


class InteractshClient(OASTClient):
    """Automated OAST via an interactsh server (registration + polling).

    Registers an RSA keypair with the interactsh server, mints unique callback
    subdomains, and polls for decrypted interactions so blind findings can be
    auto-confirmed. Requires the optional ``cryptography`` and ``requests``
    packages and network egress to the server; if either is unavailable the
    client reports ``enabled = False`` and the scanner degrades gracefully.
    """

    enabled = False

    def __init__(self, server: str, timeout: int = 15) -> None:
        parsed = urlparse(server if "//" in server else f"//{server}")
        self.server_host = (parsed.netloc or parsed.path or server).strip("/").lower()
        self.timeout = timeout
        self.correlation_id = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(20))
        self.secret = str(uuid.uuid4())
        self.mappings: Dict[str, str] = {}
        self._private_key = None
        self._crypto = None
        self._requests = None
        self._register()

    def _register(self) -> None:
        try:
            import requests
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
        except Exception:
            return

        try:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_pem = self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            payload = {
                "public-key": base64.b64encode(public_pem).decode(),
                "secret-key": self.secret,
                "correlation-id": self.correlation_id,
            }
            resp = requests.post(
                f"https://{self.server_host}/register",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                self._requests = requests
                self._crypto = {"hashes": hashes, "padding": padding}
                self.enabled = True
        except Exception:
            self.enabled = False

    def new_payload_host(self, correlation_id: str) -> Optional[str]:
        if not self.enabled:
            return None
        rand = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(13))
        self.mappings[rand] = correlation_id
        return f"{self.correlation_id}{rand}.{self.server_host}"

    def poll(self) -> List[OASTInteraction]:
        if not self.enabled or self._requests is None:
            return []
        try:
            resp = self._requests.get(
                f"https://{self.server_host}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return []
            body = resp.json()
        except Exception:
            return []

        aes_key = self._decrypt_aes_key(body.get("aes_key", ""))
        if aes_key is None:
            return []

        interactions: List[OASTInteraction] = []
        for item in body.get("data", []) or []:
            decoded = self._decrypt_data(aes_key, item)
            if not decoded:
                continue
            full_id = decoded.get("full-id", "") or decoded.get("unique-id", "")
            correlation = "unmatched"
            for rand, mapped in self.mappings.items():
                if rand in full_id:
                    correlation = mapped
                    break
            interactions.append(
                OASTInteraction(
                    correlation_id=correlation,
                    protocol=str(decoded.get("protocol", "")),
                    remote_address=str(decoded.get("remote-address", "")),
                    raw=str(decoded.get("raw-request", ""))[:2000],
                )
            )
        return interactions

    def _decrypt_aes_key(self, aes_key_b64: str) -> Optional[bytes]:
        if not aes_key_b64 or self._private_key is None or self._crypto is None:
            return None
        try:
            hashes = self._crypto["hashes"]
            padding = self._crypto["padding"]
            return self._private_key.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            return None

    @staticmethod
    def _decrypt_data(aes_key: bytes, data_b64: str) -> Optional[dict]:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            raw = base64.b64decode(data_b64)
            iv, ciphertext = raw[:16], raw[16:]
            decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode("utf-8", errors="replace"))
        except Exception:
            return None

