"""X.509 parsing, fingerprinting, key matching and PFX generation.

Uses the `cryptography` library exclusively (no openssl shell-out for parsing).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core.exceptions import ValidationAppError
from app.core.timeutils import ensure_aware


@dataclass
class CertificateMetadata:
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    sans: list[str] = field(default_factory=list)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    public_key_algorithm: str = ""
    key_type: str = "rsa"
    key_size: int | None = None
    signature_algorithm: str = ""
    is_wildcard: bool = False
    is_ca: bool = False
    ocsp_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)


def _name_to_str(name: x509.Name) -> str:
    parts = []
    for attr in name:
        try:
            parts.append(f"{attr.oid._name}={attr.value}")
        except Exception:  # noqa: BLE001
            parts.append(str(attr.value))
    return ", ".join(parts)


def _key_meta(public_key) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecdsa", public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "ed448", 456
    return "other", None


def parse_certificate(data: bytes) -> tuple[x509.Certificate, CertificateMetadata]:
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise ValidationAppError("Unrecognized certificate format (expected PEM or DER)") from exc

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    fingerprint_colon = ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    ocsp_urls, crl_urls = [], []
    try:
        ad = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in ad.value:
            if desc.access_method._name == "caIssuers":
                pass
            if desc.access_method._name == "OCSP":
                ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass
    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for dp in crl_ext.value:
            for name in dp.full_name or []:
                crl_urls.append(name.value)
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bool(bc.value.ca)
    except x509.ExtensionNotFound:
        pass

    algo, size = _key_meta(cert.public_key())
    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else "unknown"

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = sans[0] if sans else ""

    meta = CertificateMetadata(
        subject=_name_to_str(cert.subject),
        issuer=_name_to_str(cert.issuer),
        serial_number=f"{cert.serial_number:x}",
        fingerprint_sha256=fingerprint_colon.upper(),
        sans=sans,
        valid_from=ensure_aware(cert.not_valid_before_utc),
        valid_until=ensure_aware(cert.not_valid_after_utc),
        public_key_algorithm=algo,
        key_type="rsa" if algo == "rsa" else ("ecdsa" if algo == "ecdsa" else algo),
        key_size=size,
        signature_algorithm=sig_algo,
        is_wildcard=any(s.startswith("*.") for s in sans) or (cn or "").startswith("*."),
        is_ca=is_ca,
        ocsp_urls=ocsp_urls,
        crl_urls=crl_urls,
    )
    return cert, meta


def parse_private_key(data: bytes, password: bytes | None = None):
    """Load a private key; returns (key_obj, key_type, key_size).

    Tolerates a password being supplied for an unencrypted key and encrypted
    keys in DER form.
    """
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except TypeError:
        # Password supplied but key is not encrypted — retry without password
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except Exception as exc:  # noqa: BLE001
            raise ValidationAppError("Cannot parse private key (unsupported format)") from exc
    except ValueError:
        try:
            key = serialization.load_der_private_key(data, password=password)
        except TypeError:
            key = serialization.load_der_private_key(data, password=None)
        except Exception as exc:  # noqa: BLE001
            raise ValidationAppError(
                "Cannot parse private key (wrong password or unsupported format)"
            ) from exc
    if isinstance(key, rsa.RSAPrivateKey):
        return key, "rsa", key.key_size
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key, "ecdsa", key.curve.key_size
    return key, "other", None


def public_key_matches(cert: x509.Certificate, private_key) -> bool:
    """Verify the private key belongs to the certificate."""
    try:
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cert_pub == key_pub
    except Exception:  # noqa: BLE001
        return False


def parse_pfx(data: bytes, password: str | None) -> tuple[x509.Certificate, object, list[x509.Certificate]]:
    try:
        key, cert, extra_certs = pkcs12.load_key_and_certificates(
            data, (password or "").encode("utf-8")
        )
    except ValueError as exc:
        raise ValidationAppError("Invalid PKCS12 password") from exc
    if cert is None:
        raise ValidationAppError("PFX/PKCS12 contains no certificate")
    if key is None:
        raise ValidationAppError("PFX/PKCS12 contains no private key")
    return cert, key, list(extra_certs or [])


def private_key_to_pem(key, password: str | None = None) -> bytes:
    enc = serialization.BestAvailableEncryption(password.encode("utf-8")) if password else serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )


def build_pfx(cert_pem: bytes, key_pem: bytes, chain_pem: bytes | None = None,
              password: str = "") -> bytes:
    """Package cert + key (+chain) into a PKCS12 blob."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    extra: list[x509.Certificate] = []
    if chain_pem:
        # May contain multiple PEM certs
        idx = 0
        data = chain_pem
        while idx < len(data):
            start = data.find(b"-----BEGIN CERTIFICATE-----", idx)
            if start == -1:
                break
            end = data.find(b"-----END CERTIFICATE-----", start)
            if end == -1:
                break
            end += len(b"-----END CERTIFICATE-----")
            extra.append(x509.load_pem_x509_certificate(data[start:end]))
            idx = end
    return pkcs12.serialize_key_and_certificates(
        name=b"certmgr",
        key=key,
        cert=cert,
        cas=extra or None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")) if password else serialization.NoEncryption(),
    )


def parse_chain_pem(data: bytes) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    idx = 0
    while idx < len(data):
        start = data.find(b"-----BEGIN CERTIFICATE-----", idx)
        if start == -1:
            break
        end = data.find(b"-----END CERTIFICATE-----", start)
        if end == -1:
            break
        end += len(b"-----END CERTIFICATE-----")
        certs.append(x509.load_pem_x509_certificate(data[start:end]))
        idx = end
    return certs
