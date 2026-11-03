"""S3 SigV4 for fixed worker bucket/policy paths; no SDK/runtime dependency.

Only signs bytes; it performs no IO. Returned headers are sensitive and must not
be logged. This is not acceptance of a MinIO authorization/revocation capability.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import re
from urllib.parse import parse_qsl, quote, urlsplit


def sign_s3(
    *,
    access_key: str,
    secret_key: str,
    authority: str,
    method: str,
    target: str,
    body: bytes = b"",
    now: datetime,
    region: str = "us-east-1",
    headers: dict[str, str] | None = None,
) -> dict[str, str]:
    try:
        valid = (
            type(access_key) is str
            and re.fullmatch(r"[A-Za-z0-9_-]{3,128}", access_key)
            and type(secret_key) is str
            and 8 <= len(secret_key) <= 256
            and not any(ord(c) < 32 for c in secret_key)
            and type(region) is str
            and re.fullmatch(r"[a-z0-9-]{1,64}", region)
            and type(authority) is str
            and re.fullmatch(
                r"(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::[1-9][0-9]{0,4})?", authority
            )
            and method in {"GET", "HEAD", "POST", "PUT"}
            and type(target) is str
            and target.startswith("/")
            and not target.startswith("//")
            and not any(ord(c) <= 32 or ord(c) >= 127 for c in target)
            and type(body) is bytes
            and len(body) <= 1024 * 1024
            and isinstance(now, datetime)
            and now.utcoffset() is not None
        )
        if not valid:
            raise ValueError
        path = urlsplit(target)
        # Worker operations use only fixed ASCII bucket/admin paths, never S3
        # object-key paths. Refuse ambiguous percent/path normalization here.
        if (
            path.scheme
            or path.netloc
            or path.fragment
            or not re.fullmatch(r"/[A-Za-z0-9_./-]*", path.path)
            or any(part in {".", ".."} for part in path.path.split("/"))
            or "+" in path.query
            or re.search(r"%(?![0-9A-Fa-f]{2})", path.query)
        ):
            raise ValueError
        query = []
        for key, value in parse_qsl(
            path.query, keep_blank_values=True, encoding="utf-8", errors="strict"
        ):
            if any(ord(c) < 32 for c in key + value):
                raise ValueError
            query.append((quote(key, safe="-_.~"), quote(value, safe="-_.~")))
        canonical_query = "&".join(f"{key}={value}" for key, value in sorted(query))
        stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        payload_hash = hashlib.sha256(body).hexdigest()
        signed = {
            "host": authority,
            "x-amz-date": stamp,
            "x-amz-content-sha256": payload_hash,
        }
        if headers is not None and type(headers) is not dict:
            raise ValueError
        for name, value in (headers or {}).items():
            if (
                type(name) is not str
                or name.lower() not in {"content-type", "x-amz-security-token", "range"}
                or name.lower() in signed
                or type(value) is not str
                or not value
                or any(ord(c) < 32 or ord(c) >= 127 for c in value)
            ):
                raise ValueError
            signed[name.lower()] = " ".join(value.split())
        secret = secret_key.encode("utf-8")
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise ValueError("invalid_s3_signing_request") from None

    names = ";".join(sorted(signed))
    canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
    canonical = "\n".join(
        [method, path.path, canonical_query, canonical_headers, names, payload_hash]
    )
    scope = f"{stamp[:8]}/{region}/s3/aws4_request"
    message = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            stamp,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )
    key = b"AWS4" + secret
    for part in [stamp[:8], region, "s3", "aws4_request"]:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    signed["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={names}, Signature={signature}"
    )
    return signed
