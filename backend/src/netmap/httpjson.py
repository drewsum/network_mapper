"""A small blocking JSON-over-HTTP client with cookies, for the Fingerbank API and Wi-Fi
controllers (UniFi, OpenWrt). Never goes through a proxy; can skip checking a self-signed
certificate."""

import http.cookiejar
import json
import ssl
import urllib.error
import urllib.request

TIMEOUT = 20.0


class HttpError(Exception):
    pass


class JsonClient:
    def __init__(self, base: str, verify_tls: bool = True, timeout: float = TIMEOUT) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        context = None
        if not verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )

    def call(
        self,
        method: str,
        path: str,
        body: dict | list | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, object, dict[str, str]]:
        """(status, decoded JSON or None, response headers). Raises HttpError when the
        server can't be reached."""
        hdrs = {"Accept": "application/json", **(headers or {})}
        data = None
        if body is not None:
            hdrs["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=hdrs, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status, payload, rh = resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as err:
            status, payload, rh = err.code, err.read(), dict(err.headers or {})
        except (OSError, ValueError) as err:
            raise HttpError(f"can't reach {self.base}: {err}") from err
        try:
            return status, json.loads(payload) if payload else None, rh
        except ValueError:
            return status, None, rh
