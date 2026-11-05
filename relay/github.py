"""GitHub as the App: a short-lived JWT signed with the App key, swapped
for an installation token (Issues read/write on the two repos only)."""

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

API = 'https://api.github.com'
UA = 'nexus-reports-relay'


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def app_jwt(app_id: str, pem: str, now: float | None = None) -> str:
    now = int(now if now is not None else time.time())
    head = _b64(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())
    body = _b64(json.dumps({'iat': now - 60, 'exp': now + 540, 'iss': str(app_id)}).encode())
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64(sig)}"


def verify_webhook(secret: str, raw: bytes, header: str | None) -> bool:
    if not secret or not header or not header.startswith('sha256='):
        return False
    want = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header[7:])


class GitHubError(RuntimeError):
    pass


class GitHub:
    def __init__(self, app_id: str, pem: str, installation: str):
        self.app_id, self.pem, self.installation = app_id, pem, installation
        self._token, self._exp = None, 0.0

    def _call(self, method, path, data=None, token=None):
        req = urllib.request.Request(
            API + path, method=method,
            data=None if data is None else json.dumps(data).encode(),
            headers={'Accept': 'application/vnd.github+json', 'User-Agent': UA,
                     'X-GitHub-Api-Version': '2022-11-28',
                     'Authorization': f"{'Bearer' if token is None else 'token'} "
                                      f"{token or app_jwt(self.app_id, self.pem)}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise GitHubError(f"{method} {path.split('?')[0]}: HTTP {e.code}") from None
        return json.loads(raw) if raw else {}

    def token(self) -> str:
        if not self._token or time.time() > self._exp:
            d = self._call('POST', f"/app/installations/{self.installation}/access_tokens")
            self._token, self._exp = d['token'], time.time() + 50 * 60
        return self._token

    def api(self, method, path, data=None):
        return self._call(method, path, data, token=self.token())

    def create_issue(self, repo, title, body, labels) -> int:
        return self.api('POST', f"/repos/{repo}/issues",
                        {'title': title, 'body': body, 'labels': labels})['number']

    def edit_issue(self, repo, number, **fields) -> None:
        self.api('PATCH', f"/repos/{repo}/issues/{int(number)}", fields)

    def comment(self, repo, number, body) -> None:
        self.api('POST', f"/repos/{repo}/issues/{int(number)}/comments", {'body': body})
