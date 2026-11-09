"""Vercel entry: one WSGI app for /v1/*. Built once per cold start."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from relay.github import GitHub, GitHubError  # noqa: E402
from relay.service import Config, Relay       # noqa: E402

_relay = None


def _get():
    global _relay
    if _relay is None:
        from relay.store import Store
        env = os.environ
        _relay = Relay(Config(env), Store(env['DATABASE_URL']),
                       GitHub(env['APP_ID'], env['APP_PRIVATE_KEY'].replace('\\n', '\n'),
                              env['INSTALLATION_ID']))
    return _relay


def _route(environ) -> str:
    path = environ.get('PATH_INFO') or ''
    return path.rstrip('/').rsplit('/', 1)[-1]


def app(environ, start_response):
    method = environ.get('REQUEST_METHOD', 'GET')
    route = _route(environ)
    headers = {k[5:].replace('_', '-').lower(): v for k, v in environ.items()
               if k.startswith('HTTP_')}
    try:
        size = int(environ.get('CONTENT_LENGTH') or 0)
    except ValueError:
        size = 0
    raw = environ['wsgi.input'].read(min(size, 200_000)) if size else b''
    ip = (headers.get('x-real-ip') or (headers.get('x-forwarded-for') or '').split(',')[0]).strip()
    try:
        if route == 'status' and method == 'GET':
            code, out = _get().status()
        elif route == 'report' and method == 'POST':
            code, out = _get().report(raw, ip)
        elif route == 'count' and method == 'POST':
            code, out = _get().count(raw, ip)
        elif route == 'track' and method == 'POST':
            code, out = _get().track(raw, ip)
        elif route == 'similar' and method == 'POST':
            code, out = _get().similar(raw, ip)
        elif route == 'github-webhook' and method == 'POST':
            code, out = _get().webhook(raw, headers)
        else:
            code, out = 404, {'error': 'not-found'}
    except GitHubError as e:
        print(f"relay: {e}", file=sys.stderr)
        code, out = 502, {'error': 'github', 'reason': 'GitHub did not take the report.'}
    except Exception as e:                    # never echo internals back
        print(f"relay: {type(e).__name__}", file=sys.stderr)
        code, out = 500, {'error': 'internal'}
    data = json.dumps(out).encode()
    reasons = {200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 404: 'Not Found',
               413: 'Payload Too Large', 429: 'Too Many Requests', 500: 'Internal Server Error',
               502: 'Bad Gateway', 503: 'Service Unavailable'}
    start_response(f"{code} {reasons.get(code, 'OK')}",
                   [('Content-Type', 'application/json'), ('Cache-Control', 'no-store'),
                    ('Content-Length', str(len(data)))])
    return [data]
