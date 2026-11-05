"""The relay's pure logic: check a payload, scrub it again, decide where it
goes and render the issue. No network and no database here, so all of it
is unit-tested.

A payload is what `nexus-cli --report-send` POSTs: the draft's groups the
user kept (removed lines already blanked), their own words, and an
optional GitHub username that stays in the private inbox."""

import hashlib
import re

from . import render as _render
from .scrub import scrub_lines

SCHEMA = 1
KINDS = ('gui-exception', 'cli-internal', 'native-crash', 'game-failure', 'user-report')
EDITIONS = ('linux', 'windows')
GROUPS = _render.ORDER
KEYS = {'schema', 'client', 'kind', 'sig', 'version', 'edition', 'title', 'groups',
        'removed_lines', 'description', 'contact', 'mention_me', 'pow'}
REQUIRED = ('schema', 'client', 'kind', 'version', 'edition', 'groups')
MAX_BYTES = 96_000
MAX_LINES = {'proton_log': 120}            # per group; everything else MAX_GROUP
MAX_GROUP = 80
MAX_LINE = 400
MAX_TITLE = 120
_VERSION = re.compile(r'^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?(?:[.+-][\w.]{1,20})?$')
_SIG = re.compile(r'^[0-9a-f]{6,16}$')
_GH_USER = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$')
_CTRL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]')
CRASH_LABEL = {'gui-exception': 'crash', 'cli-internal': 'crash', 'native-crash': 'crash',
               'game-failure': 'game-failure', 'user-report': 'user-report'}


class Rejected(ValueError):
    """The payload breaks the schema; the message is safe to send back."""


def _text(v, what, limit) -> str:
    if not isinstance(v, str):
        raise Rejected(f"{what}: not a string")
    if len(v) > limit:
        raise Rejected(f"{what}: too long")
    return _CTRL.sub('', v)


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r'\d+', v)[:3])


def validate(payload, min_client: str = '0') -> dict:
    """The payload, checked and normalised, or Rejected."""
    if not isinstance(payload, dict):
        raise Rejected("not a JSON object")
    extra = set(payload) - KEYS
    if extra:
        raise Rejected(f"unknown keys: {', '.join(sorted(extra))}")
    missing = [k for k in REQUIRED if k not in payload]
    if missing:
        raise Rejected(f"missing: {', '.join(missing)}")
    if payload['schema'] != SCHEMA:
        raise Rejected("unsupported schema")
    out = {'schema': SCHEMA}
    for key in ('client', 'version'):
        v = _text(payload[key], key, 40)
        if not _VERSION.match(v):
            raise Rejected(f"{key}: not a version")
        out[key] = v
    if version_tuple(out['client']) < version_tuple(min_client):
        raise Rejected("client too old")
    if payload['kind'] not in KINDS:
        raise Rejected("kind: unknown")
    out['kind'] = payload['kind']
    if payload['edition'] not in EDITIONS:
        raise Rejected("edition: unknown")
    out['edition'] = payload['edition']
    sig = payload.get('sig')
    if sig is not None and (not isinstance(sig, str) or not _SIG.match(sig)):
        raise Rejected("sig: not a signature")
    out['sig'] = sig
    out['title'] = _text(payload.get('title') or 'Problem report', 'title', MAX_TITLE).strip() \
        or 'Problem report'
    groups = payload['groups']
    if not isinstance(groups, dict) or not groups:
        raise Rejected("groups: empty")
    out['groups'] = {}
    for key, lines in groups.items():
        if key not in GROUPS:
            raise Rejected(f"groups: unknown group {key[:20]!r}")
        if not isinstance(lines, list) or len(lines) > MAX_LINES.get(key, MAX_GROUP):
            raise Rejected(f"groups.{key}: too many lines")
        out['groups'][key] = [_text(x, f"groups.{key}", MAX_LINE) for x in lines]
    if 'app' not in out['groups']:
        raise Rejected("groups: app is required")
    removed = payload.get('removed_lines') or 0
    if not isinstance(removed, int) or isinstance(removed, bool) or not 0 <= removed <= 1000:
        raise Rejected("removed_lines: bad count")
    out['removed_lines'] = removed
    out['description'] = _text(payload.get('description') or '', 'description',
                               _render.DESCRIPTION_MAX).strip()
    contact = payload.get('contact')
    if contact is not None:
        contact = _text(contact, 'contact', 39).strip().lstrip('@')
        if contact and not _GH_USER.match(contact):
            raise Rejected("contact: not a GitHub username")
    out['contact'] = contact or None
    mention = payload.get('mention_me', False)
    if not isinstance(mention, bool):
        raise Rejected("mention_me: not a boolean")
    out['mention_me'] = bool(mention and out['contact'])
    return out


# ---- the second scrub and the deny-list -----------------------------------

def deny_patterns(text: str) -> list:
    """DENY_LIST: one regex per line (blank and # lines skipped), case-blind.
    A bad line is skipped rather than taking the relay down."""
    out = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            out.append(re.compile(line, re.IGNORECASE))
        except re.error:
            continue
    return out


def scrub_report(rep: dict, deny) -> tuple[dict, bool]:
    """(report with every line scrubbed again, deny-list hit). A hit never
    says which word: the words are the private data."""
    groups = {k: scrub_lines(v, {}) for k, v in rep['groups'].items()}
    desc = '\n'.join(scrub_lines(rep['description'].splitlines(), {})) if rep['description'] \
        else ''
    title = scrub_lines([rep['title']], {})[0]
    texts = [title, desc, *(x for v in groups.values() for x in v)]
    hit = any(rx.search(t) for rx in deny for t in texts)
    return {**rep, 'groups': groups, 'description': desc, 'title': title}, hit


# ---- where it goes ---------------------------------------------------------

def destination(rep: dict, mode: str, deny_hit: bool) -> str:
    """'inbox' or 'public'. `open` files only clean, signed crash reports
    in public; anything with words, a game or a deny-list hit is held."""
    if mode != 'open' or deny_hit:
        return 'inbox'
    clean = (rep['kind'] != 'user-report' and rep['sig'] and not rep['description']
             and 'game' not in rep['groups'])
    return 'public' if clean else 'inbox'


def labels(rep: dict, inbox: bool) -> list[str]:
    out = ['anonymous-report', CRASH_LABEL[rep['kind']], f"edition:{rep['edition']}"]
    return out + ['needs-triage'] if inbox else out


# ---- rendering -------------------------------------------------------------

def safe_title(title: str) -> str:
    """Titles don't render markdown, but mentions and links in them still
    look like a call-out; break them."""
    t = _CTRL.sub('', title).replace('@', '@​').replace('://', ':​//')
    return ('[Report] ' + t)[:MAX_TITLE + 9]


def seen_line(count: int, versions, editions) -> str:
    times = '1 time' if count == 1 else f"{count} times"
    return f"Seen {times} on {', '.join(sorted(versions)) or '?'} ({', '.join(sorted(editions)) or '?'})"


def body(rep: dict, seen: str | None = None, inbox: bool = False, report_id=None) -> str:
    """The issue text: the vendored render() over the groups as sent, plus
    the seen-count line, and for the inbox only the contact."""
    draft = {'groups': rep['groups'], 'default_exclude': (), 'version': rep['version'],
             'edition': rep['edition'], 'kind': rep['kind'], 'signature': rep['sig'],
             'title': rep['title']}
    sel = {'exclude': (), 'with_game': 'game' in rep['groups'],
           'description': rep['description']}
    text = _render.render(draft, sel)['body']
    head, _, rest = text.partition('\n')
    parts = [head]
    if seen:
        parts.append(seen)
    if rep.get('removed_lines'):
        parts.append(f"{rep['removed_lines']} line(s) removed by the reporter")
    out = '\n'.join(parts) + ('\n' + rest if rest else '')
    out = out.replace("Made by Nexus's \"Report a problem\".",
                      "Sent anonymously from Nexus's \"Report a problem\".")
    if inbox:
        who = f"`{rep['contact']}`" if rep.get('contact') else 'none'
        out += (f"\n\n---\n**Inbox only.** Contact: {who}"
                f"{' (asked to be mentioned)' if rep.get('mention_me') else ''}. "
                "Add the `promote` label to file this publicly without the contact.")
    elif rep.get('mention_me') and rep.get('contact'):
        out += f"\n\nReporter: @{rep['contact']}"
    if report_id is not None:
        out += f"\n<!-- nexus-report:{int(report_id)} -->"
    return out[:65_000]


# ---- rate limits -----------------------------------------------------------

def rl_key(salt: str, ip: str) -> str:
    """The only trace of a sender: a hash of today's random salt and the
    address. The salt is deleted daily, so yesterday's keys mean nothing."""
    return hashlib.sha256(f"{salt}|{ip}".encode()).hexdigest()[:32]
