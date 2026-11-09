"""POST /v1/count: the anonymous install count (opt-in in the app).

A ping carries no id. The app sends it at most once a UTC day, with
`periods` saying whether this is its first ping of the day (d), ISO week (w)
and month (m), Fedora countme style. The relay adds one to a counter per
field and period; it never stores a ping as a row, so fields can't be
joined back into one install. Every value is checked against an allow-list
and anything unknown is counted as "other". Pure logic, unit-tested."""

import re

from .core import Rejected, version_tuple

SCHEMA = 1
MAX_BYTES = 2_000
PERIODS = ('d', 'w', 'm')
KEYS = {'schema', 'client', 'periods', 'edition', 'install', 'os', 'os_ver', 'desktop',
        'session', 'lang', 'py', 'age'}
REQUIRED = ('schema', 'client', 'periods', 'edition')
EDITIONS = ('linux', 'windows')

# The one pair counted together: edition with version (which build is out there).
PAIR = 'ed_ver'

ALLOWED = {
    'install': ('git', 'source', 'win-installer', 'win-portable'),
    'os': ('windows', 'arch', 'cachyos', 'endeavouros', 'manjaro', 'garuda', 'artix',
           'fedora', 'nobara', 'bazzite', 'ultramarine', 'rhel', 'centos', 'almalinux',
           'rocky', 'ubuntu', 'pop', 'linuxmint', 'zorin', 'elementary', 'kubuntu', 'debian',
           'mx', 'kali', 'opensuse-tumbleweed', 'opensuse-leap', 'opensuse-aeon', 'nixos',
           'gentoo', 'void', 'solus', 'steamos', 'chimeraos', 'slackware', 'alpine',
           'vanilla', 'bluefin', 'aurora'),
    'desktop': ('windows', 'kde', 'gnome', 'niri', 'hyprland', 'sway', 'river', 'xfce',
                'cinnamon', 'mate', 'lxqt', 'lxde', 'budgie', 'pantheon', 'deepin', 'cosmic',
                'gamescope', 'i3', 'awesome', 'qtile', 'wayfire', 'labwc', 'unity', 'enlightenment'),
    'session': ('wayland', 'x11', 'tty'),
    'age': ('<2w', '2-5w', '5-25w', '25w+'),
}
_FORMAT = {
    'os_ver': re.compile(r'^\d{1,4}(?:\.\d{1,2})?$'),
    'lang': re.compile(r'^[a-z]{2}$'),
    'py': re.compile(r'^3\.\d{1,2}$'),
}
_RELEASE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$')
FIELDS = ('install', 'os', 'os_ver', 'desktop', 'session', 'lang', 'py', 'age')


def _value(field, v):
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > 40:
        return 'other'
    v = v.strip().lower()
    if field in ALLOWED:
        return v if v in ALLOWED[field] else 'other'
    return v if _FORMAT[field].match(v) else 'other'


def client_of(v, latest: str = '') -> str:
    """A release version as is; a git build, a pre-release or anything newer
    than the latest release (when the relay knows it) counts as 'dev'."""
    if not isinstance(v, str) or not _RELEASE.match(v):
        return 'dev'
    if latest and version_tuple(v) > version_tuple(latest):
        return 'dev'
    return v


def validate(payload, latest: str = '') -> dict:
    """The ping, normalised: {client, edition, periods, <field>: value|None}."""
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
    if payload['edition'] not in EDITIONS:
        raise Rejected("edition: unknown")
    periods = payload['periods']
    if (not isinstance(periods, list) or not periods or len(periods) > len(PERIODS)
            or any(p not in PERIODS for p in periods) or len(set(periods)) != len(periods)):
        raise Rejected("periods: a non-empty list of d, w, m")
    out = {'client': client_of(payload['client'], latest), 'edition': payload['edition'],
           'periods': [p for p in PERIODS if p in periods]}
    for f in FIELDS:
        out[f] = _value(f, payload.get(f))
    return out


def rows(ping: dict) -> list[tuple[str, str, str]]:
    """(period, field, value) counters to add one to: 'all', edition, client,
    the edition/version pair, and every field that was sent."""
    vals = [('all', 'all'), ('edition', ping['edition']), ('client', ping['client']),
            (PAIR, f"{ping['edition']}/{ping['client']}")]
    vals += [(f, ping[f]) for f in FIELDS if ping[f] is not None]
    return [(p, f, v) for p in ping['periods'] for f, v in vals]
