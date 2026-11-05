"""The three routes, with the store and GitHub passed in (tests use fakes).

    POST /v1/report          a report from `nexus-cli --report-send`
    POST /v1/github-webhook  `promote` label on an inbox issue
    GET  /v1/status          {mode, pow_bits, min_client, repo}
"""

import json

from . import core
import sys

from .github import GitHubError, verify_webhook

PER_IP = 6                      # reports per address per day
GLOBAL = 300                    # reports per day, everyone
PATCH_EVERY = 600               # seconds between body edits for a repeated crash
MODES = ('hold', 'open', 'off')


class Config:
    def __init__(self, env: dict):
        self.mode = env.get('REPORTS_MODE', 'hold') if env.get('REPORTS_MODE') in MODES \
            else 'hold'
        self.inbox = env.get('INBOX_REPO', '')
        self.public = env.get('PUBLIC_REPO', '')
        self.secret = env.get('WEBHOOK_SECRET', '')
        self.min_client = env.get('MIN_CLIENT', '0.5.4')
        self.deny = core.deny_patterns(env.get('DENY_LIST', ''))
        self.per_ip = int(env.get('PER_IP') or PER_IP)
        self.global_cap = int(env.get('GLOBAL_CAP') or GLOBAL)


def _url(repo, n):
    return f"https://github.com/{repo}/issues/{n}" if repo and n else None


class Relay:
    def __init__(self, cfg: Config, store, gh):
        self.cfg, self.store, self.gh = cfg, store, gh

    # ---- GET /v1/status ----------------------------------------------------
    def status(self):
        return 200, {'mode': self.cfg.mode, 'pow_bits': 0, 'min_client': self.cfg.min_client,
                     'repo': self.cfg.public}

    # ---- POST /v1/report ---------------------------------------------------
    def report(self, raw: bytes, ip: str):
        if self.cfg.mode == 'off':
            return 503, {'error': 'off', 'reason': 'Anonymous reports are paused for now.'}
        if len(raw) > core.MAX_BYTES:
            return 413, {'error': 'too-big'}
        salt = self.store.salt_today()
        if self.store.hit(core.rl_key(salt, ip or '?')) > self.cfg.per_ip:
            return 429, {'error': 'limit', 'reason': 'Too many reports today from here.'}
        if self.store.hit('global') > self.cfg.global_cap:
            return 429, {'error': 'limit', 'reason': 'The relay is full for today.'}
        try:
            rep = core.validate(json.loads(raw.decode('utf-8')), self.cfg.min_client)
        except (ValueError, UnicodeDecodeError) as e:
            msg = str(e) if isinstance(e, core.Rejected) else 'not JSON'
            return 400, {'error': 'schema', 'reason': msg}
        rep, deny_hit = core.scrub_report(rep, self.cfg.deny)
        known = self.store.sig_get(rep['sig']) if rep['sig'] else None
        if known:
            return self._count(rep, known)
        return self._file(rep, core.destination(rep, self.cfg.mode, deny_hit))

    def _file(self, rep, where):
        rid = self.store.report_add(rep['sig'], rep, 'held' if where == 'inbox' else 'public')
        seen = core.seen_line(1, [rep['version']], [rep['edition']])
        inbox = where == 'inbox'
        repo = self.cfg.inbox if inbox else self.cfg.public
        n = self.gh.create_issue(repo, core.safe_title(rep['title']),
                                 core.body(rep, seen, inbox=inbox, report_id=rid),
                                 core.labels(rep, inbox))
        if inbox:
            self.store.report_set(rid, inbox_issue=n)
        else:
            self.store.report_set(rid, public_issue=n, json=_public_json(rep))
        if rep['sig']:
            self.store.sig_add(rep['sig'], n if inbox else None, None if inbox else n,
                               rep['version'], rep['edition'])
        return 200, {'status': 'filed', 'where': where, 'issue': None if inbox else _url(repo, n)}

    def _count(self, rep, known):
        sig = rep['sig']
        self.store.sig_count(sig, rep['version'], rep['edition'])
        self.store.report_add(sig, rep, 'counted')
        known = self.store.sig_get(sig)
        try:                    # the count is stored; a failed edit or comment must not
            self._extras(rep, known)        # turn a counted report into an error
        except GitHubError as e:
            print(f"relay: count kept, issue not updated ({e})", file=sys.stderr)
        return 200, {'status': 'counted', 'where': 'public' if known['public_issue'] else 'inbox',
                     'issue': _url(self.cfg.public, known['public_issue'])}

    def _extras(self, rep, known):
        if known['since_patch'] is None or known['since_patch'] >= PATCH_EVERY:
            self._refresh(known)
        if (rep['description'] or rep['contact']) and known['inbox_issue']:
            lines = [f"Another report of this ({rep['version']}, {rep['edition']})."]
            if rep['description']:
                lines += ['```text', *(x.replace('```', "'''")
                                       for x in rep['description'].splitlines()), '```']
            if rep['contact']:
                lines.append(f"Contact: `{rep['contact']}` (inbox only)")
            self.gh.comment(self.cfg.inbox, known['inbox_issue'], '\n'.join(lines))

    def _refresh(self, known):
        """Rewrite the issue's seen-count line (throttled by PATCH_EVERY)."""
        first = self.store.first_report(known['sig'])
        if not first:
            return
        rep = first['json'] if isinstance(first['json'], dict) else json.loads(first['json'])
        seen = core.seen_line(known['count'], known['versions'], known['editions'])
        if known['public_issue']:
            self.gh.edit_issue(self.cfg.public, known['public_issue'],
                               body=core.body(_public_json(rep), seen))
        elif known['inbox_issue']:
            self.gh.edit_issue(self.cfg.inbox, known['inbox_issue'],
                               body=core.body(rep, seen, inbox=True, report_id=first['id']))
        self.store.sig_set(known['sig'], last_patch=True)

    # ---- POST /v1/github-webhook --------------------------------------------
    def webhook(self, raw: bytes, headers: dict):
        if not verify_webhook(self.cfg.secret, raw, headers.get('x-hub-signature-256')):
            return 401, {'error': 'signature'}
        if headers.get('x-github-event') != 'issues':
            return 200, {'status': 'ignored'}
        ev = json.loads(raw)
        if (ev.get('action') != 'labeled' or (ev.get('label') or {}).get('name') != 'promote'
                or (ev.get('repository') or {}).get('full_name') != self.cfg.inbox):
            return 200, {'status': 'ignored'}
        return self.promote(int(ev['issue']['number']))

    def promote(self, number: int):
        """Re-create the inbox issue in the public repo, without the contact
        (a private issue can't be transferred to a public repo)."""
        row = self.store.report_by_inbox(number)
        if not row:
            return 200, {'status': 'unknown-issue'}
        if row['state'] == 'public':
            return 200, {'status': 'already-public'}
        rep = row['json'] if isinstance(row['json'], dict) else json.loads(row['json'])
        known = self.store.sig_get(row['sig']) if row['sig'] else None
        if known and known['public_issue']:
            n = known['public_issue']
        else:
            seen = core.seen_line(known['count'], known['versions'], known['editions']) \
                if known else core.seen_line(1, [rep['version']], [rep['edition']])
            n = self.gh.create_issue(self.cfg.public, core.safe_title(rep['title']),
                                     core.body(rep, seen), core.labels(rep, inbox=False))
            if known:
                self.store.sig_set(row['sig'], public_issue=n, last_patch=True)
        self.store.report_set(row['id'], public_issue=n, state='public', json=_public_json(rep))
        link = f"{self.cfg.public}#{n}"
        self.gh.comment(self.cfg.inbox, number, f"Promoted: {link} (filed without the contact).")
        self.gh.edit_issue(self.cfg.inbox, number, state='closed', state_reason='completed')
        return 200, {'status': 'promoted', 'issue': _url(self.cfg.public, n)}


def _public_json(rep: dict) -> dict:
    """What we keep once a report is public: everything but the contact."""
    return {k: v for k, v in rep.items() if k not in ('contact', 'mention_me')}
