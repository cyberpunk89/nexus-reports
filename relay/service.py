"""The routes, with the store and GitHub passed in (tests use fakes).

    POST /v1/report          a report from `nexus-cli --report-send`; answers
                             a token, the only handle for tracking it later
    POST /v1/track           {tokens: [...]} -> each report's coarse state
    POST /v1/similar         {sig} -> the public issue with that signature
    POST /v1/github-webhook  `promote` on an inbox issue; open/closed and
                             fixed-<version> labels on public issues
    GET  /v1/status          {mode, pow_bits, min_client, repo}

Lookups are POSTs so tokens never land in request-path logs, and they are not
under /v1/report*, which the firewall throttles hard.
"""

import json

from . import core
import sys

from .github import GitHubError, verify_webhook

PER_IP = 6                      # reports per address per day
GLOBAL = 300                    # reports per day, everyone
PATCH_EVERY = 600               # seconds between body edits for a repeated crash
LOOKUPS = 60                    # track/similar requests per address per day
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
        token = core.new_token()
        rid = self.store.report_add(rep['sig'], rep, 'held' if where == 'inbox' else 'public',
                                    core.token_hash(token))
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
        return 200, {'status': 'filed', 'where': where, 'issue': None if inbox else _url(repo, n),
                     'token': token}

    def _count(self, rep, known):
        sig = rep['sig']
        token = core.new_token()
        self.store.sig_count(sig, rep['version'], rep['edition'])
        self.store.report_add(sig, rep, 'counted', core.token_hash(token))
        known = self.store.sig_get(sig)
        try:                    # the count is stored; a failed edit or comment must not
            self._extras(rep, known)        # turn a counted report into an error
        except GitHubError as e:
            print(f"relay: count kept, issue not updated ({e})", file=sys.stderr)
        return 200, {'status': 'counted', 'where': 'public' if known['public_issue'] else 'inbox',
                     'issue': _url(self.cfg.public, known['public_issue']), 'token': token}

    # ---- POST /v1/track and /v1/similar --------------------------------------
    def _lookup_limited(self, ip) -> bool:
        salt = self.store.salt_today()
        return self.store.hit('look|' + core.rl_key(salt, ip or '?')) > LOOKUPS

    def _body(self, raw, parse):
        try:
            return parse(json.loads(raw.decode('utf-8'))), None
        except (ValueError, UnicodeDecodeError) as e:
            msg = str(e) if isinstance(e, core.Rejected) else 'not JSON'
            return None, (400, {'error': 'schema', 'reason': msg})

    def track(self, raw: bytes, ip: str):
        """The coarse state of the reports a sender holds tokens for. A token
        the relay doesn't know (expired, or never issued) is left out."""
        if self._lookup_limited(ip):
            return 429, {'error': 'limit', 'reason': 'Too many lookups today from here.'}
        toks, err = self._body(raw, core.tokens)
        if err:
            return err
        out = {}
        for t in toks:
            row = self.store.report_by_token(core.token_hash(t))
            if not row:
                continue
            sig_row = self.store.sig_get(row['sig']) if row['sig'] else None
            n = row.get('public_issue') or (sig_row or {}).get('public_issue')
            out[t] = core.resolve(row, sig_row, self.store.issue_get(n) if n else None,
                                  self.cfg.public)
        return 200, {'reports': out}

    def similar(self, raw: bytes, ip: str):
        """A public issue with this signature, if there is one. Held reports
        never answer: that a signature sits in the inbox is private."""
        if self._lookup_limited(ip):
            return 429, {'error': 'limit', 'reason': 'Too many lookups today from here.'}
        sig, err = self._body(raw, core.sig_of)
        if err:
            return err
        known = self.store.sig_get(sig)
        n = (known or {}).get('public_issue')
        return 200, {'match': core.issue_state(n, self.store.issue_get(n), self.cfg.public)
                     if n else None}

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
        action = ev.get('action')
        repo = (ev.get('repository') or {}).get('full_name')
        issue = ev.get('issue') or {}
        if (action == 'labeled' and (ev.get('label') or {}).get('name') == 'promote'
                and repo == self.cfg.inbox):
            return self.promote(int(issue['number']))
        if not isinstance(issue.get('number'), int):
            return 200, {'status': 'ignored'}
        n = issue['number']
        if repo == self.cfg.public and action in ('closed', 'reopened', 'labeled', 'unlabeled'):
            if not self.store.issue_known(n):
                return 200, {'status': 'ignored'}
            # Recomputed from the issue on every event, so labelling before or
            # after closing both work, and reopening clears fixed-in.
            state = 'closed' if issue.get('state') == 'closed' else 'open'
            fix = core.fixed_in(issue.get('labels')) if state == 'closed' else None
            self.store.issue_set(n, state, fix)
            return 200, {'status': 'tracked', 'state': state, 'fixed_in': fix}
        if repo == self.cfg.inbox and action in ('closed', 'reopened'):
            row = self.store.report_by_inbox(n)
            if not row or row['state'] == 'public':     # promote closes the inbox issue
                return 200, {'status': 'ignored'}
            self.store.inbox_closed(n, action == 'closed')
            return 200, {'status': 'tracked'}
        return 200, {'status': 'ignored'}

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
