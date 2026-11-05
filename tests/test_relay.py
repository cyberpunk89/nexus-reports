"""Relay unit tests: no network, no database (MemStore and FakeGitHub)."""

import hashlib
import hmac
import json
import unittest

from relay import core
from relay.github import verify_webhook
from relay.service import PATCH_EVERY, Config, Relay


class MemStore:
    def __init__(self):
        self.day, self.salts, self.rl, self.sigs, self.reports = 1, {}, {}, {}, {}
        self.patch_age = {}

    def salt_today(self):
        if self.day not in self.salts:
            self.rl = {k: v for k, v in self.rl.items() if k[0] >= self.day}
            self.salts = {d: v for d, v in self.salts.items() if d >= self.day}
            self.salts[self.day] = f"salt{self.day}"
        return self.salts[self.day]

    def hit(self, key):
        k = (self.day, key)
        self.rl[k] = self.rl.get(k, 0) + 1
        return self.rl[k]

    def sig_get(self, sig):
        s = self.sigs.get(sig)
        return None if not s else {**s, 'since_patch': self.patch_age.get(sig)}

    def sig_add(self, sig, inbox_issue, public_issue, version, edition):
        self.sigs.setdefault(sig, {'sig': sig, 'inbox_issue': inbox_issue,
                                   'public_issue': public_issue, 'count': 1,
                                   'versions': [version], 'editions': [edition]})
        self.patch_age[sig] = 0.0

    def sig_count(self, sig, version, edition):
        s = self.sigs[sig]
        s['count'] += 1
        if version not in s['versions']:
            s['versions'].append(version)
        if edition not in s['editions']:
            s['editions'].append(edition)

    def sig_set(self, sig, **f):
        if f.pop('last_patch', None):
            self.patch_age[sig] = 0.0
        self.sigs[sig].update(f)

    def report_add(self, sig, rep, state):
        rid = len(self.reports) + 1
        self.reports[rid] = {'id': rid, 'sig': sig, 'json': json.loads(json.dumps(rep)),
                             'inbox_issue': None, 'public_issue': None, 'state': state}
        return rid

    def report_set(self, rid, **f):
        self.reports[rid].update(f)

    def report_get(self, rid):
        return self.reports.get(rid)

    def report_by_inbox(self, n):
        return next((r for r in self.reports.values() if r['inbox_issue'] == n), None)

    def first_report(self, sig):
        return next((r for r in self.reports.values() if r['sig'] == sig), None)


class FakeGitHub:
    def __init__(self):
        self.issues, self.comments, self.edits, self.n = {}, [], [], 0

    def create_issue(self, repo, title, body, labels):
        self.n += 1
        self.issues[(repo, self.n)] = {'title': title, 'body': body, 'labels': labels}
        return self.n

    def edit_issue(self, repo, number, **f):
        self.edits.append((repo, number, f))
        if 'body' in f:
            self.issues[(repo, number)]['body'] = f['body']

    def comment(self, repo, number, body):
        self.comments.append((repo, number, body))


ENV = {'REPORTS_MODE': 'hold', 'INBOX_REPO': 'o/inbox', 'PUBLIC_REPO': 'o/public',
       'WEBHOOK_SECRET': 's3cret', 'DENY_LIST': '# private\nzorblax\n[bad(regex\n',
       'MIN_CLIENT': '0.5.4'}


def payload(**kw):
    p = {'schema': 1, 'client': '0.5.4', 'kind': 'gui-exception', 'sig': '3f9a0c1b2d4e',
         'version': '0.5.4', 'edition': 'linux', 'title': 'KeyError in library',
         'groups': {'app': ['Nexus 0.5.4 (linux, git)'],
                    'error': ['KeyError: <s>', 'nexus/gui/win_play.py:342 _game_stopped']},
         'removed_lines': 0, 'description': '', 'contact': None, 'mention_me': False}
    p.update(kw)
    return p


def raw(p):
    return json.dumps(p).encode()


def make(**env):
    st, gh = MemStore(), FakeGitHub()
    return Relay(Config({**ENV, **env}), st, gh), st, gh


def signed(event, body):
    data = json.dumps(body).encode()
    sig = 'sha256=' + hmac.new(b's3cret', data, hashlib.sha256).hexdigest()
    return data, {'x-hub-signature-256': sig, 'x-github-event': event}


class Schema(unittest.TestCase):
    def bad(self, **kw):
        with self.assertRaises(core.Rejected):
            core.validate(payload(**kw), '0.5.4')

    def test_ok(self):
        self.assertEqual(core.validate(payload(), '0.5.4')['kind'], 'gui-exception')

    def test_unknown_key(self):
        with self.assertRaises(core.Rejected):
            core.validate({**payload(), 'ip': '1.2.3.4'})

    def test_rejections(self):
        self.bad(kind='virus')
        self.bad(edition='mac')
        self.bad(sig='not-hex!')
        self.bad(groups={'app': ['x'], 'evil': ['y']})
        self.bad(groups={'error': ['x']})                     # app is required
        self.bad(groups={'app': ['x' * 500]})
        self.bad(groups={'app': ['x'] * 200})
        self.bad(contact='not a user!')
        self.bad(client='0.5.3')                              # older than MIN_CLIENT
        self.bad(schema=2)
        self.bad(mention_me='yes')

    def test_too_big(self):
        relay, _, _ = make()
        code, out = relay.report(b'{' + b' ' * (core.MAX_BYTES + 1) + b'}', '1.1.1.1')
        self.assertEqual(code, 413)

    def test_not_json(self):
        relay, _, _ = make()
        self.assertEqual(relay.report(b'nope', '1.1.1.1')[0], 400)


class Rendering(unittest.TestCase):
    def test_inert(self):
        rep = core.validate(payload(description='hi @octocat ![x](http://evil/x.png) ```',
                                    title='@octocat look http://evil'), '0.5.4')
        rep, _ = core.scrub_report(rep, [])
        body = core.body(rep, 'Seen 1 time')
        start = body.index('```text')
        self.assertIn('@octocat', body[start:])
        self.assertNotIn('@octocat', body[:start])          # only inside the fence
        self.assertNotIn('![x](http://evil', body)          # host scrubbed, fenced anyway
        self.assertNotIn('``` ', body.replace('```text', ''))
        self.assertNotIn('@octocat', core.safe_title(rep['title']).replace('@​', ''))

    def test_server_scrub(self):
        rep = core.validate(payload(groups={'app': ['x'], 'log': [
            'mail me at a.b@c.de from 10.1.2.3 in /home/bob/x']}), '0.5.4')
        rep, _ = core.scrub_report(rep, [])
        line = rep['groups']['log'][0]
        for gone in ('a.b@c.de', '10.1.2.3', 'bob'):
            self.assertNotIn(gone, line)

    def test_contact_inbox_only(self):
        rep = core.validate(payload(contact='someone'), '0.5.4')
        self.assertIn('someone', core.body(rep, inbox=True))
        self.assertNotIn('someone', core.body(rep))


class Flow(unittest.TestCase):
    def test_hold_files_in_inbox(self):
        relay, st, gh = make()
        code, out = relay.report(raw(payload(contact='someone')), '1.1.1.1')
        self.assertEqual((code, out['where'], out['issue']), (200, 'inbox', None))
        (repo, n), issue = next(iter(gh.issues.items()))
        self.assertEqual(repo, 'o/inbox')
        self.assertIn('needs-triage', issue['labels'])
        self.assertIn('crash', issue['labels'])
        self.assertIn('Seen 1 time', issue['body'])

    def test_dedupe_counts_and_throttles(self):
        relay, st, gh = make()
        relay.report(raw(payload()), '1.1.1.1')
        code, out = relay.report(raw(payload(version='0.5.5', client='0.5.5')), '2.2.2.2')
        self.assertEqual(out['status'], 'counted')
        self.assertEqual(len(gh.issues), 1)
        self.assertEqual(st.sigs['3f9a0c1b2d4e']['count'], 2)
        self.assertEqual(gh.edits, [])                       # patched < PATCH_EVERY ago
        st.patch_age['3f9a0c1b2d4e'] = PATCH_EVERY + 1
        relay.report(raw(payload()), '3.3.3.3')
        self.assertEqual(len(gh.edits), 1)
        self.assertIn('Seen 3 times on 0.5.4, 0.5.5', gh.edits[0][2]['body'])

    def test_rate_limit_and_salt_rotation(self):
        relay, st, gh = make(PER_IP='2')
        for _ in range(2):
            self.assertEqual(relay.report(raw(payload()), '9.9.9.9')[0], 200)
        self.assertEqual(relay.report(raw(payload()), '9.9.9.9')[0], 429)
        self.assertNotIn('9.9.9.9', json.dumps(list(st.rl)))   # only hashes stored
        st.day = 2                                            # next day: new salt
        self.assertEqual(relay.report(raw(payload()), '9.9.9.9')[0], 200)
        self.assertNotIn(1, st.salts)
        self.assertFalse(any(k[0] == 1 for k in st.rl))

    def test_global_cap(self):
        relay, _, _ = make(GLOBAL_CAP='1')
        relay.report(raw(payload()), '1.1.1.1')
        self.assertEqual(relay.report(raw(payload()), '2.2.2.2')[0], 429)

    def test_off(self):
        relay, _, gh = make(REPORTS_MODE='off')
        code, out = relay.report(raw(payload()), '1.1.1.1')
        self.assertEqual((code, out['error']), (503, 'off'))
        self.assertEqual(relay.status()[1]['mode'], 'off')
        self.assertEqual(gh.issues, {})

    def test_open_mode(self):
        relay, _, gh = make(REPORTS_MODE='open')
        self.assertEqual(relay.report(raw(payload()), '1.1.1.1')[1]['where'], 'public')
        out = relay.report(raw(payload(sig='aaaaaa', description='words')), '1.1.1.1')[1]
        self.assertEqual(out['where'], 'inbox')              # own words: held
        out = relay.report(raw(payload(sig='bbbbbb', kind='user-report')), '1.1.1.1')[1]
        self.assertEqual(out['where'], 'inbox')

    def test_deny_list_means_inbox_only(self):
        relay, _, gh = make(REPORTS_MODE='open')
        p = payload(groups={'app': ['x'], 'log': ['ZorBlax was here']})
        self.assertEqual(relay.report(raw(p), '1.1.1.1')[1]['where'], 'inbox')

    def test_promote_drops_contact(self):
        relay, st, gh = make()
        relay.report(raw(payload(contact='someone')), '1.1.1.1')
        data, headers = signed('issues', {'action': 'labeled', 'label': {'name': 'promote'},
                                          'repository': {'full_name': 'o/inbox'},
                                          'issue': {'number': 1}})
        code, out = relay.webhook(data, headers)
        self.assertEqual(out['status'], 'promoted')
        pub = gh.issues[('o/public', 2)]
        self.assertNotIn('someone', pub['body'])
        self.assertNotIn('needs-triage', pub['labels'])
        self.assertNotIn('contact', st.reports[1]['json'])
        self.assertEqual(st.sigs['3f9a0c1b2d4e']['public_issue'], 2)
        self.assertIn(('o/inbox', 1, {'state': 'closed', 'state_reason': 'completed'}),
                      gh.edits)
        self.assertEqual(relay.webhook(data, headers)[1]['status'], 'already-public')
        # a repeat after promotion counts on the public issue
        out = relay.report(raw(payload()), '2.2.2.2')[1]
        self.assertEqual(out['issue'], 'https://github.com/o/public/issues/2')

    def test_mention_me_on_promotion(self):
        relay, st, gh = make()
        relay.report(raw(payload(contact='someone', mention_me=True)), '1.1.1.1')
        relay.promote(1)
        self.assertIn('@someone', gh.issues[('o/public', 2)]['body'])
        self.assertNotIn('contact', st.reports[1]['json'])

    def test_webhook_signature(self):
        relay, _, _ = make()
        data, headers = signed('issues', {'action': 'labeled'})
        self.assertEqual(relay.webhook(data, {**headers, 'x-hub-signature-256': 'sha256=00'})[0],
                         401)
        self.assertEqual(relay.webhook(data, {'x-github-event': 'issues'})[0], 401)
        self.assertFalse(verify_webhook('', data, headers['x-hub-signature-256']))

    def test_webhook_ignores_other_repos_and_labels(self):
        relay, _, gh = make()
        relay.report(raw(payload()), '1.1.1.1')
        for body in ({'action': 'labeled', 'label': {'name': 'bug'},
                      'repository': {'full_name': 'o/inbox'}, 'issue': {'number': 1}},
                     {'action': 'labeled', 'label': {'name': 'promote'},
                      'repository': {'full_name': 'o/public'}, 'issue': {'number': 1}}):
            self.assertEqual(relay.webhook(*signed('issues', body))[1]['status'], 'ignored')
        self.assertEqual(len(gh.issues), 1)


class Jwt(unittest.TestCase):
    def test_sign(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from relay.github import app_jwt
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode()
        self.assertEqual(app_jwt('1', pem, now=1000).count('.'), 2)


if __name__ == '__main__':
    unittest.main()
