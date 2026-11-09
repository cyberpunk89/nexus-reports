"""POST /v1/count: schema, flow, storage shape and the 13-month roll-up."""

import json
import re
import unittest
from pathlib import Path

from relay import core, stats
from relay.service import Config, Relay
from tests.test_relay import ENV, FakeGitHub, MemStore

ROOT = Path(__file__).resolve().parent.parent


class CountMemStore(MemStore):
    """MemStore plus the counters; `day` is an int and a "month" is 30 days."""

    def __init__(self):
        super().__init__()
        self.counts, self.counts_month = {}, {}

    def count_add(self, rows):
        for p, f, v in rows:
            k = (self.day, p, f, v)
            self.counts[k] = self.counts.get(k, 0) + 1

    def salt_today(self):
        if self.day not in self.salts:
            self.rollup(self.day - 13 * 30)
        return super().salt_today()

    def rollup(self, before):
        for k in [k for k in self.counts if k[0] < before]:
            m = (k[0] // 30, *k[1:])
            self.counts_month[m] = self.counts_month.get(m, 0) + self.counts.pop(k)


def ping(**kw):
    p = {'schema': 1, 'client': '0.5.5', 'periods': ['d', 'w'], 'edition': 'linux',
         'install': 'git', 'os': 'cachyos', 'os_ver': None, 'desktop': 'niri',
         'session': 'wayland', 'lang': 'de', 'py': '3.14', 'age': '5-25w'}
    p.update(kw)
    return p


def raw(p):
    return json.dumps(p).encode()


def make(**env):
    st = CountMemStore()
    return Relay(Config({**ENV, **env}), st, FakeGitHub()), st


class CountSchema(unittest.TestCase):
    def bad(self, **kw):
        with self.assertRaises(core.Rejected):
            stats.validate(ping(**kw))

    def test_ok(self):
        out = stats.validate(ping())
        self.assertEqual(out['periods'], ['d', 'w'])
        self.assertEqual((out['os'], out['lang'], out['os_ver']), ('cachyos', 'de', None))

    def test_unknown_key(self):
        with self.assertRaises(core.Rejected):
            stats.validate({**ping(), 'id': 'abc'})
        with self.assertRaises(core.Rejected):
            stats.validate({**ping(), 'country': 'DE'})

    def test_rejections(self):
        self.bad(schema=2)
        self.bad(edition='mac')
        self.bad(periods=[])
        self.bad(periods=['d', 'd'])
        self.bad(periods=['y'])
        self.bad(periods='d')
        with self.assertRaises(core.Rejected):
            stats.validate({k: v for k, v in ping().items() if k != 'periods'})

    def test_unknown_values_become_other(self):
        out = stats.validate(ping(os='my-own-distro', desktop='weird wm', lang='deu',
                                  py='2.7', os_ver='x' * 50, session=5, install='pip'))
        for f in ('os', 'desktop', 'lang', 'py', 'os_ver', 'session', 'install'):
            self.assertEqual(out[f], 'other', f)

    def test_values_are_lowercased(self):
        self.assertEqual(stats.validate(ping(desktop='KDE'))['desktop'], 'kde')

    def test_client_not_release_is_dev(self):
        self.assertEqual(stats.validate(ping(client='0.5.5-12-gabc'))['client'], 'dev')
        self.assertEqual(stats.validate(ping(client=None))['client'], 'dev')
        self.assertEqual(stats.validate(ping(client='0.9.0'), latest='0.5.5')['client'], 'dev')
        self.assertEqual(stats.validate(ping(client='0.5.4'), latest='0.5.5')['client'], '0.5.4')

    def test_null_field_is_skipped(self):
        r = stats.rows(stats.validate(ping(os_ver=None, periods=['m'])))
        self.assertNotIn('os_ver', {f for _, f, _ in r})
        self.assertIn(('m', 'all', 'all'), r)
        self.assertIn(('m', 'ed_ver', 'linux/0.5.5'), r)

    def test_windows(self):
        out = stats.validate(ping(edition='windows', os='windows', os_ver='11',
                                  desktop='windows', session=None, install='win-installer'))
        self.assertEqual((out['os'], out['os_ver'], out['session']), ('windows', '11', None))


class CountFlow(unittest.TestCase):
    def test_upsert_adds_one_per_field_per_period(self):
        relay, st = make()
        code, out = relay.count(raw(ping()), '1.1.1.1')
        self.assertEqual((code, out), (200, {'status': 'counted'}))
        relay.count(raw(ping(periods=['d'], lang='fr')), '2.2.2.2')
        self.assertEqual(st.counts[(1, 'd', 'all', 'all')], 2)
        self.assertEqual(st.counts[(1, 'w', 'all', 'all')], 1)
        self.assertEqual(st.counts[(1, 'd', 'lang', 'de')], 1)
        self.assertEqual(st.counts[(1, 'd', 'lang', 'fr')], 1)
        self.assertNotIn((1, 'w', 'lang', 'fr'), st.counts)

    def test_rate_limit_20_per_day(self):
        relay, st = make()
        for _ in range(20):
            self.assertEqual(relay.count(raw(ping()), '1.1.1.1')[0], 200)
        self.assertEqual(relay.count(raw(ping()), '1.1.1.1')[0], 429)
        self.assertEqual(relay.count(raw(ping()), '2.2.2.2')[0], 200)
        st.day += 1
        self.assertEqual(relay.count(raw(ping()), '1.1.1.1')[0], 200)

    def test_count_limit_is_apart_from_reports(self):
        relay, st = make()
        for _ in range(20):
            relay.count(raw(ping()), '1.1.1.1')
        self.assertNotIn((1, core.rl_key('salt1', '1.1.1.1')), st.rl)   # report limit untouched
        self.assertNotIn((1, 'global'), st.rl)

    def test_global_cap(self):
        relay, _ = make(COUNT_CAP='3')
        for ip in ('1', '2', '3'):
            self.assertEqual(relay.count(raw(ping()), ip)[0], 200)
        self.assertEqual(relay.count(raw(ping()), '4')[0], 429)

    def test_off_answers_503(self):
        relay, st = make(COUNT_MODE='off')
        self.assertEqual(relay.count(raw(ping()), '1.1.1.1')[0], 503)
        self.assertEqual(st.counts, {})
        self.assertFalse(relay.status()[1]['count'])
        self.assertTrue(make()[0].status()[1]['count'])

    def test_bad_input(self):
        relay, st = make()
        self.assertEqual(relay.count(b'nope', '1')[0], 400)
        self.assertEqual(relay.count(raw({**ping(), 'id': 'x'}), '1')[0], 400)
        self.assertEqual(relay.count(b'{' + b' ' * stats.MAX_BYTES + b'}', '1')[0], 413)
        self.assertEqual(st.counts, {})

    def test_latest_client_from_env(self):
        relay, st = make(LATEST_CLIENT='0.5.5')
        relay.count(raw(ping(client='1.0.0')), '1')
        self.assertIn((1, 'd', 'client', 'dev'), st.counts)


class CountStore(unittest.TestCase):
    def test_no_ip_column(self):
        for path in [ROOT / 'schema.sql', *sorted((ROOT / 'migrations').glob('*.sql'))]:
            sql = path.read_text().lower()
            for t in re.findall(r'create table if not exists (counts\w*) \(([^;]*)\);', sql):
                self.assertNotRegex(t[1], r'\b(ip|addr|address|id|install_id|ua)\b', path.name)

    def test_migration_matches_schema(self):
        mig = (ROOT / 'migrations' / '003-counts.sql').read_text()
        schema = (ROOT / 'schema.sql').read_text()
        for line in mig.splitlines():
            if line.startswith('CREATE TABLE'):
                self.assertIn(line, schema)

    def test_rollup_moves_old_days(self):
        relay, st = make()
        relay.count(raw(ping(periods=['m'])), '1')
        st.day += 13 * 30 + 1
        relay.count(raw(ping(periods=['m'])), '1')
        self.assertEqual([k for k in st.counts if k[0] == 1], [])
        self.assertEqual(st.counts_month[(0, 'm', 'all', 'all')], 1)
        self.assertEqual(st.counts[(st.day, 'm', 'all', 'all')], 1)


if __name__ == '__main__':
    unittest.main()
