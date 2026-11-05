"""Neon (Postgres) storage. Tables, created once (see schema.sql):
reports (90 days), sigs, rl and salt (both cleared daily). No IP address
and no raw request ever reaches a table."""

import json
import secrets

KEEP_DAYS = 90


class Store:
    def __init__(self, url: str):
        import psycopg                  # only on the server; tests use MemStore
        self.db = psycopg.connect(url, autocommit=True)

    def _one(self, sql, *args):
        with self.db.cursor() as c:
            c.execute(sql, args)
            return c.fetchone() if c.description else None

    def salt_today(self) -> str:
        """Today's salt, made on the first request of the day, which also
        clears yesterday's limits and salt and the expired reports."""
        row = self._one("SELECT value FROM salt WHERE day = current_date")
        if row:
            return row[0]
        self._one("DELETE FROM rl WHERE day < current_date")
        self._one("DELETE FROM salt WHERE day < current_date")
        self._one("DELETE FROM reports WHERE received_day < current_date - %s::int", KEEP_DAYS)
        self._one("UPDATE reports SET json = json - 'contact' - 'mention_me' "
                  "WHERE state = 'public' AND json ? 'contact'")
        self._one("INSERT INTO salt (day, value) VALUES (current_date, %s) "
                  "ON CONFLICT (day) DO NOTHING", secrets.token_hex(32))
        return self._one("SELECT value FROM salt WHERE day = current_date")[0]

    def hit(self, key: str) -> int:
        return self._one("INSERT INTO rl (day, key, n) VALUES (current_date, %s, 1) "
                         "ON CONFLICT (day, key) DO UPDATE SET n = rl.n + 1 RETURNING n", key)[0]

    def sig_get(self, sig):
        row = self._one("SELECT sig, inbox_issue, public_issue, count, versions, editions, "
                        "extract(epoch FROM now() - last_patch) FROM sigs WHERE sig = %s", sig)
        if not row:
            return None
        return {'sig': row[0], 'inbox_issue': row[1], 'public_issue': row[2], 'count': row[3],
                'versions': list(row[4]), 'editions': list(row[5]),
                'since_patch': None if row[6] is None else float(row[6])}

    def sig_add(self, sig, inbox_issue, public_issue, version, edition) -> None:
        self._one("INSERT INTO sigs (sig, inbox_issue, public_issue, count, versions, editions, "
                  "last_patch) VALUES (%s, %s, %s, 1, ARRAY[%s], ARRAY[%s], now()) "
                  "ON CONFLICT (sig) DO NOTHING", sig, inbox_issue, public_issue, version,
                  edition)

    def sig_count(self, sig, version, edition) -> None:
        self._one("UPDATE sigs SET count = count + 1, "
                  "versions = CASE WHEN %s = ANY(versions) THEN versions "
                  "ELSE array_append(versions, %s) END, "
                  "editions = CASE WHEN %s = ANY(editions) THEN editions "
                  "ELSE array_append(editions, %s) END WHERE sig = %s",
                  version, version, edition, edition, sig)

    def sig_set(self, sig, **fields) -> None:
        for k, v in fields.items():
            assert k in ('inbox_issue', 'public_issue', 'last_patch')
            if k == 'last_patch':
                self._one("UPDATE sigs SET last_patch = now() WHERE sig = %s", sig)
            else:
                self._one(f"UPDATE sigs SET {k} = %s WHERE sig = %s", v, sig)

    def report_add(self, sig, rep: dict, state: str) -> int:
        return self._one("INSERT INTO reports (sig, json, state) VALUES (%s, %s::jsonb, %s) "
                         "RETURNING id", sig, json.dumps(rep), state)[0]

    def report_set(self, rid, **fields) -> None:
        for k, v in fields.items():
            assert k in ('inbox_issue', 'public_issue', 'state', 'json')
            if k == 'json':
                v = json.dumps(v)
                self._one("UPDATE reports SET json = %s::jsonb WHERE id = %s", v, rid)
            else:
                self._one(f"UPDATE reports SET {k} = %s WHERE id = %s", v, rid)

    def report_get(self, rid):
        row = self._one("SELECT id, sig, json, inbox_issue, public_issue, state FROM reports "
                        "WHERE id = %s", rid)
        return None if not row else dict(zip(
            ('id', 'sig', 'json', 'inbox_issue', 'public_issue', 'state'), row))

    def report_by_inbox(self, number):
        row = self._one("SELECT id FROM reports WHERE inbox_issue = %s ORDER BY id LIMIT 1",
                        number)
        return self.report_get(row[0]) if row else None

    def first_report(self, sig):
        row = self._one("SELECT id FROM reports WHERE sig = %s ORDER BY id LIMIT 1", sig)
        return self.report_get(row[0]) if row else None
