# nexus-reports

The small relay behind **Send anonymously** in [Nexus](https://github.com/cyberpunk89/nexus-launcher)'s
"Report a problem" page. A report goes from the app to this relay, and the relay files it as a
GitHub issue through a GitHub App (Issues only). No account is needed, and the app holds no key.

- `POST /v1/report`: checks the JSON against a strict schema, scrubs every line again, renders
  the issue on the server (every group is a fenced text block, so mentions and links stay inert),
  and files it in a private inbox. A crash with a known signature only raises the issue's count.
- `POST /v1/github-webhook`: the `promote` label on an inbox issue re-creates it in the public
  repo **without** the reporter's contact.
- `GET /v1/status`: `{mode, pow_bits, min_client, repo}`. `REPORTS_MODE` is `hold` (everything
  to the inbox), `open` (clean signed crashes go public directly) or `off`.

What is stored (Neon Postgres, `schema.sql`): the report JSON for 90 days (the contact is
deleted once a report is public), per-signature counts, and daily rate-limit counters keyed by
a hash of the address with a random salt that is deleted every day. No IP address is stored.

`relay/render.py` and `relay/scrub.py` are copies of `nexus/report/render.py` and
`nexus/report/scrub.py`, so the app's preview and the posted issue can't drift.

Environment: `APP_ID`, `APP_PRIVATE_KEY`, `INSTALLATION_ID`, `WEBHOOK_SECRET`, `DATABASE_URL`,
`INBOX_REPO`, `PUBLIC_REPO`, `REPORTS_MODE`, `DENY_LIST` (one regex per line; a hit keeps the
report in the inbox), optional `MIN_CLIENT`, `PER_IP`, `GLOBAL_CAP`.

Tests: `python3 -m unittest discover -s tests -t .`
