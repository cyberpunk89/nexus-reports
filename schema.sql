CREATE TABLE IF NOT EXISTS reports (id bigserial PRIMARY KEY, sig text, received_day date NOT NULL DEFAULT current_date, json jsonb NOT NULL, inbox_issue int, public_issue int, state text NOT NULL DEFAULT 'held');
CREATE INDEX IF NOT EXISTS reports_sig ON reports (sig);
CREATE INDEX IF NOT EXISTS reports_inbox ON reports (inbox_issue);
CREATE TABLE IF NOT EXISTS sigs (sig text PRIMARY KEY, inbox_issue int, public_issue int, count int NOT NULL DEFAULT 1, versions text[] NOT NULL DEFAULT '{}', editions text[] NOT NULL DEFAULT '{}', last_patch timestamptz);
CREATE TABLE IF NOT EXISTS rl (day date NOT NULL, key text NOT NULL, n int NOT NULL DEFAULT 0, PRIMARY KEY (day, key));
CREATE TABLE IF NOT EXISTS salt (day date PRIMARY KEY, value text NOT NULL);
