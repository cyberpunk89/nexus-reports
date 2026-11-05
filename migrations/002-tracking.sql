-- w-79: track sent reports. Only adds; safe to run twice.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS token_hash text;
CREATE UNIQUE INDEX IF NOT EXISTS reports_token ON reports (token_hash);
CREATE INDEX IF NOT EXISTS reports_public ON reports (public_issue);
CREATE TABLE IF NOT EXISTS issues (number int PRIMARY KEY, state text NOT NULL DEFAULT 'open', fixed_in text, updated timestamptz NOT NULL DEFAULT now());
INSERT INTO issues (number)
  SELECT public_issue FROM sigs WHERE public_issue IS NOT NULL
  UNION SELECT public_issue FROM reports WHERE public_issue IS NOT NULL
  ON CONFLICT (number) DO NOTHING;
