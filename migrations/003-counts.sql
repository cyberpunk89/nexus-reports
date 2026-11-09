-- w-102: the anonymous install count (POST /v1/count). Only adds; safe to run twice.
CREATE TABLE IF NOT EXISTS counts (day date NOT NULL, period char(1) NOT NULL, field text NOT NULL, value text NOT NULL, n int NOT NULL DEFAULT 0, PRIMARY KEY (day, period, field, value));
CREATE TABLE IF NOT EXISTS counts_month (month date NOT NULL, period char(1) NOT NULL, field text NOT NULL, value text NOT NULL, n bigint NOT NULL DEFAULT 0, PRIMARY KEY (month, period, field, value));
-- Active installs: DAU per day, WAU per ISO week, MAU per month (older months from counts_month).
CREATE OR REPLACE VIEW v_active AS
  SELECT 'day'::text AS span, day AS start, n::bigint AS installs FROM counts WHERE period = 'd' AND field = 'all'
  UNION ALL
  SELECT 'week', date_trunc('week', day)::date, sum(n)::bigint FROM counts WHERE period = 'w' AND field = 'all' GROUP BY 2
  UNION ALL
  SELECT 'month', date_trunc('month', day)::date, sum(n)::bigint FROM counts WHERE period = 'm' AND field = 'all' GROUP BY 2
  UNION ALL
  SELECT 'month', month, n FROM counts_month WHERE period = 'm' AND field = 'all';
-- Each field for the last full ISO week and the last full month; values under 5 fold into 'other'.
CREATE OR REPLACE VIEW v_breakdown AS
  WITH raw AS (
    SELECT 'week'::text AS span, field, value, sum(n)::bigint AS n FROM counts
     WHERE period = 'w' AND field <> 'all'
       AND day >= (date_trunc('week', current_date) - interval '7 days')::date
       AND day < date_trunc('week', current_date)::date
     GROUP BY field, value
    UNION ALL
    SELECT 'month', field, value, sum(n)::bigint FROM counts
     WHERE period = 'm' AND field <> 'all'
       AND day >= (date_trunc('month', current_date) - interval '1 month')::date
       AND day < date_trunc('month', current_date)::date
     GROUP BY field, value)
  SELECT span, field, CASE WHEN n < 5 THEN 'other' ELSE value END AS value, sum(n)::bigint AS n
    FROM raw GROUP BY 1, 2, 3;
