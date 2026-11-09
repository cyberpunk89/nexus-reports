"""Print the install count: python3 scripts/stats.py [days]

Reads DATABASE_URL from the environment, or from .env.local (never printed).
Needs psycopg (pip install 'psycopg[binary]')."""

import os
import sys
from pathlib import Path


def _url() -> str:
    if os.environ.get('DATABASE_URL'):
        return os.environ['DATABASE_URL']
    env = Path(__file__).resolve().parent.parent / '.env.local'
    for line in env.read_text().splitlines() if env.exists() else []:
        k, _, v = line.partition('=')
        if k.strip() == 'DATABASE_URL':
            return v.strip().strip('"').strip("'")
    sys.exit('stats: DATABASE_URL is not set (and not in .env.local)')


def main() -> None:
    import psycopg
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    with psycopg.connect(_url()) as db, db.cursor() as c:
        c.execute("SELECT span, start, installs FROM v_active "
                  "WHERE start >= current_date - %s::int ORDER BY span, start", (days,))
        print(f"Active installs, last {days} days")
        for span, start, n in c.fetchall():
            print(f"  {span:<6} {start}  {n}")
        c.execute("SELECT span, field, value, n FROM v_breakdown ORDER BY span, field, n DESC")
        last = None
        for span, field, value, n in c.fetchall():
            if (span, field) != last:
                print(f"\nLast full {span}: {field}")
                last = (span, field)
            print(f"  {value:<24} {n}")


if __name__ == '__main__':
    main()
