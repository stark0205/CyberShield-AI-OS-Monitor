# create tables + admin user (password: admin123)
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

import mysql.connector
import os
from auth.hashing import hash_pwd

def main():
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASS", "")

    sql_file = ROOT / "sql" / "01_create.sql"
    seed_file = ROOT / "sql" / "02_seed.sql"

    conn = mysql.connector.connect(host=host, port=port, user=user, password=password)
    cur = conn.cursor()

    # run create script statement by statement
    text = sql_file.read_text()
    for stmt in text.split(";"):
        s = stmt.strip()
        if not s:
            continue
        try:
            cur.execute(s)
        except mysql.connector.Error as e:
            # ignore "already exists" on re-run (tables / indexes)
            if e.errno in (1050, 1061):
                continue
            raise
    conn.commit()
    print("tables ready")

    # switch to db
    cur.execute("USE cybershield")

    # migrate sec_event columns for OS module fields (safe on re-run)
    for alter in (
        "ALTER TABLE sec_event ADD COLUMN ppid INT NULL",
        "ALTER TABLE sec_event ADD COLUMN proc_state VARCHAR(32) NULL",
    ):
        try:
            cur.execute(alter)
            conn.commit()
            print(f"migrated: {alter}")
        except mysql.connector.Error as e:
            # 1060 = duplicate column
            if e.errno == 1060:
                continue
            raise

    # admin user with real bcrypt hash
    cur.execute("SELECT uid FROM usr WHERE uname='admin'")
    if cur.fetchone() is None:
        pwd = hash_pwd("admin123")
        cur.execute(
            "INSERT INTO usr (uname, email, pwd_hash, role) VALUES (%s, %s, %s, %s)",
            ("admin", "admin@cybershield.local", pwd, "admin"),
        )
        conn.commit()
        print("admin user created (password: admin123)")
    else:
        print("admin already exists")

    # seed device + events if empty
    cur.execute("SELECT COUNT(*) FROM device")
    if cur.fetchone()[0] == 0:
        seed = seed_file.read_text()
        for stmt in seed.split(";"):
            s = stmt.strip()
            if s and not s.upper().startswith("USE "):
                cur.execute(s)
        conn.commit()
        print("sample device + events inserted")
    else:
        print("device data already present")

    cur.close()
    conn.close()
    print("done")

if __name__ == "__main__":
    main()
