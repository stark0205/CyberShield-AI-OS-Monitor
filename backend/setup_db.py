# create tables + interactively provision the initial administrator
from getpass import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

import mysql.connector
import os
from auth.hashing import hash_pwd


def bootstrap_password():
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    if password is None:
        if not sys.stdin.isatty():
            raise RuntimeError(
                "Set BOOTSTRAP_ADMIN_PASSWORD or run setup_db.py interactively to provision an administrator"
            )
        password = getpass("Initial administrator password (12-72 UTF-8 bytes): ")
        confirmation = getpass("Confirm administrator password: ")
        if password != confirmation:
            raise RuntimeError("Administrator passwords do not match")
    if not 12 <= len(password.encode("utf-8")) <= 72:
        raise RuntimeError("Administrator password must be 12-72 UTF-8 bytes")
    return password


def execute_sql_script(cur, path, ignored_errors=()):
    delimiter = ";"
    statement = []

    def execute(sql):
        try:
            cur.execute(sql)
        except mysql.connector.Error as error:
            if error.errno not in ignored_errors:
                raise

    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("DELIMITER "):
            delimiter = stripped.split(None, 1)[1]
            continue
        statement.append(line)
        sql = "\n".join(statement).rstrip()
        if sql.endswith(delimiter):
            sql = sql[:-len(delimiter)].strip()
            if sql:
                execute(sql)
            statement.clear()

    remaining = "\n".join(statement).strip()
    if remaining:
        execute(remaining)


def migrate_database_constraints(cur):
    cur.execute("UPDATE usr SET role='user' WHERE role IS NULL")
    cur.execute("SELECT COUNT(*) FROM usr WHERE role NOT IN ('admin', 'user')")
    if cur.fetchone()[0]:
        raise RuntimeError("Cannot constrain usr.role: migrate unsupported role values first")

    cur.execute(
        """
        SELECT IS_NULLABLE
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='usr' AND COLUMN_NAME='role'
        """
    )
    if cur.fetchone()[0] == "YES":
        cur.execute(
            "ALTER TABLE usr MODIFY role VARCHAR(20) NOT NULL DEFAULT 'user'"
        )

    cur.execute(
        """
        SELECT CONSTRAINT_NAME
        FROM information_schema.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA=DATABASE()
          AND TABLE_NAME='usr'
          AND CONSTRAINT_NAME='chk_usr_role'
        """
    )
    if cur.fetchone() is None:
        cur.execute(
            "ALTER TABLE usr ADD CONSTRAINT chk_usr_role CHECK (role IN ('admin', 'user'))"
        )

    cur.execute("UPDATE investigation SET status='Open' WHERE status IS NULL")
    cur.execute(
        "SELECT COUNT(*) FROM investigation WHERE status NOT IN ('Open', 'In Progress', 'Closed')"
    )
    if cur.fetchone()[0]:
        raise RuntimeError(
            "Cannot constrain investigation.status: migrate unsupported statuses first"
        )

    cur.execute(
        """
        SELECT IS_NULLABLE
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE()
          AND TABLE_NAME='investigation'
          AND COLUMN_NAME='status'
        """
    )
    if cur.fetchone()[0] == "YES":
        cur.execute(
            "ALTER TABLE investigation MODIFY status VARCHAR(30) NOT NULL DEFAULT 'Open'"
        )

    cur.execute(
        """
        SELECT COUNT(*)
        FROM investigation
        WHERE (status='Closed' AND closed_at IS NULL)
           OR (status<>'Closed' AND closed_at IS NOT NULL)
        """
    )
    if cur.fetchone()[0]:
        raise RuntimeError(
            "Cannot constrain investigation.closed_at: reconcile timestamps with status first"
        )

    cur.execute(
        """
        SELECT CONSTRAINT_NAME
        FROM information_schema.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA=DATABASE()
          AND TABLE_NAME='investigation'
          AND CONSTRAINT_NAME='chk_investigation_closed_at'
        """
    )
    if cur.fetchone() is None:
        cur.execute(
            """
            ALTER TABLE investigation
            ADD CONSTRAINT chk_investigation_closed_at CHECK (
                (status='Closed' AND closed_at IS NOT NULL)
                OR (status<>'Closed' AND closed_at IS NULL)
            )
            """
        )

    for table, index, columns in (
        ("sec_event", "idx_event_did_ts", "did, ts"),
        ("investigation", "idx_inv_uid_started", "uid, started_at"),
    ):
        cur.execute(
            """
            SELECT INDEX_NAME
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND INDEX_NAME=%s
            LIMIT 1
            """,
            (table, index),
        )
        if cur.fetchone() is None:
            cur.execute(f"CREATE INDEX {index} ON {table} ({columns})")

    cur.execute(
        """
        SELECT INDEX_NAME
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA=DATABASE()
          AND TABLE_NAME='sec_event'
          AND INDEX_NAME='idx_event_did'
        """
    )
    if cur.fetchone() is not None:
        cur.execute("DROP INDEX idx_event_did ON sec_event")


def main():
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_SETUP_USER", os.getenv("DB_USER", "root"))
    password = os.getenv("DB_SETUP_PASS", os.getenv("DB_PASS", ""))

    sql_file = ROOT / "sql" / "01_create.sql"
    seed_file = ROOT / "sql" / "02_seed.sql"
    features_file = ROOT / "sql" / "06_dbms_features.sql"

    conn = mysql.connector.connect(host=host, port=port, user=user, password=password)
    cur = conn.cursor()

    # Ignore "already exists" on re-run (tables / indexes).
    execute_sql_script(cur, sql_file, ignored_errors=(1050, 1061))
    conn.commit()
    print("tables ready")

    # switch to db
    cur.execute("USE cybershield")

    cur.execute("ALTER TABLE usr ALTER COLUMN role SET DEFAULT 'user'")
    conn.commit()
    migrate_database_constraints(cur)
    conn.commit()
    print("database constraints and indexes ready")

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

    # Never create or retain the documented demo password.
    admin_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@cybershield.local")
    cur.execute("SELECT uid, pwd_hash FROM usr WHERE uname=%s", ("admin",))
    admin = cur.fetchone()
    if admin is None:
        pwd = bootstrap_password()
        cur.execute(
            "INSERT INTO usr (uname, email, pwd_hash, role) VALUES (%s, %s, %s, %s)",
            ("admin", admin_email, hash_pwd(pwd), "admin"),
        )
        conn.commit()
        print("initial administrator created")
    else:
        reset_admin = os.getenv("RESET_ADMIN_PASSWORD", "false").lower() in {
            "1",
            "true",
            "yes",
        }
        if reset_admin:
            pwd = bootstrap_password()
            cur.execute(
                "UPDATE usr SET pwd_hash=%s, role='admin' WHERE uid=%s",
                (hash_pwd(pwd), admin[0]),
            )
            conn.commit()
            print("administrator password reset")
        else:
            print("administrator account already exists")

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

    execute_sql_script(cur, features_file)
    conn.commit()
    print("DBMS views, triggers, and procedures ready")

    cur.close()
    conn.close()
    print("done")

if __name__ == "__main__":
    main()
