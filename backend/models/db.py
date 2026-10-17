# MySQL connection helper
import os
from pathlib import Path
import mysql.connector
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

def get_conn():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "cybershield"),
    )

def run_query(sql, params=None, fetch=False, one=False):
    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params or ())
        if fetch:
            return cur.fetchone() if one else cur.fetchall()
        conn.commit()
        return cur.lastrowid
    finally:
        cur.close()
        conn.close()


def call_procedure(sql, params=None):
    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params or ())
        result = cur.fetchone() if cur.with_rows else None
        while cur.nextset():
            if cur.with_rows:
                cur.fetchall()
        conn.commit()
        return result
    except mysql.connector.Error:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
