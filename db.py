"""Database layer: schema, per-request connection, first-run seed data."""
import os
import sqlite3

from flask import g
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get(
    "LIBRARY_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "library.db"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL CHECK (role IN ('admin','librarian','student')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT CURRENT_DATE
);
CREATE TABLE IF NOT EXISTS books (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    title            TEXT NOT NULL,
    author           TEXT NOT NULL,
    isbn             TEXT NOT NULL DEFAULT '',
    category         TEXT NOT NULL DEFAULT '',
    total_copies     INTEGER NOT NULL CHECK (total_copies >= 0),
    available_copies INTEGER NOT NULL CHECK (available_copies >= 0),
    removed          INTEGER NOT NULL DEFAULT 0   -- soft delete keeps loan history intact
);
CREATE TABLE IF NOT EXISTS loans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id     INTEGER NOT NULL REFERENCES books(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    issued_by   INTEGER REFERENCES users(id),
    issue_date  TEXT NOT NULL,
    due_date    TEXT NOT NULL,
    return_date TEXT,
    fine        REAL NOT NULL DEFAULT 0,
    fine_paid   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

DEFAULT_SETTINGS = {"loan_days": "14", "fine_per_day": "5", "max_loans": "3"}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    for k, v in DEFAULT_SETTINGS.items():
        con.execute("INSERT OR IGNORE INTO settings VALUES (?, ?)", (k, v))
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        seed(con)
    con.commit()
    con.close()


def seed(con):
    """Demo accounts and books so the app is usable on first run."""
    users = [
        ("admin", "admin123", "System Admin", "admin@library.local", "admin"),
        ("librarian", "library123", "Meera Iyer", "meera@library.local", "librarian"),
        ("student", "student123", "Asha Rao", "asha@example.com", "student"),
        ("rahul", "student123", "Rahul Nair", "rahul@example.com", "student"),
    ]
    for username, pw, name, email, role in users:
        con.execute(
            "INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?,?,?,?,?)",
            (username, generate_password_hash(pw), name, email, role),
        )
    books = [
        ("The Pragmatic Programmer", "Hunt & Thomas", "9780135957059", "Software", 2),
        ("Clean Code", "Robert C. Martin", "9780132350884", "Software", 1),
        ("Introduction to Algorithms", "Cormen et al.", "9780262046305", "Computer Science", 3),
        ("Python Crash Course", "Eric Matthes", "9781718502703", "Programming", 2),
        ("Deep Learning", "Goodfellow, Bengio, Courville", "9780262035613", "AI/ML", 2),
        ("Hands-On Machine Learning", "Aurélien Géron", "9781098125974", "AI/ML", 2),
        ("Design Patterns", "Gamma et al.", "9780201633610", "Software", 1),
        ("Artificial Intelligence: A Modern Approach", "Russell & Norvig", "9780134610993", "AI/ML", 2),
    ]
    for title, author, isbn, cat, n in books:
        con.execute(
            "INSERT INTO books (title, author, isbn, category, total_copies, available_copies) VALUES (?,?,?,?,?,?)",
            (title, author, isbn, cat, n, n),
        )
