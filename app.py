"""Library Management System — Flask web app with role-based access control.

Roles
  admin      everything a librarian can do + manage all users + system settings
  librarian  manage books, register students, issue/return books, handle fines
  student    search the catalogue, view own loans and fines (read-only)
"""
import os
import secrets
import sqlite3
from datetime import date, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.teardown_appcontext(db.close_db)

ROLES = ("admin", "librarian", "student")
STAFF = ("admin", "librarian")
MIN_PASSWORD = 8


# ------------------------------------------------------------------ helpers
def qall(sql, args=()):
    return db.get_db().execute(sql, args).fetchall()


def qone(sql, args=()):
    return db.get_db().execute(sql, args).fetchone()


def execute(sql, args=()):
    conn = db.get_db()
    cur = conn.execute(sql, args)
    conn.commit()
    return cur


def get_settings():
    s = {r["key"]: r["value"] for r in qall("SELECT key, value FROM settings")}
    return {"loan_days": int(s["loan_days"]),
            "fine_per_day": float(s["fine_per_day"]),
            "max_loans": int(s["max_loans"])}


def fine_for(due_iso, as_of, rate):
    days_late = (as_of - date.fromisoformat(due_iso)).days
    return round(max(0, days_late) * rate, 2)


LOAN_SQL = """SELECT l.*, b.title, b.author, u.full_name, u.username
              FROM loans l JOIN books b ON b.id = l.book_id
              JOIN users u ON u.id = l.user_id"""


def decorate(loans, s):
    """Add live fine + overdue flag to loan rows."""
    today, out = date.today(), []
    for row in loans:
        d = dict(row)
        if d["return_date"] is None:
            d["overdue"] = today > date.fromisoformat(d["due_date"])
            d["live_fine"] = fine_for(d["due_date"], today, s["fine_per_day"])
        else:
            d["overdue"], d["live_fine"] = False, d["fine"]
        out.append(d)
    return out


# --------------------------------------------------- auth / access control
@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = qone("SELECT * FROM users WHERE id = ? AND active = 1", (uid,))
        if g.user is None:
            session.clear()
    if request.method == "POST":  # CSRF protection for every form
        token = session.get("csrf")
        if not token or token != request.form.get("csrf"):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.context_processor
def inject_globals():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return {"csrf": session["csrf"], "user": g.user}


def roles_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            if g.user["role"] not in roles:
                abort(403)
            return view(*a, **kw)
        return wrapper
    return deco


login_required = roles_required(*ROLES)


def handle_error(e):
    return render_template("error.html", e=e), e.code


for _code in (400, 403, 404):
    app.register_error_handler(_code, handle_error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = qone("SELECT * FROM users WHERE username = ?", (request.form.get("username", "").strip(),))
        if u and u["active"] and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear()
            session["uid"] = u["id"]
            nxt = request.args.get("next", "")
            safe = nxt.startswith("/") and not nxt.startswith("//")
            return redirect(nxt if safe else url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        cur, new, conf = (request.form.get(k, "") for k in ("current", "new", "confirm"))
        if not check_password_hash(g.user["password_hash"], cur):
            flash("Current password is incorrect.", "error")
        elif len(new) < MIN_PASSWORD:
            flash(f"New password must be at least {MIN_PASSWORD} characters.", "error")
        elif new != conf:
            flash("New passwords do not match.", "error")
        else:
            execute("UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new), g.user["id"]))
            flash("Password updated.", "success")
            return redirect(url_for("account"))
    return render_template("account.html")


# ---------------------------------------------------------------- dashboard
@app.route("/")
@login_required
def dashboard():
    s, today = get_settings(), date.today().isoformat()
    if g.user["role"] in STAFF:
        stats = {
            "Book titles": qone("SELECT COUNT(*) c FROM books WHERE removed = 0")["c"],
            "Copies available": qone("SELECT COALESCE(SUM(available_copies),0) c FROM books WHERE removed = 0")["c"],
            "Students": qone("SELECT COUNT(*) c FROM users WHERE role = 'student' AND active = 1")["c"],
            "Active loans": qone("SELECT COUNT(*) c FROM loans WHERE return_date IS NULL")["c"],
            "Overdue": qone("SELECT COUNT(*) c FROM loans WHERE return_date IS NULL AND due_date < ?", (today,))["c"],
            "Unpaid fines (₹)": "%.2f" % qone("SELECT COALESCE(SUM(fine),0) c FROM loans WHERE fine_paid = 0")["c"],
        }
        rows = qall(LOAN_SQL + " WHERE l.return_date IS NULL AND l.due_date < ? ORDER BY l.due_date LIMIT 5", (today,))
    else:
        uid = g.user["id"]
        stats = {
            "Books on loan": qone("SELECT COUNT(*) c FROM loans WHERE user_id = ? AND return_date IS NULL", (uid,))["c"],
            "Overdue": qone("SELECT COUNT(*) c FROM loans WHERE user_id = ? AND return_date IS NULL AND due_date < ?", (uid, today))["c"],
            "Unpaid fines (₹)": "%.2f" % qone("SELECT COALESCE(SUM(fine),0) c FROM loans WHERE user_id = ? AND fine_paid = 0", (uid,))["c"],
        }
        rows = qall(LOAN_SQL + " WHERE l.user_id = ? AND l.return_date IS NULL ORDER BY l.due_date", (uid,))
    return render_template("dashboard.html", stats=stats, loans=decorate(rows, s))


# -------------------------------------------------------------------- books
@app.route("/books")
@login_required
def books():
    q = request.args.get("q", "").strip()
    like = f"%{q}%"
    rows = qall("""SELECT * FROM books WHERE removed = 0 AND
                   (title LIKE ? OR author LIKE ? OR isbn LIKE ? OR category LIKE ?)
                   ORDER BY title""", (like,) * 4)
    return render_template("books.html", books=rows, q=q)


def parse_book_form():
    f = request.form
    title, author = f.get("title", "").strip(), f.get("author", "").strip()
    try:
        total = int(f.get("total_copies", ""))
    except ValueError:
        return None, "Copies must be a whole number."
    if not title or not author:
        return None, "Title and author are required."
    if total < 0:
        return None, "Copies cannot be negative."
    return {"title": title, "author": author, "isbn": f.get("isbn", "").strip(),
            "category": f.get("category", "").strip(), "total": total}, None


@app.route("/books/add", methods=["GET", "POST"])
@roles_required(*STAFF)
def add_book():
    if request.method == "POST":
        d, err = parse_book_form()
        if err:
            flash(err, "error")
        else:
            execute("""INSERT INTO books (title, author, isbn, category, total_copies, available_copies)
                       VALUES (?,?,?,?,?,?)""",
                    (d["title"], d["author"], d["isbn"], d["category"], d["total"], d["total"]))
            flash(f"Added “{d['title']}”.", "success")
            return redirect(url_for("books"))
    return render_template("book_form.html", book=None, f=request.form)


@app.route("/books/<int:bid>/edit", methods=["GET", "POST"])
@roles_required(*STAFF)
def edit_book(bid):
    book = qone("SELECT * FROM books WHERE id = ? AND removed = 0", (bid,))
    if book is None:
        abort(404)
    issued = book["total_copies"] - book["available_copies"]
    if request.method == "POST":
        d, err = parse_book_form()
        if not err and d["total"] < issued:
            err = f"{issued} copies are currently issued, so the total cannot be lower than that."
        if err:
            flash(err, "error")
        else:
            execute("""UPDATE books SET title=?, author=?, isbn=?, category=?,
                       total_copies=?, available_copies=? WHERE id=?""",
                    (d["title"], d["author"], d["isbn"], d["category"],
                     d["total"], d["total"] - issued, bid))
            flash("Book updated.", "success")
            return redirect(url_for("books"))
    return render_template("book_form.html", book=book, f=request.form if request.method == "POST" else book)


@app.post("/books/<int:bid>/delete")
@roles_required(*STAFF)
def delete_book(bid):
    book = qone("SELECT * FROM books WHERE id = ? AND removed = 0", (bid,))
    if book is None:
        abort(404)
    if book["total_copies"] != book["available_copies"]:
        flash("Cannot remove: some copies are currently issued.", "error")
    else:
        execute("UPDATE books SET removed = 1 WHERE id = ?", (bid,))
        flash(f"Removed “{book['title']}”.", "success")
    return redirect(url_for("books"))


# -------------------------------------------------------------------- users
@app.route("/users")
@roles_required(*STAFF)
def users():
    if g.user["role"] == "admin":
        rows = qall("SELECT * FROM users ORDER BY role, full_name")
    else:  # librarians only see / manage students
        rows = qall("SELECT * FROM users WHERE role = 'student' ORDER BY full_name")
    return render_template("users.html", rows=rows)


@app.route("/users/add", methods=["GET", "POST"])
@roles_required(*STAFF)
def add_user():
    if request.method == "POST":
        f = request.form
        role = f.get("role", "student") if g.user["role"] == "admin" else "student"
        username, name = f.get("username", "").strip(), f.get("full_name", "").strip()
        pw = f.get("password", "")
        if role not in ROLES:
            abort(400)
        if not username or not name:
            flash("Username and full name are required.", "error")
        elif len(pw) < MIN_PASSWORD:
            flash(f"Password must be at least {MIN_PASSWORD} characters.", "error")
        else:
            try:
                execute("INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?,?,?,?,?)",
                        (username, generate_password_hash(pw), name, f.get("email", "").strip(), role))
                flash(f"Created {role} account “{username}”.", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
    return render_template("user_form.html", f=request.form)


@app.post("/users/<int:uid>/toggle")
@roles_required("admin")
def toggle_user(uid):
    if uid == g.user["id"]:
        flash("You cannot deactivate your own account.", "error")
    elif qone("SELECT 1 FROM users WHERE id = ?", (uid,)) is None:
        abort(404)
    else:
        execute("UPDATE users SET active = 1 - active WHERE id = ?", (uid,))
        flash("User status updated.", "success")
    return redirect(url_for("users"))


# -------------------------------------------------------------------- loans
@app.route("/issue", methods=["GET", "POST"])
@roles_required(*STAFF)
def issue():
    s = get_settings()
    if request.method == "POST":
        try:
            uid, bid = int(request.form["user_id"]), int(request.form["book_id"])
        except (KeyError, ValueError):
            abort(400)
        today = date.today()
        student = qone("SELECT * FROM users WHERE id=? AND role='student' AND active=1", (uid,))
        book = qone("SELECT * FROM books WHERE id=? AND removed=0", (bid,))
        err = None
        if not student or not book:
            err = "Invalid student or book."
        elif qone("SELECT 1 FROM loans WHERE user_id=? AND return_date IS NULL AND due_date<?", (uid, today.isoformat())):
            err = f"{student['full_name']} has overdue books. Return them first."
        elif qone("SELECT 1 FROM loans WHERE user_id=? AND fine>0 AND fine_paid=0", (uid,)):
            err = f"{student['full_name']} has unpaid fines."
        elif qone("SELECT COUNT(*) c FROM loans WHERE user_id=? AND return_date IS NULL", (uid,))["c"] >= s["max_loans"]:
            err = f"Loan limit reached ({s['max_loans']} books)."
        elif qone("SELECT 1 FROM loans WHERE user_id=? AND book_id=? AND return_date IS NULL", (uid, bid)):
            err = "This student already has a copy of that book."
        if not err:
            conn = db.get_db()  # one transaction: decrement stock + create loan
            cur = conn.execute("UPDATE books SET available_copies = available_copies - 1 "
                               "WHERE id = ? AND available_copies > 0", (bid,))
            if cur.rowcount == 0:
                conn.rollback()
                err = "No copies of this book are available."
            else:
                due = today + timedelta(days=s["loan_days"])
                conn.execute("INSERT INTO loans (book_id, user_id, issued_by, issue_date, due_date) VALUES (?,?,?,?,?)",
                             (bid, uid, g.user["id"], today.isoformat(), due.isoformat()))
                conn.commit()
                flash(f"Issued “{book['title']}” to {student['full_name']}. Due {due.isoformat()}.", "success")
                return redirect(url_for("loans"))
        flash(err, "error")
    students = qall("SELECT id, full_name, username FROM users WHERE role='student' AND active=1 ORDER BY full_name")
    avail = qall("SELECT id, title, author, available_copies FROM books WHERE removed=0 AND available_copies>0 ORDER BY title")
    return render_template("issue.html", students=students, books=avail, s=s)


@app.route("/loans")
@roles_required(*STAFF)
def loans():
    s, status, today = get_settings(), request.args.get("status", "active"), date.today().isoformat()
    where = {"active": "l.return_date IS NULL",
             "overdue": "l.return_date IS NULL AND l.due_date < ?",
             "fines": "l.fine > 0 AND l.fine_paid = 0",
             "returned": "l.return_date IS NOT NULL",
             "all": "1=1"}.get(status)
    if where is None:
        abort(404)
    args = (today,) if status == "overdue" else ()
    rows = qall(f"{LOAN_SQL} WHERE {where} ORDER BY l.due_date", args)
    return render_template("loans.html", loans=decorate(rows, s), staff=True, status=status, heading="Loans")


@app.route("/my-loans")
@roles_required("student")
def my_loans():
    rows = qall(LOAN_SQL + " WHERE l.user_id = ? ORDER BY l.issue_date DESC, l.id DESC", (g.user["id"],))
    return render_template("loans.html", loans=decorate(rows, get_settings()), staff=False, status=None, heading="My loans")


@app.post("/loans/<int:lid>/return")
@roles_required(*STAFF)
def return_loan(lid):
    loan = qone("SELECT * FROM loans WHERE id = ?", (lid,))
    if loan is None:
        abort(404)
    if loan["return_date"]:
        flash("That book was already returned.", "error")
        return redirect(url_for("loans"))
    today = date.today()
    fine = fine_for(loan["due_date"], today, get_settings()["fine_per_day"])
    conn = db.get_db()
    conn.execute("UPDATE loans SET return_date = ?, fine = ? WHERE id = ?", (today.isoformat(), fine, lid))
    conn.execute("UPDATE books SET available_copies = MIN(total_copies, available_copies + 1) WHERE id = ?",
                 (loan["book_id"],))
    conn.commit()
    flash("Returned. Overdue fine: ₹%.2f" % fine if fine else "Returned on time. No fine.", "success")
    return redirect(url_for("loans"))


@app.post("/loans/<int:lid>/pay")
@roles_required(*STAFF)
def pay_fine(lid):
    if qone("SELECT 1 FROM loans WHERE id = ?", (lid,)) is None:
        abort(404)
    execute("UPDATE loans SET fine_paid = 1 WHERE id = ?", (lid,))
    flash("Fine marked as paid.", "success")
    return redirect(url_for("loans", status="fines"))


# ----------------------------------------------------------------- settings
@app.route("/settings", methods=["GET", "POST"])
@roles_required("admin")
def settings():
    if request.method == "POST":
        try:
            new = {"loan_days": int(request.form["loan_days"]),
                   "fine_per_day": float(request.form["fine_per_day"]),
                   "max_loans": int(request.form["max_loans"])}
            if new["loan_days"] < 1 or new["max_loans"] < 1 or new["fine_per_day"] < 0:
                raise ValueError
        except (KeyError, ValueError):
            flash("Enter valid positive numbers.", "error")
        else:
            for k, v in new.items():
                execute("UPDATE settings SET value = ? WHERE key = ?", (str(v), k))
            flash("Settings saved.", "success")
            return redirect(url_for("settings"))
    return render_template("settings.html", s=get_settings())


db.init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
