"""Automated tests: role-based access, core flows, fines, CSRF.  Run: python -m unittest -v"""
import os
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta

os.environ["LIBRARY_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
import app as library  # noqa: E402  (must import after LIBRARY_DB is set)


class Base(unittest.TestCase):
    def client(self, username=None, password=None):
        c = library.app.test_client()
        if username:
            self.post(c, "/login", username=username, password=password)
        return c

    def post(self, c, url, **data):
        with c.session_transaction() as s:
            s["csrf"] = "t"
        return c.post(url, data={"csrf": "t", **data})

    def admin(self):     return self.client("admin", "admin123")
    def librarian(self): return self.client("librarian", "library123")
    def student(self):   return self.client("student", "student123")

    def sql(self, query, args=()):
        con = sqlite3.connect(os.environ["LIBRARY_DB"])
        con.row_factory = sqlite3.Row
        rows = con.execute(query, args).fetchall()
        con.commit(); con.close()
        return rows


class AccessControl(Base):
    def test_anonymous_redirected_to_login(self):
        r = self.client().get("/books")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_bad_password_rejected(self):
        r = self.post(self.client(), "/login", username="admin", password="wrong")
        self.assertIn(b"Invalid username or password", r.data)

    def test_student_can_read_but_not_write(self):
        c = self.student()
        self.assertEqual(c.get("/books").status_code, 200)
        self.assertEqual(c.get("/my-loans").status_code, 200)
        for url in ("/books/add", "/issue", "/loans", "/users", "/users/add", "/settings"):
            self.assertEqual(c.get(url).status_code, 403, url)
        for url in ("/books/1/delete", "/books/1/edit", "/loans/1/return", "/loans/1/pay", "/users/1/toggle"):
            self.assertEqual(self.post(c, url).status_code, 403, url)

    def test_student_ui_hides_staff_controls(self):
        html = self.student().get("/books").data
        self.assertNotIn(b"Add book", html)
        self.assertNotIn(b"Remove", html)

    def test_librarian_can_manage_books_but_not_settings(self):
        c = self.librarian()
        self.assertEqual(c.get("/books/add").status_code, 200)
        self.assertEqual(c.get("/issue").status_code, 200)
        self.assertEqual(c.get("/settings").status_code, 403)
        self.assertEqual(self.post(c, "/users/1/toggle").status_code, 403)
        self.assertEqual(c.get("/my-loans").status_code, 403)

    def test_librarian_cannot_create_privileged_users(self):
        c = self.librarian()
        self.post(c, "/users/add", username="sneaky", full_name="Sneaky", password="password123", role="admin")
        self.assertEqual(self.sql("SELECT role FROM users WHERE username='sneaky'")[0]["role"], "student")

    def test_admin_has_full_access(self):
        c = self.admin()
        for url in ("/settings", "/users", "/loans", "/issue", "/books/add", "/"):
            self.assertEqual(c.get(url).status_code, 200, url)
        self.post(c, "/users/add", username="lib2", full_name="Lib Two", password="password123", role="librarian")
        self.assertEqual(self.sql("SELECT role FROM users WHERE username='lib2'")[0]["role"], "librarian")

    def test_csrf_required(self):
        c = self.admin()
        self.assertEqual(c.post("/books/1/delete", data={}).status_code, 400)

    def test_disabled_user_cannot_login(self):
        self.post(self.admin(), "/users/add", username="temp", full_name="Temp", password="password123")
        uid = self.sql("SELECT id FROM users WHERE username='temp'")[0]["id"]
        self.post(self.admin(), f"/users/{uid}/toggle")
        r = self.post(self.client(), "/login", username="temp", password="password123")
        self.assertIn(b"Invalid username or password", r.data)

    def test_open_redirect_blocked(self):
        r = self.post(self.client(), "/login?next=//evil.com", username="admin", password="admin123")
        self.assertNotIn("evil.com", r.headers["Location"])


class LibraryFlow(Base):
    def add_book(self, title, copies):
        self.post(self.librarian(), "/books/add", title=title, author="A. Author", total_copies=str(copies))
        return self.sql("SELECT * FROM books WHERE title=? ORDER BY id DESC", (title,))[0]

    def register(self, username):
        self.post(self.librarian(), "/users/add", username=username, full_name=username.title(), password="password123")
        return self.sql("SELECT id FROM users WHERE username=?", (username,))[0]["id"]

    def issue(self, uid, bid):
        return self.post(self.librarian(), "/issue", user_id=str(uid), book_id=str(bid), follow_redirects=True)

    def test_issue_return_updates_availability(self):
        book, uid = self.add_book("Flow Book", 1), self.register("flow1")
        self.issue(uid, book["id"])
        self.assertEqual(self.sql("SELECT available_copies a FROM books WHERE id=?", (book["id"],))[0]["a"], 0)
        # nobody else can borrow the last copy
        uid2 = self.register("flow2")
        self.issue(uid2, book["id"])
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM loans WHERE book_id=?", (book["id"],))[0]["c"], 1)
        loan = self.sql("SELECT id FROM loans WHERE book_id=?", (book["id"],))[0]["id"]
        self.post(self.librarian(), f"/loans/{loan}/return")
        self.assertEqual(self.sql("SELECT available_copies a FROM books WHERE id=?", (book["id"],))[0]["a"], 1)

    def test_overdue_fine_and_borrow_block_until_paid(self):
        b1, b2, uid = self.add_book("Late Book", 1), self.add_book("Next Book", 1), self.register("late1")
        self.issue(uid, b1["id"])
        loan = self.sql("SELECT id FROM loans WHERE user_id=?", (uid,))[0]["id"]
        past = (date.today() - timedelta(days=3)).isoformat()
        self.sql("UPDATE loans SET due_date=? WHERE id=?", (past, loan))
        self.post(self.librarian(), f"/loans/{loan}/return")
        row = self.sql("SELECT fine, fine_paid FROM loans WHERE id=?", (loan,))[0]
        self.assertEqual(row["fine"], 15.0)                     # 3 days x Rs 5
        self.issue(uid, b2["id"])                               # blocked: unpaid fine
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM loans WHERE user_id=?", (uid,))[0]["c"], 1)
        self.post(self.librarian(), f"/loans/{loan}/pay")
        self.issue(uid, b2["id"])                               # allowed after payment
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM loans WHERE user_id=?", (uid,))[0]["c"], 2)

    def test_loan_limit_enforced(self):
        uid = self.register("limit1")
        for i in range(4):
            self.issue(uid, self.add_book(f"Limit {i}", 1)["id"])
        self.assertEqual(self.sql("SELECT COUNT(*) c FROM loans WHERE user_id=?", (uid,))[0]["c"], 3)

    def test_cannot_remove_book_that_is_issued(self):
        book, uid = self.add_book("Held Book", 1), self.register("held1")
        self.issue(uid, book["id"])
        self.post(self.librarian(), f"/books/{book['id']}/delete")
        self.assertEqual(self.sql("SELECT removed FROM books WHERE id=?", (book["id"],))[0]["removed"], 0)

    def test_search_and_student_sees_only_own_loans(self):
        self.add_book("Zebra Anatomy", 1)
        self.assertIn(b"Zebra Anatomy", self.student().get("/books?q=zebra").data)
        self.assertNotIn(b"Zebra Anatomy", self.student().get("/books?q=nothingmatches").data)
        other = self.register("other1")
        self.issue(other, self.add_book("Private Loan Book", 1)["id"])
        self.assertNotIn(b"Private Loan Book", self.student().get("/my-loans").data)


if __name__ == "__main__":
    unittest.main()
