# LibraryHub — Library Management System (Flask + SQLite)

A role-based web application for running a small library: catalogue, members,
issuing/returning, availability tracking and overdue fines.

## Run
```
pip install -r requirements.txt
python app.py            # then open http://127.0.0.1:5000
python -m unittest -v    # 15 automated tests
```
On first run `library.db` (a single SQLite file) is created and seeded with demo data.

| Role      | Username    | Password     |
|-----------|-------------|--------------|
| Admin     | `admin`     | `admin123`   |
| Librarian | `librarian` | `library123` |
| Student   | `student`   | `student123` |

**Change these before any real use** (Account page) and set `SECRET_KEY` in the environment.

## Who can do what
| Feature                              | Admin | Librarian | Student |
|--------------------------------------|:-----:|:---------:|:-------:|
| Login / change own password          |  ✔   |    ✔     |   ✔    |
| Search books & see availability      |  ✔   |    ✔     |   ✔    |
| Add / edit / remove books            |  ✔   |    ✔     |   ✖    |
| Register students                    |  ✔   |    ✔     |   ✖    |
| Create librarian/admin accounts      |  ✔   |    ✖     |   ✖    |
| Enable / disable users               |  ✔   |    ✖     |   ✖    |
| Issue & return books                 |  ✔   |    ✔     |   ✖    |
| View all loans, overdue, fines       |  ✔   |    ✔     |   ✖    |
| Mark fines paid                      |  ✔   |    ✔     |   ✖    |
| View **own** loans and fines         |  —   |    —     |   ✔    |
| Change loan period / fine / limits   |  ✔   |    ✖     |   ✖    |

## Structure
```
app.py          routes, access control, business rules
db.py           SQLite schema, connection handling, demo seed data
templates/      Jinja2 pages (one base layout + one template per screen)
static/style.css
test_app.py     access-control and workflow tests
```

## Design decisions
- **Server-side RBAC.** Every protected route uses `@roles_required(...)`; hiding a button is only cosmetic. A student who types `/books/add` in the URL bar gets 403.
- **Loans are their own table** so history and fines survive returns.
- **Soft-deleting books** (`removed = 1`) keeps old loan records readable.
- **Atomic issue:** stock decrement and loan insert run in one transaction, and the decrement only succeeds if `available_copies > 0`, so the last copy can't be issued twice.
- **Borrowing rules:** blocked when the student has overdue books, unpaid fines, has hit the loan limit, or already holds that title.
- **Fine** = days late × rate (both configurable), computed live for unreturned books and stored on return.
- **Security:** hashed passwords (Werkzeug), CSRF token on every POST, open-redirect check on login, disabled users are locked out immediately, librarians cannot create privileged accounts (role is forced to `student` server-side).

## Known limits / next steps
Single-node SQLite (fine for one library; use PostgreSQL for many concurrent users), no email notifications, no book reservations, no self-registration, no login rate-limiting.
