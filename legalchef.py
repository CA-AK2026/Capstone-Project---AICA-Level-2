"""LegalChef Work Organiser. Run with Python 3.10+ or the bundled executable."""
import argparse
import base64
import hashlib
import hmac
import secrets
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path
from threading import Thread
from time import sleep

from flask import Flask, abort, flash, g, redirect, render_template_string, request, send_file, session, url_for
from waitress import serve

SERVICES = ("Income tax", "GST", "Appeals", "Bookkeeping", "Other")
STATUSES = ("Open", "Running", "Ready for review", "Completed")
ROOT = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
DB = ROOT / "LegalChef Data" / "legalchef.sqlite3"
app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=64_000, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(hours=10))

SCHEMA = """
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
 password TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
 version INTEGER NOT NULL DEFAULT 1, temporary INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clients (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, contact TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS client_services (
 client INTEGER REFERENCES clients(id), service TEXT NOT NULL, PRIMARY KEY(client, service)
);
CREATE TABLE IF NOT EXISTS tasks (
 id INTEGER PRIMARY KEY, client INTEGER NOT NULL REFERENCES clients(id), service TEXT NOT NULL,
 title TEXT NOT NULL, details TEXT NOT NULL, assignee INTEGER REFERENCES users(id),
 due TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Open',
 urgent INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS attendance (
 id INTEGER PRIMARY KEY, user INTEGER NOT NULL REFERENCES users(id),
 place TEXT NOT NULL, client INTEGER REFERENCES clients(id),
 client_name TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '',
 recorded_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS attendance_by_day ON attendance(date(recorded_at), user);
CREATE TABLE IF NOT EXISTS gst_schedules (
 client INTEGER PRIMARY KEY REFERENCES clients(id), cadence TEXT NOT NULL,
 assignee INTEGER NOT NULL REFERENCES users(id), next_period TEXT NOT NULL,
 paused INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS gst_items (
 task INTEGER PRIMARY KEY REFERENCES tasks(id), client INTEGER NOT NULL REFERENCES clients(id),
 kind TEXT NOT NULL, period_start TEXT, period_end TEXT, period_label TEXT NOT NULL,
 return_status TEXT NOT NULL, UNIQUE(client,kind,period_start,period_end)
);
CREATE TABLE IF NOT EXISTS handoffs (
 id INTEGER PRIMARY KEY, task INTEGER NOT NULL REFERENCES tasks(id),
 requester INTEGER NOT NULL REFERENCES users(id), recipient INTEGER NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending',
 decided_by INTEGER REFERENCES users(id), decision_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
 decided_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_handoff ON handoffs(task) WHERE status='Pending';
CREATE TABLE IF NOT EXISTS activity (
 id INTEGER PRIMARY KEY, task INTEGER NOT NULL REFERENCES tasks(id), actor INTEGER NOT NULL REFERENCES users(id),
 message TEXT NOT NULL, at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
"""

def connect(path):
    conn = sqlite3.connect(path, timeout=8)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init(path):
    global DB
    DB = Path(path)
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(DB)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        with conn:
            conn.execute("INSERT OR IGNORE INTO config VALUES ('secret', ?)", (secrets.token_hex(32),))
        app.secret_key = conn.execute("SELECT value FROM config WHERE key='secret'").fetchone()[0]
    finally:
        conn.close()

def db():
    if "db" not in g:
        g.db = connect(DB)
    return g.db

@app.teardown_appcontext
def close_db(error):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return salt + ":" + digest.hex()

def password_matches(password, stored):
    return hmac.compare_digest(hash_password(password, stored.split(":")[0]), stored)

def field(name, limit=200, required=False):
    value = request.form.get(name, "").strip()
    if len(value) > limit or (required and not value):
        raise ValueError(f"Enter a valid {name.replace('_', ' ')} (up to {limit} characters).")
    return value

def new_password():
    value = request.form.get("password", "")
    if not 12 <= len(value) <= 128:
        raise ValueError("Use a password of 12 to 128 characters.")
    return hash_password(value)

def number(name, default=0):
    return int(request.form.get(name) or default)

def one(sql, params=()):
    return db().execute(sql, params).fetchone()

def query(sql, params=()):
    return db().execute(sql, params).fetchall()

@app.before_request
def prepare():
    g.user = one("SELECT * FROM users WHERE id=? AND active=1 AND version=?",
                 (session.get("user"), session.get("version")))
    if request.method == "POST":
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(expected.encode(), request.form.get("csrf", "").encode()):
            abort(400, "This form expired. Reload the page and try again.")
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    g.admin = bool(g.user and g.user["role"] == "admin")
    if request.endpoint in {"login", "logo", "setup", "app_manifest", "app_icon", "install"}:
        return
    if not g.user:
        return redirect(url_for("login"))
    if g.user["temporary"] and request.endpoint not in {"password", "logout"}:
        return redirect(url_for("password"))

@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    return response

def require_admin():
    if not g.admin:
        abort(403)

def create_user(role, *, temporary=False):
    name = field("name", 100, True)
    username = field("username", 60, True)
    if not all(c.isalnum() or c in "._-" for c in username):
        raise ValueError("Use letters, numbers, dots, hyphens or underscores in the username.")
    db().execute("INSERT INTO users(username,name,password,role,temporary) VALUES (?,?,?,?,?)",
                 (username, name, new_password(), role, int(temporary)))

def sign_in(user):
    session.clear()
    session.permanent = True
    session.update(user=user["id"], version=user["version"])

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if one("SELECT id FROM users LIMIT 1"):
        return redirect(url_for("login"))
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403, "Open http://127.0.0.1 on the server to create the super admin.")
    if request.method == "POST":
        try:
            db().execute("BEGIN IMMEDIATE")
            if not one("SELECT id FROM users LIMIT 1"):
                create_user("admin")
            db().commit()
            return redirect(url_for("login"))
        except (ValueError, sqlite3.IntegrityError) as error:
            db().rollback()
            flash(str(error), "error")
    return page("Set up LegalChef", AUTH, mode="setup")

@app.route("/login", methods=["GET", "POST"])
def login():
    if not one("SELECT id FROM users LIMIT 1"):
        return redirect(url_for("setup"))
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")[:60].strip()
        password = request.form.get("password", "")
        user = one("SELECT * FROM users WHERE username=? AND active=1", (username,))
        if len(password) <= 128 and password_matches(password, user["password"] if user else DUMMY_PASSWORD) and user:
            sign_in(user)
            return redirect(url_for("dashboard"))
        flash("Check your username and password.", "error")
    return page("Sign in", AUTH, mode="login")

DUMMY_PASSWORD = hash_password(secrets.token_hex(16))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/password", methods=["GET", "POST"])
def password():
    if request.method == "POST":
        try:
            current = request.form.get("current", "")
            if len(current) > 128 or not password_matches(current, g.user["password"]):
                raise ValueError("The current password is incorrect.")
            with db():
                result = db().execute("UPDATE users SET password=?,temporary=0,version=version+1 WHERE id=? AND version=?",
                                      (new_password(), g.user["id"], g.user["version"]))
                if not result.rowcount:
                    raise ValueError("Your account changed. Sign in again.")
            sign_in(one("SELECT * FROM users WHERE id=?", (g.user["id"],)))
            flash("Password updated.")
            return redirect(url_for("dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return page("Change password", AUTH, mode="password")

TASK_SELECT = """SELECT t.*, c.name AS client_name, u.name AS staff_name
FROM tasks t JOIN clients c ON c.id=t.client LEFT JOIN users u ON u.id=t.assignee"""

def scope():
    return ("1=1", ()) if g.admin else ("t.assignee=?", (g.user["id"],))

@app.get("/")
def dashboard():
    service = request.args.get("service", "")
    state = request.args.get("state", "")
    search = request.args.get("q", "").strip()[:100]
    if service and service not in SERVICES:
        abort(404)
    where, params = scope()
    if service:
        where += " AND t.service=?"
        params += (service,)
    order = ("t.status='Completed', t.urgent DESC, t.due='', t.due, t.id DESC" if g.admin else
             "t.status='Completed', t.due='', t.due, t.urgent DESC, t.id DESC")
    tasks = query(TASK_SELECT + " WHERE " + where + " ORDER BY " + order, params)
    today = date.today().isoformat()
    def overdue(task):
        return bool(task["due"] and task["due"] < today and task["status"] != "Completed")
    counts = {status: sum(t["status"] == status for t in tasks) for status in STATUSES}
    counts["Overdue"] = sum(overdue(t) for t in tasks)
    counts["Flagged"] = sum(t["urgent"] and t["status"] != "Completed" for t in tasks)
    tasks = [t for t in tasks if (not state or t["status"] == state or
             (state == "Overdue" and overdue(t)) or
             (state == "Flagged" and t["urgent"] and t["status"] != "Completed"))
             and search.casefold() in f'{t["title"]} {t["client_name"]} {t["staff_name"] or ""}'.casefold()]
    clients = []
    if service:
        if g.admin:
            clients = query("SELECT c.* FROM clients c JOIN client_services s ON s.client=c.id WHERE s.service=? ORDER BY c.name", (service,))
        else:
            clients = query("SELECT DISTINCT c.* FROM clients c JOIN tasks t ON t.client=c.id WHERE t.service=? AND t.assignee=? ORDER BY c.name",
                            (service, g.user["id"]))
    if not g.admin and not (state or search):
        tasks = [task for task in tasks if task["status"] != "Completed"]
    pending = one("SELECT count(*) FROM handoffs WHERE status='Pending'")[0] if g.admin else 0
    show_attendance = not service
    latest_attendance = one("""SELECT * FROM attendance WHERE user=? AND date(recorded_at)=?
                              ORDER BY id DESC LIMIT 1""", (g.user["id"], today)) if show_attendance else None
    return page(service or ("Overview" if g.admin else "My queue"), DASHBOARD,
                tasks=tasks, clients=clients, counts=counts, service=service,
                state=state, search=search, today=today, overdue=overdue, pending=pending,
                gst_forms=GST_FORMS, show_attendance=show_attendance, places=ATTENDANCE_PLACES,
                attendance_clients=attendance_clients() if show_attendance else [],
                latest_attendance=latest_attendance)

@app.route("/clients", methods=["GET", "POST"])
def clients():
    require_admin()
    client_id = request.args.get("edit", 0, type=int)
    editing = one("SELECT * FROM clients WHERE id=?", (client_id,)) if client_id else None
    if client_id and not editing:
        abort(404)
    if request.method == "POST":
        try:
            name = field("name", 150, True)
            contact = field("contact", 200)
            services = set(request.form.getlist("services"))
            if not services or not services.issubset(SERVICES):
                raise ValueError("Select at least one service.")
            db().execute("BEGIN IMMEDIATE")
            if editing:
                existing = {row["service"] for row in query("SELECT DISTINCT service FROM tasks WHERE client=?", (client_id,))}
                if existing - services:
                    raise ValueError("Keep services that already have tasks attached.")
                db().execute("UPDATE clients SET name=?,contact=? WHERE id=?", (name, contact, client_id))
                db().execute("DELETE FROM client_services WHERE client=?", (client_id,))
            else:
                client_id = db().execute("INSERT INTO clients(name,contact) VALUES(?,?)", (name, contact)).lastrowid
            db().executemany("INSERT INTO client_services VALUES (?,?)",
                             [(client_id, service) for service in services])
            db().commit()
            flash("Client saved.")
            return redirect(url_for("clients"))
        except ValueError as error:
            db().rollback()
            flash(str(error), "error")
    records = query("""SELECT c.*, group_concat(s.service, ' · ') AS services
                     FROM clients c JOIN client_services s ON s.client=c.id GROUP BY c.id ORDER BY c.name""")
    selected = {row["service"] for row in query("SELECT service FROM client_services WHERE client=?", (client_id,))}
    return page("Clients", CLIENTS, records=records, editing=editing, selected=selected)

@app.route("/staff", methods=["GET", "POST"])
def staff():
    require_admin()
    if request.method == "POST":
        try:
            with db():
                action = request.form.get("action")
                if action == "add":
                    create_user("staff", temporary=True)
                elif action == "add_admin":
                    create_user("admin", temporary=True)
                elif action == "reset":
                    result = db().execute("UPDATE users SET password=?,temporary=1,version=version+1 WHERE id=? AND role='staff'",
                                          (new_password(), number("user")))
                    if not result.rowcount:
                        abort(404)
                elif action == "toggle":
                    result = db().execute("UPDATE users SET active=1-active,version=version+1 WHERE id=? AND role='staff'", (number("user"),))
                    if not result.rowcount:
                        abort(404)
                else:
                    abort(400)
            flash("Super admin added. They will choose a new password when they sign in."
                  if action == "add_admin" else "Staff account updated.")
            return redirect(url_for("staff"))
        except ValueError as error:
            flash(str(error), "error")
        except sqlite3.IntegrityError:
            flash("That username is already in use.", "error")
    return page("Staff & super admins", STAFF,
                staff=query("SELECT * FROM users WHERE role='staff' ORDER BY name"),
                admins=query("SELECT id, name, username FROM users WHERE role='admin' ORDER BY name"))

def log(task_id, message):
    db().execute("INSERT INTO activity(task,actor,message) VALUES (?,?,?)",
                 (task_id, g.user["id"], message))

@app.route("/task/new", methods=["GET", "POST"])
def new_task():
    if request.method == "POST":
        try:
            client, service = field("client_service", 50, True).split("|", 1)
            client_id = int(client)
            title, details, assignee, due = task_fields()
            db().execute("BEGIN IMMEDIATE")
            if not one("SELECT 1 FROM client_services WHERE client=? AND service=?", (client_id, service)):
                raise ValueError("Choose a service listed for the client.")
            if g.admin:
                check_assignee(assignee)
            urgent = int(request.form.get("urgent") == "yes")
            task_id = db().execute("""INSERT INTO tasks(client,service,title,details,assignee,due,urgent)
                                   VALUES (?,?,?,?,?,?,?)""",
                                   (client_id, service, title, details, assignee, due, urgent)).lastrowid
            log(task_id, "Task created")
            if urgent:
                log(task_id, "Red flag added")
            db().commit()
            return redirect(url_for("task", task_id=task_id))
        except ValueError as error:
            db().rollback()
            flash(str(error), "error")
    chosen_service = request.args.get("service", "")
    choices = query("""SELECT c.id,c.name,s.service FROM clients c JOIN client_services s ON s.client=c.id
                     WHERE ?='' OR s.service=? ORDER BY c.name,s.service""", (chosen_service, chosen_service))
    return page("New task", NEW_TASK, choices=choices, employees=employees() if g.admin else [],
                chosen_client=request.args.get("client", 0, type=int), chosen_service=chosen_service)

def task_fields():
    title = field("title", 160, True)
    details = field("details", 4000)
    assignee = (number("assignee") or None) if g.admin else g.user["id"]
    due = field("due", 10)
    if due:
        try:
            if date.fromisoformat(due).isoformat() != due:
                raise ValueError
        except ValueError:
            raise ValueError("Enter a valid due date.") from None
    return title, details, assignee, due

def check_assignee(assignee, previous=None):
    if assignee and assignee != previous and not one("SELECT 1 FROM users WHERE id=? AND role='staff' AND active=1", (assignee,)):
        raise ValueError("Choose an active member of staff.")

def employees():
    return query("SELECT id,name,active FROM users WHERE role='staff' ORDER BY name")

ATTENDANCE_PLACES = ("Office", "Client visit", "Department visit", "Other")
GST_FORMS = {"gstr1": "GSTR-1", "gstr3b": "GSTR-3B", "mismatch": "Mismatch"}
GST_CADENCES = {"Monthly": 1, "Quarterly": 3}
GST_RETURN_STATES = ("Pending", "In preparation", "Ready to file", "Filed")
GST_MISMATCH_STATES = ("Open", "Under review", "Resolved")

def attendance_clients():
    return query("SELECT id,name FROM clients ORDER BY name,id")

@app.route("/attendance", methods=["GET", "POST"])
def attendance():
    today = date.today().isoformat()
    selected = request.args.get("day", today)
    try:
        selected = date.fromisoformat(selected).isoformat()
    except ValueError:
        abort(400, "Select a valid date.")
    if request.method == "POST":
        try:
            place = field("place", 30, True)
            if place not in ATTENDANCE_PLACES:
                raise ValueError("Choose an attendance location.")
            client_id = number("client") if place == "Client visit" else None
            detail = field("location", 180, place in {"Department visit", "Other"})
            with db():
                client = one("SELECT name FROM clients WHERE id=?", (client_id,)) if client_id else None
                if place == "Client visit" and client is None:
                    raise ValueError("Choose the client you visited.")
                db().execute("""INSERT INTO attendance(user,place,client,client_name,location)
                              VALUES(?,?,?,?,?)""",
                             (g.user["id"], place, client_id, client["name"] if client else "", detail))
            flash("Attendance recorded.")
        except ValueError as error:
            flash(str(error), "error")
        return redirect(url_for("dashboard") if request.form.get("from_queue") else url_for("attendance"))
    where = "" if g.admin else " AND a.user=?"
    params = (selected,) if g.admin else (selected, g.user["id"])
    entries = query("""SELECT a.*, u.name FROM attendance a JOIN users u ON u.id=a.user
                     WHERE date(a.recorded_at)=?""" + where + " ORDER BY a.id DESC", params)
    return page("Attendance", ATTENDANCE, entries=entries, places=ATTENDANCE_PLACES,
                attendance_clients=attendance_clients(), selected=selected)

def shift_month(start, months):
    year, month = divmod(start.year * 12 + start.month - 1 + months, 12)
    return date(year, month + 1, 1)

def gst_period_start(day, months):
    return date(day.year, (day.month - 1) // months * months + 1, 1)

def gst_period_label(start, end):
    if start == end.replace(day=1):
        return start.strftime("%b %Y")
    return f'{start:%b}–{end:%b %Y}'

def create_gst_item(conn, client_id, assignee, kind, label, details, *, start=None, end=None):
    suffix = f"{GST_FORMS[kind]} · {label}"
    task_id = conn.execute("""INSERT INTO tasks(client,service,title,details,assignee)
                            VALUES(?,'GST',?,?,?)""", (client_id, suffix, details, assignee)).lastrowid
    conn.execute("""INSERT INTO gst_items(task,client,kind,period_start,period_end,period_label,return_status)
                  VALUES(?,?,?,?,?,?,?)""",
                 (task_id, client_id, kind, start.isoformat() if start else None,
                  end.isoformat() if end else None, label,
                  GST_MISMATCH_STATES[0] if kind == "mismatch" else GST_RETURN_STATES[0]))
    return task_id

def generate_gst_returns(conn, today):
    """Generate closed periods and advance each schedule inside the caller's transaction."""
    schedules = conn.execute("""SELECT s.* FROM gst_schedules s
                              JOIN users u ON u.id=s.assignee AND u.active=1
                              JOIN client_services c ON c.client=s.client AND c.service='GST'
                              WHERE s.paused=0 AND s.next_period<?""", (today.isoformat(),)).fetchall()
    count = 0
    for schedule in schedules:
        client_id = schedule["client"]
        start = date.fromisoformat(schedule["next_period"])
        months = GST_CADENCES[schedule["cadence"]]
        following = shift_month(start, months)
        while following <= today:
            end = following - timedelta(days=1)
            for kind in ("gstr1", "gstr3b"):
                previous = conn.execute("""SELECT 1 FROM gst_items WHERE client=? AND kind=?
                                          AND period_start=? AND period_end=?""",
                                        (client_id, kind, start.isoformat(), end.isoformat())).fetchone()
                if not previous:
                    create_gst_item(conn, client_id, schedule["assignee"], kind,
                                    gst_period_label(start, end),
                                    "Track preparation and filing for this GST period.", start=start, end=end)
                    count += 1
            start = following
            following = shift_month(start, months)
        if start.isoformat() != schedule["next_period"]:
            conn.execute("UPDATE gst_schedules SET next_period=? WHERE client=?", (start.isoformat(), client_id))
    return count

def gst_scheduler():
    while True:
        conn = None
        try:
            conn = connect(DB)
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                generate_gst_returns(conn, date.today())
        except sqlite3.Error:
            app.logger.exception("Could not generate scheduled GST tasks. Will retry.")
        finally:
            if conn is not None:
                conn.close()
        sleep(60)

def gst_clients():
    return query("""SELECT c.id,c.name FROM clients c JOIN client_services s ON s.client=c.id
                    WHERE s.service='GST' ORDER BY c.name,c.id""")

def valid_gst_client(client_id):
    if not one("SELECT 1 FROM client_services WHERE client=? AND service='GST'", (client_id,)):
        raise ValueError("Choose a client registered for GST.")

@app.route("/gst/schedules", methods=["GET", "POST"])
def gst_schedules():
    require_admin()
    if request.method == "POST":
        try:
            client_id = number("client")
            db().execute("BEGIN IMMEDIATE")
            valid_gst_client(client_id)
            action = request.form.get("action")
            if action == "pause":
                result = db().execute("UPDATE gst_schedules SET paused=1 WHERE client=?", (client_id,))
                if not result.rowcount:
                    raise ValueError("This client has no schedule.")
                count = 0
            elif action == "save":
                cadence = field("cadence", 20, True)
                assignee = number("assignee")
                if cadence not in GST_CADENCES or not assignee:
                    raise ValueError("Choose a filing frequency and a staff member.")
                check_assignee(assignee)
                months = GST_CADENCES[cadence]
                first = field("first_period", 7)
                previous = one("SELECT * FROM gst_schedules WHERE client=?", (client_id,))
                if first:
                    try:
                        start = date.fromisoformat(first + "-01")
                    except ValueError:
                        raise ValueError("Enter a valid first period month.") from None
                    if start.year < 2000 or start.year > 2099 or start != gst_period_start(start, months):
                        raise ValueError("Choose a valid first month. Quarterly periods start in Jan, Apr, Jul or Oct.")
                elif previous and previous["cadence"] == cadence:
                    start = date.fromisoformat(previous["next_period"])
                else:
                    start = shift_month(gst_period_start(date.today(), months), -months)
                db().execute("""INSERT INTO gst_schedules(client,cadence,assignee,next_period,paused)
                              VALUES(?,?,?,?,0) ON CONFLICT(client) DO UPDATE SET cadence=excluded.cadence,
                              assignee=excluded.assignee,next_period=excluded.next_period,paused=0""",
                             (client_id, cadence, assignee, start.isoformat()))
                count = generate_gst_returns(db(), date.today())
            else:
                abort(400)
            db().commit()
            flash(f"GST schedule saved. {count} return tasks created." if action == "save" else "GST schedule paused.")
            return redirect(url_for("gst_schedules", client=client_id))
        except ValueError as error:
            db().rollback()
            flash(str(error), "error")
    chosen = request.args.get("client", type=int)
    schedules = query("""SELECT s.*,c.name,u.name AS assignee_name,u.active FROM gst_schedules s
                        JOIN clients c ON c.id=s.client JOIN users u ON u.id=s.assignee ORDER BY c.name""")
    return page("GST schedules", GST_SCHEDULES, service="GST", gst_forms=GST_FORMS,
                schedules=schedules, clients=gst_clients(), chosen=chosen,
                current=next((row for row in schedules if row["client"] == chosen), None),
                cadences=GST_CADENCES, employees=[person for person in employees() if person["active"]])

@app.route("/gst/<kind>", methods=["GET", "POST"])
def gst_register(kind):
    if kind not in GST_FORMS:
        abort(404)
    if request.method == "POST":
        if kind != "mismatch":
            abort(405)
        try:
            client_id = number("client")
            title = field("title", 95, True)
            details = field("details", 4000)
            assignee = number("assignee") if g.admin else g.user["id"]
            if not assignee:
                raise ValueError("Choose the staff member who will own this mismatch.")
            db().execute("BEGIN IMMEDIATE")
            valid_gst_client(client_id)
            check_assignee(assignee)
            task_id = create_gst_item(db(), client_id, assignee, kind, title, details)
            log(task_id, "GST mismatch reported")
            db().commit()
            return redirect(url_for("task", task_id=task_id))
        except ValueError as error:
            db().rollback()
            flash(str(error), "error")
    where, params = scope()
    states = GST_MISMATCH_STATES if kind == "mismatch" else GST_RETURN_STATES
    state = request.args.get("state", "")
    if state and state not in states:
        abort(400)
    if state:
        where += " AND r.return_status=?"
        params += (state,)
    rows = query("""SELECT r.*, t.due,t.urgent,t.status AS task_status,
                    c.name AS client_name,u.name AS assignee_name
                    FROM gst_items r JOIN tasks t ON t.id=r.task JOIN clients c ON c.id=r.client
                    LEFT JOIN users u ON u.id=t.assignee WHERE r.kind=? AND """ + where +
                 " ORDER BY r.period_start DESC, r.period_end DESC, r.task DESC", (kind, *params))
    return page(f"GST · {GST_FORMS[kind]}", GST_REGISTER, service="GST", gst_forms=GST_FORMS,
                kind=kind, rows=rows, state=state, states=states,
                clients=gst_clients() if kind=="mismatch" else [],
                employees=[person for person in employees() if person["active"]] if g.admin and kind=="mismatch" else [])

@app.route("/task/<int:task_id>", methods=["GET", "POST"])
def task(task_id):
    where, params = scope()
    item = one(TASK_SELECT + " WHERE t.id=? AND " + where, (task_id, *params))
    if not item:
        abort(404)
    gst_item = one("SELECT * FROM gst_items WHERE task=?", (task_id,))
    gst_states = (GST_MISMATCH_STATES if gst_item and gst_item["kind"] == "mismatch"
                  else GST_RETURN_STATES)
    if request.method == "POST":
        try:
            status = field("status", 30, True)
            if status not in STATUSES:
                raise ValueError("Choose a valid status.")
            if gst_item:
                gst_status = field("gst_status", 30, True)
                if gst_status not in gst_states:
                    raise ValueError("Choose a valid GST register status.")
                if gst_status == gst_states[-1]:
                    status = "Completed"
                elif status == "Completed":
                    if gst_item["return_status"] != gst_states[-1]:
                        raise ValueError(f"Set the register status to {gst_states[-1]} to complete this task.")
                    status = "Open"
            urgent = int(request.form.get("urgent") == "yes")
            note = field("note", 2000)
            submitted_version = number("version")
            fields = task_fields() if g.admin else tuple(item[key] for key in ("title", "details", "assignee", "due"))
            title, details, assignee, due = fields
            db().execute("BEGIN IMMEDIATE")
            if g.admin:
                check_assignee(assignee, item["assignee"])
            result = db().execute(
                """UPDATE tasks SET status=?,urgent=?,title=?,details=?,assignee=?,due=?,version=version+1
                   WHERE id=? AND version=? AND """ + ("1=1" if g.admin else "assignee=?"),
                (status, urgent, title, details, assignee, due, task_id, submitted_version, *params))
            if not result.rowcount or item["version"] != submitted_version:
                raise ValueError("Someone changed this task. Reload it before saving your update.")
            updates = []
            if gst_item and gst_status != gst_item["return_status"]:
                db().execute("UPDATE gst_items SET return_status=? WHERE task=?", (gst_status, task_id))
                updates.append(f"GST register status changed to {gst_status}")
            if status != item["status"]:
                updates.append(f'Status changed to {status}')
            if urgent != item["urgent"]:
                updates.append("Red flag added" if urgent else "Red flag cleared")
            if fields != tuple(item[key] for key in ("title", "details", "assignee", "due")):
                updates.append("Task details updated")
            if assignee != item["assignee"] or status == "Completed":
                expired = db().execute("""UPDATE handoffs SET status='Closed', decided_at=datetime('now','localtime'),
                                        decision_note='The task was completed or reassigned.'
                                        WHERE task=? AND status='Pending'""", (task_id,))
                if expired.rowcount:
                    updates.append("Pending handoff closed because the task was completed or reassigned")
            for message in updates + ([note] if note else []):
                log(task_id, message)
            db().commit()
            flash("Task saved.")
            return redirect(url_for("task", task_id=task_id))
        except ValueError as error:
            db().rollback()
            flash(str(error), "error")
    history = query("""SELECT a.*,u.name FROM activity a JOIN users u ON u.id=a.actor
                     WHERE a.task=? ORDER BY a.id DESC""", (task_id,))
    pending = one("SELECT id FROM handoffs WHERE task=? AND status='Pending'", (task_id,))
    employees_list = employees()
    return page(item["title"], TASK, item=item, history=history, pending_handoff=pending,
                gst_item=gst_item, gst_states=gst_states, gst_forms=GST_FORMS,
                employees=employees_list if g.admin else [],
                recipients=[person for person in employees_list if person["active"] and person["id"] != g.user["id"]])

HANDOFF_SELECT = """SELECT h.*, t.title, t.due, t.urgent, c.name AS client_name,
 requester.name AS requester_name, recipient.name AS recipient_name, reviewer.name AS reviewer_name
 FROM handoffs h JOIN tasks t ON t.id=h.task JOIN clients c ON c.id=t.client
 JOIN users requester ON requester.id=h.requester JOIN users recipient ON recipient.id=h.recipient
 LEFT JOIN users reviewer ON reviewer.id=h.decided_by"""

@app.get("/handoffs")
def handoffs():
    where, params = ("", ()) if g.admin else (" WHERE h.requester=?", (g.user["id"],))
    rows = query(HANDOFF_SELECT + where + " ORDER BY h.status!='Pending', h.id DESC", params)
    return page("Handoffs", HANDOFFS, rows=rows)

@app.post("/task/<int:task_id>/handoff")
def request_handoff(task_id):
    if g.admin:
        abort(403)
    try:
        recipient = number("recipient")
        reason = field("reason", 1200, True)
        db().execute("BEGIN IMMEDIATE")
        item = one("SELECT status FROM tasks WHERE id=? AND assignee=?", (task_id, g.user["id"]))
        if not item:
            abort(404)
        if item["status"] == "Completed":
            raise ValueError("Completed tasks cannot be handed off.")
        if not recipient or recipient == g.user["id"]:
            raise ValueError("Choose another active staff member.")
        check_assignee(recipient)
        if one("SELECT id FROM handoffs WHERE task=? AND status='Pending'", (task_id,)):
            raise ValueError("This task already has a pending handoff.")
        db().execute("INSERT INTO handoffs(task,requester,recipient,reason) VALUES (?,?,?,?)",
                     (task_id, g.user["id"], recipient, reason))
        log(task_id, "Handoff requested")
        db().commit()
        flash("Handoff sent for super admin approval. The task is still in your queue.")
    except ValueError as error:
        db().rollback()
        flash(str(error), "error")
    return redirect(url_for("task", task_id=task_id))

@app.post("/handoffs/<int:handoff_id>/decide")
def decide_handoff(handoff_id):
    require_admin()
    try:
        action = request.form.get("action")
        if action not in {"approve", "decline"}:
            abort(400)
        note = field("decision_note", 1200)
        db().execute("BEGIN IMMEDIATE")
        row = one(HANDOFF_SELECT + " WHERE h.id=?", (handoff_id,))
        if not row:
            abort(404)
        if row["status"] != "Pending":
            raise ValueError("This handoff has already been decided or closed.")
        if action == "approve":
            check_assignee(row["recipient"])
            moved = db().execute("""UPDATE tasks SET assignee=?,version=version+1
                                  WHERE id=? AND assignee=? AND status!='Completed'""",
                                 (row["recipient"], row["task"], row["requester"]))
            if not moved.rowcount:
                raise ValueError("The task has already been completed or reassigned.")
            status = "Approved"
            log(row["task"], f'Handoff approved to {row["recipient_name"]}')
        else:
            status = "Declined"
            log(row["task"], "Handoff declined")
        db().execute("""UPDATE handoffs SET status=?,decided_by=?,decision_note=?,
                     decided_at=datetime('now','localtime') WHERE id=?""",
                     (status, g.user["id"], note, handoff_id))
        db().commit()
        flash("Handoff " + status.lower() + ".")
    except ValueError as error:
        db().rollback()
        flash(str(error), "error")
    return redirect(url_for("handoffs"))

@app.get("/backup")
def backup():
    require_admin()
    from io import BytesIO
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(dir=DB.parent) as folder:
        snapshot = Path(folder) / "backup.sqlite3"
        destination = sqlite3.connect(snapshot)
        try:
            db().backup(destination)
            destination.execute("UPDATE config SET value=? WHERE key='secret'", (secrets.token_hex(32),))
            destination.commit()
        finally:
            destination.close()
        data = BytesIO(snapshot.read_bytes())
    return send_file(data, as_attachment=True, download_name=f"LegalChef-{date.today()}.sqlite3")

@app.get("/logo")
def logo():
    from io import BytesIO
    return send_file(BytesIO(base64.b64decode(LOGO)), mimetype="image/png")

@app.get("/manifest.webmanifest")
def app_manifest():
    return app.response_class(app.json.dumps({
        "id": "/", "name": "LegalChef Work Organiser", "short_name": "LegalChef",
        "start_url": "/", "scope": "/", "display": "standalone",
        "background_color": "#121212", "theme_color": "#171717",
        "icons": [
            {"src": url_for("app_icon", size=size), "sizes": f"{size}x{size}",
             "type": "image/png", "purpose": "any"}
            for size in (192, 512)
        ],
    }), mimetype="application/manifest+json")

@app.get("/app-icon/<int:size>.png")
def app_icon(size):
    from io import BytesIO
    if size not in APP_ICONS:
        abort(404)
    return send_file(BytesIO(base64.b64decode(APP_ICONS[size])), mimetype="image/png")

@app.get("/install")
def install():
    return page("Use LegalChef on your devices", INSTALL)


BASE = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#171717">
<link rel="manifest" href="{{ url_for('app_manifest') }}">
<link rel="icon" href="{{ url_for('app_icon', size=192) }}" type="image/png">
<link rel="apple-touch-icon" sizes="180x180" href="{{ url_for('app_icon', size=180) }}">
<title>{{ title }} · LegalChef</title><style>
:root{color-scheme:dark;--gold:#e8cb81;--line:#3b3428;--muted:#c0b8a9}*{box-sizing:border-box}body{margin:0;background:#121212;color:#f8f1e3;font:15px/1.5 system-ui,sans-serif}
a{color:var(--gold);text-decoration:none}a:hover{text-decoration:underline}:focus-visible{outline:2px solid var(--gold);outline-offset:3px}
.shell{display:grid;grid-template-columns:230px minmax(0,1fr);min-height:100vh}aside{padding:25px 17px;display:flex;flex-direction:column;background:#181717;border-right:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:25px}.brand img{width:51px;border-radius:7px}.brand strong{display:block;font:24px Georgia,serif}small,.muted{color:var(--muted)}
nav{display:grid;gap:3px}nav a{padding:8px 11px;border-radius:7px;color:#e8dfcf}nav a:hover,nav a.current{background:#342b1d;color:var(--gold)}nav small{margin:10px 11px 2px}.account{margin-top:auto;padding:18px 10px 0}
.gst-tabs{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:16px}.attendance-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
main{padding:37px clamp(17px,4vw,58px);width:100%;max-width:1540px;margin:0 auto}
header,.actions{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}header{margin-bottom:22px}
h1,h2{font:normal 44px/1.15 Georgia,serif;margin:0}h2{font-size:24px;margin:0 0 14px}p{margin:0 0 12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:12px;margin-bottom:20px}
.stat,.panel{background:#1c1b19;border:1px solid var(--line);border-radius:12px}.stat{padding:13px 14px;color:var(--muted)}.stat strong{display:block;font:32px Georgia,serif;color:var(--gold)}.stat:hover,.stat.current{border-color:var(--gold);text-decoration:none}
.panel{padding:18px;margin-bottom:15px}.split{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.scroll{overflow:auto}
table{border-collapse:collapse;width:100%;text-align:left}td,th{padding:10px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px}td:first-child{min-width:140px}.tag{display:inline-block;border-radius:15px;padding:2px 8px;background:#3b3120;color:#f4da94;white-space:nowrap;font-size:12px}.danger{color:#ffaaa5}.flag{background:#492a28;color:#ffaaa5}.done{background:#23382b;color:#bbe7c8}
label{display:block;margin-bottom:12px}input,button,select,textarea{font:inherit}input:not([type=checkbox]),select,textarea{width:100%;padding:8px 10px;border:1px solid #62563e;border-radius:7px;margin-top:4px;background:#131313;color:#f8f1e3}textarea{min-height:85px;resize:vertical}
fieldset{border:1px solid var(--line);border-radius:7px;margin:0 0 12px}fieldset label{display:inline-block;margin:4px 10px 4px 0}input[type=checkbox]{accent-color:var(--gold)}
button,.button{display:inline-block;background:var(--gold);color:#241b0a;font-weight:650;border:1px solid transparent;border-radius:7px;padding:7px 12px;cursor:pointer}.secondary{background:#292318;color:var(--gold);border-color:#5b4a2c}button:hover,.button:hover{filter:brightness(1.15);text-decoration:none}
.record{padding:10px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}.pre{white-space:pre-wrap;overflow-wrap:anywhere}.stack{margin-top:10px}
.notice{background:#322a1b;padding:9px 12px;border-radius:7px;margin-bottom:12px}.error{background:#452c28;color:#ffbbb1}
.auth{max-width:445px;margin:7vh auto;padding:16px}.auth header{display:grid;justify-items:center;justify-content:center;text-align:center}.auth img{width:110px}.auth h1{font-size:33px}.search{display:flex;gap:8px;align-items:baseline;margin-bottom:12px;max-width:460px}
@media(max-width:800px){.shell,.split{grid-template-columns:1fr}aside{border:0;border-bottom:1px solid var(--line);padding:12px}.brand{margin-bottom:8px}nav{display:flex;flex-wrap:wrap}nav small{display:none}main{padding-top:19px}}
@media(max-width:600px){
aside{padding:12px 14px}nav a{padding:8px}main{padding:18px 13px 30px}h1{font-size:34px;overflow-wrap:anywhere}
.panel{padding:14px}.stat{padding:12px}.search{width:100%;max-width:none}
input,select,textarea{font-size:16px}button,.button{min-height:42px}
.scroll{max-width:100%}.scroll table{min-width:570px}
.queue-table{min-width:0!important;display:block}.queue-table thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
.queue-table tbody,.queue-table tr,.queue-table td{display:block;width:100%;min-width:0}
.queue-table tr{margin-bottom:10px;padding:7px 11px;border:1px solid var(--line);border-radius:8px}
.queue-table td{border:0;padding:4px 0;overflow-wrap:anywhere}.queue-table td:first-child{font-size:17px}
.queue-table td[data-label]::before{content:attr(data-label) " · ";font-size:13px;color:var(--muted)}
}
</style>
{% macro csrf() %}<input type="hidden" name="csrf" value="{{ session.csrf }}">{% endmacro %}
{% macro user_fields() %}
<label>Display name<input name="name" required maxlength="100"></label><label>Username<input name="username" required maxlength="60"></label>
<label>Password <small>(at least 12 characters)</small><input name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required></label>
{% endmacro %}
{% macro task_fields(item) %}
<label>Task title<input name="title" required maxlength="160" value="{{ item.title|default('') }}"></label>
<label>Instructions<textarea name="details" maxlength="4000">{{ item.details|default('') }}</textarea></label>
{% if g.admin %}<label>Assigned to<select name="assignee"><option value="">Unassigned</option>{% for e in employees %}{% if e.active or e.id==item.assignee %}<option value="{{ e.id }}"{% if e.id==item.assignee %} selected{% endif %}>{{ e.name }}{% if not e.active %} (inactive){% endif %}</option>{% endif %}{% endfor %}</select></label>{% endif %}
<label>Due date <small>(optional)</small><input name="due" type="date" value="{{ item.due|default('') }}"></label>
{% endmacro %}
<body>{% if g.user and not g.user.temporary %}
<div class="shell"><aside><a class="brand" href="{{ url_for('dashboard') }}"><img src="/logo" alt=""><span><strong>LegalChef</strong><small>Work Organiser</small></span></a>
<nav aria-label="Workspace"><a href="/" class="{{ 'current' if title in ('Overview','My queue') }}">{{ 'Overview' if g.admin else 'My queue' }}</a><a href="{{ url_for('handoffs') }}">Handoffs</a><a href="{{ url_for('attendance') }}">Attendance</a><a href="{{ url_for('install') }}">Install app</a><small>Services</small>
{% for category in services %}<a href="{{ url_for('dashboard',service=category) }}" class="{{ 'current' if service==category }}">{{ category }}</a>{% endfor %}
{% if g.admin %}<small>Administration</small><a href="/clients">Clients</a><a href="/staff">Staff &amp; super admins</a><a href="/backup">Download backup</a>{% endif %}</nav>
<div class="account"><strong>{{ g.user.name }}</strong><br><small>{{ 'Super admin' if g.admin else 'Staff' }}</small><br><a href="/password">Change password</a>
<form method="post" action="/logout" class="stack">{{ csrf() }}<button class="secondary">Sign out</button></form></div></aside><main>
<header><h1>{{ title }}</h1>{% if request.endpoint=='dashboard' %}<a class="button" href="{{ url_for('new_task',service=service) }}">New task</a>{% endif %}</header>
{% else %}<div class="auth"><header><img src="/logo" alt="LegalChef"><h1>{{ title }}</h1></header><div class="panel">{% endif %}
{% for category,message in get_flashed_messages(with_categories=true) %}<div role="status" class="notice {{ category }}">{{ message }}</div>{% endfor %}
__CONTENT__
{% if g.user and not g.user.temporary %}</main></div>{% else %}</div>{% if request.endpoint != 'install' %}<p><a href="{{ url_for('install') }}">Install app</a></p>{% endif %}</div>{% endif %}</body></html>"""

INSTALL = """
<section class="{{ 'panel' if g.user else '' }}">
<p>Use the same LegalChef account and office server address on each device.</p>
<h2>Windows</h2><p>In Microsoft Edge, open LegalChef and choose <strong>Apps → Install this site as an app</strong> from the menu. The Windows desktop launcher also opens your server in a dedicated window.</p>
<h2>iPhone and iPad</h2><p>In Safari, open the office server address. Choose <strong>Share → Add to Home Screen</strong> and enable <strong>Open as Web App</strong> when offered.</p>
<h2>Android</h2><p>In Chrome, open the office server address and choose <strong>Install and create shortcut</strong> or <strong>Add to Home screen</strong> from the Chrome menu. Choose <strong>Install</strong> when available, or add a shortcut. Use a trusted HTTPS server address for full web app installation.</p>
<p class="muted">Connect to the office network and keep the LegalChef server running.</p>
<a class="button secondary" href="{{ url_for('dashboard') }}">Open LegalChef</a>
</section>
"""

AUTH = """
<form method="post">{{ csrf() }}
{% if mode=='setup' %}<p class="muted">Create the super admin account on this server.</p>{{ user_fields() }}
{% elif mode=='login' %}<label>Username<input name="username" autocomplete="username" maxlength="60" required autofocus></label><label>Password<input name="password" type="password" autocomplete="current-password" maxlength="128" required></label>
{% else %}{% if g.user.temporary %}<p class="muted">Choose your own password to activate your account.</p>{% endif %}<label>Current password<input name="current" type="password" autocomplete="current-password" required></label><label>New password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label>{% endif %}
<button>{{ {'setup':'Create super admin','login':'Sign in','password':'Save password'}[mode] }}</button></form>
{% if mode=='password' and g.user.temporary %}<form class="stack" method="post" action="/logout">{{ csrf() }}<button class="secondary">Sign out</button></form>{% endif %}
"""
DASHBOARD = """
{% if service=='GST' %}{{ gst_tabs(gst_forms, '') }}{% endif %}
{% if show_attendance %}<details class="panel"><summary>Record attendance{% if latest_attendance %} · Last today {{ latest_attendance.recorded_at[11:] }} · {{ latest_attendance.client_name or latest_attendance.location or latest_attendance.place }}{% endif %}</summary>
{{ attendance_form(places, attendance_clients, true) }}<p class="stack"><a href="{{ url_for('attendance') }}">View attendance log</a></p></details>{% endif %}
{% if pending %}<p class="notice"><a href="{{ url_for('handoffs') }}">{{ pending }} pending handoff{{ 's' if pending != 1 }}</a> awaiting super admin review.</p>{% endif %}
<section class="stats" aria-label="Task totals">{% for label,total in counts.items() %}<a class="stat {{ 'current' if state==label }}" href="{{ url_for('dashboard',service=service,state='' if state==label else label,q=search) }}"><strong>{{ total }}</strong>{{ label }}</a>{% endfor %}</section>
<section class="panel"><div class="actions"><h2>{{ state or ('Tasks' if g.admin else 'Task timeline') }}</h2><form class="search" method="get">
<input type="hidden" name="service" value="{{ service }}"><input type="hidden" name="state" value="{{ state }}"><input name="q" aria-label="Search tasks" placeholder="Task, client or staff" maxlength="100" value="{{ search }}"><button class="secondary">Search</button>{% if state or search %}<a href="{{ url_for('dashboard',service=service) }}">Clear</a>{% endif %}</form></div>
{% if tasks %}<div class="scroll"><table class="queue-table"><thead><tr><th>Task</th><th>Client</th><th>Service</th><th>Assigned to</th><th>Due date</th><th>Status</th></tr></thead><tbody>
{% for t in tasks %}<tr><td><a href="{{ url_for('task',task_id=t.id) }}">{{ t.title }}</a>{% if t.urgent %}<br><span class="tag flag">Red flag</span>{% endif %}</td>
<td data-label="Client">{{ t.client_name }}</td><td data-label="Service">{{ t.service }}</td><td data-label="Assigned to">{{ t.staff_name or 'Unassigned' }}</td><td data-label="Due" class="{{ 'danger' if overdue(t) }}">{{ t.due or 'No due date' }}{% if overdue(t) %}<br>Overdue{% elif t.due==today and t.status!='Completed' %}<br>Due today{% endif %}</td><td data-label="Status"><span class="tag {{ 'done' if t.status=='Completed' }}">{{ t.status }}</span></td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="muted">No tasks to show.</p>{% endif %}</section>
{% if service %}<section class="panel"><h2>Clients</h2>{% for c in clients %}<div class="record actions"><div><strong>{{ c.name }}</strong>{% if g.admin and c.contact %}<br><small>{{ c.contact }}</small>{% endif %}</div>
<a class="button secondary" href="{{ url_for('new_task',client=c.id,service=service) }}">Add task</a></div>
{% else %}<p class="muted">No clients to show.{% if g.admin %} <a href="/clients">Manage clients</a>{% endif %}</p>{% endfor %}</section>{% endif %}
"""
CLIENTS = """
<div class="split"><section class="panel"><h2>{{ 'Edit client' if editing else 'Add client' }}</h2><form method="post">{{ csrf() }}
<label>Client name<input name="name" required maxlength="150" value="{{ editing.name if editing else '' }}"></label><label>Contact <small>(optional)</small><input name="contact" maxlength="200" value="{{ editing.contact if editing else '' }}"></label>
<fieldset><legend>Services</legend>{% for category in services %}<label><input type="checkbox" name="services" value="{{ category }}"{% if category in selected %} checked{% endif %}> {{ category }}</label>{% endfor %}</fieldset>
<button>Save client</button>{% if editing %} <a href="/clients">Cancel</a>{% endif %}</form></section>
<section class="panel"><h2>Client directory</h2>{% for c in records %}<div class="record actions"><div><strong>{{ c.name }}</strong><br><small>{{ c.services }}</small>{% if c.contact %}<br><small>{{ c.contact }}</small>{% endif %}</div><a href="{{ url_for('clients',edit=c.id) }}">Edit</a></div>{% else %}<p class="muted">No clients added yet.</p>{% endfor %}</section></div>
"""
STAFF = """
<div class="split"><section class="panel"><h2>Add staff account</h2><form method="post">{{ csrf() }}<input type="hidden" name="action" value="add">{{ user_fields() }}<button>Add staff member</button></form></section>
<section class="panel"><h2>Add super admin</h2>
<p class="muted">A super admin can manage all clients, tasks, accounts and backups.</p>
<form method="post">{{ csrf() }}<input type="hidden" name="action" value="add_admin">{{ user_fields() }}<button>Add super admin</button></form></section>
<section class="panel"><h2>Staff accounts</h2>{% for member in staff %}<div class="record"><div class="actions"><div><strong>{{ member.name }}</strong><br><small>{{ member.username }} · {{ 'Active' if member.active else 'Inactive' }}</small></div>
<form method="post">{{ csrf() }}<input type="hidden" name="user" value="{{ member.id }}"><button name="action" value="toggle" class="secondary">{{ 'Deactivate' if member.active else 'Reactivate' }}</button></form></div>
<details class="stack"><summary>Reset password</summary><form method="post" class="stack">{{ csrf() }}<input type="hidden" name="user" value="{{ member.id }}"><label>Temporary password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label><button name="action" value="reset">Reset password</button></form></details></div>{% else %}<p class="muted">No staff accounts added yet.</p>{% endfor %}</section>
<section class="panel"><h2>Super admin accounts</h2>
{% for admin in admins %}<div class="record"><strong>{{ admin.name }}</strong>{% if admin.id==g.user.id %} <small>(you)</small>{% endif %}<br><small>{{ admin.username }}</small></div>{% endfor %}
</section></div>
"""
NEW_TASK = """
<section class="panel">{% if choices %}<form method="post">{{ csrf() }}
<label>Client and service<select name="client_service" required><option value="">Choose a client and service</option>{% for c in choices %}{% if not chosen_service or c.service==chosen_service %}<option value="{{ c.id }}|{{ c.service }}"{% if c.id==chosen_client and c.service==chosen_service %} selected{% endif %}>{{ c.name }} · {{ c.service }}</option>{% endif %}{% endfor %}</select></label>
{{ task_fields({}) }}{% if not g.admin %}<p class="muted">This task will be assigned to you.</p>{% endif %}
<label class="danger"><input type="checkbox" name="urgent" value="yes"> Red flag for urgent review</label>
<button>Create task</button></form>
{% else %}<p>No clients are registered for this selection.</p><a href="{{ url_for('new_task') }}">Show all services</a>{% if g.admin %} · <a href="/clients">Add client</a>{% endif %}{% endif %}</section>
"""
TASK = """
<p class="muted">{{ item.client_name }} · <a href="{{ url_for('dashboard',service=item.service) }}">{{ item.service }}</a> · Task #{{ item.id }}</p>
<div class="split"><section class="panel"><h2>Update task</h2><form method="post">{{ csrf() }}<input type="hidden" name="version" value="{{ item.version }}">
{% if g.admin %}{{ task_fields(item) }}{% else %}<p class="pre">{{ item.details or 'No instructions added.' }}</p><p class="muted">Due {{ item.due or '—' }}</p>{% endif %}
{% if gst_item %}<p class="muted"><a href="{{ url_for('gst_register',kind=gst_item.kind) }}">{{ gst_forms[gst_item.kind] }} register</a> · {{ gst_item.period_label }}</p>
<label>{{ 'Mismatch status' if gst_item.kind=='mismatch' else 'Return status' }}<select name="gst_status" required>
{% for state in gst_states %}<option{% if state==gst_item.return_status %} selected{% endif %}>{{ state }}</option>{% endfor %}</select></label>
{% endif %}
<label>Task status<select name="status">{% for status in statuses %}<option{% if item.status==status %} selected{% endif %}>{{ status }}</option>{% endfor %}</select></label>
<label class="danger"><input type="checkbox" name="urgent" value="yes"{% if item.urgent %} checked{% endif %}> Red flag for urgent review</label>
<label>Progress note <small>(optional)</small><textarea name="note" maxlength="2000"></textarea></label><button>Save update</button></form></section>
<div>{% if pending_handoff %}<section class="panel"><h2>Handoff pending</h2><a href="{{ url_for('handoffs') }}">View request</a></section>
{% elif not g.admin and item.status!='Completed' and recipients %}
<section class="panel"><h2>Request a handoff</h2><form method="post" action="{{ url_for('request_handoff',task_id=item.id) }}">{{ csrf() }}
<label>Send to<select name="recipient" required><option value="">Choose a staff member</option>{% for person in recipients %}<option value="{{ person.id }}">{{ person.name }}</option>{% endfor %}</select></label>
<label>Reason<textarea name="reason" required maxlength="1200"></textarea></label>
<button class="secondary">Request approval</button></form></section>{% endif %}
<section class="panel"><h2>Activity</h2>{% for entry in history %}<div class="record"><strong>{{ entry.name }}</strong> <small>{{ entry.at }}</small><div class="pre">{{ entry.message }}</div></div>{% endfor %}</section></div></div>
"""

HANDOFFS = """
<section class="panel"><h2>{{ 'Handoff requests' if g.admin else 'My handoff requests' }}</h2>
{% for row in rows %}<article class="record">
<div class="actions"><div><strong>{% if g.admin or row.status=='Pending' %}<a href="{{ url_for('task',task_id=row.task) }}">{{ row.title }}</a>{% else %}{{ row.title }}{% endif %}</strong>
<br><small>{{ row.client_name }} · {{ row.requester_name }} → {{ row.recipient_name }} · {{ row.created_at }}</small></div>
<div><span class="tag">{{ row.status }}</span>{% if row.urgent %} <span class="tag flag">Red flag</span>{% endif %}</div></div>
<p class="pre stack">{{ row.reason }}</p>
{% if row.status=='Pending' and g.admin %}
<p class="muted">Due {{ row.due or '—' }}</p>
<form method="post" action="{{ url_for('decide_handoff',handoff_id=row.id) }}">{{ csrf() }}
<label>Decision note <small>(optional)</small><input name="decision_note" maxlength="1200"></label>
<button name="action" value="approve">Approve and reassign</button>
<button name="action" value="decline" class="secondary">Decline</button></form>
{% elif row.decided_at %}<p class="muted">{{ row.status }}{% if row.reviewer_name %} by {{ row.reviewer_name }}{% endif %} · {{ row.decided_at }}</p>
{% if row.decision_note %}<p class="pre">{{ row.decision_note }}</p>{% endif %}{% endif %}</article>
{% else %}<p class="muted">No handoff requests yet.</p>{% endfor %}</section>
"""

GST_TABS = """
{% macro gst_tabs(forms, active) %}
<nav class="gst-tabs" aria-label="GST sections">
<a href="{{ url_for('dashboard',service='GST') }}"{% if not active %} class="current" aria-current="page"{% endif %}>GST tasks</a>
{% for key,label in forms.items() %}<a href="{{ url_for('gst_register',kind=key) }}"{% if key==active %} class="current" aria-current="page"{% endif %}>{{ label }}</a>{% endfor %}
{% if g.admin %}<a href="{{ url_for('gst_schedules') }}"{% if active=='schedules' %} class="current" aria-current="page"{% endif %}>Filing schedules</a>{% endif %}
</nav>
{% endmacro %}
"""

ATTENDANCE_FORM = """
{% macro attendance_form(places, clients, from_queue=false) %}
<form method="post" action="{{ url_for('attendance') }}" class="stack">{{ csrf() }}
{% if from_queue %}<input type="hidden" name="from_queue" value="1">{% endif %}
<div class="attendance-fields"><label>Place<select name="place" required>
{% for place in places %}<option>{{ place }}</option>{% endfor %}</select></label>
<label>Client <small>(for a client visit)</small><select name="client"><option value="">Choose a client</option>
{% for client in clients %}<option value="{{ client.id }}">{{ client.name }}</option>{% endfor %}</select></label>
<label>Location detail <small>(department name or other place)</small><input name="location" maxlength="180" placeholder="e.g. GST Division Office"></label></div>
<button>Record attendance</button></form>
{% endmacro %}
"""

ATTENDANCE = """
<section class="panel"><h2>Record attendance</h2>{{ attendance_form(places, attendance_clients) }}</section>
<section class="panel"><div class="actions"><h2>{{ 'Staff attendance' if g.admin else 'My attendance' }}</h2>
<form class="search" method="get"><input type="date" name="day" aria-label="Attendance date" value="{{ selected }}" required><button class="secondary">View</button></form></div>
{% if entries %}<div class="scroll"><table><thead><tr><th>Timestamp (server time)</th><th>Staff member</th><th>Place</th><th>Client</th><th>Location detail</th></tr></thead><tbody>
{% for entry in entries %}<tr><td>{{ entry.recorded_at }}</td><td>{{ entry.name }}</td><td>{{ entry.place }}</td><td>{{ entry.client_name or '—' }}</td><td>{{ entry.location or '—' }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="muted">No attendance recorded for this date.</p>{% endif %}</section>
"""

GST_SCHEDULES = """
{{ gst_tabs(gst_forms, 'schedules') }}
<div class="split"><section class="panel"><h2>{{ 'Edit filing schedule' if current else 'Set filing schedule' }}</h2>
{% if clients and employees %}
<form method="post">{{ csrf() }}
<label>GST client<select name="client" required><option value="">Choose a client</option>
{% for c in clients %}<option value="{{ c.id }}"{% if c.id==chosen %} selected{% endif %}>{{ c.name }}</option>{% endfor %}</select></label>
<label>Filing frequency<select name="cadence">{% for cadence in cadences %}<option{% if current and current.cadence==cadence %} selected{% endif %}>{{ cadence }}</option>{% endfor %}</select></label>
<label>Assign new return tasks to<select name="assignee" required><option value="">Choose a staff member</option>
{% for person in employees %}<option value="{{ person.id }}"{% if current and current.assignee==person.id %} selected{% endif %}>{{ person.name }}</option>{% endfor %}</select></label>
<label>First period month <small>(optional)</small><input type="month" name="first_period" min="2000-01" max="2099-12"></label>
<p class="muted">Leave the first month blank to start a new schedule with the most recent closed period or continue an existing schedule at its next period. For quarterly schedules, enter Jan, Apr, Jul or Oct.</p>
<button name="action" value="save">{{ 'Save or resume schedule' if current else 'Save schedule' }}</button>
</form>{% else %}<p class="muted">Add a GST client and an active staff member to set up a filing schedule.</p>{% endif %}</section>
<section class="panel"><h2>Client schedules</h2>
{% for row in schedules %}<div class="record actions"><div><strong>{{ row.name }}</strong><br><small>{{ row.cadence }} · {{ row.assignee_name }}{% if not row.active %} (inactive){% endif %} · {{ 'Paused' if row.paused else 'Active' }}</small><br><small>Next period starts {{ row.next_period }}</small></div>
<div><a href="{{ url_for('gst_schedules',client=row.client) }}">Edit</a>{% if not row.paused %}<form class="stack" method="post">{{ csrf() }}<input type="hidden" name="client" value="{{ row.client }}"><button class="secondary" name="action" value="pause">Pause</button></form>{% endif %}</div></div>
{% else %}<p class="muted">No filing schedules configured.</p>{% endfor %}</section></div>
"""

GST_REGISTER = """
{{ gst_tabs(gst_forms, kind) }}
{% if kind=='mismatch' %}<details class="panel"><summary>Report a mismatch</summary>
{% if clients %}<form method="post" class="stack">{{ csrf() }}
<label>GST client<select name="client" required><option value="">Choose a client</option>
{% for c in clients %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}</select></label>
<label>Mismatch title<input name="title" required maxlength="95"></label>
<label>Details<textarea name="details" maxlength="4000"></textarea></label>
{% if g.admin %}<label>Assign to<select name="assignee" required><option value="">Choose a staff member</option>
{% for person in employees %}<option value="{{ person.id }}">{{ person.name }}</option>{% endfor %}</select></label>{% endif %}
<button>Create mismatch task</button></form>{% else %}<p class="muted">No GST clients are available.</p>{% endif %}
</details>{% endif %}
<section class="panel"><div class="actions"><h2>{{ 'Mismatch register' if kind=='mismatch' else 'Return register' }}</h2>
<form method="get" class="search"><select aria-label="Filter by status" name="state"><option value="">All statuses</option>
{% for value in states %}<option{% if state==value %} selected{% endif %}>{{ value }}</option>{% endfor %}</select><button class="secondary">Filter</button></form></div>
{% if rows %}<div class="scroll"><table><thead><tr><th>Client</th><th>{{ 'Issue' if kind=='mismatch' else 'Period' }}</th><th>Assigned to</th><th>Due date</th><th>{{ 'Mismatch' if kind=='mismatch' else 'Return' }} status</th><th>Task status</th></tr></thead><tbody>
{% for row in rows %}<tr><td>{{ row.client_name }}</td><td><a href="{{ url_for('task',task_id=row.task) }}">{{ row.period_label }}</a>{% if row.urgent %}<br><span class="tag flag">Red flag</span>{% endif %}</td><td>{{ row.assignee_name or 'Unassigned' }}</td><td>{{ row.due or '—' }}</td><td><span class="tag{% if row.return_status in ('Filed','Resolved') %} done{% endif %}">{{ row.return_status }}</span></td><td>{{ row.task_status }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="muted">No entries to show.</p>{% endif %}</section>
"""

def page(title, content, **context):
    template = BASE.replace("__CONTENT__", GST_TABS + ATTENDANCE_FORM + content)
    return render_template_string(template, title=title,
                                  services=SERVICES, statuses=STATUSES, **context)

def main():
    parser = argparse.ArgumentParser(description="Run LegalChef Work Organiser on the office network.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", type=Path, default=DB.parent)
    parser.add_argument("--secure-cookie", action="store_true", help="Require HTTPS for session cookies")
    options = parser.parse_args()
    init(options.data_dir / DB.name)
    Thread(target=gst_scheduler, name="gst-scheduler", daemon=True).start()
    app.config["SESSION_COOKIE_SECURE"] = options.secure_cookie
    print(f"LegalChef Work Organiser: http://127.0.0.1:{options.port}", flush=True)
    print(f"Office network: http://<server-IP>:{options.port}", flush=True)
    print(f"Database: {DB}", flush=True)
    print("Leave this window open. Press Ctrl+C to stop.", flush=True)
    serve(app, host=options.host, port=options.port, threads=8,
          channel_timeout=30, max_request_body_size=64_000)

LOGO = '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'

APP_ICONS = {180: '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', 192: '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', 512: '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AQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAAAIAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAeH74/wFwdKlMJcSoVwAAAABJRU5ErkJggg=='}

if __name__ == "__main__":
    main()

