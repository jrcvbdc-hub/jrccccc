import hmac
import os
import secrets
import sqlite3
from datetime import date
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "development-key-change-before-deploy")
app.config["DATABASE"] = os.environ.get("COLLEGE_DATABASE", str(Path(__file__).parent / "instance" / "college.db"))


def get_db():
    if "db" not in g:
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def initialize_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'faculty', 'student')),
            record_id TEXT
        );
        CREATE TABLE IF NOT EXISTS students (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
            program TEXT NOT NULL, year INTEGER NOT NULL, phone TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS faculty (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
            department TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS courses (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, code TEXT NOT NULL UNIQUE,
            faculty_id TEXT NOT NULL REFERENCES faculty(id), credits INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL REFERENCES students(id),
            course_id TEXT NOT NULL REFERENCES courses(id),
            attendance_date TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('Present', 'Absent', 'Late')),
            UNIQUE(student_id, course_id, attendance_date)
        );
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL REFERENCES students(id),
            course_id TEXT NOT NULL REFERENCES courses(id),
            term TEXT NOT NULL, marks REAL NOT NULL CHECK (marks >= 0 AND marks <= 100),
            grade TEXT NOT NULL, UNIQUE(student_id, course_id, term)
        );
        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL REFERENCES students(id),
            description TEXT NOT NULL, amount REAL NOT NULL CHECK (amount >= 0),
            due_date TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('Paid', 'Pending'))
        );
        """
    )
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.execute("INSERT INTO students VALUES (?, ?, ?, ?, ?, ?)", ("ST-2048", "Maya Chen", "maya.chen@northstar.edu", "Computer Science", 2, "+1 555 010 2048"))
        db.execute("INSERT INTO faculty VALUES (?, ?, ?, ?)", ("FC-013", "Dr. Elias Morgan", "e.morgan@northstar.edu", "Computing & Data"))
        db.execute("INSERT INTO courses VALUES (?, ?, ?, ?, ?)", ("CR-101", "Foundations of Computing", "CS 210", "FC-013", 4))
        db.execute("INSERT INTO courses VALUES (?, ?, ?, ?, ?)", ("CR-102", "Data & Society", "DS 105", "FC-013", 3))
        db.execute("INSERT INTO users VALUES (?, ?, ?, ?)", ("admin", generate_password_hash("admin123"), "admin", None))
        db.execute("INSERT INTO users VALUES (?, ?, ?, ?)", ("faculty", generate_password_hash("faculty123"), "faculty", "FC-013"))
        db.execute("INSERT INTO users VALUES (?, ?, ?, ?)", ("student", generate_password_hash("student123"), "student", "ST-2048"))
        db.execute("INSERT INTO attendance (student_id, course_id, attendance_date, status) VALUES (?, ?, ?, ?)", ("ST-2048", "CR-101", date.today().isoformat(), "Present"))
        db.execute("INSERT INTO results (student_id, course_id, term, marks, grade) VALUES (?, ?, ?, ?, ?)", ("ST-2048", "CR-101", "Fall 2025", 92, "A"))
        db.execute("INSERT INTO fees (student_id, description, amount, due_date, status) VALUES (?, ?, ?, ?, ?)", ("ST-2048", "Fall 2025 tuition", 2450, "2026-10-15", "Pending"))
    db.commit()


with app.app_context():
    initialize_db()


@app.before_request
def protect_forms():
    session.setdefault("csrf_token", secrets.token_hex(32))
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        if not hmac.compare_digest(session["csrf_token"], submitted):
            abort(400, "Invalid form token")


@app.context_processor
def template_context():
    today = date.today()
    return {
        "current_user": session.get("user"),
        "csrf_token": session.get("csrf_token", ""),
        "now_date": today.strftime("%A, %B %-d"),
        "now_month": today.strftime("%b").upper(),
        "now_day": today.strftime("%-d"),
    }


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = session.get("user")
            if not user:
                return redirect(url_for("login"))
            if user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def rows(query, parameters=()):
    return get_db().execute(query, parameters).fetchall()


def grade_for(marks):
    if marks >= 90:
        return "A"
    if marks >= 80:
        return "B"
    if marks >= 70:
        return "C"
    if marks >= 60:
        return "D"
    return "F"


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user"] = {"username": user["username"], "role": user["role"], "record_id": user["record_id"]}
            session["csrf_token"] = secrets.token_hex(32)
            return redirect(url_for("dashboard"))
        flash("That username and password combination was not recognized.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@roles_required("admin", "faculty", "student")
def dashboard():
    user = session["user"]
    db = get_db()
    if user["role"] == "student":
        student_id = user["record_id"]
        student = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        if not student:
            abort(403)
        present_count = db.execute("SELECT COUNT(*) FROM attendance WHERE student_id = ? AND status = 'Present'", (student_id,)).fetchone()[0]
        stats = [("Courses", db.execute("SELECT COUNT(DISTINCT course_id) FROM results WHERE student_id = ?", (student_id,)).fetchone()[0], "enrolled"),
                 ("Attendance", present_count, "sessions present"),
                 ("Average mark", db.execute("SELECT ROUND(AVG(marks)) FROM results WHERE student_id = ?", (student_id,)).fetchone()[0] or "—", "across results")]
        recent = rows("SELECT r.term, r.marks, r.grade, c.code, c.title FROM results r JOIN courses c ON c.id = r.course_id WHERE r.student_id = ? ORDER BY r.id DESC LIMIT 4", (student_id,))
        return render_template("dashboard.html", stats=stats, recent=recent, student=student)
    if user["role"] == "faculty":
        faculty_id = user["record_id"]
        stats = [("Students", db.execute("SELECT COUNT(DISTINCT a.student_id) FROM attendance a JOIN courses c ON c.id = a.course_id WHERE c.faculty_id = ?", (faculty_id,)).fetchone()[0], "in your classes"),
                 ("Courses", db.execute("SELECT COUNT(*) FROM courses WHERE faculty_id = ?", (faculty_id,)).fetchone()[0], "assigned to you"),
                 ("Marked today", db.execute("SELECT COUNT(*) FROM attendance a JOIN courses c ON c.id = a.course_id WHERE c.faculty_id = ? AND a.attendance_date = ?", (faculty_id, date.today().isoformat())).fetchone()[0], "attendance entries")]
        recent = rows("SELECT a.attendance_date AS term, a.status AS marks, s.name AS grade, c.code, c.title FROM attendance a JOIN students s ON s.id = a.student_id JOIN courses c ON c.id = a.course_id WHERE c.faculty_id = ? ORDER BY a.attendance_date DESC LIMIT 4", (faculty_id,))
        return render_template("dashboard.html", stats=stats, recent=recent)
    stats = [("Students", db.execute("SELECT COUNT(*) FROM students").fetchone()[0], "enrolled records"),
             ("Faculty", db.execute("SELECT COUNT(*) FROM faculty").fetchone()[0], "teaching staff"),
             ("Courses", db.execute("SELECT COUNT(*) FROM courses").fetchone()[0], "this term"),
             ("Open fees", db.execute("SELECT COUNT(*) FROM fees WHERE status = 'Pending'").fetchone()[0], "awaiting payment")]
    recent = rows("SELECT r.term, r.marks, r.grade, c.code, c.title FROM results r JOIN courses c ON c.id = r.course_id ORDER BY r.id DESC LIMIT 4")
    return render_template("dashboard.html", stats=stats, recent=recent)


@app.route("/students", methods=["GET", "POST"])
@roles_required("admin")
def students_page():
    db = get_db()
    if request.method == "POST":
        values = [request.form.get(key, "").strip() for key in ("id", "name", "email", "program", "year", "phone", "username", "password")]
        student_id, name, email, program, year, phone, username, password = values
        try:
            year_number = int(year)
            if not all(values) or year_number < 1 or year_number > 8 or len(password) < 8:
                raise ValueError
            db.execute("INSERT INTO students VALUES (?, ?, ?, ?, ?, ?)", (student_id, name, email, program, year_number, phone))
            db.execute("INSERT INTO users VALUES (?, ?, 'student', ?)", (username, generate_password_hash(password), student_id))
            db.commit()
            flash(f"Student record for {name} created.", "success")
        except (ValueError, sqlite3.IntegrityError):
            db.rollback()
            flash("Check all fields, use a year from 1 to 8, an 8-character password, and unused IDs.", "error")
        return redirect(url_for("students_page"))
    return render_template("students.html", students=rows("SELECT * FROM students ORDER BY name"))


@app.route("/faculty", methods=["GET", "POST"])
@roles_required("admin")
def faculty_page():
    db = get_db()
    if request.method == "POST":
        values = [request.form.get(key, "").strip() for key in ("id", "name", "email", "department", "username", "password")]
        faculty_id, name, email, department, username, password = values
        try:
            if not all(values) or len(password) < 8:
                raise ValueError
            db.execute("INSERT INTO faculty VALUES (?, ?, ?, ?)", (faculty_id, name, email, department))
            db.execute("INSERT INTO users VALUES (?, ?, 'faculty', ?)", (username, generate_password_hash(password), faculty_id))
            db.commit()
            flash(f"Faculty profile for {name} created.", "success")
        except (ValueError, sqlite3.IntegrityError):
            db.rollback()
            flash("Check all fields, use an 8-character password, and choose unused IDs.", "error")
        return redirect(url_for("faculty_page"))
    return render_template("faculty.html", faculty=rows("SELECT * FROM faculty ORDER BY name"))


@app.route("/courses", methods=["GET", "POST"])
@roles_required("admin", "faculty")
def courses_page():
    db = get_db()
    user = session["user"]
    if request.method == "POST":
        if user["role"] != "admin":
            abort(403)
        values = [request.form.get(key, "").strip() for key in ("id", "title", "code", "faculty_id", "credits")]
        course_id, title, code, faculty_id, credits = values
        try:
            credit_count = int(credits)
            if not all(values) or not 1 <= credit_count <= 8:
                raise ValueError
            db.execute("INSERT INTO courses VALUES (?, ?, ?, ?, ?)", (course_id, title, code.upper(), faculty_id, credit_count))
            db.commit()
            flash(f"Course {code.upper()} added.", "success")
        except (ValueError, sqlite3.IntegrityError):
            db.rollback()
            flash("Check the course details, credit count, and unique course ID/code.", "error")
        return redirect(url_for("courses_page"))
    query = "SELECT c.*, f.name AS faculty_name FROM courses c JOIN faculty f ON f.id = c.faculty_id"
    parameters = ()
    if user["role"] == "faculty":
        query += " WHERE c.faculty_id = ?"
        parameters = (user["record_id"],)
    return render_template("courses.html", courses=rows(query + " ORDER BY c.code", parameters), faculty=rows("SELECT id, name FROM faculty ORDER BY name") if user["role"] == "admin" else [])


def class_options(user):
    if user["role"] == "faculty":
        courses = rows("SELECT id, code, title FROM courses WHERE faculty_id = ? ORDER BY code", (user["record_id"],))
    else:
        courses = rows("SELECT id, code, title FROM courses ORDER BY code")
    if user["role"] == "student":
        students = rows("SELECT id, name FROM students WHERE id = ? ORDER BY name", (user["record_id"],))
    else:
        students = rows("SELECT id, name FROM students ORDER BY name")
    return courses, students


@app.route("/attendance", methods=["GET", "POST"])
@roles_required("admin", "faculty", "student")
def attendance_page():
    user = session["user"]
    db = get_db()
    courses, students = class_options(user)
    if request.method == "POST":
        if user["role"] == "student":
            abort(403)
        student_id = request.form.get("student_id", "")
        course_id = request.form.get("course_id", "")
        attendance_date = request.form.get("attendance_date", "")
        status = request.form.get("status", "")
        allowed_courses = {course["id"] for course in courses}
        try:
            date.fromisoformat(attendance_date)
            if student_id not in {student["id"] for student in students} or course_id not in allowed_courses or status not in ("Present", "Absent", "Late"):
                raise ValueError
            db.execute("INSERT INTO attendance (student_id, course_id, attendance_date, status) VALUES (?, ?, ?, ?) ON CONFLICT(student_id, course_id, attendance_date) DO UPDATE SET status = excluded.status", (student_id, course_id, attendance_date, status))
            db.commit()
            flash("Attendance saved.", "success")
        except (ValueError, sqlite3.IntegrityError):
            db.rollback()
            flash("Choose a valid student, course, date, and attendance status.", "error")
        return redirect(url_for("attendance_page"))
    query = "SELECT a.*, s.name AS student_name, c.code, c.title FROM attendance a JOIN students s ON s.id = a.student_id JOIN courses c ON c.id = a.course_id"
    params = ()
    if user["role"] == "student":
        query += " WHERE a.student_id = ?"
        params = (user["record_id"],)
    elif user["role"] == "faculty":
        query += " WHERE c.faculty_id = ?"
        params = (user["record_id"],)
    return render_template("attendance.html", entries=rows(query + " ORDER BY a.attendance_date DESC, c.code LIMIT 100", params), courses=courses, students=students, today=date.today().isoformat(), can_edit=user["role"] != "student")


@app.route("/results", methods=["GET", "POST"])
@roles_required("admin", "faculty", "student")
def results_page():
    user = session["user"]
    db = get_db()
    courses, students = class_options(user)
    if request.method == "POST":
        if user["role"] == "student":
            abort(403)
        student_id = request.form.get("student_id", "")
        course_id = request.form.get("course_id", "")
        term = request.form.get("term", "").strip()
        marks = request.form.get("marks", "")
        try:
            mark_value = float(marks)
            if student_id not in {student["id"] for student in students} or course_id not in {course["id"] for course in courses} or not term or not 0 <= mark_value <= 100:
                raise ValueError
            db.execute("INSERT INTO results (student_id, course_id, term, marks, grade) VALUES (?, ?, ?, ?, ?) ON CONFLICT(student_id, course_id, term) DO UPDATE SET marks = excluded.marks, grade = excluded.grade", (student_id, course_id, term, mark_value, grade_for(mark_value)))
            db.commit()
            flash("Result saved.", "success")
        except (ValueError, sqlite3.IntegrityError):
            db.rollback()
            flash("Choose a valid student and course, and enter marks from 0 to 100.", "error")
        return redirect(url_for("results_page"))
    query = "SELECT r.*, s.name AS student_name, c.code, c.title FROM results r JOIN students s ON s.id = r.student_id JOIN courses c ON c.id = r.course_id"
    params = ()
    if user["role"] == "student":
        query += " WHERE r.student_id = ?"
        params = (user["record_id"],)
    elif user["role"] == "faculty":
        query += " WHERE c.faculty_id = ?"
        params = (user["record_id"],)
    return render_template("results.html", entries=rows(query + " ORDER BY r.id DESC", params), courses=courses, students=students, can_edit=user["role"] != "student")


@app.route("/fees", methods=["GET", "POST"])
@roles_required("admin", "student")
def fees_page():
    user = session["user"]
    db = get_db()
    if request.method == "POST":
        if user["role"] != "admin":
            abort(403)
        if request.form.get("action") == "status":
            fee_id = request.form.get("fee_id", "")
            status = request.form.get("status", "")
            if status not in ("Pending", "Paid"):
                abort(400)
            db.execute("UPDATE fees SET status = ? WHERE id = ?", (status, fee_id))
            db.commit()
            flash("Fee status updated.", "success")
        else:
            try:
                student_id = request.form.get("student_id", "")
                description = request.form.get("description", "").strip()
                amount = float(request.form.get("amount", ""))
                due_date = request.form.get("due_date", "")
                date.fromisoformat(due_date)
                if not db.execute("SELECT 1 FROM students WHERE id = ?", (student_id,)).fetchone() or not description or amount < 0:
                    raise ValueError
                db.execute("INSERT INTO fees (student_id, description, amount, due_date, status) VALUES (?, ?, ?, ?, 'Pending')", (student_id, description, amount, due_date))
                db.commit()
                flash("Fee charge created.", "success")
            except (ValueError, sqlite3.IntegrityError):
                db.rollback()
                flash("Enter a valid student, description, amount, and due date.", "error")
        return redirect(url_for("fees_page"))
    query = "SELECT f.*, s.name AS student_name FROM fees f JOIN students s ON s.id = f.student_id"
    params = ()
    if user["role"] == "student":
        query += " WHERE f.student_id = ?"
        params = (user["record_id"],)
    return render_template("fees.html", fees=rows(query + " ORDER BY f.due_date", params), students=rows("SELECT id, name FROM students ORDER BY name") if user["role"] == "admin" else [], can_edit=user["role"] == "admin")


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We couldn't find that page."), 404


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")