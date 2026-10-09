# Northstar College Management System

A Flask and SQLite college portal for student, faculty, and administrative workflows. It includes role-based access to student and faculty directories, course assignments, attendance, results, and fee records.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The SQLite database is created in `instance/college.db` on first run and is seeded with sample records.

## Demo accounts

| Role | Username | Password |
| --- | --- | --- |
| Administrator | `admin` | `admin123` |
| Faculty | `faculty` | `faculty123` |
| Student | `student` | `student123` |

The administrator can create student and faculty accounts. Faculty accounts can record attendance and marks only for their assigned courses. Students can view only their own academic and fee records.

## Configuration

Set `SECRET_KEY` to a strong random value before deployment. Set `COLLEGE_DATABASE` to change the SQLite file location. Set `FLASK_DEBUG=1` only for local development.

Demo credentials and the development secret are for local evaluation only. Change credentials, set a production secret, and use a production WSGI server before deployment.