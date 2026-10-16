"""Audit fixture: a Python-only Flask app whose vulnerable shapes must fire the
reviewed Python rules (A-17) while the parameterized twin stays silent (A-15)."""

from flask import Flask, request
import requests
import sqlite3

app = Flask(__name__)
DB = sqlite3.connect("app.db")


@app.route("/user")
def user():
    uid = request.args.get("uid")
    query = "SELECT * FROM users WHERE id = '%s'" % uid
    row = DB.execute(query).fetchone()
    return {"row": row}


@app.route("/user-safe")
def user_safe():
    uid = request.args.get("uid")
    row = DB.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return {"row": row}


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url)
    return {"status": response.status_code}


@app.route("/fetch-safe")
def fetch_safe():
    response = requests.get("https://api.example.invalid/v1/status")
    return {"status": response.status_code}
