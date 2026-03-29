import os
import string
import sqlite3
import random
import time

from flask import Flask, request, send_file, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# ------------------ APP SETUP ------------------

app = Flask(__name__)
app.secret_key = "super_secret_key"

# ------------------ MAIL CONFIG ------------------

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

mail = Mail(app)

# ------------------ CONFIG ------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024
LINK_EXPIRY = 15 * 60  # 15 minutes

# ------------------ UTIL FUNCTIONS ------------------

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_otp():
    return str(random.randint(100000, 999999))

# ------------------ DATABASE ------------------

def init_db():
    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            random_id TEXT UNIQUE,
            filename TEXT,
            filepath TEXT,
            upload_time REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_verification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            random_id TEXT,
            otp TEXT,
            otp_expiry REAL
        )
    """)

    conn.commit()
    conn.close()

# ------------------ ROUTES ------------------

@app.route("/")
def home():
    return redirect(url_for("login_user"))

# -------- REGISTER --------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))

        try:
            with sqlite3.connect("files.db") as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, password)
                )
                conn.commit()
            return redirect(url_for("login_user"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="User already exists")

    return render_template("register.html")

# -------- LOGIN --------

@app.route("/login", methods=["GET", "POST"])
def login_user():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        with sqlite3.connect("files.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()
        print("Entered Email:", email)
        print("Entered Password:", password)
        print("User from DB:", user)

        if user and check_password_hash(user[3], password):
            session["user"] = user[1]
            return redirect(url_for("upload"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

# -------- LOGOUT --------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_user"))

# -------- UPLOAD --------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login_user"))

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            return render_template("index.html", error="No file selected", link=None)

        random_id = generate_random_string()
        filename = random_id + "_" + secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        with sqlite3.connect("files.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO files (random_id, filename, filepath, upload_time) VALUES (?, ?, ?, ?)",
                (random_id, filename, filepath, time.time())
            )
            conn.commit()

        share_link = request.host_url.rstrip("/") + "/" + random_id
        return render_template("index.html", link=share_link, error=None)

    return render_template("index.html", link=None, error=None)

# -------- DOWNLOAD WITH OTP --------

@app.route("/<random_id>", methods=["GET", "POST"])
def download_with_otp(random_id):

    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()

    if request.method == "POST":

        # SEND OTP
        if "email" in request.form:
            email = request.form.get("email")
            otp = generate_otp()
            expiry = time.time() + 300

            cursor.execute(
                "INSERT INTO otp_verification (random_id, otp, otp_expiry) VALUES (?, ?, ?)",
                (random_id, otp, expiry)
            )
            conn.commit()

            msg = Message("Your OTP Code", recipients=[email])
            msg.body = f"Your OTP is {otp}. Valid for 5 minutes."
            mail.send(msg)

            return render_template("enter_otp.html", random_id=random_id)

        # VERIFY OTP
        elif "otp" in request.form:
            entered_otp = request.form.get("otp")

            cursor.execute(
                "SELECT otp, otp_expiry FROM otp_verification WHERE random_id=? ORDER BY id DESC LIMIT 1",
                (random_id,)
            )
            data = cursor.fetchone()

            if not data:
                return "Invalid OTP"

            if entered_otp != data[0] or time.time() > data[1]:
                return "Invalid or Expired OTP"

            cursor.execute(
                "SELECT filepath, filename, upload_time FROM files WHERE random_id=?",
                (random_id,)
            )
            file_data = cursor.fetchone()

            if not file_data:
                return "File not found"

            if time.time() - file_data[2] > LINK_EXPIRY:
                return "Link expired"

            if not os.path.exists(file_data[0]):
                return "File missing"

            cursor.execute(
                "DELETE FROM otp_verification WHERE random_id=?",
                (random_id,)
            )
            conn.commit()
            conn.close()

            return send_file(
                file_data[0],
                download_name=file_data[1],
                as_attachment=True
            )

    conn.close()
    return render_template("verify_email.html", random_id=random_id)

# ------------------ RUN ------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)