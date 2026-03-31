from dotenv import load_dotenv
import os

from flask_mail import Mail, Message

load_dotenv()

import string
import sqlite3
import random
import time
from flask import Flask, request, send_file, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

import smtplib
def send_otp_email(receiver_email, otp):
    try:
        msg = Message(
            subject="OTP Verification",
            recipients=[receiver_email],
            body=f"Your OTP is: {otp}"
        )
        mail.send(msg)
        return True
    except Exception as e:
        print("MAIL ERROR:", e)
        return False

# ------------------ APP SETUP ------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")
# ------------------ MAIL CONFIG ------------------

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
print("EMAIL:", os.environ.get("MAIL_USERNAME"))
print("PASS:", os.environ.get("MAIL_PASSWORD"))
print("SECRET:", os.environ.get("SECRET_KEY"))
mail = Mail(app)

# ------------------ CONFIG ------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------ UTIL ------------------

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_otp():
    return str(random.randint(100000, 999999))

# ------------------ DATABASE -----------------

def init_db():
    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()


    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            random_id TEXT,
            filename TEXT,
            filepath TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_verification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            otp TEXT,
            expiry REAL
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ------------------ ROUTES ------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

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
            return redirect(url_for("login"))
        except:
            return "User already exists"

    return render_template("register.html")

# -------- LOGIN --------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        with sqlite3.connect("files.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            session["user"] = user[1]
            session["email"] = user[2]
            return redirect(url_for("verify_email"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

# -------- EMAIL PAGE --------

@app.route("/verify_email")
def verify_email():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("verify_email.html")

# ------------------ send_otp------------------

@app.route("/send_otp", methods=["POST"])
def send_otp():
    if "email" not in session:
        return redirect(url_for("login"))

    email = session["email"]

    otp = generate_otp()
    expiry = time.time() + 300   # 5 minutes

    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()

    # delete old OTP
    cursor.execute("DELETE FROM otp_verification WHERE email=?", (email,))

    # insert new OTP
    cursor.execute(
        "INSERT INTO otp_verification (email, otp, expiry) VALUES (?, ?, ?)",
        (email, otp, expiry)
    )
    conn.commit()
    conn.close()

    try:
        if not send_otp_email(email, otp):
         return "Failed to send OTP email"
    except Exception as e:
        return f"Error sending email: {e}"

    return render_template("enter_otp.html")

# -------- VERIFY OTP --------

@app.route("/check_otp", methods=["POST"])
def check_otp():
    entered_otp = request.form.get("otp")
    email = session.get("email")

    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()

    cursor.execute(
    "SELECT otp, expiry FROM otp_verification WHERE email=? ORDER BY id DESC LIMIT 1",
    (email,)
)
    data = cursor.fetchone()
    conn.close()

    if data and entered_otp == data[0] and time.time() < data[1]:
        session["verified"] = True
        return redirect(url_for("upload"))
    else:
        return render_template("enter_otp.html", error="Invalid or expired OTP")
    
# -------- UPLOAD --------

import os

if not os.path.exists("uploads"):
    os.makedirs("uploads")

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if "user" not in session:
        return redirect(url_for("login"))

    if "verified" not in session:
        return redirect(url_for("verify_email"))

    if request.method == "POST":
        file = request.files.get("file")

        if not file:
            return "No file selected"

        random_id = generate_random_string()
        filename = random_id + "_" + secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        with sqlite3.connect("files.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO files (random_id, filename, filepath) VALUES (?, ?, ?)",
                (random_id, filename, filepath)
            )
            conn.commit()

            link = url_for("download", random_id=random_id, _external=True)
        return render_template("success.html", link=link, error=None)
    
    return render_template("index.html")

# -------- DOWNLOAD --------

@app.route("/<random_id>")
def download(random_id):

    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filepath, filename FROM files WHERE random_id=?",
        (random_id,)
    )
    file = cursor.fetchone()
    conn.close()

    if not file:
        return "File not found"

    return send_file(file[0], download_name=file[1], as_attachment=True)

# ------------------ RUN -----------------
if __name__ == "__main__":
    app.run()