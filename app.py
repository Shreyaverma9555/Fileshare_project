from dotenv import load_dotenv
import os
import random
import string
import time
import psycopg2
from flask import Flask, request, render_template, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from twilio.rest import Client

# ------------------ LOAD ENV ------------------
load_dotenv()

# ------------------ APP ------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")

# ------------------ DATABASE ------------------
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            phone TEXT UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_verification (
            id SERIAL PRIMARY KEY,
            phone TEXT,
            otp TEXT,
            expiry DOUBLE PRECISION
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            random_id TEXT,
            filename TEXT,
            filepath TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ------------------ TWILIO CONFIG ------------------
def send_otp_sms(phone, otp):
    try:
        client = Client(
            os.environ.get("TWILIO_SID"),
            os.environ.get("TWILIO_AUTH_TOKEN")
        )

        message = client.messages.create(
            body=f"Your OTP is: {otp}",
            from_=os.environ.get("TWILIO_PHONE"),
            to=phone
        )

        print("✅ OTP SENT:", message.sid)
        return True

    except Exception as e:
        print("❌ SMS ERROR:", e)
        return False

# ------------------ CONFIG ------------------
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ------------------ ROUTES ------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

# -------- LOGIN (PHONE) --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone")

        if not phone:
            return render_template("login.html", error="Enter phone number")

        # Save user if not exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE phone=%s", (phone,))
        user = cursor.fetchone()

        if not user:
            cursor.execute("INSERT INTO users (phone) VALUES (%s)", (phone,))
            conn.commit()

        conn.close()

        # Generate OTP
        otp = generate_otp()
        expiry = time.time() + 300

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM otp_verification WHERE phone=%s", (phone,))
        cursor.execute(
            "INSERT INTO otp_verification (phone, otp, expiry) VALUES (%s, %s, %s)",
            (phone, otp, expiry)
        )
        conn.commit()
        conn.close()

        # Send SMS
        send_otp_sms(phone, otp)

        session["phone"] = phone
        return redirect(url_for("verify_otp"))

    return render_template("login.html")

# -------- VERIFY OTP --------
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        phone = session.get("phone")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT otp, expiry FROM otp_verification WHERE phone=%s ORDER BY id DESC LIMIT 1",
            (phone,)
        )
        data = cursor.fetchone()
        conn.close()

        if data and entered_otp == data[0] and time.time() < data[1]:
            session["user"] = phone
            return redirect(url_for("upload"))
        else:
            return render_template("enter_otp.html", error="Invalid or expired OTP")

    return render_template("enter_otp.html")

# -------- UPLOAD --------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            return "No file selected"

        random_id = generate_random_string()
        filename = random_id + "_" + secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (random_id, filename, filepath) VALUES (%s, %s, %s)",
            (random_id, filename, filepath)
        )
        conn.commit()
        conn.close()

        link = url_for("download", random_id=random_id, _external=True)
        return render_template("success.html", link=link)

    return render_template("index.html")

# -------- DOWNLOAD --------
@app.route("/<random_id>")
def download(random_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filepath, filename FROM files WHERE random_id=%s",
        (random_id,)
    )
    file = cursor.fetchone()
    conn.close()

    if not file:
        return "File not found"

    return send_file(file[0], download_name=file[1], as_attachment=True)

# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ------------------ RUN ------------------
if __name__ == "__main__":
    app.run()