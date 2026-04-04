from dotenv import load_dotenv
import os
import string
import random
import psycopg2
from flask import Flask, request, render_template, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client

# ------------------ LOAD ENV ------------------
load_dotenv()

# ------------------ APP ------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_key")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ------------------ TWILIO CONFIG ------------------
client = Client(
    os.environ.get("TWILIO_SID"),
    os.environ.get("TWILIO_AUTH_TOKEN")
)

VERIFY_SERVICE_SID = os.environ.get("VERIFY_SERVICE_SID")

def send_otp(phone):
    try:
        client.verify.services(VERIFY_SERVICE_SID).verifications.create(
            to=phone,
            channel="sms"
        )
        return True
    except Exception as e:
        print("OTP ERROR:", e)
        return False

def verify_otp(phone, otp):
    try:
        result = client.verify.services(VERIFY_SERVICE_SID).verification_checks.create(
            to=phone,
            code=otp
        )
        return result.status == "approved"
    except Exception as e:
        print("VERIFY ERROR:", e)
        return False

# ------------------ DATABASE ------------------
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set")

    if "localhost" in DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    else:
        return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            phone TEXT UNIQUE,
            password TEXT
        )
    """)

    # Files table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            random_id TEXT UNIQUE,
            filename TEXT,
            filepath TEXT
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()

# Initialize DB once
init_db()

# ------------------ FILE CONFIG ------------------
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "pdf", "txt",  "jpeg", "gif", "doc", "docx", "ppt", "pptx", "zip", "csv", "xls", "xlsx"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ------------------ ROUTES ------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = generate_password_hash(request.form.get("password"))

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (phone, password) VALUES (%s, %s)",
                (phone, password)
            )
            conn.commit()
        except Exception:
            conn.rollback()
            return render_template("register.html", error="Phone already exists")
        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")
        if not phone.startswith("+"):
         phone = "+" + phone

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE phone=%s", (phone,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template("login.html", error="User not found")

        if not check_password_hash(user[2], password):
            return render_template("login.html", error="Wrong password")

        # Send OTP
        send_otp(phone)

        session["phone"] = phone
        return redirect(url_for("verify_otp_page"))

    return render_template("login.html")

# -------- FORGOT PASSWORD --------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        phone = request.form.get("phone")

        if not phone.startswith("+"):
            phone = "+" + phone

        # Send OTP
        if send_otp(phone):
            session["reset_phone"] = phone
            return redirect(url_for("reset_password.html"))
        else:
            return render_template("forgot.html", error="Failed to send OTP")

    return render_template("forgot.html")

# -------- RESET PASSWORD --------
@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        otp = request.form.get("otp")
        new_password = request.form.get("password")
        phone = session.get("reset_phone")

        if verify_otp(phone, otp):
            conn = get_db_connection()
            cursor = conn.cursor()

            hashed_password = generate_password_hash(new_password)

            cursor.execute(
                "UPDATE users SET password=%s WHERE phone=%s",
                (hashed_password, phone)
            )

            conn.commit()
            conn.close()

            return redirect(url_for("login"))
        else:
            return render_template("reset_password.html", error="Invalid OTP")

    return render_template("reset_password.html")

# -------- OTP VERIFY --------
@app.route("/verify", methods=["GET", "POST"])
def verify_otp_page():
    if request.method == "POST":
        otp = request.form.get("otp")
        phone = session.get("phone")

        if verify_otp(phone, otp):
            session["user"] = phone
            return redirect(url_for("upload"))
        else:
            return render_template("enter_otp.html", error="Invalid OTP")

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

        if not allowed_file(file.filename):
            return "File type not allowed"

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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
