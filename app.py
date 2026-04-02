from dotenv import load_dotenv
import os
import string
import random
import time
import psycopg2

from flask import Flask, request, send_file, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# ------------------ LOAD ENV ------------------
load_dotenv()

# ------------------ APP SETUP ------------------
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
            username TEXT,
            email TEXT UNIQUE,
            password TEXT
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_verification (
            id SERIAL PRIMARY KEY,
            email TEXT,
            otp TEXT,
            expiry DOUBLE PRECISION
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ------------------ MAIL CONFIG ------------------
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

mail = Mail(app)

print("USER:", os.environ.get("MAIL_USERNAME"))
print("PASS:", os.environ.get("MAIL_PASSWORD"))

def send_otp_email(receiver_email, otp):
    try:
        msg = Message(
            subject="OTP Verification",
            recipients=[receiver_email],
            body=f"Your OTP is: {otp}"
        )
        mail.send(msg)
        print("MAIL SENT")
        return True
    except Exception as e:
        print("MAIL ERROR:", e)
        return False

# ------------------ CONFIG ------------------
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ------------------ UTIL ------------------
def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_otp():
    return str(random.randint(100000, 999999))

# ------------------ ROUTES ------------------

@app.route("/")
def home():
    return redirect(url_for("login"))
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
@app.route("/verify_email")
def verify_email():
    if "user" not in session:
        return redirect(url_for("login"))
    
    return render_template("verify_email.html")

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, password)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        
        except Exception as e:
                print("DB ERROR:", e)
                return render_template("register.html", error="Email already registered")
    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[3], password):
            session["user"] = user[1]
            session["email"] = user[2]
            return redirect(url_for("verify_email"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")
# -------- SEND OTP --------
@app.route("/send_otp", methods=["POST"])
def send_otp():
    email = session.get("email")
    if not email:
        return redirect(url_for("login"))
    otp = generate_otp()
    expiry = time.time() + 300

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM otp_verification WHERE email=%s", (email,))
    cursor.execute(
        "INSERT INTO otp_verification (email, otp, expiry) VALUES (%s, %s, %s)",
        (email, otp, expiry)
    )
    conn.commit()
    conn.close()

    send_otp_email(email, otp)
    return render_template("enter_otp.html")

# -------- VERIFY OTP --------
@app.route("/check_otp", methods=["POST"])
def check_otp():
    entered_otp = request.form.get("otp")
    email = session.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT otp, expiry FROM otp_verification WHERE email=%s ORDER BY id DESC LIMIT 1",
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
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    if "verified" not in session:
        return redirect(url_for("verify_email"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return "No file selected"
        if not allowed_file(file.filename):
            return render_template("index.html", error="File type not allowed")

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

# ------------------ RUN ------------------
if __name__ == "__main__":
    app.run()