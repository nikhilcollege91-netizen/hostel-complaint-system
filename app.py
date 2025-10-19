import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "your-secret-key"

# Folder for uploads
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "mov", "mp3", "wav"}

# Database
DATABASE = "hostel.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- INITIALIZE DB ----------
def init_db():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_warden INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        title TEXT,
        category TEXT,
        description TEXT,
        proof_file TEXT,
        status TEXT DEFAULT 'Pending',
        remark TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Add default warden if missing
    check = cursor.execute("SELECT * FROM users WHERE is_warden=1").fetchone()
    if not check:
        cursor.execute(
            "INSERT INTO users (name,email,password,is_warden) VALUES (?,?,?,1)",
            ("Hostel Warden", "hostelwarden.cu@gmail.com", generate_password_hash("warden123")),
        )

    db.commit()

with app.app_context():
    init_db()

# ---------- ROUTES ----------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        db = get_db()
        try:
            db.execute("INSERT INTO users (name,email,password,is_warden) VALUES (?,?,?,0)",
                       (name, email, password))
            db.commit()
            flash("Registered successfully! Please login.")
            return redirect(url_for("student_login"))
        except:
            flash("Email already exists.")
    return render_template("student_register.html")

@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND is_warden=0", (email,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["is_warden"] = False
            session["user_name"] = user["name"]
            return redirect(url_for("student_dashboard"))
        flash("Invalid login.")
    return render_template("student_login.html")

@app.route("/student/dashboard")
def student_dashboard():
    if "user_id" not in session or session.get("is_warden"):
        return redirect(url_for("student_login"))
    return render_template("student_dashboard.html", name=session.get("user_name"))

@app.route("/student/add_complaint", methods=["GET", "POST"])
def add_complaint():
    if "user_id" not in session or session.get("is_warden"):
        return redirect(url_for("student_login"))

    if request.method == "POST":
        title = request.form["title"]
        category = request.form["category"]
        description = request.form["description"]
        file = request.files.get("proof")
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db = get_db()
        db.execute(
            "INSERT INTO complaints (student_id,title,category,description,proof_file) VALUES (?,?,?,?,?)",
            (session["user_id"], title, category, description, filename),
        )
        db.commit()
        flash("Complaint submitted successfully.")
        return redirect(url_for("my_complaints"))

    return render_template("add_complaint.html")

@app.route("/student/my_complaints")
def my_complaints():
    if "user_id" not in session or session.get("is_warden"):
        return redirect(url_for("student_login"))
    db = get_db()
    complaints = db.execute("SELECT * FROM complaints WHERE student_id=? ORDER BY created_at DESC",
                            (session["user_id"],)).fetchall()
    return render_template("my_complaints.html", complaints=complaints)

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/warden/login", methods=["GET", "POST"])
def warden_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND is_warden=1", (email,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["is_warden"] = True
            session["user_name"] = user["name"]
            return redirect(url_for("warden_dashboard"))
        flash("Invalid login.")
    return render_template("warden_login.html")

@app.route("/warden/dashboard")
def warden_dashboard():
    if "user_id" not in session or not session.get("is_warden"):
        return redirect(url_for("warden_login"))
    db = get_db()
    complaints = db.execute("""
        SELECT c.*, u.name as student_name
        FROM complaints c
        JOIN users u ON c.student_id = u.id
        ORDER BY c.created_at DESC
    """).fetchall()
    return render_template("warden_dashboard.html", complaints=complaints)

@app.route("/warden/update_status", methods=["POST"])
def warden_update_status():
    if "user_id" not in session or not session.get("is_warden"):
        return redirect(url_for("warden_login"))
    cid = request.form["id"]
    status = request.form["status"]
    remark = request.form["remark"]
    db = get_db()
    db.execute("UPDATE complaints SET status=?, remark=? WHERE id=?", (status, remark, cid))
    db.commit()
    flash("Complaint updated.")
    return redirect(url_for("warden_dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
