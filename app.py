import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------- FLASK CONFIG ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['DATABASE'] = 'hostel.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'mp3', 'wav'}

# Ensure uploads folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------------- DATABASE SETUP ----------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    # Create users table
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_warden BOOLEAN NOT NULL DEFAULT 0
        )
    """)
    # Create complaints table
    db.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            proof_file TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            remark TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users (id)
        )
    """)
    # Default warden account
    warden_email = "hostelwarden.cu@gmail.com"
    warden_pass = generate_password_hash("CUWARDEN")
    existing = db.execute("SELECT * FROM users WHERE email=?", (warden_email,)).fetchone()
    if not existing:
        db.execute("INSERT INTO users (name, email, password, is_warden) VALUES (?, ?, ?, 1)",
                   ("Warden", warden_email, warden_pass))
        print("✅ Warden account created: hostelwarden.cu@gmail.com / CUWARDEN")
    db.commit()

with app.app_context():
    init_db()

# ---------------- HELPERS ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_by_id(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    return render_template('index.html')

# ---------- STUDENT REGISTER ----------
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        db = get_db()
        try:
            db.execute("INSERT INTO users (name, email, password, is_warden) VALUES (?, ?, ?, 0)",
                       (name, email, password))
            db.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
    return render_template('student_register.html')

# ---------- STUDENT LOGIN ----------
@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND is_warden=0", (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = False
            return redirect(url_for('student_dashboard'))
        flash("Invalid email or password.", "error")
    return render_template('student_login.html')

# ---------- STUDENT DASHBOARD ----------
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    return render_template('student_dashboard.html', name=session['user_name'])

# ---------- ADD COMPLAINT ----------
@app.route('/student/add_complaint', methods=['GET', 'POST'])
def add_complaint():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))

    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        description = request.form['description']
        proof_file = request.files.get('proof')
        filename = None

        if proof_file and allowed_file(proof_file.filename):
            filename = secure_filename(proof_file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                proof_file.save(save_path)
            except Exception as e:
                print("File upload error:", e)
                filename = None

        db = get_db()
        db.execute("INSERT INTO complaints (student_id, title, category, description, proof_file) VALUES (?, ?, ?, ?, ?)",
                   (session['user_id'], title, category, description, filename))
        db.commit()
        flash("Complaint submitted successfully!", "success")
        return redirect(url_for('my_complaints'))
    return render_template('add_complaint.html')

# ---------- MY COMPLAINTS ----------
@app.route('/student/my_complaints')
def my_complaints():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    db = get_db()
    complaints = db.execute("SELECT * FROM complaints WHERE student_id=? ORDER BY created_at DESC",
                            (session['user_id'],)).fetchall()
    return render_template('my_complaints.html', complaints=complaints)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------- STUDENT PROFILE ----------
@app.route('/student/profile', methods=['GET', 'POST'])
def student_profile():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    user_id = session['user_id']
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        if password:
            password = generate_password_hash(password)
            db.execute("UPDATE users SET name=?, email=?, password=? WHERE id=?",
                       (name, email, password, user_id))
        else:
            db.execute("UPDATE users SET name=?, email=? WHERE id=?",
                       (name, email, user_id))
        db.commit()
        flash("Profile updated successfully!", "success")
    user = get_user_by_id(user_id)
    return render_template('profile.html', user=user, title="Student Profile")

# ---------- WARDEN LOGIN ----------
@app.route('/warden/login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND is_warden=1", (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = True
            return redirect(url_for('warden_dashboard'))
        flash("Invalid email or password.", "error")
    return render_template('warden_login.html')

# ---------- WARDEN DASHBOARD ----------
@app.route('/warden/dashboard')
def warden_dashboard():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    db = get_db()
    complaints = db.execute("""
        SELECT c.*, u.name as student_name 
        FROM complaints c
        JOIN users u ON c.student_id=u.id
        ORDER BY c.created_at DESC
    """).fetchall()
    return render_template('warden_dashboard.html', complaints=complaints)

# ---------- WARDEN PROFILE ----------
@app.route('/warden/profile', methods=['GET', 'POST'])
def warden_profile():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    user_id = session['user_id']
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        if password:
            password = generate_password_hash(password)
            db.execute("UPDATE users SET name=?, email=?, password=? WHERE id=?",
                       (name, email, password, user_id))
        else:
            db.execute("UPDATE users SET name=?, email=? WHERE id=?",
                       (name, email, user_id))
        db.commit()
        flash("Profile updated successfully!", "success")
    user = get_user_by_id(user_id)
    return render_template('profile.html', user=user, title="Warden Profile")

# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
