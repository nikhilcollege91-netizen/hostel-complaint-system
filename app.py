import os
import sqlite3
import mimetypes
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ------------------ App Setup ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key')
app.config['DATABASE'] = 'hostel.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'mp3', 'wav', 'm4a', 'aac'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------ Disable Buffering + Cache FIXED ------------------
@app.after_request
def disable_caching(response):
    if response.mimetype == 'text/html':
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    response.headers["X-Accel-Buffering"] = "no"
    return response

# ------------------ Database Helpers ------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_warden BOOLEAN NOT NULL DEFAULT 0
    );

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
    );
    """
    db = get_db()
    db.executescript(schema)
    db.commit()

def ensure_warden_exists():
    db = get_db()
    warden_pass = generate_password_hash('CUWARDEN')
    db.execute("""
        INSERT OR IGNORE INTO users (name, email, password, is_warden)
        VALUES (?, ?, ?, 1)
    """, ('Warden', 'hostelwarden.cu@gmail.com', warden_pass))
    db.commit()

with app.app_context():
    init_db()
    ensure_warden_exists()

# ------------------ Utility ------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_by_id(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

# ------------------ Routes ------------------
@app.route('/')
def index():
    return render_template('index.html')

# --- Student Register/Login ---
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed = generate_password_hash(password)

        db = get_db()
        try:
            db.execute('INSERT INTO users (name, email, password, is_warden) VALUES (?, ?, ?, 0)',
                       (name, email, hashed))
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
    return render_template('student_register.html')

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ? AND is_warden = 0', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = False
            return redirect(url_for('student_dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('student_login.html')

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    return render_template('student_dashboard.html', name=session['user_name'])

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

        if proof_file and proof_file.filename != '' and allowed_file(proof_file.filename):
            filename = secure_filename(proof_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            proof_file.save(filepath)

        db = get_db()
        db.execute(
            'INSERT INTO complaints (student_id, title, category, description, proof_file) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], title, category, description, filename)
        )
        db.commit()
        flash('Complaint submitted successfully!', 'success')
        return redirect(url_for('my_complaints'))

    return render_template('add_complaint.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    mime_type, _ = mimetypes.guess_type(filepath)
    if not mime_type:
        mime_type = 'application/octet-stream'
    return send_file(filepath, mimetype=mime_type, as_attachment=False, conditional=True)

@app.route('/student/my_complaints')
def my_complaints():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    db = get_db()
    complaints = db.execute(
        'SELECT * FROM complaints WHERE student_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('my_complaints.html', complaints=complaints)

@app.route('/student/profile', methods=['GET', 'POST'])
def student_profile():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    db = get_db()
    user = get_user_by_id(session['user_id'])
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        if password:
            hashed = generate_password_hash(password)
            db.execute('UPDATE users SET name=?, email=?, password=? WHERE id=?',
                       (name, email, hashed, user['id']))
        else:
            db.execute('UPDATE users SET name=?, email=? WHERE id=?',
                       (name, email, user['id']))
        db.commit()
        session['user_name'] = name
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('student_profile'))
    return render_template('profile.html', user=user, title="Student Profile")

# --- Warden ---
@app.route('/warden/login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=? AND is_warden=1', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = True
            return redirect(url_for('warden_dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('warden_login.html')

@app.route('/warden/dashboard')
def warden_dashboard():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    db = get_db()
    complaints = db.execute("""
        SELECT c.*, u.name AS student_name FROM complaints c
        JOIN users u ON c.student_id = u.id
        ORDER BY c.created_at DESC
    """).fetchall()
    new_count = db.execute("SELECT COUNT(*) FROM complaints WHERE status='Pending'").fetchone()[0]
    return render_template('warden_dashboard.html', complaints=complaints, new_count=new_count)

@app.route('/warden/update_status/<int:id>', methods=['POST'])
def update_status(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    status = request.form['status']
    db = get_db()
    db.execute('UPDATE complaints SET status=? WHERE id=?', (status, id))
    db.commit()
    flash('Status updated.', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/add_remark/<int:id>', methods=['POST'])
def add_remark(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    remark = request.form['remark']
    db = get_db()
    db.execute('UPDATE complaints SET remark=? WHERE id=?', (remark, id))
    db.commit()
    flash('Remark added successfully.', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/analytics')
def warden_analytics():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    db = get_db()
    status_data = db.execute("SELECT status, COUNT(*) as count FROM complaints GROUP BY status").fetchall()
    status_counts = {'Pending': 0, 'In Progress': 0, 'Resolved': 0}
    for row in status_data:
        if row['status'] in status_counts:
            status_counts[row['status']] = row['count']
    total = sum(status_counts.values())
    category_data = db.execute("SELECT category, COUNT(*) as count FROM complaints GROUP BY category").fetchall()
    categories = [r['category'] for r in category_data]
    category_counts = [r['count'] for r in category_data]
    return render_template('analytics.html',
                           status_counts=status_counts,
                           total_complaints=total,
                           categories=categories,
                           category_counts=category_counts)

@app.route('/warden/profile', methods=['GET', 'POST'])
def warden_profile():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    db = get_db()
    user = get_user_by_id(session['user_id'])
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        if password:
            hashed = generate_password_hash(password)
            db.execute('UPDATE users SET name=?, email=?, password=? WHERE id=?',
                       (name, email, hashed, user['id']))
        else:
            db.execute('UPDATE users SET name=?, email=? WHERE id=?',
                       (name, email, user['id']))
        db.commit()
        session['user_name'] = name
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('warden_profile'))
    return render_template('profile.html', user=user, title="Warden Profile")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ------------------ Run ------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
