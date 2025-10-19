import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-change-this'

# --- This is the new, correct path for permanent storage ---
# We tell Render to create a "Disk" at '/data'
# Then we save all our permanent files there.
PERMANENT_STORAGE_DIR = '/data'
UPLOAD_FOLDER = os.path.join(PERMANENT_STORAGE_DIR, 'uploads')
DATABASE_PATH = os.path.join(PERMANENT_STORAGE_DIR, 'hostel.db')
# --- End of new paths ---

app.config['DATABASE'] = DATABASE_PATH
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'mp3', 'wav'}

# Create the folders if they don't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    print(f"Created folder: {app.config['UPLOAD_FOLDER']}")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Database Setup ---
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
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_warden BOOLEAN NOT NULL DEFAULT 0
        );
        """)
        
        # Create complaints table
        cursor.execute("""
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
        """)
        
        # Create Warden Account
        try:
            warden_pass = generate_password_hash('CUWARDEN')
            cursor.execute(
                "INSERT OR IGNORE INTO users (name, email, password, is_warden) VALUES (?, ?, ?, 1)",
                ('Warden', 'hostelwarden.cu@gmail.com', warden_pass)
            )
        except Exception as e:
            print(f"Error creating warden: {e}")
        
        db.commit()
        cursor.close()
        print("Database initialized and warden created.")

# Run the setup logic
with app.app_context():
    init_db()

# --- Helper Functions ---
def get_user_by_id(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return user

# --- General Routes ---
@app.route('/')
def index():
    return render_template('index.html')

# --- Student Routes ---
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        db = get_db()
        try:
            db.execute('INSERT INTO users (name, email, password, is_warden) VALUES (?, ?, ?, 0)',
                       (name, email, hashed_password))
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
            return render_template('student_register.html')
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
        else:
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
        if proof_file and proof_file.filename and allowed_file(proof_file.filename):
            filename = secure_filename(proof_file.filename)
            # Save the file to the permanent UPLOAD_FOLDER
            proof_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            print(f"File saved to: {os.path.join(app.config['UPLOAD_FOLDER'], filename)}")

        db = get_db()
        db.execute('INSERT INTO complaints (student_id, title, category, description, proof_file) VALUES (?, ?, ?, ?, ?)',
                   (session['user_id'], title, category, description, filename))
        db.commit()
        
        # --- THIS IS THE FIXED LINE ---
        flash(f"Complaint '{title}' submitted successfully!", 'success')
        
        return redirect(url_for('my_complaints'))

    return render_template('add_complaint.html')

@app.route('/student/my_complaints')
def my_complaints():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))

    db = get_db()
    complaints = db.execute('SELECT * FROM complaints WHERE student_id = ? ORDER BY created_at DESC',
                            (session['user_id'],)).fetchall()
    return render_template('my_complaints.html', complaints=complaints)

# This route lets the warden see the files
@app.route('/data/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Warden Routes ---
@app.route('/warden/login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if email != 'hostelwarden.cu@gmail.com':
             flash('Invalid email or password.', 'error')
             return render_template('warden_login.html')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ? AND is_warden = 1', (email,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = True
            return redirect(url_for('warden_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('warden_login.html')

@app.route('/warden/dashboard')
def warden_dashboard():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))

    db = get_db()
    complaints = db.execute("""
        SELECT c.*, u.name as student_name 
        FROM complaints c
        JOIN users u ON c.student_id = u.id
        ORDER BY c.created_at DESC
    """).fetchall()
    
    new_complaints_count = db.execute("SELECT COUNT(*) FROM complaints WHERE status = 'Pending'").fetchone()[0]
    
    return render_template('warden_dashboard.html', complaints=complaints, new_count=new_complaints_count)

@app.route('/warden/update_status/<int:id>', methods=['POST'])
def update_status(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
        
    new_status = request.form['status']
    db = get_db()
    db.execute('UPDATE complaints SET status = ? WHERE id = ?', (new_status, id))
    db.commit()
    flash('Complaint status updated.', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/add_remark/<int:id>', methods=['POST'])
def add_remark(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
        
    remark = request.form['remark']
    db = get_db()
    db.execute('UPDATE complaints SET remark = ? WHERE id = ?', (remark, id))
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
    total_complaints = sum(status_counts.values())

    category_data = db.execute("SELECT category, COUNT(*) as count FROM complaints GROUP BY category").fetchall()
    categories = [row['category'] for row in category_data]
    category_counts = [row['count'] for row in category_data]
    
    return render_template('analytics.html', 
                           status_counts=status_counts, 
                           total_complaints=total_complaints,
                           categories=categories,
                           category_counts=category_counts)

# This new route handles BOTH student and warden profiles
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    db = get_db()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        
        if password:
            hashed_password = generate_password_hash(password)
            db.execute('UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?',
                       (name, email, hashed_password, user_id))
        else:
            db.execute('UPDATE users SET name = ?, email = ? WHERE id = ?',
                       (name, email, user_id))
        db.commit()
        session['user_name'] = name
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    user = get_user_by_id(user_id)
    title = "Warden Profile" if session.get('is_warden') else "Student Profile"
    return render_template('profile.html', user=user, title=title)

@app.route('/student/profile')
def student_profile_redirect():
    return redirect(url_for('profile'))

@app.route('/warden/profile')
def warden_profile_redirect():
    return redirect(url_for('profile'))

# --- Logout ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
