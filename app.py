import os
import psycopg2
import dj_database_url
from psycopg2.extras import DictCursor
from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-change-this'

# --- New Database Setup (PostgreSQL) ---
# This will get the connection string you set in Render's Environment
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL is None:
    print("FATAL: DATABASE_URL environment variable is not set.")
    # You might want to raise an exception here or set a default for local testing
    # For now, we'll just print, but Render *must* have this set.

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db_info = dj_database_url.parse(DATABASE_URL)
            db = g._database = psycopg2.connect(
                dbname=db_info['NAME'],
                user=db_info['USER'],
                password=db_info['PASSWORD'],
                host=db_info['HOST'],
                port=db_info['PORT']
            )
            db.autocommit = True
        except Exception as e:
            print(f"Error connecting to database: {e}")
            return None
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    if db is None:
        print("Cannot initialize DB: Connection failed.")
        return
        
    cursor = db.cursor()
    
    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_warden BOOLEAN NOT NULL DEFAULT FALSE
    );
    """)
    
    # Create complaints table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS complaints (
        id SERIAL PRIMARY KEY,
        student_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        remark TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)
    
    # Create Warden Account
    try:
        warden_pass = generate_password_hash('CUWARDEN')
        cursor.execute(
            "INSERT INTO users (name, email, password, is_warden) VALUES (%s, %s, %s, TRUE) ON CONFLICT (email) DO NOTHING",
            ('Warden', 'hostelwarden.cu@gmail.com', warden_pass)
        )
    except Exception as e:
        print(f"Error creating warden: {e}")
    
    cursor.close()
    print("Database initialized and warden created.")

# Run the setup logic
with app.app_context():
    init_db()

# --- Helper Functions ---
def get_user_by_id(user_id):
    db = get_db()
    cursor = db.cursor(cursor_factory=DictCursor)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
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
        cursor = db.cursor()
        try:
            cursor.execute('INSERT INTO users (name, email, password, is_warden) VALUES (%s, %s, %s, FALSE)',
                           (name, email, hashed_password))
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('student_login'))
        except psycopg2.IntegrityError:
            flash('Email already exists.', 'error')
            return render_template('student_register.html')
        finally:
            cursor.close()
    return render_template('student_register.html')

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s AND is_warden = FALSE', (email,))
        user = cursor.fetchone()
        cursor.close()
        
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

        db = get_db()
        cursor = db.cursor()
        cursor.execute('INSERT INTO complaints (student_id, title, category, description) VALUES (%s, %s, %s, %s)',
                       (session['user_id'], title, category, description))
        cursor.close()
        
        flash(f"Complaint '{title}' submitted successfully!", 'success')
        return redirect(url_for('my_complaints'))

    return render_template('add_complaint.html')

@app.route('/student/my_complaints')
def my_complaints():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))

    db = get_db()
    cursor = db.cursor(cursor_factory=DictCursor)
    cursor.execute('SELECT * FROM complaints WHERE student_id = %s ORDER BY created_at DESC',
                   (session['user_id'],))
    complaints = cursor.fetchall()
    cursor.close()
    return render_template('my_complaints.html', complaints=complaints)

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
        cursor = db.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s AND is_warden = TRUE', (email,))
        user = cursor.fetchone()
        cursor.close()
        
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
    cursor = db.cursor(cursor_factory=DictCursor)
    cursor.execute("""
        SELECT c.*, u.name as student_name 
        FROM complaints c
        JOIN users u ON c.student_id = u.id
        ORDER BY c.created_at DESC
    """)
    complaints = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM complaints WHERE status = 'Pending'")
    new_complaints_count = cursor.fetchone()[0]
    cursor.close()
    
    return render_template('warden_dashboard.html', complaints=complaints, new_count=new_complaints_count)

@app.route('/warden/update_status/<int:id>', methods=['POST'])
def update_status(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
        
    new_status = request.form['status']
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE complaints SET status = %s WHERE id = %s', (new_status, id))
    cursor.close()
    flash('Complaint status updated.', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/add_remark/<int:id>', methods=['POST'])
def add_remark(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
        
    remark = request.form['remark']
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE complaints SET remark = %s WHERE id = %s', (remark, id))
    cursor.close()
    flash('Remark added successfully.', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/analytics')
def warden_analytics():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))

    db = get_db()
    cursor = db.cursor(cursor_factory=DictCursor)
    
    # Status analytics
    cursor.execute("SELECT status, COUNT(*) as count FROM complaints GROUP BY status")
    status_data = cursor.fetchall()
    status_counts = {'Pending': 0, 'In Progress': 0, 'Resolved': 0}
    for row in status_data:
        if row['status'] in status_counts:
            status_counts[row['status']] = row['count']
    total_complaints = sum(status_counts.values())

    # Category analytics
    cursor.execute("SELECT category, COUNT(*) as count FROM complaints GROUP BY category")
    category_data = cursor.fetchall()
    categories = [row['category'] for row in category_data]
    category_counts = [row['count'] for row in category_data]
    cursor.close()
    
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
    cursor = db.cursor(cursor_factory=DictCursor)
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        
        if password:
            hashed_password = generate_password_hash(password)
            cursor.execute('UPDATE users SET name = %s, email = %s, password = %s WHERE id = %s',
                           (name, email, hashed_password, user_id))
        else:
            cursor.execute('UPDATE users SET name = %s, email = %s WHERE id = %s',
                           (name, email, user_id))
        
        session['user_name'] = name
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile')) # Redirects to the same profile page

    user = get_user_by_id(user_id)
    cursor.close()
    
    title = "Warden Profile" if session.get('is_warden') else "Student Profile"
    return render_template('profile.html', user=user, title=title)

# --- Delete Old Profile Routes ---
# We delete these because the new /profile route handles both
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
