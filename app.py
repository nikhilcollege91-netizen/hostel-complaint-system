import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'hostel_complaint.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXT = {'png','jpg','jpeg','gif','mp3','wav','m4a','pdf','mp4','mov','avi'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')
    complaints = db.relationship('Complaint', backref='student', lazy=True)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(300))
    status = db.Column(db.String(50), default='Pending')  # Pending, In Progress, Resolved
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'warden':
            return redirect(url_for('warden_dashboard'))
        return redirect(url_for('student_dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        if not name or not email or not password:
            flash('Please fill all fields', 'warning')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(name=name, email=email, password=password, role='student')
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            flash('Logged in successfully.', 'success')
            if user.role == 'warden':
                return redirect(url_for('warden_dashboard'))
            return redirect(url_for('student_dashboard'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    complaints = Complaint.query.filter_by(student_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('student_dashboard.html', complaints=complaints)

@app.route('/student/complaint/add', methods=['GET','POST'])
@login_required
def add_complaint():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        category = request.form.get('category','').strip()
        description = request.form.get('description','').strip()
        file = request.files.get('file')
        filename = None
        if file and file.filename and allowed_file(file.filename):
            fname = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"{current_user.id}_{timestamp}_{fname}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        comp = Complaint(title=title, category=category, description=description, filename=filename, student_id=current_user.id)
        db.session.add(comp)
        db.session.commit()
        flash('Complaint submitted', 'success')
        return redirect(url_for('student_dashboard'))
    return render_template('add_complaint.html')

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/warden/dashboard')
@login_required
def warden_dashboard():
    if current_user.role != 'warden':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    pending_count = Complaint.query.filter_by(status='Pending').count()
    return render_template('warden_dashboard.html', complaints=complaints, pending_count=pending_count)

@app.route('/warden/complaint/<int:cid>/update', methods=['GET','POST'])
@login_required
def update_complaint(cid):
    if current_user.role != 'warden':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    comp = Complaint.query.get_or_404(cid)
    if request.method == 'POST':
        comp.status = request.form.get('status', comp.status)
        comp.remarks = request.form.get('remarks','').strip()
        db.session.commit()
        flash('Complaint updated', 'success')
        return redirect(url_for('warden_dashboard'))
    return render_template('update_complaint.html', comp=comp)

# Ensure tables exist before the first request
with app.app_context():
    db.create_all()
    # create default warden if missing
    if not User.query.filter_by(email='hostelwarden.cu@gmail.com').first():
        w = User(name='Hostel Warden', email='hostelwarden.cu@gmail.com', password='CUWARDEN', role='warden')
        db.session.add(w)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
