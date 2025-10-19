import os
from datetime import datetime
from types import SimpleNamespace
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'student_login'

ALLOWED_EXT = {'png','jpg','jpeg','gif','mp3','wav','m4a','pdf','mp4','mov','avi'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


# ---------------- Models ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')  # 'student' or 'warden'
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

    # property used by templates (templates reference c.proof)
    @property
    def proof(self):
        return self.filename


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- Helpers ----------------
def complaint_to_dict(c: Complaint):
    """Return a plain object/dict with attributes templates expect."""
    return SimpleNamespace(
        id=c.id,
        title=c.title,
        category=c.category,
        description=c.description,
        status=c.status,
        proof=c.filename,
        created_at=c.created_at,
        student_name=c.student.name if c.student else "Student"
    )


# ---------------- Routes ----------------

@app.route('/')
def index():
    return render_template('index.html')


# ---- Student auth & flows ----
@app.route('/student_register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not name or not email or not password:
            flash('Please fill all fields', 'danger')
            return redirect(url_for('student_register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('student_register'))

        user = User(name=name, email=email, password=password, role='student')
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Redirecting to login...', 'success')
        return redirect(url_for('student_login'))
    return render_template('student_register.html')


@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email, password=password, role='student').first()
        if user:
            login_user(user)
            return redirect(url_for('student_dashboard'))
        flash('Invalid email or password', 'danger')
        return redirect(url_for('student_login'))
    return render_template('student_login.html')


@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('warden_dashboard'))
    # show name in template using {{ name }}
    return render_template('student_dashboard.html', name=current_user.name)


@app.route('/add_complaint', methods=['GET', 'POST'])
@login_required
def add_complaint():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('warden_dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        file = request.files.get('proof') or request.files.get('file')  # accept both names

        if not title or not category or not description:
            flash('Please fill required fields', 'danger')
            return redirect(url_for('add_complaint'))

        filename = None
        if file and file.filename and allowed_file(file.filename):
            fname = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"{current_user.id}_{timestamp}_{fname}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        comp = Complaint(title=title, category=category, description=description, filename=filename, student_id=current_user.id)
        db.session.add(comp)
        db.session.commit()
        flash(f"Complaint '{title}' submitted successfully!", 'success')
        return redirect(url_for('view_complaints'))

    return render_template('add_complaint.html')


@app.route('/complaints')
@login_required
def view_complaints():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('warden_dashboard'))

    complaints = Complaint.query.filter_by(student_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    data = [complaint_to_dict(c) for c in complaints]
    # templates expect variable 'complaints'
    return render_template('complaints.html', complaints=data)


@app.route('/student_profile', methods=['GET', 'POST'])
@login_required
def student_profile():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('warden_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if name:
            current_user.name = name
        if email:
            # ensure email unique (if changing)
            existing = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing:
                flash('Email already in use', 'danger')
                return redirect(url_for('student_profile'))
            current_user.email = email
        if password:
            current_user.password = password

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('student_profile'))

    # templates expect 'student'
    return render_template('profile.html', student=current_user)


# ---- Warden auth & flows ----
@app.route('/warden_login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email, password=password, role='warden').first()
        if user:
            login_user(user)
            return redirect(url_for('warden_dashboard'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('warden_login'))
    return render_template('warden_login.html')


@app.route('/warden_dashboard')
@login_required
def warden_dashboard():
    if current_user.role != 'warden':
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))

    complaints_objs = Complaint.query.order_by(Complaint.created_at.desc()).all()
    complaints = [complaint_to_dict(c) for c in complaints_objs]
    new_count = Complaint.query.filter_by(status='Pending').count()
    return render_template('warden_dashboard.html', complaints=complaints, new_count=new_count)


@app.route('/update_status/<int:cid>', methods=['POST'])
@login_required
def update_status(cid):
    if current_user.role != 'warden':
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))

    comp = Complaint.query.get_or_404(cid)
    new_status = request.form.get('status', comp.status)
    comp.status = new_status
    db.session.commit()
    flash('Complaint status updated', 'success')
    return redirect(url_for('warden_dashboard'))


@app.route('/warden_profile', methods=['GET', 'POST'])
@login_required
def warden_profile():
    if current_user.role != 'warden':
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if name:
            current_user.name = name
        if email:
            existing = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing:
                flash('Email already in use', 'danger')
                return redirect(url_for('warden_profile'))
            current_user.email = email
        if password:
            current_user.password = password

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('warden_profile'))

    return render_template('warden_profile.html', warden=current_user)


@app.route('/analytics')
@login_required
def analytics():
    if current_user.role != 'warden':
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))

    pending = Complaint.query.filter_by(status='Pending').count()
    progress = Complaint.query.filter_by(status='In Progress').count()
    resolved = Complaint.query.filter_by(status='Resolved').count()
    return render_template('analytics.html', pending=pending, progress=progress, resolved=resolved)


# ---- Upload serving (public) ----
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)


# ---- Logout ----
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


# ---------------- Ensure DB + default warden ----------------
with app.app_context():
    db.create_all()
    # create default warden if not exists
    if not User.query.filter_by(email='hostelwarden.cu@gmail.com', role='warden').first():
        w = User(name='Hostel Warden', email='hostelwarden.cu@gmail.com', password='CUWARDEN', role='warden')
        db.session.add(w)
        db.session.commit()


# Run (locally)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
