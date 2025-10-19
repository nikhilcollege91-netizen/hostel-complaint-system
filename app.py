from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel_complaint.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(10), default='student')

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(200))
    category = db.Column(db.String(50))
    description = db.Column(db.Text)
    filename = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'warden':
            return redirect(url_for('warden_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can login now.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            if user.role == 'warden':
                return redirect(url_for('warden_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('home'))
    complaints = Complaint.query.filter_by(student_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('student_dashboard.html', complaints=complaints)

@app.route('/student/complaint/add', methods=['GET', 'POST'])
@login_required
def add_complaint():
    if current_user.role != 'student':
        return redirect(url_for('home'))
    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        description = request.form['description']
        file = request.files['file']
        filename = None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        new_complaint = Complaint(student_id=current_user.id, title=title, category=category, description=description, filename=filename)
        db.session.add(new_complaint)
        db.session.commit()
        return redirect(url_for('student_dashboard'))
    return render_template('add_complaint.html')

@app.route('/warden/dashboard')
@login_required
def warden_dashboard():
    if current_user.role != 'warden':
        return redirect(url_for('home'))
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    pending_count = Complaint.query.filter_by(status='Pending').count()
    return render_template('warden_dashboard.html', complaints=complaints, pending_count=pending_count)

@app.route('/warden/complaint/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update_complaint(id):
    if current_user.role != 'warden':
        return redirect(url_for('home'))
    complaint = Complaint.query.get_or_404(id)
    if request.method == 'POST':
        complaint.status = request.form['status']
        complaint.remarks = request.form['remarks']
        db.session.commit()
        return redirect(url_for('warden_dashboard'))
    return render_template('update_complaint.html', complaint=complaint)

if __name__ == '__main__':
    db.create_all()
    if not User.query.filter_by(email='hostelwarden.cu@gmail.com').first():
        warden = User(name='Hostel Warden', email='hostelwarden.cu@gmail.com', password='CUWARDEN', role='warden')
        db.session.add(warden)
        db.session.commit()
    app.run(debug=True)
