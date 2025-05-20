from flask import Flask, render_template, request, redirect, url_for, jsonify, Response , session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_cors import CORS
import random
import string
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename
import cv2
import numpy as np
import face_recognition
import base64
from datetime import datetime, date
import os
import dlib


app = Flask(__name__)
bcrypt = Bcrypt(app)

#secret key
app.secret_key = '0091c1a43a17eb0f6d656a736f69a72ccfa791621b605aab193bbb2b4c210b1b'


# MySQL Configurationg
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:pooja%40Sql@localhost/attendance_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


# Email configuration for password reset
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Enter your email
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Enter your email password
mail = Mail(app)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Create database tables
with app.app_context():
    db.create_all()

# Set max upload size to 10MB (adjust as needed)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

# Load face detector
detector = dlib.get_frontal_face_detector()

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class NewUser(db.Model):  # Updated class name to match new_users table
    __tablename__ = 'new_user'  # Explicitly defining table name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    gender = db.Column(db.Enum('Male', 'Female', 'Other'), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(255), nullable=True)


# Admin Model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)



# Define the Attendance Table
class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(100), nullable=False)
    time = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=False)  # New column for gender
    attendance_status = db.Column(db.String(10), nullable=False)  # New column for attendance status

class StudentSchedule(db.Model):
    __tablename__ = 'StudentSchedule'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('new_users.id'), nullable=False)
    day_of_week = db.Column(db.String(10), nullable=False)  # Stores 'Monday', 'Tuesday', etc.
    period = db.Column(db.Integer, nullable=False)  # Period number (e.g., 1, 2, 3)
    time_start = db.Column(db.String(5), nullable=False)  # Start time (HH:MM)
    time_end = db.Column(db.String(5), nullable=False)  # End time (HH:MM)
    subject = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Schedule {self.day_of_week} Period {self.period}: {self.subject} ({self.time_start}-{self.time_end}) at {self.location}>"



# Route for Login page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        else:
            return "Invalid username or password", 401

    return render_template('login.html')

# Route for Registration page
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        email = data['email']
        password = data['password']
        hashed_password = generate_password_hash(password)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {"message": "Username already exists"}, 400

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return {"message": "Email already registered"}, 400

        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {"message": "Registration successful!"}, 200

    return render_template('login.html')

# Route for Forget Password page
@app.route('/forget-password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            return "Email not found", 404

        token = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'Your password reset code is: {token}'
        mail.send(msg)

        return f"Password reset code sent to {email}."

    return render_template('login.html')

# Route to Reset Password page
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            hashed_password = generate_password_hash(new_password)
            user.password_hash = hashed_password
            db.session.commit()
            return "Password has been reset successfully"

    return render_template('login.html', token=token)


# Logout Route (For Both Users & Admin)
@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/signup', methods=['POST'])
def admin_signup():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if not username or not email or not password:
        return jsonify({'message': 'All fields are required'}), 400

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long'}), 400

    if Admin.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_admin = Admin(username=username, email=email, password=hashed_password)

    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'message': 'Account created successfully!'}), 201  # JSON response

# Route for Admin Login
@app.route('/admin-login', methods=['POST'])
def admin_login():
    data = request.json
    email, password = data.get('email'), data.get('password')

    admin = Admin.query.filter_by(email=email).first()
    if admin and bcrypt.check_password_hash(admin.password, password):
        session['logged_in'] = True  # ✅ Ensure session is set
        return jsonify({'message': 'Login successful', 'redirect': '/form'}), 200  # JSON response

    return jsonify({'message': 'Invalid credentials'}), 401  # JSON response

@app.before_request
def disable_csrf_for_api():
    if request.endpoint in ['signup', 'admin_login']:
        request.csrf_valid = True  # Disable CSRF for these routes


@app.route('/form-register', methods=['POST'])
def register_user():
    data = request.form
    profile_pic = request.files.get('profile_pic')
    captured_image = data.get('captured_image')

    name = data.get('name')
    roll = data.get('roll')
    email = data.get('email')
    phone = data.get('phone')
    gender = data.get('gender')
    department = data.get('department')

    if not all([name, roll, email, phone, gender, department]):
        return jsonify({'message': 'All fields are required!'}), 400

    filename = None
    if profile_pic:
        filename = secure_filename(f"{roll}_{profile_pic.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_pic.save(filepath)
    elif captured_image and captured_image.startswith("data:image"):
        filename = f"{roll}_captured.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, "wb") as img_file:
            img_file.write(base64.b64decode(captured_image.split(',')[1]))

    try:
        new_user = NewUser(name=name, roll=roll, email=email, phone=phone, gender=gender, department=department, profile_pic=filename)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!', 'redirect': url_for('dashboard')}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error: ' + str(e)}), 500

# Attendance marking code
def get_face_encoding(image_path):
    image = face_recognition.load_image_file(image_path)
    encodings = face_recognition.face_encodings(image)
    return encodings[0] if encodings else None


def compare_faces(known_encodings, unknown_encoding):
    if unknown_encoding is None:
        return None
    matches = face_recognition.compare_faces(list(known_encodings.values()), unknown_encoding)
    face_distances = face_recognition.face_distance(list(known_encodings.values()), unknown_encoding)
    best_match_index = np.argmin(face_distances) if len(face_distances) > 0 else None
    return list(known_encodings.keys())[best_match_index] if best_match_index is not None and matches[best_match_index] else None


def predict_gender(image):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    faces = detector(gray)
    return "Male" if len(faces) > 0 and faces[0].width() > faces[0].height() else "Female"


@app.route('/process_attendance', methods=['POST'])
def process_attendance():
    data = request.get_json()
    image_data = data['image'].split(',')[1]
    image_bytes = base64.b64decode(image_data)
    np_arr = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    unknown_encoding = face_recognition.face_encodings(image)
    if not unknown_encoding:
        return jsonify({"message": "No face detected."}), 400
    unknown_encoding = unknown_encoding[0]

    known_encodings = {}
    users = NewUser.query.all()
    for user in users:
        if user.profile_pic:
            profile_pic_path = user.profile_pic.decode() if isinstance(user.profile_pic, bytes) else user.profile_pic
            encoding = get_face_encoding(os.path.join(app.config['UPLOAD_FOLDER'], profile_pic_path))
            if encoding is not None:
                known_encodings[user.id] = encoding

    matched_user_id = compare_faces(known_encodings, unknown_encoding)
    if matched_user_id is None:
        return jsonify({"message": "User not recognized."}), 400

    user = db.session.get(NewUser, matched_user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 400
    
    # Predict gender
    gender_prediction = predict_gender(image)

    # Fetch student's schedule for today (day-wise)
    today_day = date.today().strftime("%A").capitalize()  # Get current day (e.g., 'Monday')
    schedule = StudentSchedule.query.filter_by(student_id=user.roll, day_of_week=today_day).all()
    schedule_data = [{"period": s.period,"time_start": s.time_start,"time_end": s.time_end, "subject": s.subject, "location": s.location} for s in schedule]


    # Insert into attendance
    attendance_entry = Attendance(
        student_id=user.roll,
        student_name=user.name,
        date=date.today().strftime("%Y-%m-%d"),
        time=datetime.now().strftime("%H:%M:%S"),
        gender=gender_prediction,  
        attendance_status="Present",
    )
    db.session.add(attendance_entry)
    db.session.commit()

    return jsonify({"message": f"Attendance marked for {user.name}. Predicted Gender: {gender_prediction}",
                    "name": user.name,
                    "roll": user.roll,
                    "gender": gender_prediction,  # Use predicted gender
                    "schedule": schedule_data,
                    "redirect": url_for('dashboard')})



# Route for Dashboard (after successful login)
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/newuser')
def new_user():
    return render_template('newuser.html')  # Correctly render the HTML file

@app.route('/mark_attendance')
def mark_attendance():
    return render_template('mark_attendance.html')


#Route for registration form
@app.route('/form')
def form():
    if not session.get('logged_in'):
        return redirect(url_for('new_user'))  # Redirect to the correct route
    return render_template('form.html')

if __name__ == '__main__':
    with app.app_context():  # Correct context usage
        db.create_all()  # Creates tables
    app.run(debug=True)






