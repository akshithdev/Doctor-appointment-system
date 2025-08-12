from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Ensure instance directory exists
os.makedirs('instance', exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinic.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(20))
    doctor = db.relationship('Doctor', backref='user', lazy=True, uselist=False)
    appointments = db.relationship('Appointment', backref='patient', lazy=True)

class Hospital(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(500), nullable=False)
    contact = db.Column(db.String(20))
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.Text)
    doctors = db.relationship('Doctor', backref='hospital', lazy=True)
    appointments = db.relationship('Appointment', backref='hospital', lazy=True)

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    consultation_fee = db.Column(db.Float, default=50.00)  # Default fee is $50
    about = db.Column(db.Text)
    appointments = db.relationship('Appointment', backref='doctor', lazy=True)

    @property
    def name(self):
        return self.user.name if self.user else "Unknown"

class DoctorAvailability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    day_of_week = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)
    appointment_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  
    symptoms = db.Column(db.Text)
    notes = db.Column(db.Text)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Role required decorator
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_type' not in session or session['user_type'] not in allowed_roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    hospitals = Hospital.query.all()
    return render_template('index.html', hospitals=hospitals)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clear any existing session
    if request.method == 'GET':
        session.clear()
    
    # Get user type from query parameter
    user_type = request.args.get('user_type', 'patient')
    next_url = request.args.get('next')
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user_type = request.form.get('user_type', 'patient')
        
        if not email or not password:
            flash('Please provide both email and password', 'danger')
            return render_template('login.html', user_type=user_type)
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Verify user type matches
            if user.user_type != user_type:
                flash(f'This login is for {user_type}s only. Please use the correct login page.', 'danger')
                return render_template('login.html', user_type=user_type)
            
            # Store user info in session
            session.clear()
            session['user_id'] = user.id
            session['user_type'] = user.user_type
            session['user_name'] = user.name
            
            flash('Logged in successfully!', 'success')
            
            # Redirect based on user type or next URL
            if next_url:
                return redirect(next_url)
            if user.user_type == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user.user_type == 'hospital_admin':
                return redirect(url_for('hospital_dashboard'))
            else:
                return redirect(url_for('patient_dashboard'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('login.html', user_type=user_type, next=next_url)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        user_type = request.form['user_type']
        phone = request.form['phone']

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            name=name,
            user_type=user_type,
            phone=phone
        )
        db.session.add(user)
        db.session.commit()

        # If user is hospital admin, create hospital
        if user_type == 'hospital_admin':
            hospital = Hospital(
                name=request.form['hospital_name'],
                address=request.form['hospital_address'],
                contact=phone,
                admin_id=user.id,
                description=request.form.get('hospital_description', '')
            )
            db.session.add(hospital)
            db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/hospitals')
def list_hospitals():
    hospitals = Hospital.query.all()
    return render_template('hospitals.html', hospitals=hospitals)

@app.route('/register_hospital', methods=['GET', 'POST'])
@login_required
@role_required(['hospital_admin'])
def register_hospital():
    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        contact = request.form.get('contact')
        description = request.form.get('description')
        
        if not all([name, address, contact]):
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('register_hospital'))
        
        try:
            hospital = Hospital(
                name=name,
                address=address,
                contact=contact,
                description=description,
                admin_id=session['user_id']
            )
            db.session.add(hospital)
            db.session.commit()
            flash('Hospital registered successfully!', 'success')
            return redirect(url_for('hospital_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error registering hospital. Please try again.', 'danger')
            return redirect(url_for('register_hospital'))
    
    return render_template('hospital/register.html')

@app.route('/add_doctor/<int:hospital_id>', methods=['GET', 'POST'])
@login_required
@role_required(['hospital_admin'])
def add_doctor_to_hospital(hospital_id):
    hospital = Hospital.query.get_or_404(hospital_id)
    
    # Check if user is the hospital admin
    if hospital.admin_id != session['user_id']:
        flash('You do not have permission to add doctors to this hospital.', 'danger')
        return redirect(url_for('hospital_dashboard'))
    
    if request.method == 'POST':
        try:
            # Create user account for doctor
            doctor_user = User(
                name=request.form['name'],
                email=request.form['email'],
                password_hash=generate_password_hash(request.form['password']),
                user_type='doctor'
            )
            db.session.add(doctor_user)
            db.session.flush()  # Get the user ID
            
            # Create doctor profile
            doctor = Doctor(
                user_id=doctor_user.id,
                hospital_id=hospital.id,
                specialization=request.form['specialization'],
                experience=int(request.form['experience']),
                consultation_fee=float(request.form['consultation_fee']),
                about=request.form['about']
            )
            db.session.add(doctor)
            db.session.commit()
            
            flash('Doctor added successfully!', 'success')
            return redirect(url_for('hospital_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error adding doctor: {str(e)}")  # Log the error
            flash('Error adding doctor. Please try again.', 'danger')
            return redirect(url_for('add_doctor_to_hospital', hospital_id=hospital_id))
    
    return render_template('hospital/add_doctor.html', hospital=hospital)

@app.route('/add_doctor', methods=['POST'])
@login_required
def add_doctor():
    if session.get('user_type') != 'hospital_admin':
        flash('Only hospitals can add doctors', 'danger')
        return redirect(url_for('index'))

    try:
        # Get the hospital
        hospital = Hospital.query.filter_by(admin_id=session.get('user_id')).first()
        if not hospital:
            flash('Hospital not found', 'danger')
            return redirect(url_for('index'))

        # Create user account for doctor
        doctor_user = User(
            email=request.form['email'],
            password_hash=generate_password_hash(request.form['password']),
            user_type='doctor'
        )
        db.session.add(doctor_user)
        db.session.flush()  # Get the user ID

        # Create doctor profile
        doctor = Doctor(
            user_id=doctor_user.id,
            hospital_id=hospital.id,
            specialization=request.form['specialization'],
            experience=int(request.form['experience']),
            consultation_fee=float(request.form['consultation_fee']),
            about=request.form['about']
        )
        db.session.add(doctor)
        db.session.commit()

        flash('Doctor added successfully', 'success')
        return redirect(url_for('hospital_dashboard'))

    except Exception as e:
        print('Error:', str(e))
        db.session.rollback()
        flash('Error adding doctor', 'danger')
        return redirect(url_for('hospital_dashboard'))

@app.route('/book_appointment/<int:doctor_id>', methods=['GET', 'POST'])
@login_required
@role_required(['patient'])
def book_appointment(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    
    if request.method == 'POST':
        appointment_date = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        symptoms = request.form.get('symptoms')
        
        if not appointment_date or not appointment_time:
            flash('Please select both date and time for the appointment.', 'danger')
            return redirect(url_for('book_appointment', doctor_id=doctor_id))
        
        try:
            # Convert date and time strings to datetime
            appointment_datetime = datetime.strptime(f"{appointment_date} {appointment_time}", "%Y-%m-%d %H:%M")
            
            # Check if appointment time is in the future
            if appointment_datetime <= datetime.now():
                flash('Please select a future date and time.', 'danger')
                return redirect(url_for('book_appointment', doctor_id=doctor_id))
            
            # Create appointment
            appointment = Appointment(
                doctor_id=doctor_id,
                patient_id=session['user_id'],
                hospital_id=doctor.hospital_id,
                appointment_time=appointment_datetime,
                symptoms=symptoms,
                status='pending'
            )
            db.session.add(appointment)
            db.session.commit()
            
            flash('Appointment booked successfully! Waiting for doctor approval.', 'success')
            return redirect(url_for('patient_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error booking appointment. Please try again.', 'danger')
            return redirect(url_for('book_appointment', doctor_id=doctor_id))
    
    return render_template('book_appointment.html', doctor=doctor, today=datetime.now())

@app.route('/patient/dashboard')
@login_required
@role_required(['patient'])
def patient_dashboard():
    user = User.query.get(session['user_id'])
    appointments = Appointment.query.filter_by(patient_id=session['user_id']).order_by(Appointment.appointment_time.desc()).all()
    return render_template('patient/dashboard.html', user=user, appointments=appointments)

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if session.get('user_type') != 'doctor':
        flash('Access denied. This page is only for doctors.', 'danger')
        return redirect(url_for('index'))

    try:
        # Get the doctor's profile
        doctor = Doctor.query.filter_by(user_id=session.get('user_id')).first()
        if not doctor:
            flash('Doctor profile not found.', 'danger')
            return redirect(url_for('index'))

        # Get today's date
        today = datetime.now().date()

        # Get pending appointments for this doctor's hospital
        pending_appointments = (Appointment.query
            .join(User, User.id == Appointment.patient_id)  # Join with User to get patient details
            .filter(
                Appointment.hospital_id == doctor.hospital_id,
                Appointment.status == 'pending'
            )
            .order_by(Appointment.appointment_time, Appointment.appointment_time)
            .all())

        # Get today's appointments
        todays_appointments = (Appointment.query
            .join(User, User.id == Appointment.patient_id)  # Join with User to get patient details
            .filter(
                Appointment.hospital_id == doctor.hospital_id,
                Appointment.appointment_time >= datetime.combine(today, datetime.min.time()),
                Appointment.appointment_time < datetime.combine(today, datetime.max.time()),
                Appointment.status == 'approved'
            )
            .order_by(Appointment.appointment_time)
            .all())

        # Get upcoming approved appointments
        upcoming_appointments = (Appointment.query
            .join(User, User.id == Appointment.patient_id)  # Join with User to get patient details
            .filter(
                Appointment.hospital_id == doctor.hospital_id,
                Appointment.appointment_time > datetime.combine(today, datetime.max.time()),
                Appointment.status == 'approved'
            )
            .order_by(Appointment.appointment_time)
            .all())

        # Get completed appointments
        completed_appointments = (Appointment.query
            .join(User, User.id == Appointment.patient_id)  # Join with User to get patient details
            .filter(
                Appointment.hospital_id == doctor.hospital_id,
                Appointment.status == 'completed'
            )
            .order_by(Appointment.appointment_time.desc())
            .all())

        return render_template('doctor/dashboard.html',
                            doctor=doctor,
                            pending_appointments=pending_appointments,
                            todays_appointments=todays_appointments,
                            upcoming_appointments=upcoming_appointments,
                            completed_appointments=completed_appointments)

    except Exception as e:
        print('Error:', str(e))
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('index'))

@app.route('/hospital/dashboard')
@login_required
def hospital_dashboard():
    if session.get('user_type') != 'hospital_admin':
        flash('Access denied. This page is only for hospitals.', 'danger')
        return redirect(url_for('index'))

    try:
        hospital = Hospital.query.filter_by(admin_id=session.get('user_id')).first()
        if not hospital:
            flash('Hospital profile not found.', 'danger')
            return redirect(url_for('index'))

        # Get all doctors in this hospital
        doctors = Doctor.query.filter_by(hospital_id=hospital.id).all()
        
        # Get appointments
        today = datetime.now().date()
        tomorrow = today + timedelta(days=1)
        
        # Today's appointments
        today_appointments = (Appointment.query
            .join(Doctor)
            .filter(
                Doctor.hospital_id == hospital.id,
                Appointment.appointment_time >= datetime.combine(today, datetime.min.time()),
                Appointment.appointment_time < datetime.combine(tomorrow, datetime.min.time())
            )
            .order_by(Appointment.appointment_time)
            .all())
        
        # Pending appointments
        pending_appointments = (Appointment.query
            .join(Doctor)
            .filter(
                Doctor.hospital_id == hospital.id,
                Appointment.status == 'pending'
            )
            .order_by(Appointment.appointment_time)
            .all())
        
        # Completed appointments
        completed_appointments = (Appointment.query
            .join(Doctor)
            .filter(
                Doctor.hospital_id == hospital.id,
                Appointment.status == 'completed'
            )
            .order_by(Appointment.appointment_time.desc())
            .all())

        return render_template('hospital/dashboard.html',
            hospital=hospital,
            doctors=doctors,
            today_appointments=today_appointments,
            pending_appointments=pending_appointments,
            completed_appointments=completed_appointments
        )

    except Exception as e:
        print('Error:', str(e))
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('index'))

@app.route('/hospital/<int:hospital_id>')
def hospital_details(hospital_id):
    hospital = Hospital.query.options(db.joinedload(Hospital.doctors).joinedload(Doctor.user)).get_or_404(hospital_id)
    today = datetime.now().date()
    return render_template('hospital_details.html', hospital=hospital, today=today)

@app.route('/update_appointment_status', methods=['POST'])
@login_required
def update_appointment_status():
    if session.get('user_type') != 'doctor':
        return jsonify({'success': False, 'message': 'Only doctors can update appointments'}), 403

    try:
        data = request.get_json()
        appointment_id = data.get('appointment_id')
        new_status = data.get('status')

        if not appointment_id or not new_status:
            return jsonify({'success': False, 'message': 'Missing appointment_id or status'}), 400

        # Get the doctor's profile
        doctor = Doctor.query.filter_by(user_id=session.get('user_id')).first()
        if not doctor:
            return jsonify({'success': False, 'message': 'Doctor profile not found'}), 404

        # Get the appointment
        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({'success': False, 'message': 'Appointment not found'}), 404

        # Check if the appointment belongs to the doctor's hospital
        if appointment.hospital_id != doctor.hospital_id:
            return jsonify({'success': False, 'message': 'You can only update appointments from your hospital'}), 403

        # Update the appointment status
        appointment.status = new_status
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Appointment {new_status} successfully'
        })

    except Exception as e:
        print('Error updating appointment:', str(e))
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while updating the appointment'}), 500

@app.route('/cancel_appointment/<int:appointment_id>', methods=['POST'])
def cancel_appointment(appointment_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify that this patient owns the appointment
        if appointment.patient_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        
        # Only allow cancellation of pending appointments
        if appointment.status != 'pending':
            return jsonify({'success': False, 'message': 'Can only cancel pending appointments'}), 400
        
        db.session.delete(appointment)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

def init_db():
    with app.app_context():
        # Create all tables
        db.drop_all()
        db.create_all()
        
        # Create a test admin user if not exists
        admin = User.query.filter_by(email='admin@test.com').first()
        if not admin:
            admin = User(
                email='admin@test.com',
                password_hash=generate_password_hash('admin123'),
                name='Admin User',
                user_type='hospital_admin',
                phone='1234567890'
            )
            db.session.add(admin)
            
            # Create a test patient user
            patient = User(
                email='patient@test.com',
                password_hash=generate_password_hash('patient123'),
                name='Test Patient',
                user_type='patient',
                phone='9876543210'
            )
            db.session.add(patient)
            
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True)
