from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import bcrypt
from models.user_model import UserModel
from models.file_model import FileModel
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import pyotp
import qrcode
import qrcode.image.svg
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from config import Config  

# Initialize Flask app
app = Flask(__name__)

# Load configuration from Config class
app.config.from_object(Config)

# Initialize MySQL and Models
mysql = MySQL(app)
user_model = UserModel(mysql)
file_model = FileModel(mysql)

# Load the encryption key for file encryption
key = app.config['ENCRYPTION_KEY'].encode()
cipher_suite = Fernet(key)

# Logging Configuration
LOG_FILE_PATH = app.config.get('LOG_FILE_PATH', './logs/activity.log')
if not os.path.exists(os.path.dirname(LOG_FILE_PATH)):
    os.makedirs(os.path.dirname(LOG_FILE_PATH))

logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=100000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

@app.route('/')
def index():
    return redirect(url_for('login'))

# User registration with error handling
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Generate a TOTP secret for 2FA
            otp_secret = pyotp.random_base32()

            # Store user data, including the OTP secret
            user_model.create_user(username, email, hashed_password, otp_secret)

            flash('You have successfully registered! Please set up 2FA.')
            app.logger.info(f"New user registered: {email} at {datetime.now()}")
            return redirect(url_for('setup_2fa', username=username, otp_secret=otp_secret))
        except Exception as e:
            app.logger.error(f"Error during registration: {e}")
            flash('An error occurred during registration. Please try again later.')
            return redirect(url_for('register'))

    return render_template('register.html')

# User login with error handling
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            otp_code = request.form['otp_code']

            user = user_model.get_user_by_email(email)

            if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                # Check the OTP code
                otp_secret = user[4]  # Assuming the OTP secret is stored at index 4
                totp = pyotp.TOTP(otp_secret)

                if totp.verify(otp_code):
                    session['loggedin'] = True
                    session['id'] = user[0]  # Store the user ID in the session
                    session['username'] = user[1]
                    flash('Login successful!', 'success')
                    app.logger.info(f"User {email} successfully logged in at {datetime.now()}")
                    return redirect(url_for('dashboard'))
                else:
                    app.logger.warning(f"Failed 2FA attempt for {email} at {datetime.now()}")
                    flash('Invalid 2FA code! Please try again.', 'error')
            else:
                app.logger.warning(f"Failed login attempt for {email} at {datetime.now()}")
                flash('Incorrect email or password. Please try again.', 'error')

        except Exception as e:
            app.logger.error(f"Error during login: {e}")
            flash('An error occurred during login. Please try again later.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard with error handling
@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        try:
            user_files = file_model.get_files_by_user(session['id'])  # Ensure session['id'] is set
            app.logger.info(f"User {session['username']} accessed dashboard at {datetime.now()}")
            return render_template('dashboard.html', username=session['username'], files=user_files)
        except Exception as e:
            app.logger.error(f"Error accessing dashboard: {e}")
            flash('An error occurred while loading the dashboard. Please try again later.')
            return redirect(url_for('login'))
    return redirect(url_for('login'))

# File upload with error handling
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'loggedin' in session and request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('dashboard'))

            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('dashboard'))

            if file:
                filename = secure_filename(file.filename)
                file_data = file.read()

                # Encrypt the file
                encrypted_data = cipher_suite.encrypt(file_data)
                file_path = os.path.join('uploads', filename)

                # Save the encrypted file
                with open(file_path, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_data)

                # Save file metadata in the database
                file_model.upload_file(filename, file_path, session['id'])
                flash('File uploaded and encrypted successfully!')
                app.logger.info(f"User {session['username']} uploaded file {filename} at {datetime.now()}")
                return redirect(url_for('dashboard'))
        except Exception as e:
            app.logger.error(f"Error uploading file: {e}")
            flash('An error occurred while uploading the file. Please try again later.')
            return redirect(url_for('dashboard'))
    return render_template('upload.html')

# User logout
@app.route('/logout')
def logout():
    try:
        username = session.get('username', 'Unknown user')
        session.clear()
        app.logger.info(f"User {username} logged out at {datetime.now()}")
    except Exception as e:
        app.logger.error(f"Error during logout: {e}")
    return redirect(url_for('login'))

# 2FA setup with error handling
@app.route('/setup_2fa/<username>/<otp_secret>', methods=['GET', 'POST'])
def setup_2fa(username, otp_secret):
    try:
        totp = pyotp.TOTP(otp_secret)

        if request.method == 'POST':
            otp_code = request.form['otp_code']
            if totp.verify(otp_code):
                flash('2FA setup complete! You are now logged in.')
                session['loggedin'] = True
                session['username'] = username
                app.logger.info(f"User {username} successfully set up 2FA at {datetime.now()}")
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid 2FA code. Please try again.', 'error')
                app.logger.warning(f"Failed 2FA setup attempt for {username} at {datetime.now()}")
                return render_template('setup_2fa.html', username=username, otp_secret=otp_secret)

        qr_code_dir = os.path.join('static', 'qr_codes')
        if not os.path.exists(qr_code_dir):
            os.makedirs(qr_code_dir)

        img_path = f'static/qr_codes/{username}_2fa.svg'
        if not os.path.exists(img_path):
            img = qrcode.make(totp.provisioning_uri(username, issuer_name="SecureFileStorage"), image_factory=qrcode.image.svg.SvgImage)
            img.save(img_path)

        return render_template('setup_2fa.html', username=username, otp_secret=otp_secret, qr_code=img_path)
    except Exception as e:
        app.logger.error(f"Error during 2FA setup: {e}")
        flash('An error occurred during 2FA setup. Please try again later.')
        return redirect(url_for('login'))

# 2FA verification with error handling
@app.route('/verify_2fa/<username>', methods=['POST'])
def verify_2fa(username):
    try:
        user = user_model.get_user_by_username(username)

        if user is None:
            flash('User not found.', 'error')
            return redirect(url_for('login'))

        otp_secret = user[4]  # Assuming the OTP secret is at index 4 in the user tuple
        totp = pyotp.TOTP(otp_secret)
        otp_code = request.form['otp_code']

        if totp.verify(otp_code):
            flash('2FA setup complete! You are now logged in.', 'success')
            session['loggedin'] = True
            session['id'] = user[0]  # Set the user ID in session after successful verification
            session['username'] = username
            app.logger.info(f"User {username} successfully verified 2FA at {datetime.now()}")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code. Please try again.', 'error')
            app.logger.warning(f"Failed 2FA verification attempt for {username} at {datetime.now()}")
            return render_template('setup_2fa.html', username=username, otp_secret=otp_secret, qr_code=f'static/qr_codes/{username}_2fa.svg')
    except Exception as e:
        app.logger.error(f"Error during 2FA verification: {e}")
        flash('An error occurred during 2FA verification. Please try again later.')
        return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)