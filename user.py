import bcrypt
import psycopg2
import pyotp
import re
import io
import base64
from datetime import datetime, timedelta
from flask import session, render_template, url_for, request, redirect
from database import get_db_connection
from utils import is_password_complex, generate_qr_code, generate_csrf_token

def register():
    # Check if the user is already logged in using the session data
    if 'username' in session:
        # If the user is logged in, redirect to the homepage
        return redirect(url_for('index'))

    # Retrieve the CSRF token from the session or generate a new one if it doesn't exist
    csrf_token = session.get('csrf_token')
    if not csrf_token:
        csrf_token = generate_csrf_token()
        session['csrf_token'] = csrf_token

    if request.method == 'POST':
        # Verify CSRF token to prevent CSRF attacks
        csrf_token_from_form = request.form.get('csrf_token')
        if not csrf_token_from_form or csrf_token_from_form != session.get('csrf_token'):
            return "Invalid CSRF token"

        # Retrieve the user's input from the registration form
        username = request.form['username']
        password = request.form['password']

        # Validate the input (e.g., check if the username is unique, enforce password complexity)
        if not username or not password:
            error = 'Please provide both username and password.'
            return render_template('register.html', error=error, csrf_token=csrf_token)

        # Check if the username is unique (not already taken)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
            user_count = cursor.fetchone()[0]

            if user_count > 0:
                error = 'Username already taken. Please choose a different username.'
                return render_template('register.html', error=error, csrf_token=csrf_token)

        # Check password complexity requirements
        if not is_password_complex(password):
            error = 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'
            return render_template('register.html', error=error, csrf_token=csrf_token)

        # Generate TOTP secret for the user
        totp = pyotp.TOTP(pyotp.random_base32())
        totp_secret = totp.secret

        # Hash the password using bcrypt before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Store the user's information (username, hashed password, and TOTP secret) in the PostgreSQL database
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password, totp_secret) VALUES (%s, %s, %s)', (username, hashed_password, totp_secret))
                conn.commit()

            # Create QR code containing the TOTP secret for the user
            qr_code_img, totp_uri = generate_qr_code(username, totp_secret)

            # Reset CSRF token after successful registration
            session.pop('csrf_token', None)

            # Redirect to the 2FA setup page after successful registration
            return render_template('setup_2fa.html', username=username, qr_code_img=qr_code_img, totp_uri=totp_uri)
        except psycopg2.Error as e:
            # Handle any errors that may occur during database operation
            error = 'An error occurred during registration. Please try again later.'
            return render_template('register.html', error=error, csrf_token=csrf_token)

    return render_template('register.html', csrf_token=csrf_token)

def login():
    # Check if the user is already logged in using the session data
    if 'username' in session:
        # If the user is logged in, redirect to the homepage
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Verify CSRF token to prevent CSRF attacks
        csrf_token_from_form = request.form.get('csrf_token')
        if not csrf_token_from_form or csrf_token_from_form != session.get('csrf_token'):
            return "Invalid CSRF token"

        # Retrieve the user's input from the login form
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form['totp_code']

        # Retrieve the failed login attempts count for the current IP address
        ip_address = request.remote_addr
        failed_attempts = get_failed_login_attempts(ip_address)

        # Check if the user's account is temporarily blocked due to excessive failed login attempts
        if failed_attempts >= 5:
            blocked_until = get_blocked_until(ip_address)
            if blocked_until and blocked_until > datetime.now():
                time_remaining = blocked_until - datetime.now()
                error = f'Your account is temporarily blocked due to multiple failed login attempts. Please try again after {time_remaining.seconds // 60} minutes.'
                return render_template('login.html', error=error, csrf_token=session['csrf_token'])

        # Verify the login credentials against the stored data in the database
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username, password, totp_secret FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()

                if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                    # Successful login, verify the TOTP code
                    totp_secret = user[2]
                    totp = pyotp.TOTP(totp_secret)

                    if totp.verify(totp_code):
                        # TOTP code is valid, create a session for the user
                        session['username'] = user[0]

                        # Reset failed login attempts count for the current IP address
                        reset_failed_login_attempts(ip_address)

                        # Reset CSRF token after successful login
                        session.pop('csrf_token', None)

                        return redirect(url_for('index'))
                    else:
                        # Invalid TOTP code, show an error message on the login page
                        error = 'Invalid TOTP code. Please try again.'
                        increase_failed_login_attempts(ip_address)
                        return render_template('login.html', error=error, csrf_token=session['csrf_token'])

                else:
                    # Invalid login credentials, show an error message on the login page
                    error = 'Invalid credentials. Please try again.'
                    increase_failed_login_attempts(ip_address)
                    return render_template('login.html', error=error, csrf_token=session['csrf_token'])
        except psycopg2.Error as e:
            # Handle any errors that may occur during database operation
            error = 'An error occurred during login. Please try again later.'
            return render_template('login.html', error=error, csrf_token=session['csrf_token'])

    # Generate a new CSRF token for the login form
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token

    return render_template('login.html', csrf_token=session['csrf_token'])


# API route for user logout
def logout():
    # Clear the user's session to log them out
    session.clear()
    return redirect(url_for('login'))

# Route for the homepage
def index():
    # Check if the user is logged in using the session data
    if 'username' in session:
        username = session['username']
        return render_template('index.html', username=username)
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))



from datetime import datetime, timedelta

# Function to increase the failed login attempts count for the given IP address
def increase_failed_login_attempts(ip_address):
    max_attempts = 5  # Number of allowed failed attempts before blocking
    block_duration = timedelta(minutes=5)  # Adjust the block duration as needed

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Insert or update the login_attempts table for the given IP address
        cursor.execute('INSERT INTO login_attempts (ip_address, attempts) VALUES (%s, 1) ON CONFLICT (ip_address) DO UPDATE SET attempts = login_attempts.attempts + 1', (ip_address,))

        # Get the latest attempts count for the given IP address
        cursor.execute('SELECT attempts FROM login_attempts WHERE ip_address = %s', (ip_address,))
        attempts = cursor.fetchone()[0]

        # Check if the attempts exceed the maximum allowed attempts
        if attempts >= max_attempts:
            # Set the block_until timestamp for the given IP address
            cursor.execute('UPDATE login_attempts SET blocked_until = NOW() + %s WHERE ip_address = %s', (block_duration, ip_address))
        else:
            # Reset the block_until timestamp if the attempts are below the maximum
            cursor.execute('UPDATE login_attempts SET blocked_until = NULL WHERE ip_address = %s', (ip_address,))

        conn.commit()

# Function to reset the failed login attempts count for the given IP address
def reset_failed_login_attempts(ip_address):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM login_attempts WHERE ip_address = %s', (ip_address,))
        conn.commit()

# Function to get the number of failed login attempts for the given IP address
def get_failed_login_attempts(ip_address):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT attempts FROM login_attempts WHERE ip_address = %s', (ip_address,))
        attempts = cursor.fetchone()
        if attempts:
            return attempts[0]
        return 0

# Function to get the blocked until datetime for the given IP address
def get_blocked_until(ip_address):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT blocked_until FROM login_attempts WHERE ip_address = %s', (ip_address,))
        blocked_until = cursor.fetchone()
        if blocked_until:
            return blocked_until[0]
        return None