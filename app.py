from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
import bcrypt
import psycopg2
import re

# Create a Flask app instance
app = Flask(__name__)

# Set a secret key to secure the session
app.secret_key = 'my_super_secret_key'  # Replace with your actual secret key

# Use Flask-Session to handle the session (note: this is a client-side session, not recommended for production)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Create the PostgreSQL database connection
def get_db_connection():
    return psycopg2.connect(
        host='localhost',
        database='secure_file_system',
        user='ruegen',
        password='ruegen'
    )

# Create the users table if it doesn't exist
def create_users_table():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

# Step 1: Set up the PostgreSQL database
create_users_table()

# Function to check password complexity requirements
def is_password_complex(password):
    # Require at least 8 characters, with at least one uppercase letter, one lowercase letter, and one digit
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$', password))

# Step 2: API route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve the user's input from the registration form
        username = request.form['username']
        password = request.form['password']

        # Validate the input (e.g., check if the username is unique, enforce password complexity)
        if not username or not password:
            error = 'Please provide both username and password.'
            return render_template('register.html', error=error)

        # Check if the username is unique (not already taken)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
            user_count = cursor.fetchone()[0]

            if user_count > 0:
                error = 'Username already taken. Please choose a different username.'
                return render_template('register.html', error=error)

        # Check password complexity requirements
        if not is_password_complex(password):
            error = 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit.'
            return render_template('register.html', error=error)

        # Hash the password using bcrypt before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Store the user's information (username and hashed password) in the PostgreSQL database
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
                conn.commit()

            # Redirect to the login page after successful registration
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            # Handle any errors that may occur during database operation
            error = 'An error occurred during registration. Please try again later.'
            return render_template('register.html', error=error)

    return render_template('register.html')

# Step 3: API route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve the user's input from the login form
        username = request.form['username']
        password = request.form['password']

        # Verify the login credentials against the stored data in the database
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username, password FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()

                if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                    # Successful login, create a session for the user
                    session['username'] = user[0]
                    return redirect(url_for('index'))
                else:
                    # Invalid login, show an error message on the login page
                    error = 'Invalid credentials. Please try again.'
                    return render_template('login.html', error=error)
        except psycopg2.Error as e:
            # Handle any errors that may occur during database operation
            error = 'An error occurred during login. Please try again later.'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Step 4: API route for user logout
@app.route('/logout')
def logout():
    # Clear the user's session to log them out
    session.clear()
    return redirect(url_for('login'))

# Step 5: Route for the homepage
@app.route('/')
def index():
    # Check if the user is logged in using the session data
    if 'username' in session:
        username = session['username']
        return render_template('index.html', username=username)
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
