from flask import Flask, render_template, session, redirect, url_for
from flask_session import Session
from user import register, login, logout, index

# Create a Flask app instance
app = Flask(__name__)

# Set a secret key to secure the session
app.secret_key = 'my_super_secret_key'  # Replace with your actual secret key

# Use Flask-Session to handle the session (note: this is a client-side session, not recommended for production)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Register routes from the 'user' module
app.add_url_rule('/register', view_func=register, methods=['GET', 'POST'])
app.add_url_rule('/login', view_func=login, methods=['GET', 'POST'])
app.add_url_rule('/logout', view_func=logout)
app.add_url_rule('/', view_func=index)

if __name__ == '__main__':
    app.run(debug=True)
