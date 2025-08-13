from flask import Flask, request, render_template, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import sqlite3

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # In production, use a strong random key

# Define forms with CSRF protection
class ProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Update Email')

class PasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Update Password')

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT,
        password TEXT
    )''')
    cursor.execute("INSERT OR IGNORE INTO users (username, email, password) VALUES ('admin', 'admin@example.com', 'secret')")
    cursor.execute("INSERT OR IGNORE INTO users (username, email, password) VALUES ('user1', 'user1@example.com', 'pass123')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    form = ProfileForm()  # Create form with CSRF token
    if form.validate_on_submit():  # Checks if CSRF token is valid
        email = form.email.data
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET email=? WHERE username=?", (email, session['username']))
        conn.commit()
        conn.close()
        return render_template('profile.html', message='Email updated successfully', email=email, form=form)

    # GET request: show current email
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE username=?", (session['username'],))
    email = cursor.fetchone()[0]
    conn.close()
    return render_template('profile.html', email=email, form=form)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    form = PasswordForm()  # Form with CSRF token
    if form.validate_on_submit():  # Validates CSRF token
        new_password = form.new_password.data
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE username=?", (new_password, session['username']))
        conn.commit()
        conn.close()
        return render_template('change_password.html', message='Password updated successfully', form=form)

    return render_template('change_password.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=3000)