from flask import Flask, request, render_template, session, redirect, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key in production


def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (username TEXT PRIMARY KEY, email TEXT, password TEXT)''')
    cursor.execute('''INSERT OR IGNORE INTO users (username, email, password)
                      VALUES ('admin', 'admin@example.com', 'secret')''')
    cursor.execute('''INSERT OR IGNORE INTO users (username, email, password)
                      VALUES ('user1', 'user1@example.com', 'pass123')''')
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
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
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

    if request.method == 'POST':
        email = request.form.get('email')
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # Vulnerable to CSRF: No token validation
        cursor.execute('UPDATE users SET email = ? WHERE username = ?', (email, session['username']))
        conn.commit()
        conn.close()
        return render_template('profile.html', message='Email updated successfully', email=email)

    # GET request: Load current email
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE username = ?', (session['username'],))
    email = cursor.fetchone()[0]
    conn.close()
    return render_template('profile.html', email=email)


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # Vulnerable to CSRF: No token validation
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, session['username']))
        conn.commit()
        conn.close()
        return render_template('change_password.html', message='Password updated successfully')

    return render_template('change_password.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=3000)