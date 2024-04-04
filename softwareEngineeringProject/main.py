import csv
import bcrypt
# import socket

from flask import Flask, render_template, request, redirect

app = Flask(__name__)

# Define the path to the CSV file
CSV_FILE_PATH = 'users.csv'

# Define the columns in the CSV file
CSV_COLUMNS = ['username', 'password', 'email']

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login form submission
        username = request.form['username']
        password = request.form['password']

        # Search for username in the CSV file
        with open(CSV_FILE_PATH, 'r') as csv_file:
            csv_reader = csv.DictReader(csv_file, fieldnames=CSV_COLUMNS)
            for row in csv_reader:
                if row['username'] == username:
                    # Verify password using bcrypt
                    if bcrypt.checkpw(password.encode('utf-8'), row['password'].encode('utf-8')):
                        return redirect('/index')

            # Show error message if username is not found in the CSV file
            return render_template('login.html', error='Invalid username or password')

    else:
        return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle registration form submission
        username = request.form['username']
        password = request.form['password']
        confirm_password =request.form['confirm-password']
        email = request.form['email']

        # Check if username already exists in CSV file
        with open(CSV_FILE_PATH, 'r') as csv_file:
            csv_reader = csv.DictReader(csv_file, fieldnames=CSV_COLUMNS)
            for row in csv_reader:
                if row['username'] == username:
                    error = "Username already exists. Please choose a different username."
                    return render_template('registration.html', error=error)

        with open(CSV_FILE_PATH, 'r') as csv_file:
            csv_reader = csv.DictReader(csv_file, fieldnames=CSV_COLUMNS)
            for row in csv_reader:
                if row['email'] == email:
                    error = "email already exists. Please choose a different email."
                    return render_template('registration.html', error=error)

        if not len(password) >=8:
            error= "Password must be at least 8 characters."
            return render_template('registration.html', error=error)
        elif not any(char.isdigit() for char in password):
            error= "password must contain at least 1 digit."
            return render_template('registration.html', error=error)
        elif not any(char.islower() for char in password):
            error= "password must contain at least 1 lowercase character."
            return render_template('registration.html', error=error)
        elif not any(char.isupper() for char in password):
            error= "password must contain at least 1 uppercase character."
            return render_template('registration.html', error=error)
        if (confirm_password != password):
            error = "Passwords do not match."
            return render_template('registration.html', error=error)

        if(confirm_password == password):
            # Hash password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Save new user data to CSV file
            with open(CSV_FILE_PATH, 'a') as csv_file:
                csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
                csv_writer.writerow({
                    'username': username,
                    'password': hashed_password.decode('utf-8'),
                    'email': email
                })

            # Redirect to login page on successful registration
            return redirect('/index')
        else:
            return render_template('registration.html', error=error)
    else:
        return render_template('registration.html')

if __name__ == '__main__':
    # ip_address = socket.gethostbyname(socket.gethostname())
    app.run(host='0.0.0.0', port=8000, debug=True)
    