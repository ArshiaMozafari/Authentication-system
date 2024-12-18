import bcrypt
import pyotp
import smtplib
from smtplib import SMTPException
from dotenv import load_dotenv
import os
import sqlite3

# Load environment variables
load_dotenv()

# Connect to SQLite database
conn = sqlite3.connect(os.environ.get('MY_DB'))
cursor = conn.cursor()

# Create users table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    login2FAstatus INTEGER NOT NULL,
    totp_secret TEXT
)
''')
conn.commit()

# Define the User class
class User:
    def __init__(self, username, password, email, login2FAstatus, totp_secret=None):
        self.username = username
        self.password = password
        self.email = email
        self.login2FAstatus = login2FAstatus
        self.totp_secret = totp_secret or pyotp.random_base32()

    def save_to_db(self):
        cursor.execute('''
        INSERT INTO users (username, password, email, login2FAstatus, totp_secret)
        VALUES (?, ?, ?, ?, ?)
        ''', (self.username, self.password, self.email, self.login2FAstatus, self.totp_secret))
        conn.commit()

    @staticmethod
    def get_user(username):
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return User(*row)
        return None

    @staticmethod
    def delete_user(username):
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()

    def update_password(self, new_password):
        self.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
        UPDATE users SET password = ? WHERE username = ?
        ''', (self.password, self.username))
        conn.commit()

# Define the EmailSender class
class EmailSender:
    def __init__(self, email, subject, message):
        self.sender = os.environ.get("EMAIL")
        self.email_password = os.environ.get("PASSWORD")
        self.email = email
        self.subject = subject
        self.message = message

    def send_email(self):
        text = f"Subject: {self.subject}\n{self.message}"
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(self.sender, self.email_password)
            server.sendmail(self.sender, self.email, text)
            server.quit()
        except SMTPException as e:
            print(f"Email wasn't sent. Connection error or invalid email address:\n{e}")

# Function for user sign-up
def sign_up():
    while True:
        username = input("Enter your username: ")
        if User.get_user(username):
            print("The username is already taken, please enter another")
        else:
            break

    while True:
        password = input("Enter your password: ")
        if check_password_strength(password):
            break
        else:
            print("Your password isn't strong enough, make sure your password matches these criteria:\n1) Uppercase\n2) Lowercase\n3) Digits\n4) Special characters")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    email = input("Enter your email: ")
    login2FAstatus = input("Please select your two-factor authentication status\n1. ON\n2. OFF\nEnter your choice: ")
    login2FAstatus = login2FAstatus == "1"

    if login2FAstatus:
        totp_secret = pyotp.random_base32()
        if _2FA(email, totp_secret):
            user = User(username, hashed_password, email, login2FAstatus, totp_secret)
            user.save_to_db()
            subject = "Sign-up successful!"
            message = f"Dear {username},\nYour account was created successfully."
        else:
            subject = "Sign-up failed!"
            message = "Email verification was unsuccessful."
    else:
        user = User(username, hashed_password, email, login2FAstatus)
        user.save_to_db()
        subject = "Sign-up successful!"
        message = f"Dear {username},\nYour account was created successfully."

    print(subject)
    send_email = EmailSender(email, subject, message)
    send_email.send_email()

# Function for user log-in
def log_in():
    username = input("Enter your username: ")
    user = User.get_user(username)
    if not user:
        print("Username doesn't exist")
        return

    password = input("Enter your password: ")

    hashed_password = user.password
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        if user.login2FAstatus and _2FA(user.email, user.totp_secret):
            subject = "New log-in"
            message = f"Dear {user.username},\nA new log-in to your account was recognized."
            print("Do you want to change password?")
            response = input("1. Yes\n2. No\nEnter your choice: ")
            if response == "1":
                password_reset(username)
        else:
            subject = "New log-in"
            message = f"Dear {user.username},\nA new log-in to your account was recognized."
        print(subject)
        send_email = EmailSender(user.email, subject, message)
        send_email.send_email()
    else:
        print("The password is wrong")

# Function for deleting a user
def del_user():
    username = input("Enter your username: ")
    user = User.get_user(username)
    if not user:
        print("Username doesn't exist")
        return

    password = input("Enter your password: ")

    if bcrypt.checkpw(password.encode('utf-8'), user.password):
        if user.login2FAstatus and _2FA(user.email, user.totp_secret):
            print("Your account will be deleted. Are you sure?")
            while True:
                response = input("1. Yes\n2. No\nEnter your choice: ")
                if response == "1":
                    User.delete_user(username)
                    print("Account deleted")
                    return
                elif response == "2":
                    return
                else:
                    print("Invalid input")
        else:
            print("Authentication failed")
    else:
        print("Wrong password")

# Function to check password strength
def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 8
    if any(char.isupper() for char in password):
        score += 4
    if any(char.islower() for char in password):
        score += 3
    if any(char.isdigit() for char in password):
        score += 4
    special_characters = set('!@#$%^&*()_+-=[]{};:\'"|,.<>/?')
    if any(char in special_characters for char in password):
        score += 6

    return score >= 18

# Function for password reset
def password_reset(username=None):
    if not username:
        username = input("Enter your username: ")
    user = User.get_user(username)
    if not user:
        print("Username doesn't exist")
        return

    if user.login2FAstatus and _2FA(user.email, user.totp_secret):
        while True:
            password = input("Enter your new password: ")
            if check_password_strength(password):
                break
            else:
                print("Your password isn't strong enough, make sure your password matches these criteria:\n1) Uppercase\n2) Lowercase\n3) Digits\n4) Special characters")

        user.update_password(password)
        print("Password reset successful")
    else:
        print("Verification failed")

# Function for two-factor authentication
def _2FA(email, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    code = totp.now()
    subject = "Verification code"
    message = f"Your code is {code}\nEnter quickly before it expires"
    send_email = EmailSender(email, subject, message)
    send_email.send_email()
    print(f"{subject} has been sent to {email}.")
    user_input = input("Enter verification code: ")
    return user_input == code

# Main script

while True:
    choice = input("1. Log in\n2. Sign up\n3. Delete\n4. Reset password\n5. Exit\nEnter your choice: ")
    if choice == '1':
        log_in()
    elif choice == '2':
        sign_up()
    elif choice == '3':
        del_user()
    elif choice == '4':
        password_reset()
    elif choice == '5':
        print("Exiting...")
        break
    else:
        print("Invalid choice, please choose again.")
