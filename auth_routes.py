from flask import render_template, request, redirect, url_for, flash, session, current_app
import bcrypt
import pyotp
import os
import qrcode
import logging
from flask_mail import Mail
from utils import validate_password
import userManagement as dbHandler
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

app_log = logging.getLogger(__name__)

# Flask-Mail configuration for Gmail
mail = Mail()

def init_mail(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'pixelpigeon82@gmail.com'  
    app.config['MAIL_PASSWORD'] = 'PigeonPasswordEats'  
    mail.init_app(app)

def register_auth_routes(app):

    class LoginForm(FlaskForm):
        email = StringField('Email', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Login')

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        """Handle user signup."""
        if request.method == "GET":
            return render_template("signup.html")
        if request.method == "POST":
            email = request.form["email"]
            username = request.form["username"]
            password = request.form["password"]
            role = request.form["role"]
            
            existing_user = dbHandler.get_user_by_email(email)
            if existing_user:
                flash("This email is already associated with an account. Please log in instead.")
                return render_template("signup.html", error="This email is already associated with an account. Please log in instead.")
            
            # Check if the username already exists
            existing_user_by_username = dbHandler.get_user(username)
            if existing_user_by_username:
                flash("This username is already taken. Please choose a different username.")
                return render_template("signup.html", error="This username is already taken. Please choose a different username.")

            validation_result = validate_password(password)
            if validation_result != "Password is valid.":
                return render_template("signup.html", error=validation_result)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            totp_secret = pyotp.random_base32()
            dbHandler.add_user(email, username, hashed_password.decode('utf-8'), role, totp_secret)

            qr_code_dir = os.path.join(current_app.static_folder, 'qr_codes')
            if not os.path.exists(qr_code_dir):
                os.makedirs(qr_code_dir)

            totp = pyotp.TOTP(totp_secret)
            qr_code_path = os.path.join(qr_code_dir, f"{username}.png")
            qr_code = qrcode.make(totp.provisioning_uri(username, issuer_name="MyApp"))
            qr_code.save(qr_code_path)

            flash("Signup successful! Scan the QR code with your authenticator app.")
            return render_template("signup_success.html", username=username)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Handle user login."""
        form = LoginForm()
        if form.validate_on_submit():
            username_or_email = form.email.data
            password = form.password.data
            if "@" in username_or_email:
                user = dbHandler.get_user_by_email(username_or_email)
            else:
                user = dbHandler.get_user(username_or_email)
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
                session['username'] = user['username']
                session['email'] = user['email']
                session['role'] = user['role']
                log_user_login(user['username'])  
                flash("Enter your 2FA code.")
                return redirect(url_for('verify_2fa'))
            else:
                flash("Invalid username/email or password")
                return render_template("login.html", form=form, error="Invalid username/email or password")
        return render_template("login.html", form=form)

    @app.route("/verify_2fa", methods=["GET", "POST"])
    def verify_2fa():
        """Handle 2FA verification."""
        if request.method == "GET":
            return render_template("verify_2fa.html")
        if request.method == "POST":
            code = request.form["code"]
            username = session.get('username')
            user = dbHandler.get_user(username)
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(code):
                session.permanent = True
                session['username'] = user['username']
                session['email'] = user['email']
                session['role'] = user['role']
                flash("Login successful!")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid 2FA code")
                return render_template("verify_2fa.html", error="Invalid 2FA code")

    @app.route("/logout")
    def logout():
        """Handle user logout."""
        session.pop('username', None)
        session.pop('email', None)
        session.pop('role', None)
        flash("You have been logged out.")
        return redirect(url_for('login'))

    def log_user_login(username):
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logins (username) VALUES (?)", (username,))
        conn.commit()
        conn.close()