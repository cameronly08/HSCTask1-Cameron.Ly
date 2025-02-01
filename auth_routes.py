import os
import logging
import secrets
from datetime import datetime, timedelta
import sqlite3

import bcrypt
import pyotp
import qrcode
from flask import render_template, request, redirect, url_for, flash, session, current_app, send_file
from flask_mail import Mail, Message
from flask_wtf.csrf import validate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse, urljoin
from io import BytesIO
from utils import validate_password, basic_sanitize_input, validate_email, validate_username
import userManagement as dbHandler

app_log = logging.getLogger(__name__)

# Flask-Mail configuration for Gmail
mail = Mail()

def init_mail(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'pixelpigeon82@gmail.com'
    app.config['MAIL_PASSWORD'] = 'nofj qhxx tmkt kqlw'
    mail.init_app(app)

SAFE_DIRECT_URLS = [
    "/login",
    "/signup",
    "/forgot_password",
    "/reset_password",
    "/verify_2fa"
    "/dashboard",
    "/create_log",
    "/edit_log",
    "/update_profile"
]

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def get_safe_redirect(target):
    if is_safe_url(target) and target in SAFE_DIRECT_URLS:
        return target
    return url_for('home_logged_in')
    
def register_auth_routes(app):
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100 per day", "10 per hour"]
    )

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        """Handle user signup."""
        if request.method == "GET":
            return render_template("signup.html")
        if request.method == "POST":
            try:
                validate_csrf(request.form['csrf_token'])
            except ValueError:
                flash("CSRF token is missing or invalid.")
                return render_template("signup.html", error="CSRF token is missing or invalid.")

            email = basic_sanitize_input(request.form["email"])
            username = basic_sanitize_input(request.form["username"])
            password = request.form["password"]
            role = basic_sanitize_input(request.form["role"])

            # Validate inputs
            if not validate_email(email):
                flash("Invalid email format.")
                return render_template("signup.html", error="Invalid email format.")

            if not validate_username(username):
                flash("Invalid username format. Use only letters, numbers, and underscores.")
                return render_template("signup.html", error="Invalid username format.")

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
    @limiter.limit("5 per minute")
    def login():
        """Handle user login."""
        if request.method == "POST":
            try:
                validate_csrf(request.form['csrf_token'])
            except ValueError:
                flash("CSRF token is missing or invalid.")
                return render_template("login.html", error="CSRF token is missing or invalid.")

            username_or_email = basic_sanitize_input(request.form["username_or_email"])
            password = request.form["password"]
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
                return render_template("login.html", error="Invalid username/email or password")
        return render_template("login.html")

    @app.route("/verify_2fa", methods=["GET", "POST"])
    def verify_2fa():
        """Handle 2FA verification."""
        if request.method == "POST":
            try:
                validate_csrf(request.form['csrf_token'])
            except ValueError:
                flash("CSRF token is missing or invalid.")
                return render_template("verify_2fa.html", error="CSRF token is missing or invalid.", hide_navbar=True)

            code = basic_sanitize_input(request.form["code"])
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
                return render_template("verify_2fa.html", error="Invalid 2FA code", hide_navbar=True)
        return render_template("verify_2fa.html", hide_navbar=True)

    @app.route("/logout")
    def logout():
        """Handle user logout."""
        session.pop('username', None)
        session.pop('email', None)
        session.pop('role', None)
        flash("You have been logged out.")
        return redirect(url_for('login'))

    @app.route("/forgot_password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = basic_sanitize_input(request.form["email"])
            try:
                if not validate_email(email):
                    flash("Invalid email format.")
                    return render_template("forgot_password.html")

                user = dbHandler.get_user_by_email(email)
                if user:
                    token = secrets.token_urlsafe(16)
                    expiration = datetime.now() + timedelta(hours=1)
                    dbHandler.store_reset_token(email, token, expiration)
                    reset_link = f'https://sturdy-carnival-qr5gr9qxr5xh9qpq.github.dev/reset_password?token={token}'
                    msg = Message('Password Reset Request', sender='your-email@gmail.com', recipients=[email])
                    msg.body = f'Click the link to reset your password: {reset_link}'
                    mail.send(msg)
                    flash("Password reset link has been sent to your email.")
                else:
                    flash("Email not found.")
            except sqlite3.Error as e:
                app_log.error("Database error during password reset request: %s", e)
                flash("A database error occurred. Please try again later.")
            except (ConnectionError, TimeoutError) as e:
                app_log.error("Network error during password reset request: %s", e)
                flash("A network error occurred. Please try again later.")
            except ValueError as e:
                app_log.error("Value error during password reset request: %s", e)
                flash("An unexpected error occurred. Please try again later.")
        return render_template("forgot_password.html")

    @app.route("/reset_password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        try:
            reset = dbHandler.get_reset_token(token)
            if not reset or datetime.now() > reset["expiration"]:
                flash("Invalid or expired token.")
                return redirect(url_for('forgot_password'))

            if request.method == "POST":
                try:
                    validate_csrf(request.form['csrf_token'])
                except ValueError:
                    flash("CSRF token is missing or invalid.")
                    return render_template("reset_password.html", token=token, error="CSRF token is missing or invalid.")

                new_password = request.form["password"]
                validation_result = validate_password(new_password)
                if validation_result != "Password is valid.":
                    flash(validation_result)
                    return render_template("reset_password.html", token=token)

                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                dbHandler.update_password(reset["email"], hashed_password)
                flash("Your password has been reset successfully.")
                return redirect(url_for('login'))
        except sqlite3.Error as e:
            app_log.error("Database error during password reset: %s", e)
            flash("A database error occurred. Please try again later.")
        except ValueError as e:
            app_log.error("Value error during password reset: %s", e)
            flash("An unexpected error occurred. Please try again later.")
        except (ConnectionError, TimeoutError) as e:
            app_log.error("Network error during password reset: %s", e)
            flash("A network error occurred. Please try again later.")

        return render_template("reset_password.html", token=token)

    def log_user_login(username):
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logins (username) VALUES (?)", (username,))
        conn.commit()
        conn.close()
    
    @app.route("/privacy")
    def privacy():
        return render_template("privacy.html")
    

    @app.route("/settings")
    def settings():
        """Render the settings page."""
        if 'username' not in session:
            flash("You must be logged in to access settings.")
            return redirect(url_for('login'))
        
        user = dbHandler.get_user(session['username'])  # Get user from DB
        if not user:
            flash("User not found.")
            return redirect(url_for('login'))

        return render_template("settings.html", user=user)

    @app.route("/download_data", methods=["GET"])
    def download_data():
        """Allow users to download their personal data."""
        if 'username' not in session:
            flash("You must be logged in to download data.")
            return redirect(url_for('login'))

        user = dbHandler.get_user(session['username'])
        if not user:
            flash("User not found.")
            return redirect(url_for('login'))

        # Fetch user logs
        logs = dbHandler.get_logs_by_user(user['username'])

        # Create a text file in memory
        output = BytesIO()
        output.write(f"Username: {user['username']}\n".encode())
        output.write(f"Email: {user['email']}\n".encode())
        output.write(f"Role: {user['role']}\n\n".encode())
        output.write("Logs:\n".encode())

        for log in logs:
            output.write(f"- {log['date']}: {log['project']} - {log['content']}\n".encode())

        output.seek(0)  # Move cursor to the start

        return send_file(output, as_attachment=True, download_name=f"{user['username']}_data.txt", mimetype="text/plain")

    @app.route("/delete_data", methods=["POST"])
    def delete_data():
        """Allow users to delete their personal data (e.g., logs, projects)."""
        if 'username' not in session:
            flash("You must be logged in to delete your data.")
            return redirect(url_for('login'))

        user = dbHandler.get_user(session['username'])
        if not user:
            flash("User not found.")
            return redirect(url_for('login'))

        # Ensure that user confirms their action
        confirm = request.form.get('confirm_delete')
        if confirm != 'YES':
            flash("You must confirm your action to delete your data.")
            return redirect(url_for('settings'))

        # Delete user data (logs, projects, etc.) but leave account intact
        try:
            dbHandler.delete_user_data(user['username']) 
            flash("Your data has been successfully deleted.")
            return redirect(url_for('settings'))
        except Exception as e:
            app_log.error(f"Error deleting user data: {e}")
            flash("An error occurred while deleting your data. Please try again.")
            return redirect(url_for('settings'))