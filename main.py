
import logging
import re
from datetime import timedelta
import os

from flask import Flask, redirect, render_template, request, flash, session, url_for
import bcrypt
import pyotp
import qrcode
import userManagement as dbHandler

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

def validate_password(password: str) -> str:
    """Validate the strength of the password."""
    if len(password) < 8 or len(password) > 12:
        return "Password must be between 8 and 12 characters."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return "Password must contain at least one special character."
    return "Password is valid."

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

        validation_result = validate_password(password)
        if validation_result != "Password is valid.":
            return render_template("signup.html", error=validation_result)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        totp_secret = pyotp.random_base32()
        dbHandler.add_user(email, username, hashed_password.decode('utf-8'), role, totp_secret)

        qr_code_dir = os.path.join(app.static_folder, 'qr_codes')
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
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        username_or_email = request.form["username_or_email"]
        password = request.form["password"]   
        if "@" in username_or_email:
            user = dbHandler.get_user_by_email(username_or_email)
        else:
            user = dbHandler.get_user(username_or_email)
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            session['username'] = user['username']
            flash("Enter your 2FA code.")
            return redirect(url_for('verify_2fa'))
        else:
            flash("Invalid username/email or password")
            return render_template("login.html", error="Invalid username/email or password")

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
            app_log.debug("2FA verified for user: %s", user['username'])
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid 2FA code")
            return render_template("verify_2fa.html", error="Invalid 2FA code")

@app.route("/dashboard")
def dashboard():
    """Render the user dashboard."""
    if 'username' in session:
        app_log.debug("Session active for user: %s", session['username'])
        return render_template("dashboard.html", username=session['username'], email=session['email'], role=session['role'])
    else:
        app_log.debug("Session expired or not found.")
        flash("You need to log in first.")
        return redirect(url_for('login'))

@app.route("/logout")
def logout():
    """Handle user logout."""
    session.pop('username', None)
    session.pop('email', None)
    session.pop('role', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route("/index.html", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
def home():
    """Render the home page."""
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = dbHandler.get_user(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            flash("Login successful!")
            return render_template("/success.html", value=username, state=True)
        else:
            flash("Invalid username or password")
            return render_template("/index.html")

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)