from flask import Flask, redirect, render_template, request, flash
import userManagement as dbHandler
import bcrypt
import logging
import re

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"

def validate_password(password: str) -> str:
    if len(password) < 8 or len(password) > 12:
        return "Password must be between 8 and 12 characters."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character."
    return "Password is valid."

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        
        # Validate the password
        validation_result = validate_password(password)
        if validation_result != "Password is valid.":
            return render_template("signup.html", error=validation_result)
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            dbHandler.add_user(email, username, hashed_password.decode('utf-8'), role)
            flash("Signup successful!")
        except Exception as e:
            app_log.error(f"Error inserting user: {e}")
            return render_template("signup.html", error="Error inserting user")
        
        return redirect("/index.html")

@app.route("/index.html", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
def home():
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