import logging
from datetime import timedelta
from flask import Flask
from flask_mail import Mail
import auth_routes
import main_routes

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

# Initialize Flask-Mail
mail = Mail()
auth_routes.init_mail(app)

# Register routes
auth_routes.register_auth_routes(app)
main_routes.register_main_routes(app)

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)