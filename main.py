import logging
from datetime import timedelta
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import auth_routes
import main_routes
import api_routes

# Configure logging
app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s",
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure Flask-Mail
mail = Mail()
auth_routes.init_mail(app)

# Register authentication and main routes
auth_routes.register_auth_routes(app)
main_routes.register_main_routes(app)

# Register API routes for data sharing
api_routes.api.init_app(app)

# Initialize rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Set Content Security Policy (CSP) headers
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net; "
        "style-src 'self' https://stackpath.bootstrapcdn.com; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response

if __name__ == '__main__':
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)