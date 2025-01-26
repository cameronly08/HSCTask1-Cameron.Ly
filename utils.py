import re

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


def basic_sanitize_input(user_input):
    # Remove any script tags
    sanitized_input = re.sub(r'<script.*?>.*?</script>', '', user_input, flags=re.IGNORECASE)
    # Escape special characters
    sanitized_input = sanitized_input.replace('&', '&amp;')
    sanitized_input = sanitized_input.replace('<', '&lt;')
    sanitized_input = sanitized_input.replace('>', '&gt;')
    sanitized_input = sanitized_input.replace('"', '&quot;')
    sanitized_input = sanitized_input.replace("'", '&#x27;')
    sanitized_input = sanitized_input.replace("/", '&#x2F;')
    return sanitized_input


def validate_email(email):
    """
    Validates the format of an email address using a regular expression.
    Returns True if the email is valid, False otherwise.
    """
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def validate_username(username):
    """
    Validates the format of a username.
    A valid username contains only letters, numbers, and underscores, and is 3-30 characters long.
    Returns True if the username is valid, False otherwise.
    """
    username_regex = r'^[a-zA-Z0-9_]{3,30}$'
    return bool(re.match(username_regex, username))
