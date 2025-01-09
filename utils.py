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