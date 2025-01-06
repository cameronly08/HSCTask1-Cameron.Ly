import sqlite3

class DatabaseError(Exception):
    pass

def get_user(username):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4], "totp_secret": user[5]}
    return None

def get_user_by_email(email):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4], "totp_secret": user[5]}
    return None

def add_user(email, username, password, role, totp_secret):
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, username, password, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
            (email, username, password, role, totp_secret)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def set_totp_secret(username, secret):
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e