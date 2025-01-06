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
    

def add_log(date, developer_name, project, content, code_snippet):
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (date, developer_name, project, content, code_snippet) VALUES (?, ?, ?, ?, ?)",
            (date, developer_name, project, content, code_snippet)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e
    
def get_recent_logs():
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT date, developer_name, project, content, code_snippet FROM logs ORDER BY date DESC LIMIT 10")
    logs = cursor.fetchall()
    conn.close()
    return [{"date": log[0], "developer_name": log[1], "project": log[2], "content": log[3], "code_snippet": log[4]} for log in logs]