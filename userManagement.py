import sqlite3

def add_user(email, username, hashed_password, role):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)", (email, username, hashed_password, role))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4]}
    return None