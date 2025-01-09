import sqlite3

class DatabaseError(Exception):
    pass

def execute_query(query, params=None):
    """Execute a query and return the results."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        results = cursor.fetchall()
        conn.commit()
        return results
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e
    finally:
        if conn:
            cursor.close()
            conn.close()

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
    
    # Truncate content and code_snippet
    truncated_logs = []
    for log in logs:
        truncated_content = log[3][:100] + '...' if len(log[3]) > 100 else log[3]
        truncated_code_snippet = log[4][:100] + '...' if len(log[4]) > 100 else log[4]
        
        truncated_logs.append({
            "date": log[0],
            "developer_name": log[1],
            "project": log[2],
            "content": log[3],
            "code_snippet": log[4],
            "truncated_content": truncated_content,
            "truncated_code_snippet": truncated_code_snippet
        })
    
    return truncated_logs

def search_logs(developer=None, date=None, project=None, sort_by='date', sort_order='asc'):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    query = "SELECT date, developer_name, project, content, code_snippet FROM logs WHERE 1=1"
    params = []
    if developer:
        query += " AND developer_name LIKE ?"
        params.append(f"%{developer}%")
    if date:
        query += " AND date LIKE ?"
        params.append(f"%{date}%")
    if project:
        query += " AND project LIKE ?"
        params.append(f"%{project}%")
    query += f" ORDER BY {sort_by} {sort_order.upper()}"
    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()
    return [{"date": log[0], "developer_name": log[1], "project": log[2], "content": log[3], "code_snippet": log[4]} for log in logs]

def get_logs_paginated(page, per_page):
    """Fetch logs with pagination and truncated content."""
    offset = (page - 1) * per_page
    query = "SELECT date, developer_name, project, content, code_snippet FROM logs ORDER BY date DESC LIMIT ? OFFSET ?"
    logs = execute_query(query, (per_page, offset))
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            "date": log[0],
            "developer_name": log[1],
            "project": log[2],
            "content": log[3],
            "code_snippet": log[4],
            "truncated_content": truncate_content(log[3], 150),
            "truncated_code_snippet": truncate_content(log[4], 80)
        })
    return formatted_logs

def get_total_logs_count():
    """Fetch the total number of logs."""
    query = "SELECT COUNT(*) FROM logs"
    result = execute_query(query)
    return result[0][0]  # Direct count value

def truncate_content(content, length=100):
    """Truncate content to a specific length with '...'."""
    if len(content) > length:
        return content[:length] + "..."
    return content