import sqlite3
from datetime import datetime

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
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4], "totp_secret": user[5], "is_verified": user[6]}
    return None

def get_user_by_email(email):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4], "totp_secret": user[5], "is_verified": user[6]}
    return None

def add_user(email, username, password, role, totp_secret):
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, username, password, role, totp_secret, is_verified) VALUES (?, ?, ?, ?, ?, ?)",
            (email, username, password, role, totp_secret, False)
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
    cursor.execute("SELECT id, date, developer_name, project, content, code_snippet, last_edited FROM logs ORDER BY date DESC LIMIT 10")
    logs = cursor.fetchall()
    conn.close()
    
    # Truncate content and code_snippet
    truncated_logs = []
    for log in logs:
        truncated_content = log[4][:100] + '...' if len(log[4]) > 100 else log[4]
        truncated_code_snippet = log[5][:100] + '...' if len(log[5]) > 100 else log[5]
        
        truncated_logs.append({
            "id": log[0],
            "date": log[1],
            "developer_name": log[2],
            "project": log[3],
            "content": log[4],
            "code_snippet": log[5],
            "last_edited": log[6],
            "truncated_content": truncated_content,
            "truncated_code_snippet": truncated_code_snippet
        })
    
    return truncated_logs

def search_logs(developer=None, date=None, project=None, sort_by='date', sort_order='asc'):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    query = "SELECT id, date, developer_name, project, content, code_snippet, last_edited FROM logs WHERE 1=1"
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
    return [{"id": log[0], "date": log[1], "developer_name": log[2], "project": log[3], "content": log[4], "code_snippet": log[5], "last_edited": log[6]} for log in logs]

def get_logs_paginated(page, per_page):
    """Fetch logs with pagination and truncated content."""
    offset = (page - 1) * per_page
    query = "SELECT id, date, developer_name, project, content, code_snippet, last_edited FROM logs ORDER BY date DESC LIMIT ? OFFSET ?"
    logs = execute_query(query, (per_page, offset))
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            "id": log[0],
            "date": log[1],
            "developer_name": log[2],
            "project": log[3],
            "content": log[4],
            "code_snippet": log[5],
            "last_edited": log[6],
            "truncated_content": truncate_content(log[4], 150),
            "truncated_code_snippet": truncate_content(log[5], 80)
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

def get_log_by_id(log_id):
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    log = cursor.fetchone()
    conn.close()
    if log:
        return {
            "id": log[0],
            "date": log[1],
            "developer_name": log[2],
            "project": log[3],
            "content": log[4],
            "code_snippet": log[5],
            "is_approved": log[6],
            "is_archived": log[7],
            "last_edited": log[8]
        }
    return None

def update_log(log_id, project, content, code_snippet):
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE logs SET project = ?, content = ?, code_snippet = ?, last_edited = ? WHERE id = ?",
            (project, content, code_snippet, datetime.now(), log_id)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def delete_log(log_id):
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def is_log_editable(log_id, username):
    log = get_log_by_id(log_id)
    if log and log['developer_name'] == username and not log['is_approved'] and not log['is_archived']:
        return True
    return False

def is_log_deletable(log_id, username):
    log = get_log_by_id(log_id)
    if log and log['developer_name'] == username and not log['is_approved'] and not log['is_archived']:
        return True
    return False