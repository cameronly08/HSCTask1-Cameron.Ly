"""
This module provides database interaction functions for the developer logging application.
"""

import sqlite3
from datetime import datetime

class DatabaseError(Exception):
    """Custom exception for database errors."""

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
    """Fetch a user by username."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4], "totp_secret": user[5], "is_verified": user[6]}
    return None

def get_user_by_email(email):
    """Fetch a user by email."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "email": user[1], "username": user[2], "password": user[3], "role": user[4], "totp_secret": user[5], "is_verified": user[6]}
    return None

def add_user(email, username, password, role, totp_secret):
    """Add a new user to the database."""
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
    """Set the TOTP secret for a user."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def add_log(date, developer_name, project, content, code_snippet, repository_link=None):
    """Add a new log entry."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (date, developer_name, project, content, code_snippet, repository_link) VALUES (?, ?, ?, ?, ?, ?)",
            (date, developer_name, project, content, code_snippet, repository_link)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def get_recent_logs(username):
    """Fetch recent logs for a user."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, developer_name, project, content, code_snippet, last_edited, repository_link FROM logs WHERE developer_name = ? ORDER BY date DESC LIMIT 10", (username,))
    logs = cursor.fetchall()
    conn.close()
    
    truncated_logs = []
    for log in logs:
        truncated_content = log[4][:100] + '...' if len(log[4]) > 100 else log[4]
        truncated_code_snippet = log[5][:100] + '...' if len(log[5]) > 100 else log[5]
        
        truncated_logs.append({
            "id": log[0],
            "date": log[1],
            "developer_name": log[2],
            "project": log[3],
            "content": truncated_content,
            "code_snippet": truncated_code_snippet,
            "last_edited": log[6],
            "repository_link": log[7]
        })
    
    return truncated_logs

def search_logs(developer=None, date=None, project=None, sort_by='date', sort_order='asc'):
    """Search logs based on various criteria."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    query = "SELECT id, date, developer_name, project, content, code_snippet, last_edited, repository_link FROM logs WHERE 1=1"
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
    return [{"id": log[0], "date": log[1], "developer_name": log[2], "project": log[3], "content": log[4], "code_snippet": log[5], "last_edited": log[6], "repository_link": log[7]} for log in logs]

def get_logs_paginated(page, per_page):
    """Fetch logs with pagination and truncated content."""
    offset = (page - 1) * per_page
    query = "SELECT id, date, developer_name, project, content, code_snippet, last_edited, repository_link FROM logs ORDER BY date DESC LIMIT ? OFFSET ?"
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
            "repository_link": log[7],
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
    """Fetch a log by its ID."""
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
            "last_edited": log[8],
            "repository_link": log[9]
        }
    return None

def update_log(log_id, project, content, code_snippet, repository_link=None):
    """Update a log entry."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE logs SET project = ?, content = ?, code_snippet = ?, repository_link = ?, last_edited = ? WHERE id = ?",
            (project, content, code_snippet, repository_link, datetime.now(), log_id)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def delete_log(log_id):
    """Delete a log entry."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def is_log_editable(log_id, username):
    """Check if a log is editable by a user."""
    log = get_log_by_id(log_id)
    if log and log['developer_name'] == username and not log['is_approved'] and not log['is_archived']:
        return True
    return False

def is_log_deletable(log_id, username):
    """Check if a log is deletable by a user."""
    log = get_log_by_id(log_id)
    if log and log['developer_name'] == username and not log['is_approved'] and not log['is_archived']:
        return True
    return False

def store_reset_token(email, token, expiration):
    """Store a password reset token."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO password_resets (email, token, expiration) VALUES (?, ?, ?)",
            (email, token, expiration)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def get_reset_token(token):
    """Fetch a password reset token."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email, expiration FROM password_resets WHERE token = ?", (token,))
    reset = cursor.fetchone()
    conn.close()
    if reset:
        return {"email": reset[0], "expiration": reset[1]}
    return None

def update_password(email, new_password):
    """Update a user's password."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def update_user_profile(current_username, new_email, new_username, new_password):
    """Update a user's profile."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        if new_password:
            cursor.execute(
                "UPDATE users SET email = ?, username = ?, password = ? WHERE username = ?",
                (new_email, new_username, new_password, current_username)
            )
        else:
            cursor.execute(
                "UPDATE users SET email = ?, username = ? WHERE username = ?",
                (new_email, new_username, current_username)
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e

def get_user_stats(username):
    """Fetch user statistics."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM logins WHERE username = ?", (username,))
    num_logins = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE developer_name = ?", (username,))
    num_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT project, COUNT(*) FROM logs WHERE developer_name = ? GROUP BY project", (username,))
    activity_trends = cursor.fetchall()
    
    conn.close()
    
    return {
        "num_logins": num_logins,
        "num_logs": num_logs,
        "activity_trends": activity_trends
    }

def get_top_projects(username):
    """Fetch top projects for a user."""
    conn = sqlite3.connect('.databaseFiles/database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT project, COUNT(*) FROM logs WHERE developer_name = ? GROUP BY project ORDER BY COUNT(*) DESC LIMIT 5", (username,))
    projects = cursor.fetchall()
    conn.close()
    
    project_list = [(project[0], project[1]) for project in projects]
    
    return project_list


def get_logs_by_user(username):
    """Retrieve all logs associated with a specific user."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        
        # Query to fetch all logs for the user
        cursor.execute("SELECT * FROM logs WHERE developer_name = ?", (username,))
        logs = cursor.fetchall()
        
        conn.close()
        
        # Convert logs to a list of dictionaries
        column_names = ["id", "date", "developer_name", "project", "content", "code_snippet", "last_edited", "repository_link"]
        logs_as_dicts = [dict(zip(column_names, log)) for log in logs]
        
        return logs_as_dicts

    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e


def delete_user_data(username):
    """Delete all user-related data except the account itself."""
    try:
        conn = sqlite3.connect('.databaseFiles/database.db')
        cursor = conn.cursor()
        
        # Delete logs created by the user
        cursor.execute("DELETE FROM logs WHERE developer_name = ?", (username,))
        
        # Delete login history for the user (if applicable)
        cursor.execute("DELETE FROM logins WHERE username = ?", (username,))
        
        conn.commit()
        conn.close()
        
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}") from e
