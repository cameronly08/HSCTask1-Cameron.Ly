from flask import render_template, request, redirect, url_for, flash, session
from datetime import datetime
import userManagement as dbHandler
import bcrypt
from utils import validate_password, basic_sanitize_input
from flask_wtf.csrf import validate_csrf

def register_main_routes(app):
    @app.route("/", methods=["GET"])
    @app.route("/index.html", methods=["GET"])
    def home():
        """Render the home page."""
        if 'username' in session:
            return redirect(url_for('home_logged_in'))
        else:
            return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        """Render the user dashboard."""
        if 'username' in session:
            username = session['username']
            email = session['email']
            role = session['role']
            
            logs = dbHandler.get_recent_logs(username)
            stats = dbHandler.get_user_stats(username)
            
            return render_template("dashboard.html", username=username, email=email, role=role, logs=logs, stats=stats)
        else:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
    @app.route("/analytics")
    def analytics():
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
        user = dbHandler.get_user(session['username'])
        stats = dbHandler.get_user_stats(user['username'])
        recent_logs = dbHandler.get_recent_logs(user['username'])
        top_projects = dbHandler.get_top_projects(user['username'])
        
        return render_template("analytics.html", user=user, stats=stats, recent_logs=recent_logs, top_projects=top_projects)

    @app.route("/create_log", methods=["GET", "POST"])
    def create_log():
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
        if request.method == "GET":
            current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return render_template("create_log.html", current_datetime=current_datetime, username=session['username'])
        if request.method == "POST":
            try:
                validate_csrf(request.form['csrf_token'])
            except ValueError:
                flash("CSRF token is missing or invalid.")
                return redirect(url_for('create_log'))

            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            developer_name = session['username']
            project = basic_sanitize_input(request.form["project"])
            content = basic_sanitize_input(request.form["content"])
            code_snippet = basic_sanitize_input(request.form["code_snippet"])
            repository = basic_sanitize_input(request.form.get("repository_link"))
            
            dbHandler.add_log(date, developer_name, project, content, code_snippet, repository)
            flash("Log created successfully!")
            return redirect(url_for("dashboard"))

    @app.route("/home_logged_in", methods=["GET"])
    def home_logged_in():
        """Render the home page for logged-in users with pagination."""
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
        page = request.args.get('page', 1, type=int)
        per_page = 5
        logs = dbHandler.get_logs_paginated(page, per_page)
        total_logs = dbHandler.get_total_logs_count()
        
        if not logs:
            logs = []  # Default to empty if no logs found

        return render_template("home_logged_in.html", 
                            username=session['username'], 
                            email=session['email'], 
                            role=session['role'], 
                            logs=logs, 
                            page=page, 
                            per_page=per_page, 
                            total_logs=total_logs)

    @app.route("/search_logs", methods=["GET"])
    def search_logs():
        """Search logs by developer, date, and project."""
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
        developer = basic_sanitize_input(request.args.get('developer'))
        date = basic_sanitize_input(request.args.get('date'))
        project = basic_sanitize_input(request.args.get('project'))
        sort_by = basic_sanitize_input(request.args.get('sort_by', 'date'))
        sort_order = basic_sanitize_input(request.args.get('sort_order', 'asc'))
        
        page = request.args.get('page', 1, type=int)
        per_page = 5
        logs = dbHandler.search_logs(developer, date, project, sort_by, sort_order)
        total_logs = len(logs)  # Assuming search_logs returns all matching logs
        print(f"Logs passed to template: {logs}")  # Debug print
        return render_template("home_logged_in.html", username=session['username'], email=session['email'], role=session['role'], logs=logs, page=page, per_page=per_page, total_logs=total_logs)

    @app.route("/edit_log/<int:log_id>", methods=["GET", "POST"])
    def edit_log(log_id):
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))

        log = dbHandler.get_log_by_id(log_id)
        if not log or not dbHandler.is_log_editable(log_id, session['username']):
            flash("You do not have permission to edit this log.")
            return redirect(url_for('dashboard'))

        if request.method == "GET":
            return render_template("edit_log.html", log=log)
        if request.method == "POST":
            try:
                validate_csrf(request.form['csrf_token'])
            except ValueError:
                flash("CSRF token is missing or invalid.")
                return render_template("edit_log.html", log=log, error="CSRF token is missing or invalid.")

            project = basic_sanitize_input(request.form["project"])
            content = basic_sanitize_input(request.form["content"])
            code_snippet = basic_sanitize_input(request.form["code_snippet"])
            
            dbHandler.update_log(log_id, project, content, code_snippet)
            flash("Log updated successfully!")
            return redirect(url_for("dashboard"))

    @app.route("/delete_log/<int:log_id>", methods=["POST"])
    def delete_log(log_id):
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))

        try:
            validate_csrf(request.form['csrf_token'])
        except ValueError:
            flash("CSRF token is missing or invalid.")
            return redirect(url_for('dashboard'))

        if not dbHandler.is_log_deletable(log_id, session['username']):
            flash("You do not have permission to delete this log.")
            return redirect(url_for('dashboard'))

        dbHandler.delete_log(log_id)
        flash("Log deleted successfully!")
        return redirect(url_for("dashboard"))
    
    @app.route("/profile", methods=["GET"])
    def profile():
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
        user = dbHandler.get_user(session['username'])
        return render_template("profile.html", user=user)

    @app.route("/update_profile", methods=["POST"])
    def update_profile():
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))

        try:
            validate_csrf(request.form['csrf_token'])
        except ValueError:
            flash("CSRF token is missing or invalid.")
            return redirect(url_for('profile'))
        
        email = basic_sanitize_input(request.form["email"])
        new_username = basic_sanitize_input(request.form["username"])
        new_password = request.form["password"]  # Password validation is done separately
        current_username = session['username']
        
        username_error = None
        password_error = None
        
        hashed_password = None
        try:
            if new_username != current_username and dbHandler.get_user(new_username):
                username_error = "Username is already taken."
            
            # Validate the new password if provided
            if new_password:
                validation_result = validate_password(new_password)
                if validation_result != "Password is valid.":
                    password_error = validation_result
                else:
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if username_error or password_error:
                user = dbHandler.get_user(current_username)
                return render_template("profile.html", user=user, username_error=username_error, password_error=password_error)
            
            dbHandler.update_user_profile(current_username, email, new_username, hashed_password)
            if new_username != current_username:
                flash("Username updated successfully.")
                session['username'] = new_username  # Update session username if changed
            if new_password:
                flash("Password updated successfully.")
            flash("Profile updated successfully.")
            session['username'] = new_username  # Update session username if changed
        except ValueError as e:
            flash(f"Value error occurred: {e}")
        except KeyError as e:
            flash(f"Key error occurred: {e}")
        except dbHandler.DatabaseError as e:
            flash(f"An error occurred: {e}")
        
        return redirect(url_for('profile'))