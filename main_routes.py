from flask import render_template, request, redirect, url_for, flash, session
from datetime import datetime
import userManagement as dbHandler

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
            logs = dbHandler.get_recent_logs()
            return render_template("dashboard.html", username=session['username'], email=session['email'], role=session['role'], logs=logs)
        else:
            flash("You need to log in first.")
            return redirect(url_for('login'))

    @app.route("/create_log", methods=["GET", "POST"])
    def create_log():
        if 'username' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        
        if request.method == "GET":
            current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return render_template("create_log.html", current_datetime=current_datetime, username=session['username'])
        if request.method == "POST":
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            developer_name = session['username']
            project = request.form["project"]
            content = request.form["content"]
            code_snippet = request.form["code_snippet"]
            
            dbHandler.add_log(date, developer_name, project, content, code_snippet)
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
        
        developer = request.args.get('developer')
        date = request.args.get('date')
        project = request.args.get('project')
        sort_by = request.args.get('sort_by', 'date')
        sort_order = request.args.get('sort_order', 'asc')
        
        page = request.args.get('page', 1, type=int)
        per_page = 5
        logs = dbHandler.search_logs(developer, date, project, sort_by, sort_order)
        total_logs = len(logs)  # Assuming search_logs returns all matching logs
        print(f"Logs passed to template: {logs}")  # Debug print
        return render_template("home_logged_in.html", username=session['username'], email=session['email'], role=session['role'], logs=logs, page=page, per_page=per_page, total_logs=total_logs)