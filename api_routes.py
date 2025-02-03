import time
from flask import jsonify, request
from flask_restful import Resource, Api
import userManagement as dbHandler
import logging

# Initialize the API and logger
api = Api()
logger = logging.getLogger(__name__)

# ServerStatus - Route to get the status of the server
class ServerStatus(Resource):
    def __init__(self):
        # To track the time when the server started
        self.start_time = time.time()

    def get(self):
        """Get the current status of the server with uptime"""
        logger.debug("ServerStatus endpoint called")

        # Get uptime in seconds
        uptime_seconds = time.time() - self.start_time
        uptime = self.format_uptime(uptime_seconds)

        # Return server status with online status and uptime
        status = {
            "server": "online",
            "message": "The server is running.",
            "uptime": uptime,
        }

        logger.debug("Returning server status: %s", status)
        return jsonify(status)

    def format_uptime(self, seconds):
        """Helper function to format the uptime from seconds to a readable format"""
        days = seconds // (24 * 3600)
        seconds %= (24 * 3600)
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        return f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"


# UserStats - Example route to get user statistics by username
class UserStats(Resource):
    def get(self):
        logger.debug("UserStats endpoint called")
        
        # Retrieve the username from the query parameters
        username = request.args.get('username')
        if not username:
            logger.debug("Username is required")
            return jsonify({"message": "Username is required"}), 400
        logger.debug("Username from query parameters: %s", username)
        
        user = dbHandler.get_user(username)
        if user:
            logger.debug("User found: %s", user)
            stats = dbHandler.get_user_stats(user['username'])
            logger.debug("User stats: %s", stats)
            data = {
                "num_logins": stats['num_logins'],
                "num_logs": stats['num_logs'],
                "activity_trends": stats['activity_trends']
            }
            logger.debug("Returning user stats: %s", data)
            return jsonify(data)
        else:
            logger.debug("User not found: %s", username)
            return jsonify({"message": "User not found"}), 404


# Add routes to the API
api.add_resource(UserStats, '/api/user_stats')
api.add_resource(ServerStatus, '/api/server_status')  # New route for server status
