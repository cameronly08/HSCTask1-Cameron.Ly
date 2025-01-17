from flask import jsonify, request
from flask_restful import Resource, Api
import userManagement as dbHandler
import logging

api = Api()
logger = logging.getLogger(__name__)

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

api.add_resource(UserStats, '/api/user_stats')