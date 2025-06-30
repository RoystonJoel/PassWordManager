# MongoAPI.py
import os
import json
from pymongo import MongoClient
from flask import Flask, jsonify, session, redirect, request, make_response
from functools import wraps

# You would typically have your MongoDB connection and API logic here.
# For simplicity, this example just provides a basic Flask app.
# Make sure to install 'Flask' if you use this example.

app = Flask(__name__)
app.secret_key = "hd72bd8a"
CONNSTRING = os.environ['MONGO_CONN_STR']
""" Connect to MongoDB Database """
client = MongoClient(CONNSTRING)
db = client["MyDatabase"]
VALID_USERS = {
    "admin": "securepassword123",
    "user1": "pass123"
}


@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Mongo API! If connected, this would show data from MongoDB."})

@app.route('/data')
def get_data():
    # In a real application, you would fetch data from MongoDB here.
    # Example: data = db.your_collection.find({})
    sample_data = {
        "items": [
            {"id": 1, "name": "Item A", "description": "This is a sample item."},
            {"id": 2, "name": "Item B", "description": "Another sample item."}
        ]
    }
    return jsonify(sample_data)

@app.route('/datadb')
def get_datadb():
        return db.UserAccounts.find_one({'username': 'user1'})

@app.route('/authenticate', methods=['POST'])
def authenticate():
        auth_data = request.get_json()
        username = auth_data.get('username')
        password = auth_data.get('password')
        account = db.UserAccounts.find_one({'username': username, 'password': password})
        if account is not None:
            session["user"] = username
            return jsonify({"message": f"Login successful for {username}", "status": "authenticated"}), 200
        else:
            return jsonify({"message": "Invalid login credentials"}), 401
        
@app.route('/protected_resource', methods=['POST'])
def protected_resource():
    if "user" in session:
        """
        This endpoint requires authentication.
        Only authenticated users (who provide correct username/password in POST body)
        can access this.
        """
        # If the decorator passed, the user is authenticated.
        # You can access the request data if needed
        request_data = request.get_json()
        return jsonify({
            "message": "Welcome, you accessed a protected resource!",
            "received_data": request_data # Shows the data sent with the POST request
        }), 200
    else:
        return make_response(jsonify({"message": "Authentication required. Please log in."}), 401)
        
     


if __name__ == '__main__':
    # This runs the Flask development server.
    # For production, you'd typically use a WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)
