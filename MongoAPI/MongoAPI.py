# MongoAPI.py
import os
import json
from bson import ObjectId
from pymongo import MongoClient
from flask import Flask, jsonify, session, redirect, request, make_response
from datetime import timedelta
from functools import wraps

# You would typically have your MongoDB connection and API logic here.
# For simplicity, this example just provides a basic Flask app.
# Make sure to install 'Flask' if you use this example.

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=3) # Set to 30 minutes
CONNSTRING = os.environ['MONGO_CONN_STR']
""" Connect to MongoDB Database """
client = MongoClient(CONNSTRING)
db = client["MyDatabase"]

def serialize_document(doc):
    doc_copy = dict(doc) # Create a copy to modify
    if '_id' in doc_copy and isinstance(doc_copy['_id'], ObjectId):
        doc_copy['_id'] = str(doc_copy['_id'])
    # ... (other type conversions) ...
    return doc_copy

@app.errorhandler(401)
@app.route('/invld_creds')
def invld_creds():
    return jsonify({"message": "Invalid login credentials"}), 401

@app.route('/authenticate', methods=['POST'])
def authenticate():
        if "_id" in session:
             session.clear()
        auth_data = request.get_json()
        username = auth_data.get('username')
        password = auth_data.get('password')
        account = db.UserAccounts.find_one({'username': username, 'password': password})
        if account is not None:
            session["_id"] = account['_id']
            return jsonify({"message": f"Login successful for {username}", "status": "authenticated"}), 200
        else:
            return redirect('/invld_creds')
        
@app.route('/deauthenticate', methods=['GET'])
def deauthenticate():
        if "_id" in session:
            session.clear()
            return make_response(jsonify({"message": "Session cleared"}), 200)
        else:
            return make_response(jsonify({"message": "Authentication required. Please log in."}), 401)
          
     
        
@app.route('/protected_resource', methods=['POST'])
def protected_resource():
    if "_id" in session:
        """
        This endpoint requires authentication.
        Only authenticated users (who provide correct username/password in POST body)
        can access this.
        """
        return jsonify({
            "message": "Welcome, you accessed a protected resource!",
            "received_data": request_data # Shows the data sent with the POST request
        }), 200
    else:
        return redirect('/invld_creds')
    
@app.route('/Get_vault_list', methods=['GET'])
def Get_vault_list():
    result_names = []
    if "_id" in session:
        dat_cursor = db.Items.find(
            {"owner": session.get("_id",None)}, # This is the filter condition
            {'name': 1, 'valut_id': 1, '_id': 0}          # This is the projection
        )
        return [serialize_document(dat) for dat in dat_cursor], 200
        
    else:
        return redirect('/invld_creds')
    
@app.route('/Get_folders', methods=['GET'])
def Get_folders():
    if "_id" in session:
        dat_cursor = db.Folders.find({"owner" : session.get("_id",None)})
        return [serialize_document(dat) for dat in dat_cursor], 200
    else:
        return redirect('/invld_creds')

@app.route('/Get_vault_item', methods=['POST'])
def Get_vault_item():
    if "_id" in session:
        auth_data = request.get_json()
        valut_id = auth_data.get('valut_id')
        return db.Items.find_one({'owner': session.get("_id",None), 'valut_id': valut_id},{'_id': 0, 'valut_id': 0})
    else:
        return redirect('/invld_creds')

        
if __name__ == '__main__':
    # This runs the Flask development server.
    # For production, you'd typically use a WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)
