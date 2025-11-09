import os
import jwt
import io
import click
import pyotp
import qrcode
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from flask import (
    Flask, request, jsonify, render_template, make_response, send_file, redirect, url_for
)
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from functools import wraps
import redis

# ------------------------------------------------------------------
# 🔹 App Configuration
# ------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-and-strong-key-for-my-ztna-project'

# Initialize extensions
bcrypt = Bcrypt(app)
CORS(app)

# ------------------------------------------------------------------
# 🔹 Logging Configuration
# ------------------------------------------------------------------
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file = 'ztna_audit.log'
file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024*5, backupCount=2)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
audit_logger = logging.getLogger('ztna_audit')
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(file_handler)
audit_logger.propagate = False
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)
audit_logger.addHandler(console_handler)
audit_logger.info("ZTNA Audit Logger initialized.")

# ------------------------------------------------------------------
# 🔹 Redis Connection
# ------------------------------------------------------------------
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    audit_logger.info("✅ Connected to Redis server.")
except redis.exceptions.ConnectionError as e:
    audit_logger.warning(f"⚠️ Error: Could not connect to Redis. {e}")
    audit_logger.warning("Token revocation will NOT be persistent.")
    redis_client = None

# ------------------------------------------------------------------
# 🔹 MongoDB Connection
# ------------------------------------------------------------------
try:
    mongo_client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    mongo_client.server_info()
    db = mongo_client.ztna_professional_db
    users_collection = db.users
    policies_collection = db.policies
    audit_logger.info("✅ Connected to MongoDB server.")
except Exception as e:
    audit_logger.error(f"⚠️ Error: Could not connect to MongoDB. {e}")
    mongo_client = None
    db = None

# ------------------------------------------------------------------
# 🔹 Audit Log Helper
# ------------------------------------------------------------------
def audit_log(message):
    audit_logger.info(message)

# ------------------------------------------------------------------
# 🔹 ZTNA Policy Enforcer (Decorator) - --- MODIFIED ---
# ------------------------------------------------------------------
def ztna_policy_enforcer(resource_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                try:
                    token = request.headers['Authorization'].split(" ")[1]
                except IndexError:
                    return jsonify({"message": "Invalid Token format"}), 401

            if not token:
                audit_log(f"Access DENIED to {resource_name}: No token provided")
                return jsonify({"message": "Token is missing"}), 401

            try:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                
                if not payload.get('full_access'):
                    raise jwt.InvalidTokenError("Not a full access token")

                if redis_client and redis_client.get(payload['jti']):
                    audit_log(f"Access DENIED to {resource_name} for {payload['user_id']}: Token is REVOKED")
                    return jsonify({"message": "Token has been revoked"}), 401

            except jwt.ExpiredSignatureError:
                audit_log(f"Access DENIED to {resource_name}: Token has expired")
                return jsonify({"message": "Token has expired"}), 401
            except jwt.InvalidTokenError as e:
                audit_log(f"Access DENIED to {resource_name}: Invalid token ({e})")
                return jsonify({"message": "Invalid token"}), 401

            user_role = payload.get('role')
            user_id = payload.get('user_id')
            
            if resource_name != "any":
                # --- NEW Context-Aware Policy Logic ---
                user_ip = request.remote_addr
                now = datetime.now(timezone.utc)
                
                matching_policies = db.policies.find({
                    "role": user_role,
                    "resource": resource_name
                })
                
                allowed = False
                for policy in matching_policies:
                    policy_id = policy['_id']
                    
                    # 1. Check IP
                    allowed_ips = policy.get("allowed_ips")
                    if allowed_ips: # If IP list exists and is not empty
                        if user_ip not in allowed_ips:
                            audit_log(f"Policy {policy_id} DENIED for {user_id}: IP {user_ip} not in {allowed_ips}")
                            continue # This policy fails, try the next one
                    
                    # 2. Check Start Time (Format "HH:MM")
                    start_time_str = policy.get("start_time")
                    if start_time_str:
                        try:
                            start_time = datetime.strptime(start_time_str, "%H:%M").time()
                            if now.time() < start_time:
                                audit_log(f"Policy {policy_id} DENIED for {user_id}: Access before {start_time_str} UTC")
                                continue # This policy fails, try the next one
                        except ValueError:
                            audit_log(f"Invalid start_time format in policy {policy_id}: {start_time_str}")
                            
                    # 3. Check End Time (Format "HH:MM")
                    end_time_str = policy.get("end_time")
                    if end_time_str:
                        try:
                            end_time = datetime.strptime(end_time_str, "%H:%M").time()
                            if now.time() > end_time:
                                audit_log(f"Policy {policy_id} DENIED for {user_id}: Access after {end_time_str} UTC")
                                continue # This policy fails, try the next one
                        except ValueError:
                            audit_log(f"Invalid end_time format in policy {policy_id}: {end_time_str}")
                    
                    # If we passed all checks for *this* policy, we are allowed.
                    allowed = True
                    audit_log(f"Policy {policy_id} GRANTED for {user_id}")
                    break
                
                if not allowed:
                    audit_log(f"Access DENIED to {resource_name} for {user_id}: No valid policy found for IP {user_ip} at time {now.time()}")
                    return jsonify({"message": f"Access Denied: Your role ('{user_role}') cannot access '{resource_name}' from this IP or at this time."}), 403
                # --- End of new logic ---
            
            audit_log(f"Access GRANTED to {resource_name} for {user_id}")
            return f(payload, *args, **kwargs)
        return decorated_function
    return decorator

# ------------------------------------------------------------------
# 🔹 HTML Page Serving Routes - --- MODIFIED ---
# ------------------------------------------------------------------
@app.route('/')
def serve_home_page():
    return render_template('home.html')

@app.route('/register')
def serve_register_page():
    return render_template('register.html')

@app.route('/login')
def serve_login_page():
    return render_template('login.html')

@app.route('/verify-mfa')
def serve_verify_mfa_page():
    return render_template('verify_mfa.html')

@app.route('/dashboard')
def serve_dashboard_page():
    return render_template('dashboard.html')

# --- NEW Admin and Profile Routes ---
@app.route('/profile')
def serve_profile_page():
    # This page will use the ZTNA token to fetch its own data
    return render_template('profile.html')

@app.route('/admin')
def serve_admin_page():
    # This page will be protected by the decorator on its API calls
    return render_template('admin.html')

# ------------------------------------------------------------------
# 🔹 Registration & Login APIs (Unchanged)
# ------------------------------------------------------------------

@app.route('/api/register-mfa-secret', methods=['GET'])
def get_mfa_secret_for_registration():
    mfa_secret = pyotp.random_base32()
    temp_payload = {
        'mfa_secret': mfa_secret,
        'action': 'register-secret',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=10)
    }
    temp_token = jwt.encode(temp_payload, app.config['SECRET_KEY'], algorithm="HS256")
    
    totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
        name="New ZTNA User", 
        issuer_name="ZTNA Pro Demo"
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    response = send_file(buf, mimetype='image/png')
    response.headers['x-mfa-temp-token'] = temp_token
    audit_log("Issued new MFA secret/QR for registration.")
    return response

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    temp_token = data.get('mfa_temp_token')
    
    try:
        payload = jwt.decode(temp_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        if payload.get('action') != 'register-secret':
            raise jwt.InvalidTokenError("Token not for registration")
        mfa_secret = payload['mfa_secret']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        audit_log(f"Registration failed: Invalid/Expired temp token. {e}")
        return jsonify({"message": "Your registration session expired. Please refresh and try again."}), 401
    
    if db.users.find_one({"username": data.get('username')}):
        return jsonify({"message": "Username already taken."}), 400
    if db.users.find_one({"email": data.get('email')}):
        return jsonify({"message": "Email already registered."}), 400

    totp = pyotp.TOTP(mfa_secret)
    if not totp.verify(data.get('mfa_code')):
        audit_log(f"Registration failed for {data.get('username')}: Invalid MFA code.")
        return jsonify({"message": "Invalid MFA code. Please check your authenticator app."}), 400
        
    try:
        new_user_doc = {
            "username": data.get('username'),
            "email": data.get('email'),
            "password_hash": bcrypt.generate_password_hash(data.get('password')).decode('utf-8'),
            "role": data.get('role'),
            "mfa_secret": mfa_secret,
            "mfa_enabled": True,
            "last_login": None
        }
        db.users.insert_one(new_user_doc)
        audit_log(f"SUCCESS: New user registered: {new_user_doc['username']} (Role: {new_user_doc['role']})")
        return jsonify({"message": "Registration successful! Redirecting to login..."}), 201
    except Exception as e:
        audit_log(f"Registration failed: Database error. {e}")
        return jsonify({"message": "An error occurred. Please try again."}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = db.users.find_one({"username": username})

    if not user or not bcrypt.check_password_hash(user['password_hash'], password):
        audit_log(f"Failed login attempt for user: {username} (Invalid credentials)")
        return jsonify({"message": "Invalid username or password"}), 401
    
    user_agent = request.headers.get('User-Agent', '')
    if "Mac" not in user_agent and "Windows" not in user_agent:
        audit_log(f"Failed login for user: {username} (Device posture failed: {user_agent})")
        return jsonify({"message": "Device is not compliant (Must be a Mac or Windows PC)"}), 403

    temp_payload = {
        'user_id': str(user['_id']),
        'action': 'mfa-verify',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=3)
    }
    temp_token = jwt.encode(temp_payload, app.config['SECRET_KEY'], algorithm="HS256")
    audit_log(f"Login Step 1 OK for {username}. MFA required.")
    return jsonify({"message": "Credentials OK", "mfa_token": temp_token}), 200

@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa_login():
    data = request.json
    temp_token = data.get('mfa_token')
    mfa_code = data.get('mfa_code')
    
    try:
        payload = jwt.decode(temp_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        if payload.get('action') != 'mfa-verify':
            raise jwt.InvalidTokenError("Token not for MFA verification")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        audit_log(f"MFA verification failed: Invalid/Expired temp token. {e}")
        return jsonify({"message": "Your login session expired. Please log in again."}), 401
        
    try:
        user = db.users.find_one({"_id": ObjectId(payload['user_id'])})
    except Exception as e:
        audit_log(f"MFA verification failed: Invalid user ID format {e}")
        return jsonify({"message": "Invalid user session."}), 401
    
    if not user or not user['mfa_enabled'] or not user['mfa_secret']:
        audit_log(f"MFA verification failed: User {payload['user_id']} not found or MFA not enabled.")
        return jsonify({"message": "MFA is not enabled for this user."}), 400
    
    totp = pyotp.TOTP(user['mfa_secret'])
    if not totp.verify(mfa_code):
        audit_log(f"Failed MFA attempt for user: {user['username']} (Invalid code)")
        return jsonify({"message": "Invalid MFA code"}), 401
        
    try:
        db.users.update_one(
            {"_id": user['_id']},
            {"$set": {"last_login": datetime.now(timezone.utc)}}
        )
    except Exception as e:
        audit_log(f"Failed to update last_login for {user['username']}: {e}")
        
    audit_log(f"MFA verified. Full ZTNA token issued for user: {user['username']}")
    ztna_payload = {
        'user_id': str(user['_id']),
        'username': user['username'],
        'role': user['role'],
        'full_access': True,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=15),
        'jti': os.urandom(16).hex()
    }
    ztna_token = jwt.encode(ztna_payload, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({"token": ztna_token}), 200

# ------------------------------------------------------------------
# 🔹 Protected Resources & Logout APIs (Unchanged)
# ------------------------------------------------------------------
@app.route('/api/resource/financeDB')
@ztna_policy_enforcer(resource_name="financeDB")
def access_finance_db(token_payload):
    return jsonify({
        "message": f"Access Granted. Welcome, {token_payload['username']}. You are viewing the TOP SECRET Finance Database.",
        "data": "Q4 Profits: $1,000,000,000"
    })

@app.route('/api/resource/hrPortal')
@ztna_policy_enforcer(resource_name="hrPortal")
def access_hr_portal(token_payload):
    return jsonify({
        "message": f"Access Granted. Welcome, {token_payload['username']}. You are viewing the HR Portal.",
        "data": "New Employee: Jane Smith"
    })

@app.route('/api/logout', methods=['POST'])
@ztna_policy_enforcer(resource_name="any")
def logout(token_payload):
    if not redis_client:
        return jsonify({"message": "Revocation service is down"}), 500
        
    jti = token_payload.get('jti')
    token_exp = token_payload.get('exp')
    
    try:
        ttl = datetime.fromtimestamp(token_exp, timezone.utc) - datetime.now(timezone.utc)
    except TypeError:
        return jsonify({"message": "Invalid token expiration"}), 400

    redis_client.setex(name=jti, time=ttl, value="revoked")
    audit_log(f"Token revoked (logout) for user: {token_payload.get('user_id')}")
    return jsonify({"message": "You have been logged out. Token revoked."}), 200

# ------------------------------------------------------------------
# 🔹 --- NEW User Profile APIs ---
# ------------------------------------------------------------------

@app.route('/api/profile/reset-mfa-secret', methods=['POST'])
@ztna_policy_enforcer(resource_name="any")
def reset_mfa_secret(token_payload):
    """
    Generates a NEW MFA secret for the logged-in user.
    Does NOT save it yet. Just returns the QR code and a temp token.
    """
    mfa_secret = pyotp.random_base32()
    
    # Temp token holds the new secret until user verifies it
    temp_payload = {
        'user_id': token_payload['user_id'],
        'new_mfa_secret': mfa_secret,
        'action': 'mfa-reset-verify',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    temp_token = jwt.encode(temp_payload, app.config['SECRET_KEY'], algorithm="HS256")
    
    totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
        name=token_payload['username'], # Use user's real username
        issuer_name="ZTNA Pro Demo"
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    response = send_file(buf, mimetype='image/png')
    response.headers['x-mfa-temp-token'] = temp_token
    audit_log(f"Issued new MFA secret for reset (pending) for user {token_payload['user_id']}")
    return response

@app.route('/api/profile/confirm-mfa-reset', methods=['POST'])
@ztna_policy_enforcer(resource_name="any")
def confirm_mfa_reset(token_payload):
    """
    Verifies the temp token and the NEW MFA code.
    If valid, it saves the new secret to the user's document in MongoDB.
    """
    data = request.json
    temp_token = data.get('mfa_temp_token')
    mfa_code = data.get('mfa_code')
    
    # 1. Verify the temporary reset token
    try:
        reset_payload = jwt.decode(temp_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        if reset_payload.get('action') != 'mfa-reset-verify':
            raise jwt.InvalidTokenError("Token not for MFA reset")
        
        # Security check: ensure the user in the reset token is the same as the logged-in user
        if reset_payload['user_id'] != token_payload['user_id']:
            audit_log(f"MFA Reset FAILED: Token user ({reset_payload['user_id']}) does not match session user ({token_payload['user_id']})")
            return jsonify({"message": "Token mismatch. Cannot reset MFA."}), 403
            
        new_mfa_secret = reset_payload['new_mfa_secret']
        
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        audit_log(f"MFA Reset FAILED: Invalid/Expired temp token. {e}")
        return jsonify({"message": "Your MFA reset session expired. Please try again."}), 401
    
    # 2. Verify the NEW MFA code
    totp = pyotp.TOTP(new_mfa_secret)
    if not totp.verify(mfa_code):
        audit_log(f"MFA Reset FAILED for {token_payload['user_id']}: Invalid new MFA code.")
        return jsonify({"message": "Invalid MFA code. Please check your authenticator app."}), 400
        
    # 3. Save the new secret to the database
    try:
        db.users.update_one(
            {"_id": ObjectId(token_payload['user_id'])},
            {"$set": {"mfa_secret": new_mfa_secret}}
        )
        audit_log(f"MFA Reset SUCCESS for user {token_payload['user_id']}")
        return jsonify({"message": "MFA has been successfully reset!"}), 200
    except Exception as e:
        audit_log(f"MFA Reset FAILED for user {token_payload['user_id']} at database step: {e}")
        return jsonify({"message": "An error occurred while saving. Please try again."}), 500

# ------------------------------------------------------------------
# 🔹 --- NEW Admin Panel APIs ---
# ------------------------------------------------------------------

@app.route('/api/admin/policies', methods=['GET'])
@ztna_policy_enforcer(resource_name="adminPanel")
def get_policies(token_payload):
    """
    Returns a list of all policies in the database.
    Protected for 'admin' role only.
    """
    try:
        policies_cursor = db.policies.find({})
        policies_list = []
        for policy in policies_cursor:
            policy['_id'] = str(policy['_id']) # Convert ObjectId to string for JSON
            policies_list.append(policy)
        return jsonify(policies_list), 200
    except Exception as e:
        audit_log(f"Admin {token_payload['user_id']} failed to get policies: {e}")
        return jsonify({"message": "Error fetching policies."}), 500

@app.route('/api/admin/policies', methods=['POST'])
@ztna_policy_enforcer(resource_name="adminPanel")
def create_policy(token_payload):
    """
    Creates a new policy.
    Protected for 'admin' role only.
    """
    data = request.json
    try:
        # Basic validation
        role = data.get('role')
        resource = data.get('resource')
        if not role or not resource:
            return jsonify({"message": "Policy must have a 'role' and 'resource'"}), 400
        
        new_policy = {
            "role": role,
            "resource": resource
        }
        
        # Add optional context fields if they exist
        if data.get('allowed_ips'):
            # Ensure it's a list
            new_policy['allowed_ips'] = data.get('allowed_ips').split(',')
        if data.get('start_time'):
            new_policy['start_time'] = data.get('start_time')
        if data.get('end_time'):
            new_policy['end_time'] = data.get('end_time')
            
        result = db.policies.insert_one(new_policy)
        new_policy['_id'] = str(result.inserted_id)
        
        audit_log(f"Admin {token_payload['user_id']} CREATED policy {result.inserted_id}")
        return jsonify(new_policy), 201
        
    except Exception as e:
        audit_log(f"Admin {token_payload['user_id']} FAILED to create policy: {e}")
        return jsonify({"message": "Error creating policy."}), 500

@app.route('/api/admin/policy/<policy_id>', methods=['DELETE'])
@ztna_policy_enforcer(resource_name="adminPanel")
def delete_policy(token_payload, policy_id):
    """
    Deletes a policy by its ID.
    Protected for 'admin' role only.
    """
    try:
        result = db.policies.delete_one({"_id": ObjectId(policy_id)})
        
        if result.deleted_count == 0:
            return jsonify({"message": "Policy not found."}), 404
            
        audit_log(f"Admin {token_payload['user_id']} DELETED policy {policy_id}")
        return jsonify({"message": "Policy deleted."}), 200
        
    except Exception as e:
        audit_log(f"Admin {token_payload['user_id']} FAILED to delete policy {policy_id}: {e}")
        return jsonify({"message": "Error deleting policy (invalid ID?)."}), 500

# ------------------------------------------------------------------
# --- HTML Templates (7 Pages) ---
# ------------------------------------------------------------------

# This is our global stylesheet.
GLOBAL_CSS = """
<style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: #0f172a;
        color: #e2e8f0;
        line-height: 1.6;
        min-height: 100vh;
        overflow-x: hidden;
        background: linear-gradient(135deg, #0f172a, #1e293b, #334155, #0f172a);
        background-size: 400% 400%;
        animation: gradientBG 25s ease infinite;
        display: flex; /* --- NEW: Flex column to push footer down --- */
        flex-direction: column; /* --- NEW --- */
    }
    @keyframes gradientBG {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    nav {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 2rem;
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border-bottom: 1px solid rgba(51, 65, 85, 0.5);
        position: fixed;
        width: 100%;
        top: 0;
        z-index: 1000;
        animation: slideInDown 0.5s ease-out;
    }
    @keyframes slideInDown {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
    }
    nav .logo { font-size: 1.5rem; font-weight: 700; color: #fff; text-decoration: none; }
    nav .logo span { color: #38bdf8; }
    nav .nav-links { display: flex; gap: 1.5rem; list-style: none; }
    nav .nav-links a, .nav-links button {
        text-decoration: none;
        color: #cbd5e1;
        font-weight: 500;
        padding: 0.5rem 1rem;
        border: 2px solid transparent;
        border-radius: 99px;
        background: none;
        cursor: pointer;
        font-family: inherit;
        font-size: 1rem;
        transition: all 0.3s ease;
    }
    nav .nav-links a:hover, .nav-links button:hover { color: #fff; background-color: rgba(56, 189, 248, 0.1); }
    nav .nav-links a.button-primary, .nav-links button.button-primary {
        background-color: #38bdf8;
        color: #0f172a;
        font-weight: 700;
    }
    nav .nav-links a.button-primary:hover, .nav-links button.button-primary:hover {
        background-color: #7dd3fc;
        color: #0f172a;
        transform: translateY(-2px);
        box-shadow: 0 4px 20px rgba(56, 189, 248, 0.3);
    }
    nav .nav-links a.button-secondary { border-color: #334155; }
    nav .nav-links a.button-secondary:hover { border-color: #38bdf8; color: #fff; }
    
    .container {
        max-width: 1100px;
        margin: 0 auto;
        padding: 2rem;
        padding-top: 8rem;
        width: 100%; /* --- NEW --- */
        flex-grow: 1; /* --- NEW: Makes container grow to fill space --- */
    }
    
    .form-card {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(15px);
        -webkit-backdrop-filter: blur(15px);
        border: 1px solid rgba(51, 65, 85, 0.5);
        border-radius: 16px;
        padding: 2.5rem;
        max-width: 450px;
        margin: 2rem auto;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        animation: fadeIn 0.7s ease-out;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .form-card h1 { text-align: center; color: #fff; margin-bottom: 2rem; font-weight: 600; }
    .form-group { margin-bottom: 1.5rem; }
    .form-group label { display: block; margin-bottom: 0.5rem; color: #94a3b8; font-weight: 500; }
    .form-group input, .form-group select, .form-group textarea {
        width: 100%;
        padding: 0.75rem 1rem;
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        color: #e2e8f0;
        font-size: 1rem;
        transition: all 0.3s ease;
        font-family: inherit;
    }
    .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
        outline: none;
        border-color: #38bdf8;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.3);
    }
    .form-group select option { background: #1e293b; }
    .btn-submit {
        width: 100%;
        padding: 0.75rem 1.5rem;
        background-color: #38bdf8;
        color: #0f172a;
        font-weight: 700;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1.1rem;
        transition: all 0.3s ease;
    }
    .btn-submit:hover {
        background-color: #7dd3fc;
        transform: translateY(-2px);
        box-shadow: 0 4px 20px rgba(56, 189, 248, 0.3);
    }
    .btn-submit:disabled {
        background-color: #334155;
        color: #94a3b8;
        cursor: not-allowed;
    }
    .message {
        text-align: center;
        margin-top: 1.5rem;
        padding: 0.75rem;
        border-radius: 8px;
        font-weight: 500;
    }
    .message.success { background-color: rgba(22, 163, 74, 0.2); color: #4ade80; }
    .message.error { background-color: rgba(239, 68, 68, 0.2); color: #f87171; }
    
    .qr-container {
        display: flex;
        justify-content: center;
        align-items: center;
        background: #fff;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
    }
    .qr-container img { width: 200px; height: 200px; }
    
    .dashboard-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 2rem;
    }
    @media (max-width: 768px) { .dashboard-grid { grid-template-columns: 1fr; } }
    
    .dashboard-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(51, 65, 85, 0.5);
        border-radius: 16px;
        padding: 2rem;
        animation: fadeIn 0.7s ease-out;
        margin-bottom: 2rem;
    }
    .dashboard-card h3 {
        color: #fff;
        border-bottom: 1px solid #334155;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }
    .controls { display: flex; flex-wrap: wrap; gap: 1rem; }
    .controls button {
        padding: 0.75rem 1.5rem;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    #financeBtn { background-color: #22c55e; color: #fff; }
    #hrBtn { background-color: #0ea5e9; color: #fff; }
    #financeBtn:hover, #hrBtn:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    #results {
        margin-top: 1.5rem;
        padding: 1.5rem;
        min-height: 100px;
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 8px;
    }
    pre {
        background: #0f172a;
        color: #e2e8f0;
        padding: 0;
        border-radius: 4px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
    }

    /* --- NEW Footer CSS --- */
    footer {
        text-align: center;
        padding: 2rem 1rem;
        margin-top: 4rem; /* Will be pushed down by flex-grow */
        color: #94a3b8;
        border-top: 1px solid rgba(51, 65, 85, 0.5);
        font-size: 0.9rem;
        animation: fadeIn 1s ease-out;
        width: 100%;
    }
    footer a {
        color: #38bdf8;
        text-decoration: none;
    }
    footer a:hover {
        text-decoration: underline;
    }
</style>
"""

# --- NEW: Global Footer HTML ---
GLOBAL_FOOTER_HTML = """
<footer>
    <p>&copy; 2025 ZTNA Pro Demo. All rights reserved. This is a fictional demo for educational purposes.</p>
    <p>Built with Flask, MongoDB, Redis, and PyJWT.</p>
</footer>
"""

# --- Page 1: Home (--- MODIFIED ---) ---
HOME_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - Welcome</title>
    """ + GLOBAL_CSS + """
    <style>
        .hero { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 4rem 0; }
        .hero h1 { font-size: 3.5rem; font-weight: 800; color: #fff; margin-bottom: 1rem; line-height: 1.2; animation: slideInUp 0.8s ease-out; }
        .hero h1 span { color: #38bdf8; }
        .hero p.subtitle { font-size: 1.25rem; color: #cbd5e1; max-width: 650px; margin-bottom: 2rem; animation: slideInUp 0.8s ease-out 0.2s; animation-fill-mode: backwards; }
        .hero .cta-button {
            font-size: 1.1rem; padding: 0.8rem 2rem; background-color: #38bdf8; color: #0f172a;
            text-decoration: none; font-weight: 700; border-radius: 99px; transition: all 0.3s ease;
            animation: slideInUp 0.8s ease-out 0.4s; animation-fill-mode: backwards;
        }
        .hero .cta-button:hover { background-color: #7dd3fc; transform: translateY(-3px); box-shadow: 0 5px 25px rgba(56, 189, 248, 0.4); }
        @keyframes slideInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
        
        .features { margin-top: 4rem; animation: fadeIn 1s ease-out 0.6s; animation-fill-mode: backwards; }
        .features h2 { text-align: center; font-size: 2.5rem; color: #fff; margin-bottom: 2rem; }
        .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; }
        .feature-card {
            background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(51, 65, 85, 0.5);
            border-radius: 16px; padding: 2rem;
        }
        .feature-card h3 { color: #38bdf8; margin-bottom: 1rem; }
        .feature-card p { color: #cbd5e1; }
    </style>
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/login" class="button-secondary">Login</a></li>
            <li><a href="/register" class="button-primary">Register</a></li>
        </ul>
    </nav>
    <div class="container">
        <main>
            <section class="hero">
                <h1>Welcome to the Future of <span>Security</span></h1>
                <p class="subtitle">
                    Experience a professional Zero Trust Network Access (ZTNA) demonstration. 
                    This app simulates how ZTNA works by verifying user identity, checking device posture, 
                    and enforcing granular, context-aware access policies.
                </p>
                <a href="/register" class="cta-button">Get Started & Test Access</a>
            </section>
            
            <section class="features">
                <h2>How This ZTNA Demo Works</h2>
                <div class="features-grid">
                    <div class="feature-card">
                        <h3>1. Strong Identity (MFA)</h3>
                        <p>All users must register and log in using Multi-Factor Authentication (MFA). 
                        Identity is the first pillar of Zero Trust.</p>
                    </div>
                    <div class="feature-card">
                        <h3>2. Device Posture Check</h3>
                        <p>During login, the server checks your 'User-Agent'. In this demo, 
                        it only allows "Mac" or "Windows" devices, simulating a compliance check.</p>
                    </div>
                    <div class="feature-card">
                        <h3>3. Context-Aware Policy</h3>
                        <p>Access is granular. A 'Finance' role can only access the 'Finance DB' from a specific IP (127.0.0.1) and only during business hours (09:00-17:00 UTC).</p>
                    </div>
                    <div class="feature-card">
                        <h3>4. Admin-Managed Policies</h3>
                        <p>Log in as 'admin' to access a dashboard where you can add or delete access policies in real-time. Changes take effect on the user's next request.</p>
                    </div>
                </div>
            </section>
        </main>
    </div>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""

# --- Page 2: Register ---
REGISTER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - Register</title>
    """ + GLOBAL_CSS + """
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/login" class="button-secondary">Login</a></li>
            <li><a href="/register" class="button-primary">Register</a></li>
        </ul>
    </nav>
    <div class="container">
        <form class="form-card" id="registerForm">
            <h1>Create Your Account</h1>
            <div id="step1_fields">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" required>
                </div>
                <div class="form-group">
                    <label for="role">Select Role</label>
                    <select id="role" required>
                        <option value="Finance">Finance</option>
                        <option value="HR">HR</option>
                        <option value="Engineering">Engineering (No Access)</option>
                        <option value="admin">Admin</option> </select>
                    </select>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" required>
                </div>
            </div>
            <div id="step2_mfa" style="display: none;">
                <p style="text-align: center; margin-bottom: 1rem; color: #cbd5e1;">Scan this QR with your Authenticator App</p>
                <div class="qr-container">
                    <img id="qrCodeImg" src="" alt="Loading QR Code...">
                </div>
                <div class="form-group">
                    <label for="mfa_code">Enter 6-Digit Code</label>
                    <input type="text" id="mfa_code" required autocomplete="off" maxlength="6">
                </div>
            </div>
            <button type="button" class="btn-submit" id="submitBtn">Continue to MFA Setup</button>
            <div id="message" class="message"></div>
        </form>
    </div>
    <script>
        let currentState = 'step1_fields';
        let tempMfaToken = null;
        const form = document.getElementById('registerForm');
        const submitBtn = document.getElementById('submitBtn');
        const messageEl = document.getElementById('message');
        submitBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            messageEl.textContent = '';
            messageEl.className = 'message';
            submitBtn.disabled = true;
            if (currentState === 'step1_fields') {
                await handleStep1();
            } else if (currentState === 'step2_mfa') {
                await handleStep2();
            }
        });
        async function handleStep1() {
            const password = document.getElementById('password').value;
            const confirm_password = document.getElementById('confirm_password').value;
            if (password !== confirm_password) { showError('Passwords do not match.'); return; }
            if (password.length < 6) { showError('Password must be at least 6 characters.'); return; }
            submitBtn.textContent = 'Generating QR Code...';
            try {
                const response = await fetch('/api/register-mfa-secret');
                if (!response.ok) { throw new Error('Could not generate MFA secret. Please try again.'); }
                tempMfaToken = response.headers.get('x-mfa-temp-token');
                if (!tempMfaToken) { throw new Error('MFA token not received. Please try again.'); }
                const imageBlob = await response.blob();
                document.getElementById('qrCodeImg').src = URL.createObjectURL(imageBlob);
                document.getElementById('step1_fields').style.display = 'none';
                document.getElementById('step2_mfa').style.display = 'block';
                submitBtn.textContent = 'Complete Registration';
                currentState = 'step2_mfa';
            } catch (error) { showError(error.message);
            } finally { submitBtn.disabled = false; }
        }
        async function handleStep2() {
            submitBtn.textContent = 'Verifying...';
            const payload = {
                username: document.getElementById('username').value,
                email: document.getElementById('email').value,
                role: document.getElementById('role').value,
                password: document.getElementById('password').value,
                mfa_code: document.getElementById('mfa_code').value,
                mfa_temp_token: tempMfaToken
            };
            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                if (!response.ok) { throw new Error(data.message || 'Registration failed.'); }
                showSuccess(data.message);
                setTimeout(() => { window.location.href = '/login'; }, 2000);
            } catch (error) {
                showError(error.message);
                submitBtn.textContent = 'Complete Registration';
                submitBtn.disabled = false;
            }
        }
        function showError(msg) { messageEl.textContent = msg; messageEl.className = 'message error'; submitBtn.disabled = false; }
        function showSuccess(msg) { messageEl.textContent = msg; messageEl.className = 'message success'; }
    </script>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""

# --- Page 3: Login (--- MODIFIED ---) ---
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - Login</title>
    """ + GLOBAL_CSS + """
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/login" class="button-secondary">Login</a></li>
            <li><a href="/register" class="button-primary">Register</a></li>
        </ul>
    </nav>
    <div class="container">
        <form class="form-card" id="loginForm">
            <h1>Secure Login</h1>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" required>
            </div>
            <button type="button" class="btn-submit" id="submitBtn">Continue</button>
            <div id="message" class="message"></div>
        </form>
    </div>
    <script>
        const form = document.getElementById('loginForm');
        const submitBtn = document.getElementById('submitBtn');
        const messageEl = document.getElementById('message');
        submitBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            messageEl.textContent = 'Verifying...';
            messageEl.className = 'message';
            submitBtn.disabled = true;
            const payload = {
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
            };
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'User-Agent': navigator.userAgent
                    },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                if (!response.ok) { throw new Error(data.message || 'Login failed.'); }
                localStorage.setItem('mfa_temp_token', data.mfa_token);
                window.location.href = '/verify-mfa';
            } catch (error) {
                messageEl.textContent = error.message;
                messageEl.className = 'message error';
                submitBtn.disabled = false;
            }
        });
    </script>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""

# --- Page 4: Verify MFA ---
VERIFY_MFA_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - Verify MFA</title>
    """ + GLOBAL_CSS + """
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/login" class="button-secondary">Login</a></li>
            <li><a href="/register" class="button-primary">Register</a></li>
        </ul>
    </nav>
    <div class="container">
        <form class="form-card" id="mfaForm">
            <h1>Check Your Authenticator</h1>
            <p style="text-align: center; margin-bottom: 1.5rem; color: #cbd5e1;">Enter the 6-digit code from your app.</p>
            <div class="form-group">
                <label for="mfa_code">MFA Code</label>
                <input type="text" id="mfa_code" required autocomplete="off" maxlength="6">
            </div>
            <button type="button" class="btn-submit" id="submitBtn">Verify & Login</button>
            <div id="message" class="message"></div>
        </form>
    </div>
    <script>
        const form = document.getElementById('mfaForm');
        const submitBtn = document.getElementById('submitBtn');
        const messageEl = document.getElementById('message');
        const tempToken = localStorage.getItem('mfa_temp_token');
        if (!tempToken) { window.location.href = '/login'; }
        submitBtn.addEventListener('click', async (e) => { 
            e.preventDefault();
            messageEl.textContent = 'Verifying...';
            messageEl.className = 'message';
            submitBtn.disabled = true;
            const payload = {
                mfa_token: tempToken,
                mfa_code: document.getElementById('mfa_code').value
            };
            try {
                const response = await fetch('/api/verify-mfa', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                if (!response.ok) { throw new Error(data.message || 'MFA verification failed.'); }
                localStorage.removeItem('mfa_temp_token');
                localStorage.setItem('ztna_token', data.token);
                window.location.href = '/dashboard';
            } catch (error) {
                messageEl.textContent = error.message;
                messageEl.className = 'message error';
                submitBtn.disabled = false;
            }
        });
    </script>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""

# --- Page 5: Dashboard (--- MODIFIED ---) ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - Dashboard</title>
    """ + GLOBAL_CSS + """
    <style>
        .dashboard-card { margin-bottom: 2rem; }
        #tokenDisplay pre { font-size: 0.8rem; }
        #results { margin-top: 1.5rem; padding: 0; background: #0f172a; border: 1px solid #334155; border-radius: 8px; min-height: 100px; }
        .log-entry-placeholder { padding: 1.5rem; color: #94a3b8; }
        .log-entry { border-bottom: 1px solid #1e293b; animation: fadeIn 0.5s ease; }
        .log-entry:last-child { border-bottom: none; }
        .log-header {
            display: flex; justify-content: space-between; align-items: center;
            padding: 0.75rem 1.5rem; background: #1e293b;
        }
        .log-header span { font-family: monospace; font-size: 0.9rem; }
        .log-header .status-granted { font-weight: 700; color: #4ade80; }
        .log-header .status-denied { font-weight: 700; color: #f87171; }
        .log-body { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; padding: 1.5rem; }
        .log-context h4 { color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; margin-bottom: 0.5rem; }
        .log-context pre { font-size: 0.85rem; padding: 0; white-space: pre-wrap; word-wrap: break-word; }
        
    </style>
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/profile" class="button-secondary">Profile</a></li>
            <li id="admin-link-li" style="display:none;"><a href="/admin" class="button-primary">Admin Panel</a></li>
            <li><button id="logoutBtn" class="button-secondary">Logout</button></li>
        </ul>
    </nav>
    <div class="container">
        <div class="dashboard-grid">
            <div class="dashboard-card">
                <h3>Available Resources</h3>
                <div class="controls">
                    <button id="financeBtn">Access Finance DB</button>
                    <button id="hrBtn">Access HR Portal</button>
                </div>
            </div>
            <div class="dashboard-card">
                <h3>Your Access Token (JWT)</h3>
                <div id="tokenDisplay" style="word-break: break-all; background: #0f172a; padding: 1rem; border-radius: 8px;">
                    <pre>Loading...</pre>
                </div>
            </div>
        </div>
        <div class="dashboard-card">
            <h3>ZTNA Policy Decision Log</h3>
            <div id="results">
                <div class="log-entry-placeholder">Click a resource button to simulate a ZTNA decision...</div>
            </div>
        </div>
    </div>
    <script>
        const token = localStorage.getItem('ztna_token');
        const tokenDisplay = document.getElementById('tokenDisplay');
        const resultsEl = document.getElementById('results');
        let userPayload = {};

        if (!token) {
            window.location.href = '/login';
        } else {
            try {
                userPayload = JSON.parse(atob(token.split('.')[1]));
                tokenDisplay.innerHTML = `<pre>${JSON.stringify(userPayload, null, 2)}</pre>`;
                
                // --- NEW: Show Admin link if admin ---
                if (userPayload.role === 'admin') {
                    document.getElementById('admin-link-li').style.display = 'block';
                }
            } catch (e) {
                tokenDisplay.innerHTML = "<pre>Invalid token format.</pre>";
            }
        }
        
        async function fetchZtna(endpoint, options = {}) {
            const defaultOptions = {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
            };
            const config = { ...defaultOptions, ...options };
            config.headers = { ...defaultOptions.headers, ...options.headers };
            return fetch(endpoint, config);
        }

        async function requestResource(resource, resourceName) {
            const placeholder = document.querySelector('.log-entry-placeholder');
            if (placeholder) placeholder.style.display = 'none';
            try {
                const response = await fetchZtna(`/api/resource/${resource}`);
                const data = await response.json();
                if (!response.ok) throw new Error(data.message);
                logToResults(resourceName, data, true);
            } catch (error) {
                logToResults(resourceName, { message: error.message }, false);
            }
        }

        async function logout() {
            try {
                const response = await fetchZtna('/api/logout', { method: 'POST' });
                localStorage.removeItem('ztna_token');
                tokenDisplay.innerHTML = "<pre>Token has been revoked.</pre>";
                logToResults('Logout', { message: 'Token revoked. Logged out.'}, false);
                setTimeout(() => window.location.href = '/login', 1000);
            } catch (error) {
                logToResults('Logout', { message: error.message }, false);
            }
        }
        
        function logToResults(resourceName, data, isSuccess) {
            const timestamp = new Date().toLocaleTimeString();
            const statusClass = isSuccess ? 'status-granted' : 'status-denied';
            const statusText = isSuccess ? 'GRANTED' : 'DENIED';
            const requestContext = {
                user: userPayload.username,
                role: userPayload.role,
                requesting: resourceName,
                device: navigator.userAgent.substring(0, 40) + "...",
                ip: "127.0.0.1" // In a real app, this would be fetched
            };
            const decisionContext = {
                decision: statusText,
                reason: data.message,
                data: data.data || "N/A"
            };
            const logHtml = `
            <div class="log-entry">
                <div class="log-header">
                    <span>${timestamp}</span>
                    <span class="${statusClass}">${statusText}</span>
                </div>
                <div class="log-body">
                    <div class="log-context">
                        <h4>REQUEST CONTEXT</h4>
                        <pre>${JSON.stringify(requestContext, null, 2)}</pre>
                    </div>
                    <div class="log-context">
                        <h4>POLICY DECISION</h4>
                        <pre>${JSON.stringify(decisionContext, null, 2)}</pre>
                    </div>
                </div>
            </div>
            `;
            resultsEl.insertAdjacentHTML('afterbegin', logHtml);
        }

        document.getElementById('financeBtn').addEventListener('click', () => requestResource('financeDB', 'Finance Database'));
        document.getElementById('hrBtn').addEventListener('click', () => requestResource('hrPortal', 'HR Portal'));
        document.getElementById('logoutBtn').addEventListener('click', logout);
    </script>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""

# --- NEW: Page 6: User Profile ---
PROFILE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - User Profile</title>
    """ + GLOBAL_CSS + """
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/dashboard" class="button-secondary">Dashboard</a></li>
            <li id="admin-link-li" style="display:none;"><a href="/admin" class="button-primary">Admin Panel</a></li>
            <li><button id="logoutBtn" class="button-secondary">Logout</button></li>
        </ul>
    </nav>
    <div class="container">
        <div class="dashboard-card" style="max-width: 600px; margin: 2rem auto;">
            <h3>User Profile</h3>
            <div id="userInfo">
                <p><strong>Username:</strong> <span id="username">Loading...</span></p>
                <p><strong>Email:</strong> <span id="email">Loading...</span></p>
                <p><strong>Role:</strong> <span id="role">Loading...</span></p>
            </div>
        </div>
    
        <div class="dashboard-card" style="max-width: 600px; margin: 2rem auto;">
            <h3>Multi-Factor Authentication</h3>
            <p style="color: #cbd5e1; margin-bottom: 1.5rem;">
                If you lose access to your authenticator, you can reset it here.
                You will be required to scan a new QR code and verify one code.
            </p>
            <button id="resetMfaBtn" class="btn-submit" style="background-color: #f87171;">Reset MFA</button>
            
            <div id="mfa-reset-flow" style="display: none; margin-top: 2rem;">
                <p style="text-align: center; margin-bottom: 1rem; color: #cbd5e1;">Scan this new QR Code</p>
                <div class="qr-container">
                    <img id="qrCodeImg" src="" alt="Loading QR Code...">
                </div>
                <div class="form-group">
                    <label for="mfa_code">Enter 6-Digit Code from New Secret</label>
                    <input type="text" id="mfa_code" required autocomplete="off" maxlength="6">
                </div>
                <button id="confirmMfaBtn" class="btn-submit">Verify & Save New MFA</button>
            </div>
            <div id="message" class="message" style="margin-top: 1.5rem;"></div>
        </div>
    </div>
    
    <script>
        const token = localStorage.getItem('ztna_token');
        const messageEl = document.getElementById('message');
        let mfaResetTempToken = null;
        let userPayload = {};

        if (!token) {
            window.location.href = '/login';
        }

        // Helper to make authorized requests
        async function fetchZtna(endpoint, options = {}) {
            const defaultOptions = {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
            };
            const config = { ...defaultOptions, ...options };
            config.headers = { ...defaultOptions.headers, ...options.headers };
            return fetch(endpoint, config);
        }

        // --- Populate User Info ---
        try {
            userPayload = JSON.parse(atob(token.split('.')[1]));
            document.getElementById('username').textContent = userPayload.username;
            document.getElementById('role').textContent = userPayload.role;
            // Email isn't in the token, but in a real app you'd fetch /api/profile
            document.getElementById('email').textContent = "user@example.com (from token)";
            
            if (userPayload.role === 'admin') {
                document.getElementById('admin-link-li').style.display = 'block';
            }
        } catch (e) {
            window.location.href = '/login';
        }

        // --- MFA Reset Flow ---
        const resetMfaBtn = document.getElementById('resetMfaBtn');
        const confirmMfaBtn = document.getElementById('confirmMfaBtn');
        const resetFlowDiv = document.getElementById('mfa-reset-flow');

        resetMfaBtn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to reset your MFA? You will need to scan a new code.')) {
                return;
            }
            
            resetMfaBtn.disabled = true;
            resetMfaBtn.textContent = 'Generating...';
            messageEl.className = 'message';
            messageEl.textContent = '';
            
            try {
                const response = await fetchZtna('/api/profile/reset-mfa-secret', { method: 'POST' });
                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.message || 'Could not generate MFA secret.');
                }
                
                mfaResetTempToken = response.headers.get('x-mfa-temp-token');
                const imageBlob = await response.blob();
                document.getElementById('qrCodeImg').src = URL.createObjectURL(imageBlob);
                
                resetFlowDiv.style.display = 'block';
                resetMfaBtn.style.display = 'none'; // Hide initial button
                messageEl.className = 'message success';
                messageEl.textContent = 'Scan the new code and enter the 6-digit number to verify.';

            } catch (err) {
                messageEl.className = 'message error';
                messageEl.textContent = err.message;
                resetMfaBtn.disabled = false;
                resetMfaBtn.textContent = 'Reset MFA';
            }
        });

        confirmMfaBtn.addEventListener('click', async () => {
            confirmMfaBtn.disabled = true;
            confirmMfaBtn.textContent = 'Verifying...';
            const mfaCode = document.getElementById('mfa_code').value;

            try {
                const response = await fetchZtna('/api/profile/confirm-mfa-reset', {
                    method: 'POST',
                    body: JSON.stringify({
                        mfa_temp_token: mfaResetTempToken,
                        mfa_code: mfaCode
                    })
                });
                
                const data = await response.json();
                if (!response.ok) { throw new Error(data.message); }
                
                messageEl.className = 'message success';
                messageEl.textContent = data.message;
                resetFlowDiv.style.display = 'none';

            } catch (err) {
                messageEl.className = 'message error';
                messageEl.textContent = err.message;
                confirmMfaBtn.disabled = false;
                confirmMfaBtn.textContent = 'Verify & Save New MFA';
            }
        });
        
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            await fetchZtna('/api/logout', { method: 'POST' });
            localStorage.removeItem('ztna_token');
            window.location.href = '/login';
        });
    </script>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""

# --- NEW: Page 7: Admin Panel ---
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTNA Pro Demo - Admin Panel</title>
    """ + GLOBAL_CSS + """
    <style>
        .policy-table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
        .policy-table th, .policy-table td {
            padding: 0.75rem 1rem;
            border: 1px solid #334155;
            text-align: left;
        }
        .policy-table th { background-color: #1e293b; }
        .policy-table td.actions { width: 100px; text-align: center; }
        .policy-table .delete-btn {
            background: #ef4444; color: #fff; border: none; padding: 0.5rem;
            border-radius: 4px; cursor: pointer;
        }
        .policy-table .delete-btn:hover { background: #f87171; }
        
        .add-policy-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }
        @media (max-width: 768px) { .add-policy-form { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <nav>
        <a href="/" class="logo">ZTNA<span>Pro</span></a>
        <ul class="nav-links">
            <li><a href="/dashboard" class="button-secondary">Dashboard</a></li>
            <li><a href="/profile" class="button-secondary">Profile</a></li>
            <li><button id="logoutBtn" class="button-secondary">Logout</button></li>
        </ul>
    </nav>
    <div class="container">
        <div class="dashboard-card">
            <h3>Add New Policy</h3>
            <form id="addPolicyForm" class="add-policy-form">
                <div class="form-group">
                    <label for="role">Role (Required)</label>
                    <input type="text" id="new_role" placeholder="e.g., Engineering" required>
                </div>
                <div class="form-group">
                    <label for="resource">Resource (Required)</label>
                    <input type="text" id="new_resource" placeholder="e.g., hrPortal" required>
                </div>
                <div class="form-group">
                    <label for="allowed_ips">Allowed IPs (comma-separated)</label>
                    <input type="text" id="new_ips" placeholder="e.g., 127.0.0.1,192.168.1.100">
                </div>
                <div class="form-group">
                    <label for="start_time">Start Time (UTC, HH:MM)</label>
                    <input type="text" id="new_start_time" placeholder="e.g., 09:00">
                </div>
                <div class="form-group">
                    <label for="end_time">End Time (UTC, HH:MM)</label>
                    <input type="text" id="new_end_time" placeholder="e.g., 17:00">
                </div>
                <div class="form-group" style="grid-column: 1 / -1;">
                    <button type="submit" class="btn-submit">Add Policy</button>
                </div>
            </form>
            <div id="message" class="message"></div>
        </div>
        
        <div class="dashboard-card">
            <h3>Current Access Policies</h3>
            <table class="policy-table">
                <thead>
                    <tr>
                        <th>Role</th>
                        <th>Resource</th>
                        <th>Context (IPs, Time)</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="policyList">
                    <tr><td colspan="4" style="text-align: center;">Loading policies...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        const token = localStorage.getItem('ztna_token');
        const policyListEl = document.getElementById('policyList');
        const addPolicyForm = document.getElementById('addPolicyForm');
        const messageEl = document.getElementById('message');

        if (!token) { window.location.href = '/login'; }
        
        async function fetchZtna(endpoint, options = {}) {
            const defaultOptions = {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
            };
            const config = { ...defaultOptions, ...options };
            config.headers = { ...defaultOptions.headers, ...options.headers };
            
            const response = await fetch(endpoint, config);
            
            // --- NEW: Admin auth check ---
            if (response.status === 401 || response.status === 403) {
                // Token is bad or user is not admin
                localStorage.removeItem('ztna_token');
                window.location.href = '/login';
            }
            return response;
        }

        // --- Load All Policies ---
        async function loadPolicies() {
            try {
                const response = await fetchZtna('/api/admin/policies');
                const policies = await response.json();
                
                if (!response.ok) { throw new Error(policies.message); }
                
                policyListEl.innerHTML = ''; // Clear loading
                if (policies.length === 0) {
                    policyListEl.innerHTML = '<tr><td colspan="4" style="text-align: center;">No policies found.</td></tr>';
                }
                
                policies.forEach(policy => {
                    let context = [];
                    if (policy.allowed_ips) context.push(`IPs: ${policy.allowed_ips.join(', ')}`);
                    if (policy.start_time) context.push(`Start: ${policy.start_time}`);
                    if (policy.end_time) context.push(`End: ${policy.end_time}`);
                    
                    policyListEl.innerHTML += `
                        <tr data-id="${policy._id}">
                            <td>${policy.role}</td>
                            <td>${policy.resource}</td>
                            <td>${context.join(' | ') || 'None'}</td>
                            <td class="actions">
                                <button class="delete-btn" onclick="deletePolicy('${policy._id}')">Delete</button>
                            </td>
                        </tr>
                    `;
                });
            } catch (err) {
                policyListEl.innerHTML = `<tr><td colspan="4" style="text-align: center; color: #f87171;">Error: ${err.message}</td></tr>`;
            }
        }

        // --- Add New Policy ---
        addPolicyForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            messageEl.className = 'message';
            messageEl.textContent = '';
            
            const payload = {
                role: document.getElementById('new_role').value,
                resource: document.getElementById('new_resource').value,
                allowed_ips: document.getElementById('new_ips').value,
                start_time: document.getElementById('new_start_time').value,
                end_time: document.getElementById('new_end_time').value,
            };
            
            try {
                const response = await fetchZtna('/api/admin/policies', {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                
                if (!response.ok) { throw new Error(data.message); }
                
                messageEl.className = 'message success';
                messageEl.textContent = 'Policy created successfully!';
                addPolicyForm.reset();
                loadPolicies(); // Refresh the list
                
            } catch (err) {
                messageEl.className = 'message error';
                messageEl.textContent = err.message;
            }
        });
        
        // --- Delete Policy (Global function) ---
        async function deletePolicy(policyId) {
            if (!confirm('Are you sure you want to delete this policy?')) return;
            
            try {
                const response = await fetchZtna(`/api/admin/policy/${policyId}`, {
                    method: 'DELETE'
                });
                const data = await response.json();
                if (!response.ok) { throw new Error(data.message); }
                
                loadPolicies(); // Refresh the list
                
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        // --- Initial Load ---
        loadPolicies();
        
        // Logout
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            await fetchZtna('/api/logout', { method: 'POST' });
            localStorage.removeItem('ztna_token');
            window.location.href = '/login';
        });
    </script>
    """ + GLOBAL_FOOTER_HTML + """
</body>
</html>
"""


# ------------------------------------------------------------------
# --- Database Setup Command - --- MODIFIED ---
# ------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables and demo data."""
    if db is None:
        print("MongoDB not connected. Aborting init-db.")
        return
        
    print("Dropping 'users' and 'policies' collections...")
    try:
        db.users.drop()
        db.policies.drop()
    except Exception as e:
        print(f"Error dropping collections: {e}")
        return
    
    # Generate secrets for demo users
    secret_x = pyotp.random_base32()
    secret_y = pyotp.random_base32()
    secret_admin = pyotp.random_base32()

    try:
        hashed_pass_x = bcrypt.generate_password_hash("pass123").decode('utf-8')
        hashed_pass_y = bcrypt.generate_password_hash("pass456").decode('utf-8')
        hashed_pass_admin = bcrypt.generate_password_hash("admin").decode('utf-8')
    except Exception as e:
        print(f"Error hashing passwords: {e}")
        return

    # Create User documents
    user_x = {
        "username": 'userX', "email": 'userx@example.com',
        "password_hash": hashed_pass_x, "role": 'Finance',
        "mfa_secret": secret_x, "mfa_enabled": True, "last_login": None
    }
    user_y = {
        "username": 'userY', "email": 'usery@example.com',
        "password_hash": hashed_pass_y, "role": 'HR',
        "mfa_secret": secret_y, "mfa_enabled": True, "last_login": None
    }
    admin_user = {
        "username": 'admin', "email": 'admin@example.com',
        "password_hash": hashed_pass_admin, "role": 'admin',
        "mfa_secret": secret_admin, "mfa_enabled": True, "last_login": None
    }
    
    try:
        db.users.insert_many([user_x, user_y, admin_user])
        print("Adding users: userX (Finance), userY (HR), admin (admin)")
        
        # --- NEW Context-Aware Policies ---
        policy1 = {
            "role": 'Finance', 
            "resource": 'financeDB',
            "allowed_ips": ["127.0.0.1"], # Only localhost
            "start_time": "09:00",        # 9 AM UTC
            "end_time": "17:00"           # 5 PM UTC
        }
        policy2 = {
            "role": 'HR', 
            "resource": 'hrPortal'
            # No IP or time restrictions
        }
        policy_admin = {
            "role": "admin",
            "resource": "adminPanel"
        }
        
        db.policies.insert_many([policy1, policy2, policy_admin])
        print("Adding policies:")
        print("  - Finance -> financeDB (From 127.0.0.1, 09:00-17:00 UTC)")
        print("  - HR -> hrPortal (No restrictions)")
        print("  - admin -> adminPanel (No restrictions)")
        
        print("✅ Database initialized successfully.")
        print("\n" + "="*50)
        print("IMPORTANT: Add these to your Google Authenticator app:")
        print(f"  userX Secret: {secret_x}")
        print(f"  userY Secret: {secret_y}")
        print(f"  admin Secret: {secret_admin}")
        print("="*50 + "\n")
    except Exception as e:
        print(f"Error inserting documents: {e}")

# ------------------------------------------------------------------
# --- Main App Runner ---
# ------------------------------------------------------------------
if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # --- MODIFIED: Now writes 7 HTML files ---
    templates = {
        'home.html': HOME_HTML,
        'register.html': REGISTER_HTML,
        'login.html': LOGIN_HTML,
        'verify_mfa.html': VERIFY_MFA_HTML,
        'dashboard.html': DASHBOARD_HTML,
        'profile.html': PROFILE_HTML,   # --- NEW ---
        'admin.html': ADMIN_HTML        # --- NEW ---
    }
    
    for filename, content in templates.items():
        with open(os.path.join('templates', filename), 'w') as f:
            f.write(content)
    print(f"✅ Wrote {len(templates)} HTML templates to 'templates/' folder.")
        
    print("\n" + "="*50)
    print("🚀 ZTNA Professional Demo Server starting...")
    print("Access the demo at: http://127.0.0.1:5000")
    print("To initialize the database, run this in your terminal:")
    print("export FLASK_APP=app.py")
    print("python -m flask init-db")
    print("="*50 + "\n")
    
    # Note: Flask's reloader will use 127.0.0.1 as the IP,
    # which matches the 'Finance' policy.
    app.run(debug=True, host='0.0.0.0', port=5000)