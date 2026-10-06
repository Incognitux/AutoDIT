from flask import Flask, jsonify, request

app = Flask(__name__)


# Mock database
USERS_DB = {
        1: {
            "id": 1,
            "username": "geralt",
            "email": "geralt@example.com",
            "role": "user",
            # Excessive data fields that should not be returned to public callers:
            "password_hash": "$2b$12$e8kPj91gK.9uL128.9s1...",
            "ssn": "123-45-6789",
            "internal_db_id": "usr_sec_00984a"
            }
        }


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

# 1. VULNERABILITY: Excessive Data Exposure
# Exposes full database records including hashes and SSNs
@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    user = USERS_DB.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user), 200

# 2. VULNERABILITY: Missing Rate Limiting
@app.route('/api/v1/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "pass123":
        return jsonify({"token": "mock-jwt-token"}), 200

    return jsonify({"error": "Invalid credentions"}), 401

# 3. VULNERABILITY: Broken Authentication
@app.route('/api/v1/admin/dashboard', methods=['GET'])
def admin_dashboard():
    auth_header = request.headers.get('Authentication')

    # FLAW: Returns 200 OK even if the authentication header is absent
    return jsonify({
        "message": "Welcome to the admin dashboard",
        "sensitive_metrics": {"total_revenue": 450000}
        }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5050)
