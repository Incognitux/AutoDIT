"""FastAPI application with vulnerable and hardened routes for testing."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="AutoDIT Vulnerable & Hardened Test API",
    version="1.0.0",
    description="Test target containing both deliberately vulnerable and hardened routes.",
)

# Mock database
USERS_DB = {
    1: {
        "id": 1,
        "username": "geralt",
        "email": "geralt@example.com",
        "role": "user",
        # Excessive data fields leaking beyond schema:
        "password_hash": "$2b$12$e8kPj91gK.9uL128.9s1abcde12345678901234567890123",
        "ssn": "123-45-6789",
        "internal_db_id": "usr_sec_00984a123",
    }
}


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


# ---------------------------------------------------------
# Standard / Health Route
# ---------------------------------------------------------
@app.get("/api/v1/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}


# ---------------------------------------------------------
# Vulnerable Routes (Legacy testApp.py behavior)
# ---------------------------------------------------------
# 1. VULNERABILITY: Excessive Data Exposure (DATA-001)
@app.get("/api/v1/users/{user_id}", response_model=None)
def get_user_profile(user_id: int) -> dict[str, object] | JSONResponse:
    user = USERS_DB.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    return user


# 2. VULNERABILITY: Missing Rate Limiting (RATE-001)
@app.post("/api/v1/login", response_model=None)
def login(credentials: LoginRequest | None = None) -> dict[str, str] | JSONResponse:
    if credentials and credentials.username == "admin" and credentials.password == "pass123":
        return {"token": "mock-jwt-token"}

    return JSONResponse(status_code=401, content={"error": "Invalid credentials"})


# 3. VULNERABILITY: Broken Authentication (AUTH-001)
@app.get("/api/v1/admin/dashboard")
def admin_dashboard(_request: Request) -> dict[str, object]:
    # FLAW: Returns 200 OK even when authentication header is absent
    return {
        "message": "Welcome to the admin dashboard",
        "sensitive_metrics": {"total_revenue": 450000},
    }


# ---------------------------------------------------------
# Hardened Routes (Produces ZERO findings)
# ---------------------------------------------------------
@app.get("/api/v1/hardened/users/{user_id}", response_model=None)
def get_hardened_user_profile(user_id: int) -> dict[str, object] | JSONResponse:
    user = USERS_DB.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    # Only return sanitized, public attributes:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }


@app.get("/api/v1/hardened/admin/dashboard", response_model=None)
def hardened_admin_dashboard(request: Request) -> dict[str, object] | JSONResponse:
    auth_header = request.headers.get("Authorization") or request.headers.get("Authentication")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "Unauthorized: Token missing"})

    return {
        "message": "Welcome to the admin dashboard",
        "sensitive_metrics": {"total_revenue": 450000},
    }
