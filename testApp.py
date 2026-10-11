from typing import Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="AutoDIT Vulnerable Test API")


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
        "internal_db_id": "usr_sec_00984a",
    }
}


class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None


@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy"}


# 1. VULNERABILITY: Excessive Data Exposure
# Exposes full database records including hashes and SSNs
@app.get("/api/v1/users/{user_id}")
def get_user_profile(user_id: int):
    user = USERS_DB.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    return user


# 2. VULNERABILITY: Missing Rate Limiting
@app.post("/api/v1/login")
def login(credentials: Optional[LoginRequest] = None):
    if (
        credentials
        and credentials.username == "admin"
        and credentials.password == "pass123"
    ):
        return {"token": "mock-jwt-token"}

    return JSONResponse(status_code=401, content={"error": "Invalid credentions"})


# 3. VULNERABILITY: Broken Authentication
@app.get("/api/v1/admin/dashboard")
def admin_dashboard(request: Request):
    auth_header = request.headers.get("Authentication") or request.headers.get(
        "Authorization"
    )

    # FLAW: Returns 200 OK even if the authentication header is absent
    return {
        "message": "Welcome to the admin dashboard",
        "sensitive_metrics": {"total_revenue": 450000},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=5050)
