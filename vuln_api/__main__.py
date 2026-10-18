"""Entrypoint to run vuln_api server via python -m vuln_api."""

import uvicorn

from vuln_api.app import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5050)
