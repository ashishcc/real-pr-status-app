"""Debug script for running FastAPI with uvicorn in PyCharm"""
import uvicorn
from app.main import app

if __name__ == "__main__":
    # Run with reload enabled for development
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        # Optional: Add more configuration
        log_level="debug",
        access_log=True,
        reload_dirs=["app"]
    )