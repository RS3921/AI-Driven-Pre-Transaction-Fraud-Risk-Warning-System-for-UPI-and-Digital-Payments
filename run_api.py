"""
Run this to start the API server.

Just run:   python run_api.py

Then open http://localhost:8000 in your browser.
Press CTRL+C in this terminal to stop the server.
"""

import uvicorn

if __name__ == "__main__":
    print("Starting server... open http://localhost:8000 in your browser once it's ready.\n")
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True, app_dir=".")
