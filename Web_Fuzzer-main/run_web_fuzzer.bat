@echo off
echo [INFO] Installing dependencies...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Please check your python installation.
    pause
    exit /b %errorlevel%
)

echo [INFO] Starting Web Fuzzer UI...
python web_app.py
pause
