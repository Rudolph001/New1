
#!/usr/bin/env python3
"""
Local runner for ExfilEye DLP Email Security Monitor
Run this file to start the application locally
"""

import subprocess
import sys
import os

def check_python_version():
    """Check if Python version is 3.11+"""
    if sys.version_info < (3, 11):
        print("⚠️  Warning: Python 3.11+ is recommended for best compatibility")
        print(f"Current version: {sys.version}")
    else:
        print(f"✅ Python version: {sys.version}")

def install_requirements():
    """Install required packages"""
    print("📦 Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All packages installed successfully!")
    except subprocess.CalledProcessError:
        print("❌ Failed to install packages. Please check your internet connection.")
        return False
    return True

def run_streamlit():
    """Run the Streamlit application"""
    print("🚀 Starting ExfilEye DLP Email Security Monitor...")
    print("📍 The application will open in your default web browser")
    print("🔗 Local URL: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the application")
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "app_fixed.py",
            "--server.address", "0.0.0.0",
            "--server.port", "8501",
            "--server.headless", "false"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
    except FileNotFoundError:
        print("❌ app_fixed.py not found. Make sure you're in the correct directory.")

if __name__ == "__main__":
    print("🛡️  ExfilEye DLP Email Security Monitor - Local Setup")
    print("=" * 55)
    
    check_python_version()
    
    # Check if requirements.txt exists
    if not os.path.exists("requirements.txt"):
        print("❌ requirements.txt not found. Please ensure all files are in the same directory.")
        sys.exit(1)
    
    # Check if main app file exists
    if not os.path.exists("app_fixed.py"):
        print("❌ app_fixed.py not found. Please ensure all files are in the same directory.")
        sys.exit(1)
    
    # Install requirements
    if install_requirements():
        print("\n" + "=" * 55)
        run_streamlit()
