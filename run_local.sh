
#!/bin/bash

echo "🛡️  ExfilEye DLP Email Security Monitor - macOS/Linux Launcher"
echo "============================================================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    echo "Please install Python 3.11+ from https://python.org"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "app_fixed.py" ]; then
    echo "❌ app_fixed.py not found"
    echo "Please ensure you're running this from the correct directory"
    exit 1
fi

# Make sure the script is executable
chmod +x "$0"

# Run the Python launcher
python3 run_local.py
