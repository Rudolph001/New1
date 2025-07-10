
# ExfilEye DLP Local Setup Instructions

## Quick Start Guide

### Prerequisites
- **Python 3.11+** (recommended, minimum 3.8)
- **Internet connection** for package installation

### Installation Steps

#### For Windows:
1. **Download Python** from https://python.org if not installed
2. **Download all files** from this project to a folder
3. **Double-click** `run_local.bat`
4. **Wait** for packages to install (first time only)
5. **Access** the app at http://localhost:8501

#### For macOS/Linux:
1. **Open Terminal** and navigate to the project folder
2. **Run**: `chmod +x run_local.sh`
3. **Execute**: `./run_local.sh`
4. **Wait** for packages to install (first time only)
5. **Access** the app at http://localhost:8501

### Alternative Manual Setup

If the automated scripts don't work:

```bash
# Install packages
pip install -r requirements.txt

# Run application
streamlit run app_fixed.py --server.port 8501
```

## Required Files

Make sure you have these files in the same directory:
- ✅ `app_fixed.py` (main application)
- ✅ `auth.py` (authentication system)
- ✅ `domain_classifier.py` (domain classification)
- ✅ `security_config.py` (security configuration)
- ✅ `requirements.txt` (Python packages)
- ✅ `run_local.py` (launcher script)
- ✅ `run_local.bat` (Windows launcher)
- ✅ `run_local.sh` (macOS/Linux launcher)
- ✅ `.streamlit/config.toml` (optional configuration)

## Features Available Locally

✅ **Full Application Features**:
- Data upload and processing
- Security operations dashboard
- Network analysis
- Follow-up center
- Domain classification
- User authentication
- Risk scoring and anomaly detection

## Troubleshooting

### Common Issues:

**❌ "Python not found"**
- Install Python from https://python.org
- Make sure Python is added to your system PATH

**❌ "Package installation failed"**
- Check your internet connection
- Try: `pip install --upgrade pip`
- Run: `pip install -r requirements.txt` manually

**❌ "Permission denied" (macOS/Linux)**
- Run: `chmod +x run_local.sh`
- Or use: `bash run_local.sh`

**❌ "Port already in use"**
- Close any other Streamlit applications
- Or edit `run_local.py` to use a different port

### Performance Tips:

- **First run** may take 2-3 minutes to install packages
- **Subsequent runs** will start much faster
- **Large CSV files** may take time to process
- **Network graphs** work best with moderate-sized datasets

## Default Login Credentials

- **Username**: `admin`
- **Password**: `admin123`

Additional users can be created through the User Management section.

## Support

If you encounter issues:
1. Check that all files are in the same directory
2. Ensure Python 3.11+ is installed
3. Verify internet connection for package installation
4. Try running commands manually if scripts fail

## Security Notes

- This local setup uses the same authentication system as the cloud version
- User data is stored locally in `users.json`
- Audit logs are saved in `security_audit.json`
- All data processing happens locally on your machine
