
import streamlit as st
import json
import os
from datetime import datetime
from auth import get_current_user

class SecurityAuditLogger:
    def __init__(self, log_file='security_audit.json'):
        self.log_file = log_file
        
    def log_action(self, action, details=None, risk_level='info'):
        """Log security-related actions"""
        user = get_current_user()
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user.get('full_name', 'Unknown') if user else 'System',
            'username': st.session_state.get('username', 'Unknown'),
            'role': user.get('role', 'Unknown') if user else 'System',
            'action': action,
            'details': details or {},
            'risk_level': risk_level,
            'session_id': st.session_state.get('session_id', 'Unknown')
        }
        
        # Load existing logs
        logs = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            except:
                logs = []
        
        # Add new log
        logs.append(log_entry)
        
        # Keep only last 1000 entries
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        # Save logs
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def get_recent_logs(self, limit=50):
        """Get recent audit logs"""
        if not os.path.exists(self.log_file):
            return []
        
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
            return logs[-limit:] if len(logs) > limit else logs
        except:
            return []

# Initialize audit logger
audit_logger = SecurityAuditLogger()

# Security configuration
SECURITY_CONFIG = {
    'session_timeout_minutes': 120,
    'max_failed_attempts': 5,
    'password_min_length': 8,
    'require_password_complexity': True,
    'audit_all_actions': True,
    'ip_whitelist_enabled': False,
    'ip_whitelist': [],
    'two_factor_enabled': False,
    'data_encryption_enabled': True
}

def get_security_config():
    """Get current security configuration"""
    return SECURITY_CONFIG

def update_security_config(key, value):
    """Update security configuration"""
    if key in SECURITY_CONFIG:
        SECURITY_CONFIG[key] = value
        audit_logger.log_action(
            'security_config_updated',
            {'setting': key, 'new_value': value},
            'warning'
        )
        return True
    return False

def check_password_complexity(password):
    """Check if password meets complexity requirements"""
    if not SECURITY_CONFIG['require_password_complexity']:
        return True, "Password complexity check disabled"
    
    issues = []
    
    if len(password) < SECURITY_CONFIG['password_min_length']:
        issues.append(f"At least {SECURITY_CONFIG['password_min_length']} characters")
    
    if not any(c.isupper() for c in password):
        issues.append("At least one uppercase letter")
    
    if not any(c.islower() for c in password):
        issues.append("At least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        issues.append("At least one number")
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        issues.append("At least one special character")
    
    if issues:
        return False, "Password must contain: " + ", ".join(issues)
    
    return True, "Password meets complexity requirements"

def show_security_dashboard():
    """Show security dashboard for admins"""
    st.header("🔒 Security Dashboard")
    
    # Recent security events
    st.subheader("📊 Recent Security Events")
    
    logs = audit_logger.get_recent_logs(20)
    if logs:
        for log in reversed(logs):
            risk_color = {
                'info': '🔵',
                'warning': '🟡', 
                'error': '🔴',
                'critical': '⚫'
            }.get(log['risk_level'], '⚪')
            
            with st.expander(f"{risk_color} {log['action']} - {log['user']} - {log['timestamp'][:16]}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**User:** {log['user']} (@{log['username']})")
                    st.write(f"**Role:** {log['role']}")
                    st.write(f"**Action:** {log['action']}")
                with col2:
                    st.write(f"**Risk Level:** {log['risk_level'].upper()}")
                    st.write(f"**Time:** {log['timestamp']}")
                    if log['details']:
                        st.write(f"**Details:** {log['details']}")
    else:
        st.info("No security events logged yet")
    
    # Security settings
    st.subheader("⚙️ Security Configuration")
    
    with st.expander("🔧 Security Settings"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Authentication Settings**")
            st.write(f"Session Timeout: {SECURITY_CONFIG['session_timeout_minutes']} minutes")
            st.write(f"Max Failed Attempts: {SECURITY_CONFIG['max_failed_attempts']}")
            st.write(f"Password Min Length: {SECURITY_CONFIG['password_min_length']}")
            st.write(f"Password Complexity: {'✅ Enabled' if SECURITY_CONFIG['require_password_complexity'] else '❌ Disabled'}")
        
        with col2:
            st.write("**Security Features**")
            st.write(f"Audit Logging: {'✅ Enabled' if SECURITY_CONFIG['audit_all_actions'] else '❌ Disabled'}")
            st.write(f"IP Whitelist: {'✅ Enabled' if SECURITY_CONFIG['ip_whitelist_enabled'] else '❌ Disabled'}")
            st.write(f"Two Factor Auth: {'✅ Enabled' if SECURITY_CONFIG['two_factor_enabled'] else '❌ Disabled'}")
            st.write(f"Data Encryption: {'✅ Enabled' if SECURITY_CONFIG['data_encryption_enabled'] else '❌ Disabled'}")
