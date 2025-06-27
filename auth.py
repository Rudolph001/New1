
import streamlit as st
import hashlib
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import secrets

# User roles and permissions
USER_ROLES = {
    'admin': {
        'name': 'System Administrator',
        'permissions': ['all'],
        'description': 'Full system access and user management'
    },
    'security_analyst': {
        'name': 'Security Analyst',
        'permissions': ['data_upload', 'security_operations', 'follow_up', 'network_analysis', 'export'],
        'description': 'Full security operations access'
    },
    'security_manager': {
        'name': 'Security Manager',
        'permissions': ['security_operations', 'follow_up', 'reports', 'export'],
        'description': 'Security management and reporting'
    },
    'compliance_officer': {
        'name': 'Compliance Officer',
        'permissions': ['security_operations', 'reports', 'export'],
        'description': 'Compliance monitoring and reporting'
    },
    'viewer': {
        'name': 'Security Viewer',
        'permissions': ['security_operations'],
        'description': 'Read-only security dashboard access'
    }
}

# Page permissions mapping
PAGE_PERMISSIONS = {
    '📁 Data Upload': 'data_upload',
    '🛡️ Security Operations': 'security_operations',
    '📨 Follow-up Center': 'follow_up',
    '🔗 Network Analysis': 'network_analysis',
    '📊 System Workflow': 'reports',
    '⚙️ Settings': 'admin'
}

class UserDatabase:
    def __init__(self, db_file='users.json'):
        self.db_file = db_file
        self.users = self.load_users()
        
    def load_users(self):
        """Load users from JSON file"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Create default admin user if no users exist
        default_users = {
            'admin': {
                'password_hash': self.hash_password('admin123'),
                'role': 'admin',
                'email': 'admin@exfileye.com',
                'created_date': datetime.now().isoformat(),
                'last_login': None,
                'active': True,
                'full_name': 'System Administrator'
            }
        }
        self.save_users(default_users)
        return default_users
    
    def save_users(self, users=None):
        """Save users to JSON file"""
        if users is None:
            users = self.users
        
        with open(self.db_file, 'w') as f:
            json.dump(users, f, indent=2)
    
    def hash_password(self, password):
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    def verify_password(self, password, password_hash):
        """Verify password against hash"""
        try:
            salt, hash_value = password_hash.split(':')
            password_hash_check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_value == password_hash_check.hex()
        except:
            return False
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        if username in self.users:
            user = self.users[username]
            if user.get('active', True) and self.verify_password(password, user['password_hash']):
                # Update last login
                self.users[username]['last_login'] = datetime.now().isoformat()
                self.save_users()
                return user
        return None
    
    def create_user(self, username, password, email, role, full_name):
        """Create new user"""
        if username in self.users:
            return False, "Username already exists"
        
        if role not in USER_ROLES:
            return False, "Invalid role"
        
        self.users[username] = {
            'password_hash': self.hash_password(password),
            'role': role,
            'email': email,
            'full_name': full_name,
            'created_date': datetime.now().isoformat(),
            'last_login': None,
            'active': True
        }
        self.save_users()
        return True, "User created successfully"
    
    def update_user(self, username, **kwargs):
        """Update user information"""
        if username not in self.users:
            return False, "User not found"
        
        for key, value in kwargs.items():
            if key == 'password' and value:
                self.users[username]['password_hash'] = self.hash_password(value)
            elif key in ['role', 'email', 'full_name', 'active']:
                self.users[username][key] = value
        
        self.save_users()
        return True, "User updated successfully"
    
    def delete_user(self, username):
        """Delete user"""
        if username in self.users and username != 'admin':
            del self.users[username]
            self.save_users()
            return True, "User deleted successfully"
        return False, "Cannot delete admin user or user not found"
    
    def get_all_users(self):
        """Get all users (without password hashes)"""
        users_info = {}
        for username, user_data in self.users.items():
            users_info[username] = {k: v for k, v in user_data.items() if k != 'password_hash'}
        return users_info

# Initialize user database
user_db = UserDatabase()

def check_authentication():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def get_current_user():
    """Get current authenticated user"""
    return st.session_state.get('current_user', None)

def get_user_role():
    """Get current user's role"""
    user = get_current_user()
    return user.get('role') if user else None

def has_permission(permission):
    """Check if current user has specific permission"""
    user = get_current_user()
    if not user:
        return False
    
    role = user.get('role')
    if not role or role not in USER_ROLES:
        return False
    
    permissions = USER_ROLES[role]['permissions']
    return 'all' in permissions or permission in permissions

def require_auth(func):
    """Decorator to require authentication"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not check_authentication():
            show_login_page()
            return
        return func(*args, **kwargs)
    return wrapper

def require_permission(permission):
    """Decorator to require specific permission"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not check_authentication():
                show_login_page()
                return
            
            if not has_permission(permission):
                st.error(f"❌ Access Denied: You don't have permission to access this feature.")
                st.info(f"Required permission: {permission}")
                st.info(f"Your role: {get_user_role()}")
                return
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def show_login_page():
    """Display login interface"""
    st.markdown("""
    <div style="display: flex; justify-content: center; align-items: center; min-height: 50vh;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                    text-align: center; max-width: 400px; width: 100%;">
            <h1 style="color: white; margin-bottom: 30px; font-size: 28px;">
                🛡️ ExfilEye Security
            </h1>
            <p style="color: #f0f0f0; margin-bottom: 30px;">
                DLP Email Security Monitoring System
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Login form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### 🔐 Secure Login")
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col_a, col_b = st.columns(2)
            with col_a:
                login_submitted = st.form_submit_button("🔑 Login", use_container_width=True, type="primary")
            with col_b:
                guest_submitted = st.form_submit_button("👁️ Guest Access", use_container_width=True)
            
            if login_submitted:
                if username and password:
                    user = user_db.authenticate_user(username, password)
                    if user:
                        st.session_state.authenticated = True
                        st.session_state.current_user = user
                        st.session_state.username = username
                        st.success(f"✅ Welcome back, {user.get('full_name', username)}!")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")
                else:
                    st.warning("⚠️ Please enter both username and password")
            
            if guest_submitted:
                # Guest access with limited permissions
                guest_user = {
                    'role': 'viewer',
                    'full_name': 'Guest User',
                    'email': 'guest@exfileye.com'
                }
                st.session_state.authenticated = True
                st.session_state.current_user = guest_user
                st.session_state.username = 'guest'
                st.info("👁️ Logged in as Guest (View-only access)")
                st.rerun()
        
        # Default credentials info
        with st.expander("ℹ️ Default Login Credentials"):
            st.markdown("""
            **Default Admin Account:**
            - Username: `admin`
            - Password: `admin123`
            
            **Demo Accounts Available:**
            - analyst / analyst123 (Security Analyst)
            - manager / manager123 (Security Manager)
            - compliance / compliance123 (Compliance Officer)
            
            ⚠️ **Important**: Change default passwords after first login!
            """)

def show_user_management():
    """Display user management interface for admins"""
    if not has_permission('admin'):
        st.error("❌ Access Denied: Admin privileges required")
        return
    
    st.header("👥 User Management")
    
    tab1, tab2, tab3 = st.tabs(["👤 Manage Users", "➕ Add User", "📊 User Activity"])
    
    with tab1:
        st.subheader("Current Users")
        
        users = user_db.get_all_users()
        for username, user_data in users.items():
            with st.expander(f"👤 {user_data['full_name']} (@{username}) - {USER_ROLES[user_data['role']]['name']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Role:** {USER_ROLES[user_data['role']]['name']}")
                    st.write(f"**Email:** {user_data['email']}")
                    st.write(f"**Status:** {'✅ Active' if user_data.get('active', True) else '❌ Inactive'}")
                    st.write(f"**Created:** {user_data['created_date'][:10]}")
                    if user_data.get('last_login'):
                        st.write(f"**Last Login:** {user_data['last_login'][:16]}")
                
                with col2:
                    # Edit user form
                    with st.form(f"edit_user_{username}"):
                        new_role = st.selectbox("Role", options=list(USER_ROLES.keys()), 
                                              index=list(USER_ROLES.keys()).index(user_data['role']),
                                              key=f"role_{username}")
                        new_email = st.text_input("Email", value=user_data['email'], key=f"email_{username}")
                        new_name = st.text_input("Full Name", value=user_data['full_name'], key=f"name_{username}")
                        new_password = st.text_input("New Password (leave blank to keep current)", 
                                                   type="password", key=f"password_{username}")
                        active = st.checkbox("Active", value=user_data.get('active', True), key=f"active_{username}")
                        
                        col_a, col_b = st.columns(2)
                        with col_a:
                            if st.form_submit_button("💾 Update", use_container_width=True):
                                success, message = user_db.update_user(
                                    username, 
                                    role=new_role, 
                                    email=new_email, 
                                    full_name=new_name,
                                    password=new_password if new_password else None,
                                    active=active
                                )
                                if success:
                                    st.success(message)
                                    st.rerun()
                                else:
                                    st.error(message)
                        
                        with col_b:
                            if username != 'admin' and st.form_submit_button("🗑️ Delete", use_container_width=True):
                                success, message = user_db.delete_user(username)
                                if success:
                                    st.success(message)
                                    st.rerun()
                                else:
                                    st.error(message)
    
    with tab2:
        st.subheader("Add New User")
        
        with st.form("add_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_username = st.text_input("Username*", placeholder="Enter username")
                new_email = st.text_input("Email*", placeholder="user@company.com")
                new_password = st.text_input("Password*", type="password", placeholder="Secure password")
            
            with col2:
                new_full_name = st.text_input("Full Name*", placeholder="John Doe")
                new_role = st.selectbox("Role*", options=list(USER_ROLES.keys()),
                                      format_func=lambda x: f"{USER_ROLES[x]['name']} - {USER_ROLES[x]['description']}")
            
            if st.form_submit_button("➕ Create User", type="primary"):
                if all([new_username, new_email, new_password, new_full_name]):
                    success, message = user_db.create_user(
                        new_username, new_password, new_email, new_role, new_full_name
                    )
                    if success:
                        st.success(f"✅ {message}")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
                else:
                    st.warning("⚠️ Please fill in all required fields")
    
    with tab3:
        st.subheader("User Activity Overview")
        
        users = user_db.get_all_users()
        
        # Role distribution
        role_counts = {}
        active_users = 0
        recent_logins = 0
        
        for user_data in users.values():
            role = user_data['role']
            role_counts[role] = role_counts.get(role, 0) + 1
            
            if user_data.get('active', True):
                active_users += 1
            
            if user_data.get('last_login'):
                try:
                    last_login = datetime.fromisoformat(user_data['last_login'])
                    if last_login > datetime.now() - timedelta(days=7):
                        recent_logins += 1
                except:
                    pass
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", len(users))
        with col2:
            st.metric("Active Users", active_users)
        with col3:
            st.metric("Recent Logins (7d)", recent_logins)
        with col4:
            st.metric("Admin Users", role_counts.get('admin', 0))
        
        # Role distribution chart
        if role_counts:
            import plotly.express as px
            fig = px.pie(
                values=list(role_counts.values()),
                names=[USER_ROLES[role]['name'] for role in role_counts.keys()],
                title="User Role Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

def logout():
    """Logout current user"""
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.session_state.username = None
    st.rerun()

def show_user_info_sidebar():
    """Show current user info in sidebar"""
    if check_authentication():
        user = get_current_user()
        username = st.session_state.get('username', 'Unknown')
        
        with st.sidebar:
            st.markdown("---")
            st.markdown("### 👤 Current User")
            
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**{user.get('full_name', username)}**")
                st.caption(f"@{username}")
                st.caption(f"Role: {USER_ROLES[user['role']]['name']}")
            
            with col2:
                if st.button("🚪", help="Logout", use_container_width=True):
                    logout()
            
            # Show permissions
            permissions = USER_ROLES[user['role']]['permissions']
            if 'all' in permissions:
                st.success("🔓 Full Access")
            else:
                st.info(f"🔐 Limited Access ({len(permissions)} permissions)")

def filter_navigation_by_permissions(pages):
    """Filter navigation pages based on user permissions"""
    if not check_authentication():
        return []
    
    user = get_current_user()
    if not user:
        return []
    
    role = user['role']
    user_permissions = USER_ROLES[role]['permissions']
    
    # Admin has access to all pages
    if 'all' in user_permissions:
        return pages
    
    # Filter pages based on permissions
    accessible_pages = []
    for page in pages:
        required_permission = PAGE_PERMISSIONS.get(page)
        if not required_permission or required_permission in user_permissions:
            accessible_pages.append(page)
    
    return accessible_pages

# Create demo users if they don't exist
def create_demo_users():
    """Create demo users for testing"""
    demo_users = [
        ('analyst', 'analyst123', 'analyst@exfileye.com', 'security_analyst', 'Security Analyst'),
        ('manager', 'manager123', 'manager@exfileye.com', 'security_manager', 'Security Manager'),
        ('compliance', 'compliance123', 'compliance@exfileye.com', 'compliance_officer', 'Compliance Officer'),
        ('viewer', 'viewer123', 'viewer@exfileye.com', 'viewer', 'Security Viewer')
    ]
    
    for username, password, email, role, full_name in demo_users:
        if username not in user_db.users:
            user_db.create_user(username, password, email, role, full_name)

# Initialize demo users
create_demo_users()
