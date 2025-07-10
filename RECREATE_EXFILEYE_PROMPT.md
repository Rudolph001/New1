
# ExfilEye DLP Email Security Monitor - Complete Recreation Prompt

## Application Overview

Create a comprehensive Data Loss Prevention (DLP) Email Security Monitoring System called "ExfilEye" that provides advanced email security analysis, network visualization, anomaly detection, and security operations management. This is a Streamlit-based web application with role-based authentication, interactive dashboards, and AI-powered analytics.

## Core Requirements

### 1. Technology Stack
- **Framework**: Streamlit (latest version)
- **Visualization**: Plotly for interactive charts and network graphs
- **Network Analysis**: NetworkX for graph analysis
- **Machine Learning**: Scikit-learn for anomaly detection
- **Authentication**: Custom role-based system
- **Data Processing**: Pandas, NumPy
- **Security**: Custom audit logging and encryption

### 2. Application Architecture

#### Main Application Structure
```
ExfilEye/
├── app_fixed.py              # Main Streamlit application
├── auth.py                   # Authentication and user management
├── domain_classifier.py     # Domain classification engine
├── security_config.py       # Security configuration and audit logging
├── requirements.txt          # Python dependencies
├── users.json               # User database (auto-generated)
├── security_audit.json      # Security audit logs (auto-generated)
├── .streamlit/
│   └── config.toml          # Streamlit configuration
├── run_local.py             # Local execution script
├── run_local.bat            # Windows batch launcher
├── run_local.sh             # Unix shell launcher
└── LOCAL_SETUP_INSTRUCTIONS.md  # Setup documentation
```

## Feature Requirements

### 3. Authentication System (auth.py)
- **Role-Based Access Control** with 5 user roles:
  - Admin (full access)
  - Security Analyst (data upload, operations, analysis)
  - Security Manager (operations, reports)
  - Compliance Officer (operations, compliance reports)
  - Viewer (read-only access)
- **User Management**: Create, edit, delete users
- **Password Security**: PBKDF2 hashing with salt
- **Session Management**: Secure session handling
- **Default Credentials**: admin/admin123

### 4. Core Application Features (app_fixed.py)

#### Data Upload & Processing
- CSV file upload with validation
- Email metadata parsing (sender, recipient, subject, attachments, timestamps)
- Domain extraction and classification
- Risk scoring based on 15+ factors
- Anomaly detection using statistical analysis

#### Security Operations Dashboard
- Risk level distribution (Critical, High, Medium, Low)
- Real-time security metrics
- Sender behavior analysis with temporal patterns
- Temporary/disposable email detection (RED FLAG alerts)
- Decision management system (No Action, Monitor, Investigate, Escalate)
- Status tracking and workflow integration

#### Network Analysis
- Interactive network graphs with force-directed layouts
- Community detection algorithms
- Node centrality analysis (PageRank, Eigenvector, Betweenness)
- Communication relationship mapping
- Real-time graph interactions with highlighting
- Advanced filtering and customization options

#### Follow-up Center
- Escalated email management
- Investigation queue tracking
- Monitoring status oversight
- Automatic follow-up email generation with Outlook integration
- Professional security response protocols

#### AI-Powered Q&A Assistant
- Natural language query processing
- Pre-built analytical questions
- Dynamic chart generation
- Smart pattern recognition
- Custom insight generation

### 5. Domain Classification System (domain_classifier.py)
- Daily updated domain intelligence
- Categories: Business, Free Email, Government, Educational, Suspicious
- Threat intelligence integration
- Manual domain management
- Classification statistics and reporting

### 6. Security & Audit System (security_config.py)
- Comprehensive audit logging
- Security event tracking
- Configuration management
- User activity monitoring
- Risk assessment logging

## Risk Scoring Algorithm

### Risk Factors (Configurable Points)
- Suspicious recipient domains: 40 points
- Free email domains: 25 points
- Unknown domains: 15 points
- External communication: 10 points
- External to free email: 20 points
- Subject keywords: 20 points
- Attachments: 15 points
- Attachment keywords: 25 points
- Departing employees: 30 points
- External recipients: 10 points
- Off-hours activity: 10 points

### Risk Thresholds (Configurable)
- Critical: ≥80 points
- High: ≥60 points
- Medium: ≥30 points
- Low: <30 points

## UI/UX Requirements

### Navigation Structure
1. **📁 Data Upload** - File upload and data processing
2. **🛡️ Security Operations** - Main security dashboard
3. **📨 Follow-up Center** - Action management
4. **🔗 Network Analysis** - Interactive network visualization
5. **🌐 Domain Classification** - Domain management (Admin only)
6. **📊 System Workflow** - Process documentation
7. **⚙️ Settings** - Configuration and user management (Admin only)

### Design Requirements
- Professional blue/gray color scheme
- Responsive layout with sidebar navigation
- Interactive charts and graphs
- Modal dialogs for detailed views
- Status indicators and progress tracking
- Export capabilities (PDF, CSV, JSON)

## Technical Implementation Details

### Data Processing Pipeline
1. CSV upload validation and parsing
2. Email field extraction (sender, recipients, subject, time, attachments)
3. Domain classification for recipients only
4. Risk score calculation using configurable factors
5. Anomaly detection using statistical methods
6. Network graph construction for relationship mapping

### Network Analysis Features
- Force Atlas layout algorithm
- Spring-directed positioning
- Community detection using Louvain algorithm
- Interactive node selection and highlighting
- Real-time graph manipulation
- Advanced centrality metrics calculation

### Anomaly Detection Methods
- Temporal pattern analysis (after-hours detection)
- Volume-based anomalies (unusual recipient counts)
- Content anomalies (keywords + attachments)
- Behavioral pattern deviations
- Statistical outlier detection

## Security Features

### Data Protection
- No sensitive data storage beyond session
- Secure password hashing (PBKDF2 + salt)
- Session timeout management
- Audit trail for all actions
- Role-based data access controls

### Compliance Features
- GDPR-ready data handling
- Audit log export capabilities
- User activity tracking
- Configuration change logging
- Security event documentation

## Installation & Deployment

### Python Dependencies (requirements.txt)
```
streamlit>=1.46.0
plotly>=6.1.2
networkx>=3.5
numpy>=2.3.0
scikit-learn>=1.7.0
scipy>=1.15.3
pandas>=2.3.0
reportlab>=4.4.2
igraph>=0.11.9
dash-cytoscape>=1.0.2
weasyprint>=65.1
```

### Streamlit Configuration (.streamlit/config.toml)
```toml
[server]
port = 5000
address = "0.0.0.0"
headless = true
enableCORS = false
enableXsrfProtection = false

[browser]
gatherUsageStats = false

[theme]
primaryColor = "#3498db"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
```

## Sample Data Structure

### CSV Input Format
Required fields for email analysis:
- sender: Email address of sender
- recipients: Email addresses of recipients (comma-separated)
- subject: Email subject line
- _time: Timestamp (YYYY-MM-DD HH:MM:SS format)
- attachments: Attachment information
- Wordlist_subject: Sensitive keywords in subject
- Wordlist_attachment: Sensitive keywords in attachments
- Termination: Departing employee indicator
- department: Sender department
- bunit: Business unit

## Quality Assurance Requirements

### Testing Checklist
- [ ] File upload with various CSV formats
- [ ] Risk scoring accuracy across all factors
- [ ] Network graph rendering and interactions
- [ ] User authentication and role permissions
- [ ] Data export functionality
- [ ] Responsive design across screen sizes
- [ ] Performance with large datasets (1000+ records)
- [ ] Security audit logging
- [ ] Email follow-up generation

### Performance Requirements
- Page load times <3 seconds
- Network graph rendering <5 seconds for 500+ nodes
- Real-time interactions with <1 second response
- Support for datasets up to 10,000 email records
- Concurrent user support (10+ simultaneous users)

---

# REPLIT DEPLOYMENT CHECKLIST

## Pre-Deployment Setup
- [ ] Create new Python Repl
- [ ] Set Python version to 3.11 or higher
- [ ] Configure port forwarding for port 5000

## File Creation Checklist

### 1. Core Application Files
- [ ] Create `app_fixed.py` with complete Streamlit application
- [ ] Create `auth.py` with authentication system
- [ ] Create `domain_classifier.py` with domain classification
- [ ] Create `security_config.py` with security features

### 2. Configuration Files
- [ ] Create `requirements.txt` with all dependencies
- [ ] Create `.streamlit/config.toml` with server configuration
- [ ] Create `pyproject.toml` for Python packaging

### 3. Launcher Scripts
- [ ] Create `run_local.py` for Python execution
- [ ] Create `run_local.bat` for Windows users
- [ ] Create `run_local.sh` for Unix/Mac users

### 4. Documentation Files
- [ ] Create `LOCAL_SETUP_INSTRUCTIONS.md`
- [ ] Create `README.md` with project overview
- [ ] Create `replit.md` with Replit-specific instructions

## Replit Configuration

### 1. Workflow Setup
- [ ] Configure main run command: `streamlit run app_fixed.py --server.port 5000 --server.address 0.0.0.0`
- [ ] Set run button to execute Streamlit workflow
- [ ] Test workflow execution

### 2. Environment Configuration
- [ ] Verify Python 3.11+ installation
- [ ] Install all required packages from requirements.txt
- [ ] Test package compatibility

### 3. Port Configuration
- [ ] Configure port 5000 for web access
- [ ] Test external accessibility
- [ ] Verify HTTPS redirection

## Functionality Testing

### 1. Authentication Testing
- [ ] Test default admin login (admin/admin123)
- [ ] Test user creation and role assignments
- [ ] Test permission-based navigation
- [ ] Test logout functionality

### 2. Core Features Testing
- [ ] Test CSV file upload with sample data
- [ ] Verify data processing and risk scoring
- [ ] Test network graph generation
- [ ] Test interactive graph features
- [ ] Test Q&A assistant functionality

### 3. Security Features Testing
- [ ] Test audit logging functionality
- [ ] Test role-based access controls
- [ ] Test data export capabilities
- [ ] Test follow-up email generation

### 4. UI/UX Testing
- [ ] Test responsive design on different screen sizes
- [ ] Test navigation between all sections
- [ ] Test modal dialogs and popups
- [ ] Test chart interactions and filtering

## Performance Verification

### 1. Loading Performance
- [ ] Test initial application load time (<5 seconds)
- [ ] Test large dataset processing (500+ records)
- [ ] Test network graph rendering with 100+ nodes
- [ ] Test concurrent user access

### 2. Browser Compatibility
- [ ] Test in Chrome/Chromium
- [ ] Test in Firefox
- [ ] Test in Safari (if accessible)
- [ ] Test mobile browser compatibility

## Security Verification

### 1. Authentication Security
- [ ] Test password hashing and verification
- [ ] Test session management
- [ ] Test unauthorized access prevention
- [ ] Test role permission enforcement

### 2. Data Security
- [ ] Verify no sensitive data persistence
- [ ] Test audit log generation
- [ ] Test secure file upload handling
- [ ] Test data export security

## Final Deployment Steps

### 1. Production Readiness
- [ ] Remove debug flags and test data
- [ ] Verify all error handling
- [ ] Test application stability
- [ ] Verify all documentation is accurate

### 2. User Acceptance
- [ ] Test complete user workflows
- [ ] Verify all features work as documented
- [ ] Test with realistic data volumes
- [ ] Confirm performance meets requirements

### 3. Go-Live Checklist
- [ ] Application accessible via public URL
- [ ] All features functional
- [ ] Performance acceptable
- [ ] Security measures active
- [ ] Documentation complete
- [ ] Support materials available

## Post-Deployment Monitoring

### 1. Performance Monitoring
- [ ] Monitor application response times
- [ ] Track user session activity
- [ ] Monitor resource utilization
- [ ] Check for error logs

### 2. Security Monitoring
- [ ] Review security audit logs
- [ ] Monitor authentication attempts
- [ ] Check for unauthorized access
- [ ] Verify data handling compliance

## Success Criteria

### Functional Requirements Met
- ✅ All navigation sections accessible
- ✅ File upload and processing working
- ✅ Risk scoring and anomaly detection active
- ✅ Network analysis fully functional
- ✅ User authentication and roles working
- ✅ Follow-up workflows operational
- ✅ Export capabilities functional

### Performance Requirements Met
- ✅ Application loads within 5 seconds
- ✅ Network graphs render smoothly
- ✅ Real-time interactions responsive
- ✅ Supports 500+ email records
- ✅ Multiple concurrent users supported

### Security Requirements Met
- ✅ Authentication system secure
- ✅ Role-based access enforced
- ✅ Audit logging active
- ✅ Data handling secure
- ✅ Session management proper

## Troubleshooting Guide

### Common Issues and Solutions

**Issue: Streamlit won't start**
- Solution: Check requirements.txt installation, verify Python version

**Issue: Network graphs not rendering**
- Solution: Verify NetworkX and Plotly installation, check browser JavaScript

**Issue: File upload failing**
- Solution: Check file format, verify CSV structure matches expected fields

**Issue: Authentication not working**
- Solution: Check users.json creation, verify password hashing

**Issue: Port 5000 not accessible**
- Solution: Verify Replit port forwarding, check server configuration

**Issue: Performance slow with large datasets**
- Solution: Implement data pagination, optimize graph rendering

---

## Expected Deliverables

Upon completion, the application should provide:

1. **Fully Functional DLP System** - Complete email security monitoring
2. **Interactive Dashboards** - Real-time security analytics
3. **Network Analysis** - Advanced communication visualization
4. **AI-Powered Insights** - Natural language query system
5. **Professional UI** - Enterprise-ready interface
6. **Comprehensive Security** - Role-based access and audit logging
7. **Export Capabilities** - Reports and data export
8. **Documentation** - Complete user and technical documentation

The final product should be a production-ready, enterprise-grade DLP email security monitoring system that can be deployed immediately for organizational use.
