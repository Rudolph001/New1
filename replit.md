# ExfilEye - DLP Email Security Monitor

## Overview

ExfilEye is a Data Loss Prevention (DLP) email security monitoring application built with Streamlit. The application provides comprehensive analysis and visualization of email security data, including network analysis, anomaly detection, and security monitoring capabilities. It's designed to help security teams monitor email communications for potential data exfiltration and security threats.

## System Architecture

### Frontend Architecture
- **Framework**: Streamlit web application framework
- **Visualization**: Plotly for interactive charts and network graphs
- **UI Components**: Streamlit's built-in components for file upload, data display, and user interaction
- **State Management**: Streamlit session state for maintaining application state across interactions

### Backend Architecture
- **Runtime**: Python 3.11 application
- **Data Processing**: Native Python with NumPy for numerical operations
- **Network Analysis**: NetworkX for graph analysis and network visualization
- **Machine Learning**: Scikit-learn for anomaly detection and clustering

### Data Processing Pipeline
- **Input**: CSV file upload through Streamlit interface
- **Processing**: Custom CSV parser without pandas dependency
- **Analysis**: Network graph construction, statistical analysis, and pattern detection
- **Output**: Interactive visualizations and security reports

## Key Components

### Core Modules
1. **Data Upload & Processing**: CSV file handling and data parsing
2. **Network Analysis**: Email communication pattern analysis using NetworkX
3. **Visualization Engine**: Plotly-based interactive charts and network graphs
4. **Security Monitoring**: Anomaly detection and threat identification
5. **Follow-up Decision Tracking**: Security incident response tracking

### Session State Management
- **Data Storage**: Raw and processed data persistence
- **User Preferences**: Network configuration and application settings
- **Analysis State**: Follow-up decisions and selected nodes
- **UI State**: Network layout and filtering preferences

### Security Features
- **Anomaly Detection**: Pattern-based threat identification
- **Network Analysis**: Communication flow visualization
- **Risk Assessment**: Automated security scoring

## Data Flow

1. **Data Ingestion**: Users upload CSV files through the Streamlit interface
2. **Data Processing**: Custom parser converts CSV to structured data format
3. **Network Construction**: NetworkX builds communication graphs from email data
4. **Analysis Pipeline**: Statistical analysis and anomaly detection algorithms process the data
5. **Visualization**: Plotly renders interactive charts and network visualizations
6. **User Interaction**: Streamlit handles user inputs for filtering and configuration
7. **Decision Tracking**: Security decisions are stored in session state

## External Dependencies

### Core Libraries
- **Streamlit (>=1.46.0)**: Web application framework
- **Plotly (>=6.1.2)**: Interactive visualization library
- **NetworkX (>=3.5)**: Network analysis and graph algorithms
- **NumPy (>=2.3.0)**: Numerical computing
- **Scikit-learn (>=1.7.0)**: Machine learning algorithms
- **Pandas (>=2.3.0)**: Data manipulation (listed but not currently used)

### Runtime Environment
- **Python**: 3.11+ runtime environment
- **Nix**: Package management and environment isolation
- **Replit**: Cloud hosting and deployment platform

## Deployment Strategy

### Development Environment
- **Platform**: Replit cloud development environment
- **Package Manager**: UV for Python dependency management
- **Environment**: Nix-based reproducible environment

### Production Deployment
- **Target**: Autoscale deployment on Replit
- **Port Configuration**: Internal port 5000, external port 80
- **Startup Command**: `streamlit run app.py --server.port 5000`
- **Configuration**: Headless server mode for production deployment

### Application Configuration
- **Server Settings**: Configured for headless operation with public access
- **Port Binding**: 0.0.0.0 address for external accessibility
- **Parallel Workflows**: Support for concurrent task execution

## Recent Changes

- July 14, 2025: Successfully migrated from Replit Agent to standard Replit environment with enhanced security practices
- July 14, 2025: Added automatic risk score recalculation when configuration changes, ensuring Security Operations Dashboard reflects real-time updates
- July 14, 2025: Enhanced Risk Configuration page with automatic update notifications and manual refresh capabilities
- July 14, 2025: Improved risk configuration integration with Security Operations Dashboard for seamless workflow
- July 14, 2025: Successfully migrated from Replit Agent to standard Replit environment with enhanced security practices
- July 14, 2025: Implemented automatic risk score recalculation when configuration changes in Security Operations Dashboard
- July 14, 2025: Added large file support for CSV uploads with progress indicators and enhanced memory management
- July 14, 2025: Increased Streamlit upload limits to 2GB for handling large datasets (158,000+ records)
- July 14, 2025: Enhanced CSV processing with real-time progress tracking and error reporting for large files
- July 10, 2025: Created comprehensive configurable risk scoring system with field-based conditions and dynamic thresholds
- July 10, 2025: Added "Risk Configuration" page allowing admins to define custom Critical/High/Medium/Low risk rules
- July 10, 2025: Implemented advanced risk condition operators (equals, not_equals, contains, after_hours, etc.)
- July 10, 2025: Added risk configuration templates, import/export functionality, and real-time testing capabilities
- July 10, 2025: Added "Email Check Completed" dashboard to separate reviewed emails from active monitoring tasks
- July 10, 2025: Modified Security Operations Dashboard to filter out completed senders and focus on pending/in-progress reviews
- July 10, 2025: Enhanced workflow separation with professional completion tracking and export functionality
- July 10, 2025: Successfully completed migration from Replit Agent to standard Replit environment
- July 10, 2025: Fixed domain classification import errors and updated all variable references to use new domain_classifier system
- July 10, 2025: Enhanced Security Operations Dashboard with professional styling, improved readability, and better user experience
- July 10, 2025: Added gradient headers, role-based banners, enhanced metric cards with tooltips and progress indicators
- July 10, 2025: Redesigned Security Actions Dashboard with summary cards, enhanced tabbed interface, and color-coded alerts
- July 10, 2025: Improved Red Flag Alert section with critical security banner and enhanced risk assessment formatting
- July 10, 2025: Enhanced Risk Events Management with professional progress dashboard and improved filter interface
- January 10, 2025: Created separate daily-updated domain classification system (domain_classifier.py) with change tracking and management interface
- January 10, 2025: Added "🌐 Domain Classification" page to admin navigation for domain management and daily updates
- January 10, 2025: Updated domain classification to use new system for recipients_email_domain field analysis
- January 10, 2025: Integrated daily threat intelligence updates with automatic domain list updates
- June 26, 2025: Hidden Q&A Assistant from navigation menu per user request, streamlined interface to core security features
- June 26, 2025: Fixed button display issues with improved 2-column layout and full-width buttons for better visibility
- June 26, 2025: Enhanced Outlook integration with automatic email opening and URL encoding for follow-up emails
- June 26, 2025: Successfully migrated from Replit Agent to standard Replit environment with proper security practices
- June 26, 2025: Updated domain classification to only apply to recipients field per user request, removed sender classification
- June 26, 2025: Fixed session state initialization and Streamlit configuration for proper deployment
- June 25, 2025: Enhanced Q&A Assistant with advanced natural language processing, categorized questions, deep analysis options, and comprehensive pattern matching
- June 25, 2025: Added PDF export functionality for System Workflow documentation with professional formatting
- June 25, 2025: Improved workflow diagram readability with properly sized rectangular boxes and better text visibility
- June 25, 2025: Added comprehensive System Workflow documentation page with professional process flow diagrams
- June 25, 2025: Enhanced Q&A Assistant with editable pre-built questions and advanced query processing
- June 25, 2025: Fixed Plotly chart duplicate ID errors and improved visualization stability
- June 25, 2025: Implemented attachment analysis, department analysis, and multi-domain recipient tracking
- June 21, 2025: Initial system setup and core functionality implementation

## User Preferences

Preferred communication style: Simple, everyday language.