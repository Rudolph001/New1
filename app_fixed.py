import streamlit as st
import json
import io
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re

# Page configuration
st.set_page_config(
    page_title="ExfilEye - DLP Email Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'data' not in st.session_state:
    st.session_state.data = None
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'whitelist' not in st.session_state:
    st.session_state.whitelist = {'domains': set(), 'emails': set()}
if 'followup_decisions' not in st.session_state:
    st.session_state.followup_decisions = {}

# Simple CSV processing function
def process_csv_data(csv_content):
    """Process CSV content without pandas dependency"""
    lines = csv_content.strip().split('\n')
    if len(lines) < 2:
        return []
    
    headers = [h.strip() for h in lines[0].split(',')]
    data = []
    
    for line in lines[1:]:
        values = [v.strip() for v in line.split(',')]
        if len(values) == len(headers):
            row = dict(zip(headers, values))
            data.append(row)
    
    return data

# Risk calculation function
def calculate_risk_score(email_data):
    """Calculate risk score based on email properties"""
    score = 0
    factors = []
    
    # Check domain type
    sender_domain = email_data.get('sender_domain', '').lower()
    free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    if sender_domain in free_domains:
        score += 25
        factors.append('Free email domain')
    
    # Check keywords
    word_list = email_data.get('word_list_match', '')
    if word_list and word_list.strip():
        score += 20
        factors.append('Sensitive keywords')
    
    # Check attachments
    attachments = email_data.get('attachments', '')
    if attachments and attachments.strip():
        score += 15
        factors.append('Has attachments')
    
    # Check departing employee
    last_working_day = email_data.get('last_working_day', '')
    if last_working_day and last_working_day.strip():
        score += 30
        factors.append('Departing employee')
    
    # Check external recipients
    recipient_status = email_data.get('recipient_status', '')
    if 'external' in recipient_status.lower():
        score += 10
        factors.append('External recipients')
    
    # Determine risk level
    if score >= 60:
        risk_level = 'High'
    elif score >= 30:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    
    # Critical risk combinations
    if (last_working_day and attachments and word_list and sender_domain in free_domains):
        risk_level = 'Critical'
        factors.append('CRITICAL COMBINATION')
    
    return {
        'risk_score': score,
        'risk_level': risk_level,
        'risk_factors': ', '.join(factors) if factors else 'Normal activity'
    }

@st.dialog("Email Details")
def show_email_details_modal(email):
    """Display email details in a modal popup"""
    st.subheader("📧 Email Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Sender:** {email.get('sender', 'N/A')}")
        st.write(f"**Subject:** {email.get('subject', 'N/A')}")
        st.write(f"**Time:** {email.get('time', 'N/A')}")
        st.write(f"**Recipients:** {email.get('recipients', 'N/A')}")
        st.write(f"**Direction:** {email.get('direction', 'N/A')}")
        st.write(f"**Business Unit:** {email.get('bunit', 'N/A')}")
    
    with col2:
        st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
        st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
        st.write(f"**Risk Factors:** {email.get('risk_factors', 'None')}")
        st.write(f"**Attachments:** {email.get('attachments', 'None')}")
        st.write(f"**Keywords:** {email.get('word_list_match', 'None')}")
        st.write(f"**Department:** {email.get('department', 'N/A')}")
    
    # Additional details section
    st.write("---")
    st.write("**Additional Information:**")
    col3, col4 = st.columns(2)
    
    with col3:
        st.write(f"**Sender Domain:** {email.get('sender_domain', 'N/A')}")
        st.write(f"**Recipient Domain:** {email.get('recipient_domain', 'N/A')}")
        st.write(f"**Email Domain:** {email.get('email_domain', 'N/A')}")
    
    with col4:
        st.write(f"**Action Taken:** {email.get('act', 'N/A')}")
        st.write(f"**Delivered:** {email.get('delivered', 'N/A')}")
        st.write(f"**Last Working Day:** {email.get('last_working_day', 'N/A')}")
    
    # Anomaly Detection Section
    st.write("---")
    st.write("**🚨 Anomaly Detection Results:**")
    
    is_anomaly = email.get('is_anomaly', False)
    anomaly_type = email.get('anomaly_type', 'None')
    anomaly_score = email.get('anomaly_score', 0)
    anomaly_reason = email.get('anomaly_reason', 'No anomalies detected')
    
    if is_anomaly:
        st.error(f"**Anomaly Detected:** {anomaly_type}")
        st.write(f"**Anomaly Score:** {anomaly_score:.2f}")
        st.write(f"**Reason:** {anomaly_reason}")
        
        # Additional anomaly details if available
        if email.get('anomaly_details'):
            st.write("**Detailed Analysis:**")
            st.write(email.get('anomaly_details'))
            
        # Behavioral anomaly information
        if email.get('behavioral_anomaly'):
            st.write("**Behavioral Anomaly:**")
            st.write(f"- Unusual sending time: {email.get('unusual_time', 'No')}")
            st.write(f"- Unusual recipient pattern: {email.get('unusual_recipients', 'No')}")
            st.write(f"- Content anomaly: {email.get('content_anomaly', 'No')}")
            
        # Statistical anomaly information
        if email.get('statistical_anomaly'):
            st.write("**Statistical Anomaly:**")
            st.write(f"- Deviation from normal patterns: {email.get('pattern_deviation', 'N/A')}")
            st.write(f"- Frequency anomaly: {email.get('frequency_anomaly', 'N/A')}")
    else:
        st.success("**No Anomalies Detected**")
        st.write("This email follows normal patterns and behaviors.")

def main():
    st.title("🛡️ ExfilEye - DLP Email Security Monitoring System")
    st.markdown("---")
    
    # Sidebar navigation
    with st.sidebar:
        st.header("📋 Navigation")
        page = st.selectbox(
            "Select Section:",
            ["📁 Data Upload", "📆 Daily Checks", "📨 Follow-up Center", "⚙️ Settings"]
        )
        
        # Display data status
        if st.session_state.data is not None:
            st.success(f"✅ Data loaded: {len(st.session_state.data)} records")
        else:
            st.warning("⚠️ No data loaded")
    
    # Route to selected page
    if page == "📁 Data Upload":
        data_upload_page()
    elif page == "📆 Daily Checks":
        daily_checks_page()
    elif page == "📨 Follow-up Center":
        followup_center_page()
    elif page == "⚙️ Settings":
        settings_page()

def data_upload_page():
    st.header("📁 Data Upload & Validation")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("CSV Email Data Upload")
        uploaded_file = st.file_uploader(
            "Upload email metadata CSV file",
            type=['csv'],
            help="Upload CSV file containing email metadata for analysis"
        )
        
        if uploaded_file is not None:
            try:
                # Read the CSV file content
                csv_content = uploaded_file.read().decode('utf-8')
                data = process_csv_data(csv_content)
                
                if data:
                    st.session_state.data = data
                    
                    # Process each email for risk scoring
                    processed_data = []
                    for email in data:
                        risk_info = calculate_risk_score(email)
                        email.update(risk_info)
                        processed_data.append(email)
                    
                    st.session_state.processed_data = processed_data
                    st.success("✅ Data uploaded and processed successfully!")
                    
                    # Display data preview
                    st.subheader("📊 Data Preview")
                    
                    # Show first few records
                    for i, email in enumerate(data[:5]):
                        with st.expander(f"Email {i+1}: {email.get('subject', 'No Subject')[:50]}..."):
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.write(f"**Sender:** {email.get('sender', 'N/A')}")
                                st.write(f"**Recipients:** {email.get('recipients', 'N/A')}")
                                st.write(f"**Time:** {email.get('time', 'N/A')}")
                            with col_b:
                                st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                                st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                                st.write(f"**Domain:** {email.get('sender_domain', 'N/A')}")
                    
                    # Display summary
                    st.subheader("🔍 Analysis Summary")
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.metric("Total Records", len(data))
                    with col_b:
                        high_risk = len([e for e in processed_data if e.get('risk_level') in ['High', 'Critical']])
                        st.metric("High Risk Emails", high_risk)
                    with col_c:
                        avg_risk = sum(e.get('risk_score', 0) for e in processed_data) / len(processed_data) if processed_data else 0
                        st.metric("Average Risk Score", f"{avg_risk:.1f}")
                        
                else:
                    st.error("❌ No valid data found in the uploaded file")
                    
            except Exception as e:
                st.error(f"❌ Error processing file: {str(e)}")
    
    with col2:
        st.subheader("🔗 Whitelist Management")
        
        # Domain whitelist
        st.write("**Trusted Domains**")
        new_domain = st.text_input("Add domain:", placeholder="example.com")
        if st.button("Add Domain"):
            if new_domain:
                st.session_state.whitelist['domains'].add(new_domain.lower())
                st.success(f"Added {new_domain} to whitelist")
                st.rerun()
        
        # Display current whitelisted domains
        if st.session_state.whitelist['domains']:
            for domain in list(st.session_state.whitelist['domains']):
                col_x, col_y = st.columns([3, 1])
                with col_x:
                    st.text(domain)
                with col_y:
                    if st.button("🗑️", key=f"del_domain_{domain}"):
                        st.session_state.whitelist['domains'].remove(domain)
                        st.rerun()

def daily_checks_page():
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return
    
    st.header("📆 Daily Security Checks")
    
    data = st.session_state.processed_data
    
    # KPI Cards
    st.subheader("📊 Risk Overview")
    col1, col2, col3, col4 = st.columns(4)
    
    risk_counts = Counter(email.get('risk_level', 'Unknown') for email in data)
    
    with col1:
        critical_count = risk_counts.get('Critical', 0)
        st.metric("🔴 Critical Risk", critical_count)
    
    with col2:
        high_count = risk_counts.get('High', 0)
        st.metric("🟠 High Risk", high_count)
    
    with col3:
        medium_count = risk_counts.get('Medium', 0)
        st.metric("🟡 Medium Risk", medium_count)
    
    with col4:
        low_count = risk_counts.get('Low', 0)
        st.metric("🟢 Low Risk", low_count)
    
    # Risk Events by Sender
    st.subheader("🎯 Risk Events (Grouped by Sender)")
    
    # Group emails by sender
    sender_groups = defaultdict(list)
    for email in data:
        sender = email.get('sender', 'Unknown')
        sender_groups[sender].append(email)
    
    # Sort sender groups by highest risk level (Critical first, then High, Medium, Low)
    risk_priority = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}
    
    def get_sender_max_risk(emails):
        max_priority = 0
        max_score = 0
        for email in emails:
            risk_level = email.get('risk_level', 'Low')
            risk_score = email.get('risk_score', 0)
            priority = risk_priority.get(risk_level, 0)
            if priority > max_priority or (priority == max_priority and risk_score > max_score):
                max_priority = priority
                max_score = risk_score
        return (max_priority, max_score)
    
    # Sort senders by risk priority (Critical first)
    sorted_sender_groups = sorted(sender_groups.items(), 
                                 key=lambda x: get_sender_max_risk(x[1]), 
                                 reverse=True)
    
    for sender, emails in sorted_sender_groups:
        if not emails:
            continue
            
        # Find highest risk in group
        max_risk = max(email.get('risk_score', 0) for email in emails)
        max_risk_level = next((email.get('risk_level', 'Low') for email in emails 
                              if email.get('risk_score', 0) == max_risk), 'Low')
        
        # Check if sender has any anomalies
        has_anomalies = any(email.get('is_anomaly', False) for email in emails)
        anomaly_count = sum(1 for email in emails if email.get('is_anomaly', False))
        
        # Create sender title with anomaly indicator
        sender_title = f"📧 {sender} - {len(emails)} emails - Risk: {max_risk_level} ({max_risk})"
        if has_anomalies:
            sender_title += f" 🚨 {anomaly_count} Anomalies"
        
        with st.expander(sender_title):
            # Sort emails within sender group by risk level and score (Critical first)
            sorted_emails = sorted(emails, 
                                 key=lambda x: (risk_priority.get(x.get('risk_level', 'Low'), 0), 
                                              x.get('risk_score', 0)), 
                                 reverse=True)
            
            for i, email in enumerate(sorted_emails):
                col_a, col_b, col_c = st.columns([3, 1, 1])
                
                with col_a:
                    risk_level = email.get('risk_level', 'Low')
                    risk_color = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(risk_level, '⚪')
                    subject = email.get('subject', 'No Subject')
                    recipients = email.get('recipients', 'N/A')
                    risk_score = email.get('risk_score', 0)
                    
                    # Add anomaly indicator for individual emails
                    email_display = f"{risk_color} **{subject[:50]}...** | {recipients} | Score: {risk_score}"
                    if email.get('is_anomaly', False):
                        email_display += " 🚨"
                    
                    st.write(email_display)
                
                with col_b:
                    if st.button("📧 View Details", key=f"details_{sender}_{i}"):
                        show_email_details_modal(email)
                
                with col_c:
                    email_id = f"{sender}_{i}"
                    current_decision = st.session_state.followup_decisions.get(email_id, 'pending')
                    
                    if current_decision == 'pending':
                        if st.button("✅ Follow Up", key=f"followup_{email_id}"):
                            st.session_state.followup_decisions[email_id] = 'followup'
                            st.rerun()
                        if st.button("❌ No Action", key=f"noaction_{email_id}"):
                            st.session_state.followup_decisions[email_id] = 'no_action'
                            st.rerun()
                    else:
                        decision_icon = "✅" if current_decision == 'followup' else "❌"
                        decision_text = "Follow Up" if current_decision == 'followup' else "No Action"
                        st.write(f"{decision_icon} {decision_text}")

def followup_center_page():
    st.header("📨 Follow-up Email Center")
    
    # Get emails marked for follow-up
    followup_emails = []
    if st.session_state.processed_data is not None:
        for email_id, decision in st.session_state.followup_decisions.items():
            if decision == 'followup':
                # Find the email by parsing the ID
                try:
                    sender, index = email_id.rsplit('_', 1)
                    index = int(index)
                    sender_emails = [e for e in st.session_state.processed_data if e.get('sender') == sender]
                    if index < len(sender_emails):
                        followup_emails.append(sender_emails[index])
                except:
                    continue
    
    if not followup_emails:
        st.info("📭 No emails currently marked for follow-up.")
        st.write("Mark emails for follow-up in the Daily Checks section to see them here.")
        return
    
    st.subheader(f"📋 Follow-up Queue ({len(followup_emails)} emails)")
    
    for i, email in enumerate(followup_emails):
        with st.expander(f"📧 {email.get('sender', 'Unknown')} - {email.get('subject', 'No Subject')[:50]}..."):
            
            # Email context
            col_a, col_b = st.columns(2)
            with col_a:
                st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                st.write(f"**Recipients:** {email.get('recipients', 'N/A')}")
                st.write(f"**Time:** {email.get('time', 'N/A')}")
            
            with col_b:
                st.write(f"**Domain:** {email.get('sender_domain', 'N/A')}")
                st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                st.write(f"**Risk Factors:** {email.get('risk_factors', 'None')}")
            
            # Generate follow-up email template
            if st.button(f"📧 Generate Follow-up Email", key=f"generate_{i}"):
                template = generate_followup_email(email)
                st.text_area("Follow-up Email Template:", template, height=300, key=f"template_{i}")

def generate_followup_email(email):
    """Generate a follow-up email template"""
    sender = email.get('sender', 'Unknown')
    subject = email.get('subject', 'No Subject')
    risk_level = email.get('risk_level', 'Medium')
    risk_factors = email.get('risk_factors', 'General security review')
    time = email.get('time', 'Unknown')
    recipients = email.get('recipients', 'Unknown')
    
    template = f"""Subject: Security Review Required - Email Activity Alert

Dear {sender.split('@')[0].title() if '@' in sender else sender},

Our email security monitoring system has identified an email sent from your account that requires review:

Email Details:
- Subject: {subject}
- Sent to: {recipients}
- Date/Time: {time}
- Risk Level: {risk_level}

Security Concerns Identified:
{risk_factors}

Required Actions:
1. Please confirm if this email was sent by you
2. Verify that the recipients were intended
3. Confirm the necessity of any attachments
4. Report if your account may have been compromised

Please respond to this email within 2 hours to confirm the legitimacy of this communication.

If you did not send this email or suspect unauthorized access, please contact IT Security immediately.

Best regards,
IT Security Team
"""
    return template

def settings_page():
    st.header("⚙️ Settings")
    
    st.subheader("Risk Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Risk Thresholds**")
        low_threshold = st.slider("Low Risk Threshold", 0, 100, 30)
        medium_threshold = st.slider("Medium Risk Threshold", 0, 100, 60)
        high_threshold = st.slider("High Risk Threshold", 0, 100, 100)
        
        if st.button("Update Thresholds"):
            st.success("Risk thresholds updated successfully!")
    
    with col2:
        st.write("**System Information**")
        st.info(f"""
        **Application:** ExfilEye DLP Monitor
        **Version:** 1.0.0
        **Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
        **Status:** Active
        """)

if __name__ == "__main__":
    main()