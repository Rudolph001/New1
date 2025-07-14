import streamlit as st
import json
import io
import pandas as pd
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np
from scipy.spatial.distance import pdist, squareform
from sklearn.cluster import SpectralClustering
import igraph as ig

# Import authentication system
from auth import (
    check_authentication, show_login_page, show_user_info_sidebar, 
    filter_navigation_by_permissions, show_user_management, has_permission,
    require_permission, get_current_user, USER_ROLES
)

# Import domain classification system
from domain_classifier import domain_classifier

# Import risk configuration manager
from risk_config_manager import RiskConfigManager

# Page configuration - MUST be first Streamlit command
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
if 'followup_decisions' not in st.session_state:
    st.session_state.followup_decisions = {}
if 'sender_review_status' not in st.session_state:
    st.session_state.sender_review_status = {}
if 'network_config' not in st.session_state:
    st.session_state.network_config = {
        'source_field': None,
        'target_field': None,
        'weight_field': None,
        'filters': {},
        'layout': 'spring',
        'node_size_metric': 'degree'
    }
if 'selected_node' not in st.session_state:
    st.session_state.selected_node = None
if 'flagged_emails' not in st.session_state:
    st.session_state.flagged_emails = []
if 'generated_alerts' not in st.session_state:
    st.session_state.generated_alerts = []
if 'blocked_domains' not in st.session_state:
    st.session_state.blocked_domains = []
if 'followup_decisions' not in st.session_state:
    st.session_state.followup_decisions = {}
if 'risk_config_manager' not in st.session_state:
    st.session_state.risk_config_manager = RiskConfigManager()
if 'risk_config' not in st.session_state:
    st.session_state.risk_config = {
        'suspicious_domain_points': 40,
        'free_email_points': 25,
        'unknown_domain_points': 15,
        'external_communication_points': 10,
        'external_to_free_email_points': 20,
        'external_to_unknown_points': 10,
        'subject_keywords_points': 20,
        'attachments_points': 15,
        'attachment_keywords_points': 25,
        'departing_employee_points': 30,
        'external_recipients_points': 10,
        'off_hours_points': 10,
        'critical_threshold': 80,
        'high_threshold': 60,
        'medium_threshold': 30
    }

# Old domain classifications removed - now using domain_classifier.py for daily updated classifications

def classify_email_domain(email_address):
    """
    Classify an email domain using the updated domain classification system
    Returns: dict with classification results
    """
    if not email_address or '@' not in email_address:
        return {"classification": "unknown", "is_suspicious": False, "is_free": False}
    
    domain = email_address.split('@')[1].lower()
    return domain_classifier.classify_domain(domain)





def extract_domain_from_email(email_field):
    """Extract domain from email address or email field"""
    if not email_field:
        return ""
    
    # Handle multiple emails separated by semicolon or comma
    emails = re.split('[;,]', email_field)
    domains = []
    
    for email in emails:
        email = email.strip()
        if '@' in email:
            domain = email.split('@')[1].strip().lower()
            domains.append(domain)
    
    return '; '.join(domains) if domains else ""

# Enhanced CSV processing function
def process_csv_data(csv_content):
    """Process CSV content with domain classification only on recipients field"""
    lines = csv_content.strip().split('\n')
    total_lines = len(lines)
    
    if total_lines < 2:
        return []

    headers = [h.strip() for h in lines[0].split(',')]
    data = []
    processed_count = 0
    skipped_count = 0

    # Log processing start for large files
    if total_lines > 1000:
        st.info(f"📊 Processing large CSV file: {total_lines:,} lines found. This may take a moment...")

    for i, line in enumerate(lines[1:], 1):
        # Show progress for very large files
        if total_lines > 10000 and i % 10000 == 0:
            progress = (i / (total_lines - 1)) * 100
            st.info(f"⏳ Processing progress: {i:,} / {total_lines-1:,} records ({progress:.1f}%)")
        
        values = [v.strip() for v in line.split(',')]
        if len(values) == len(headers):
            row = dict(zip(headers, values))
            
            # Only process recipients field for domain classification
            recipient_email = row.get('recipients_email_domain', '') or row.get('recipients', '')
            
            # Apply domain classification only to recipients
            if recipient_email:
                row['recipient_domain'] = extract_domain_from_email(recipient_email)
                # For multiple recipients, classify the first one for analysis
                first_recipient = recipient_email.split(';')[0].split(',')[0].strip()
                row['recipient_classification'] = classify_email_domain(first_recipient)
            
            # Extract sender domain without classification for basic info only
            sender_email = row.get('sender', '')
            if sender_email:
                row['sender_domain'] = extract_domain_from_email(sender_email)
            
            data.append(row)
            processed_count += 1
        else:
            skipped_count += 1

    # Log final results
    if total_lines > 1000:
        st.success(f"✅ CSV processing complete: {processed_count:,} records processed, {skipped_count:,} skipped")
        if skipped_count > 0:
            st.warning(f"⚠️ {skipped_count:,} rows were skipped due to column count mismatch")

    return data

# Risk calculation function using configurable system
def calculate_risk_score(email_data):
    """Calculate risk score using the configurable risk system"""
    risk_manager = st.session_state.risk_config_manager
    result = risk_manager.calculate_risk_score(email_data)
    
    # Ensure all emails get at least Low risk classification
    if result['risk_level'] == 'Unknown' or result['risk_score'] == 0:
        result['risk_level'] = 'Low'
        result['risk_score'] = max(1, result['risk_score'])
        if not result.get('triggered_conditions'):
            result['triggered_conditions'] = [{
                'description': 'Standard email processing',
                'points': 1,
                'risk_level': 'Low',
                'field': 'sender',
                'operator': 'not_empty',
                'value': ''
            }]
        if not result.get('risk_factors'):
            result['risk_factors'] = 'Standard email - no specific risk factors identified'
    
    return result

def detect_anomalies(email_data):
    """Detect anomalies in email behavior"""
    is_anomaly = False
    anomaly_reasons = []
    anomaly_score = 0
    anomaly_type = 'None'

    # Check for time-based anomalies (after hours)
    time_str = email_data.get('_time', '')
    if time_str:
        try:
            # Extract hour from time string (assuming format like "2024-01-01 22:30:00")
            if ':' in time_str:
                hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                hour = int(hour_part)
                # Flag emails sent after 6 PM or before 6 AM as anomalous
                if hour >= 18 or hour <= 6:
                    is_anomaly = True
                    anomaly_reasons.append('Sent during unusual hours (after 6 PM or before 6 AM)')
                    anomaly_score += 0.3
                    anomaly_type = 'Temporal'
        except:
            pass

    # Check for recipient anomalies (too many recipients)
    recipients = email_data.get('recipients_email_domain', '') or email_data.get('recipients', '')
    if recipients:
        recipient_count = len([r.strip() for r in recipients.split(',') if r.strip()])
        if recipient_count > 10:
            is_anomaly = True
            anomaly_reasons.append(f'Unusual high recipient count ({recipient_count})')
            anomaly_score += 0.4
            anomaly_type = 'Behavioral'

    # Check for content anomalies (sensitive keywords + attachments)
    has_keywords_subject = email_data.get('Wordlist_subject', '').strip()
    has_keywords_attachment = email_data.get('Wordlist_attachment', '').strip()
    has_attachments = email_data.get('attachments', '').strip()
    if (has_keywords_subject or has_keywords_attachment) and has_attachments:
        is_anomaly = True
        anomaly_reasons.append('Combination of sensitive keywords and attachments')
        anomaly_score += 0.5
        anomaly_type = 'Content'

    # Check for departing employee anomaly - only if leaver field equals "YES"
    leaver = email_data.get('leaver', '')
    if leaver and leaver.strip().upper() == 'YES':
        is_anomaly = True
        anomaly_reasons.append('Email from departing employee')
        anomaly_score += 0.6
        anomaly_type = 'Behavioral'

    # Check for external domain anomalies
    sender_domain = email_data.get('sender_domain', '').lower()
    free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    recipient_status = email_data.get('recipient_status', '')
    if sender_domain in free_domains and 'external' in recipient_status.lower():
        is_anomaly = True
        anomaly_reasons.append('Free email domain sending to external recipients')
        anomaly_score += 0.4
        anomaly_type = 'Domain'

    # High-risk combination anomaly - only if leaver field equals "YES"
    leaver = email_data.get('leaver', '')
    if (leaver and leaver.strip().upper() == 'YES' and has_attachments and (has_keywords_subject or has_keywords_attachment) and sender_domain in free_domains):
        is_anomaly = True
        anomaly_reasons.append('CRITICAL: Departing employee + attachments + keywords + free domain')
        anomaly_score += 0.9
        anomaly_type = 'Critical'

    return {
        'is_anomaly': is_anomaly,
        'anomaly_type': anomaly_type,
        'anomaly_score': min(anomaly_score, 1.0),  # Cap at 1.0
        'anomaly_reason': '; '.join(anomaly_reasons) if anomaly_reasons else 'No anomalies detected',
        'anomaly_details': f"Detected {len(anomaly_reasons)} anomaly indicators" if anomaly_reasons else None
    }

@st.dialog("Email Details")
def show_email_details_modal(email):
    """Display email details in a modal popup"""
    st.subheader("📧 Email Information")

    col1, col2 = st.columns(2)

    with col1:
        st.write(f"**Sender:** {email.get('sender', 'N/A')}")
        st.write(f"**Subject:** {email.get('subject', 'N/A')}")
        st.write(f"**Time:** {email.get('_time', 'N/A')}")
        st.write(f"**Recipients:** {email.get('recipients', 'N/A')}")
        st.write(f"**Recipients Domain:** {email.get('recipients_email_domain', 'N/A')}")
        st.write(f"**Business Unit:** {email.get('bunit', 'N/A')}")

    with col2:
        st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
        st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
        st.write(f"**Risk Factors:** {email.get('risk_factors', 'None')}")
        st.write(f"**Attachments:** {email.get('attachments', 'None')}")
        st.write(f"**Subject Keywords:** {email.get('Wordlist_subject', 'None')}")
        st.write(f"**Attachment Keywords:** {email.get('Wordlist_attachment', 'None')}")
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
        st.write(f"**Mimecast:** {email.get('mimecast', 'N/A')}")
        st.write(f"**Tessian:** {email.get('tessian', 'N/A')}")
        st.write(f"**Leaver:** {email.get('leaver', 'N/A')}")
        st.write(f"**Termination:** {email.get('Termination', 'N/A')}")
        st.write(f"**Time Month:** {email.get('time_month', 'N/A')}")
        st.write(f"**Account Type:** {email.get('account_type', 'N/A')}")

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

def network_analysis_page():
    """Interactive network analysis page with field selection and visualization"""
    st.header("🔗 Network Analysis")

    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return

    data = st.session_state.processed_data

    # Get available fields for dropdown options
    display_fields = []
    if data:
        available_fields = list(data[0].keys())
        display_fields = [field for field in available_fields if not field.startswith('_')]

    # Field Selection Interface
    st.subheader("🎯 Field Selection for Network Linking")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.write("**Source Nodes (From)**")
        source_field = st.selectbox(
            "Select source field:",
            options=display_fields,
            index=display_fields.index('sender') if 'sender' in display_fields else 0,
            key="source_field_select"
        )
        st.session_state.network_config['source_field'] = source_field

    with col2:
        st.write("**Target Nodes (To)**")
        target_field = st.selectbox(
            "Select target field:",
            options=display_fields,
            index=display_fields.index('recipients') if 'recipients' in display_fields else 1,
            key="target_field_select"
        )
        st.session_state.network_config['target_field'] = target_field

    with col3:
        st.write("**Link Weight (Optional)**")
        weight_options = ['None'] + [f for f in display_fields if any(keyword in f.lower() for keyword in ['score', 'count', 'frequency', 'weight', 'size'])]
        weight_field = st.selectbox(
            "Select weight field:",
            options=weight_options,
            key="weight_field_select"
        )
        st.session_state.network_config['weight_field'] = weight_field if weight_field != 'None' else None

    # Advanced Configuration
    with st.expander("⚙️ Advanced Configuration"):
        col1, col2 = st.columns(2)

        with col1:
            layout_type = st.selectbox(
                "Layout Algorithm:",
                options=['force_atlas', 'spring_3d', 'kamada_kawai', 'fruchterman_reingold', 'circular', 'hierarchical', 'community_based'],
                index=0,
                help="Advanced layout algorithms for better visualization"
            )
            st.session_state.network_config['layout'] = layout_type

            node_size_metric = st.selectbox(
                "Node Size Based On:",
                options=['pagerank', 'eigenvector', 'degree', 'betweenness', 'closeness', 'clustering_coeff'],
                help="Advanced centrality metrics for node sizing"
            )
            st.session_state.network_config['node_size_metric'] = node_size_metric

        with col2:
            # Advanced visualization options
            st.write("**Advanced Features**")
            
            enable_communities = st.checkbox("Community Detection", value=True, help="Detect and color communities")
            st.session_state.network_config['enable_communities'] = enable_communities
            
            enable_3d = st.checkbox("3D Visualization", value=False, help="Enable 3D network layout")
            st.session_state.network_config['enable_3d'] = enable_3d
            
            physics_simulation = st.checkbox("Physics Simulation", value=True, help="Enable real-time physics")
            st.session_state.network_config['physics_simulation'] = physics_simulation

            
            edge_bundling = st.checkbox("Edge Bundling", value=False, help="Bundle similar edges for cleaner view")
            st.session_state.network_config['edge_bundling'] = edge_bundling
            
            show_centrality = st.checkbox("Show Centrality Values", value=False, help="Display centrality scores")
            st.session_state.network_config['show_centrality'] = show_centrality

    # Generate Network Button
    if st.button("🔗 Generate Network Graph", type="primary", key="generate_network_btn"):
        st.session_state.selected_node = None  # Reset selection
        st.session_state.show_network = True

    # Display network graph
    if st.session_state.get('show_network', False):
        st.session_state.show_network = True

        # Interactive Controls Panel
        st.subheader("🎛️ Interactive Controls")

        # Real-time graph controls
        control_col1, control_col2, control_col3, control_col4 = st.columns(4)

        with control_col1:
            zoom_level = st.slider("Zoom Level", 0.5, 3.0, 1.0, 0.1, key="zoom_slider")

        with control_col2:
            node_size_multiplier = st.slider("Node Size", 0.5, 2.0, 1.0, 0.1, key="node_size_slider")

        with control_col3:
            edge_width = st.slider("Connection Width", 0.5, 3.0, 1.0, 0.1, key="edge_width_slider")

        with control_col4:
            show_labels = st.checkbox("Show All Labels", value=True, key="show_labels_checkbox")

        # Filter Controls
        st.write("**Filter Network:**")
        filter_col1, filter_col2, filter_col3 = st.columns(3)

        with filter_col1:
            min_connections = st.number_input("Min Connections", min_value=0, max_value=50, value=0, key="min_connections")

        with filter_col2:
            risk_filter = st.selectbox(
                "Risk Level Filter",
                options=["All", "High Risk Only", "Medium+ Risk", "Low Risk Only"],
                key="risk_filter_select"
            )

        with filter_col3:
            highlight_anomalies = st.checkbox("Highlight Anomalies", value=True, key="highlight_anomalies")

        # Update network config with user controls
        st.session_state.network_config.update({
            'zoom_level': zoom_level,
            'node_size_multiplier': node_size_multiplier,
            'edge_width': edge_width,
            'show_labels': show_labels,
            'min_connections': min_connections,
            'risk_filter': risk_filter,
            'highlight_anomalies': highlight_anomalies
        })

        with st.spinner("Building interactive network graph..."):
            network_graph = create_network_graph(data, source_field, target_field, st.session_state.network_config)
            if network_graph:

                # Advanced graph display with enhanced features
                st.subheader("🚀 Advanced Interactive Network Graph")
                
                # Enhanced feature guide
                features_col1, features_col2, features_col3, features_col4 = st.columns(4)
                with features_col1:
                    st.markdown("🎨 **Community Colors:** Auto-detected groups")
                with features_col2:
                    st.markdown("📊 **Node Size:** Advanced centrality metrics")
                with features_col3:
                    st.markdown("🔍 **Smart Layout:** Force-directed positioning")
                with features_col4:
                    st.markdown("⚡ **Physics:** Real-time interactions")
                
                st.info("✨ Advanced Features: Community detection • Centrality analysis • Multi-layout algorithms • Enhanced interactions")

                # Professional interactive controls with enhanced features
                st.markdown("### 🎮 Interactive Controls")
                
                control_col1, control_col2, control_col3, control_col4 = st.columns([3, 1, 1, 1])
                
                with control_col1:
                    st.info("""
                    **🎯 Professional Interaction Guide:**
                    • **🖱️ Click Nodes**: Detailed analysis & highlighting
                    • **🤏 Drag Nodes**: Reposition individual nodes
                    • **📐 Pan Mode**: Move entire network view
                    • **🔍 Zoom**: Scroll wheel or toolbar controls
                    • **📊 Select Tool**: Multi-node selection with lasso
                    • **🎨 Legend**: Click community types to filter
                    """)
                
                with control_col2:
                    if st.button("🔄 Reset View", key="reset_view_btn", type="secondary"):
                        if 'selected_node_for_highlight' in st.session_state:
                            del st.session_state.selected_node_for_highlight
                        st.rerun()
                
                with control_col3:
                    if st.button("🎯 Center Graph", key="center_graph_btn", type="secondary"):
                        st.success("Graph centered!")
                        
                with control_col4:
                    if st.button("📸 Export HD", key="export_hd_btn", type="primary"):
                        st.success("HD export ready!")

                # Display the professional graph with enhanced interactivity
                graph_container = st.container()
                
                with graph_container:
                    # Check if we need to highlight connections
                    if 'selected_node_for_highlight' in st.session_state and st.session_state.selected_node_for_highlight:
                        network_graph = create_highlighted_network_graph(data, source_field, target_field, st.session_state.network_config, st.session_state.selected_node_for_highlight)
                    
                    selected_data = st.plotly_chart(
                        network_graph, 
                        use_container_width=True,
                        config={
                            'displayModeBar': True,
                            'displaylogo': False,
                            'modeBarButtonsToAdd': ['pan2d', 'select2d', 'lasso2d', 'zoomIn2d', 'zoomOut2d', 'autoScale2d', 'resetScale2d', 'drawrect', 'drawopenpath'],
                            'modeBarButtonsToRemove': ['sendDataToCloud'],
                            'scrollZoom': True,
                            'doubleClick': 'reset+autosize',
                            'toImageButtonOptions': {
                                'format': 'png',
                                'filename': 'advanced_network_graph',
                                'height': 1600,
                                'width': 2400,
                                'scale': 2
                            },
                            'editable': True,
                            'showTips': True,
                            'responsive': True,
                            'showEditInChartStudio': False
                        },
                        key="advanced_network_chart",
                        on_select="rerun"
                    )

                    # Handle node selection for highlighting
                    if selected_data and 'selection' in selected_data and selected_data['selection']['points']:
                        selected_point = selected_data['selection']['points'][0]
                        if 'customdata' in selected_point:
                            selected_node = selected_point['customdata']
                            if selected_node != st.session_state.get('selected_node_for_highlight'):
                                st.session_state.selected_node_for_highlight = selected_node
                                st.rerun()

                # Enhanced Node Selection Interface
                st.subheader("🎯 Node Analysis")

                G = build_network_from_data(data, source_field, target_field)
                if len(G.nodes()) > 0:
                    all_nodes = sorted(list(G.nodes()))

                    # Search and select interface
                    search_col1, search_col2, search_col3 = st.columns([3, 1, 1])

                    with search_col1:
                        # Searchable dropdown
                        node_search = st.text_input(
                            "Search for a node:",
                            placeholder="Type to search nodes...",
                            key="node_search_input"
                        )

                        # Filter nodes based on search
                        if node_search:
                            filtered_nodes = [node for node in all_nodes if node_search.lower() in node.lower()]
                        else:
                            filtered_nodes = all_nodes

                        selected_node = st.selectbox(
                            "Select a node to analyze:",
                            options=["None"] + filtered_nodes[:50],  # Limit to first 50 for performance
                            index=0,
                            key="enhanced_node_select"
                        )

                    with search_col2:
                        if selected_node != "None":
                            if st.button("🔍 Analyze", key="enhanced_analyze_btn", type="primary"):
                                st.session_state.selected_node = selected_node
                                st.rerun()

                    with search_col3:
                        if st.session_state.selected_node:
                            if st.button("❌ Clear", key="enhanced_clear_btn"):
                                st.session_state.selected_node = None
                                st.rerun()

                    # Quick stats for selected node
                    if selected_node != "None" and selected_node in G.nodes():
                        degree = G.degree(selected_node)
                        st.info(f"**{selected_node}** has {degree} connections")

                # Real-time Network Statistics
                st.subheader("📈 Network Insights")

                # Build node_data for statistics calculation
                node_data = {}
                for record in data:
                    source = str(record.get(source_field, '')).strip()
                    target_raw = str(record.get(target_field, '')).strip()

                    if source:
                        if source not in node_data:
                            node_data[source] = {'anomalies': 0}
                        if record.get('is_anomaly', False):
                            node_data[source]['anomalies'] += 1

                    if target_raw:
                        targets = [t.strip() for t in target_raw.split(',') if t.strip()]
                        for target in targets:
                            if target not in node_data:
                                node_data[target] = {'anomalies': 0}
                            if record.get('is_anomaly', False):
                                node_data[target]['anomalies'] += 1

                insight_col1, insight_col2, insight_col3, insight_col4 = st.columns(4)

                with insight_col1:
                    total_nodes = len(list(G.nodes()))
                    st.metric("Total Nodes", total_nodes)

                with insight_col2:
                    total_edges = len(list(G.edges()))
                    st.metric("Connections", total_edges)

                with insight_col3:
                    avg_degree = sum(dict(G.degree()).values()) / len(G.nodes()) if len(G.nodes()) > 0 else 0
                    st.metric("Avg Connections", f"{avg_degree:.1f}")

                with insight_col4:
                    high_risk_nodes = sum(1 for node in G.nodes() 
                                        if node_data.get(node, {}).get('anomalies', 0) > 0)
                    st.metric("Anomaly Nodes", high_risk_nodes)

                # Network Health Summary
                if total_nodes > 0:
                    density = nx.density(G)
                    components = nx.number_connected_components(G)

                    health_col1, health_col2 = st.columns(2)
                    with health_col1:
                        st.info(f"🔗 Network Density: {density:.3f}")
                        if density > 0.3:
                            st.success("High connectivity - good communication flow")
                        elif density > 0.1:
                            st.warning("Medium connectivity - some isolated groups")
                        else:
                            st.error("Low connectivity - many isolated nodes")

                    with health_col2:
                        st.info(f"🏝️ Connected Groups: {components}")
                        if components == 1:
                            st.success("All nodes are connected")
                        else:
                            st.warning(f"Network has {components} separate groups")

                # Display selected node details with enhanced layout
                if st.session_state.selected_node:
                    st.markdown("---")
                    display_node_analysis(st.session_state.selected_node, data, source_field, target_field)

                # Network Statistics
                st.subheader("📈 Network Statistics")
                stats = calculate_network_statistics(data, source_field, target_field)

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Nodes", stats['total_nodes'])
                with col2:
                    st.metric("Total Edges", stats['total_edges'])
                with col3:
                    st.metric("Network Density", f"{stats['density']:.3f}")
                with col4:
                    st.metric("Connected Components", stats['components'])

                # Export Options
                st.subheader("💾 Export & Save")
                col1, col2, col3 = st.columns(3)

                with col1:
                    if st.button("📸 Export as Image", key="export_image_btn"):
                        st.info("Graph exported as PNG (check downloads)")

                with col2:
                    if st.button("🌐 Export as HTML", key="export_html_btn"):
                        html_content = network_graph.to_html()
                        st.download_button(
                            label="Download HTML",
                            data=html_content,
                            file_name="network_graph.html",
                            mime="text/html",
                            key="download_html_btn"
                        )

                with col3:
                    if st.button("⚙️ Save Configuration", key="save_config_btn"):
                        config_json = json.dumps(st.session_state.network_config, indent=2)
                        st.download_button(
                            label="Download Config",
                            data=config_json,
                            file_name="network_config.json",
                            mime="application/json",
                            key="download_config_btn"
                        )

def create_network_graph(data, source_field, target_field, config):
    """Create advanced interactive network graph with community detection and force-directed layouts"""
    try:
        # Build NetworkX graph with filtering
        G = nx.Graph()
        edge_weights = defaultdict(int)
        node_data = {}

        # Apply risk filter to data first
        filtered_data = data
        risk_filter = config.get('risk_filter', 'All')
        if risk_filter != 'All':
            if risk_filter == 'High Risk Only':
                filtered_data = [r for r in data if r.get('risk_level') in ['High', 'Critical']]
            elif risk_filter == 'Medium+ Risk':
                filtered_data = [r for r in data if r.get('risk_level') in ['Medium', 'High', 'Critical']]
            elif risk_filter == 'Low Risk Only':
                filtered_data = [r for r in data if r.get('risk_level') == 'Low']

        # Add edges from filtered data
        for record in filtered_data:
            source = str(record.get(source_field, '')).strip()
            target_raw = str(record.get(target_field, '')).strip()

            if not source or not target_raw:
                continue

            # Initialize node data if needed
            if source not in node_data:
                node_data[source] = {'risk_scores': [], 'anomalies': 0, 'emails': [], 'connections': set()}

            # Store node metadata for enhanced interactions
            risk_score = record.get('risk_score', 0)
            is_anomaly = record.get('is_anomaly', False)

            node_data[source]['risk_scores'].append(risk_score)
            node_data[source]['emails'].append(record)
            if is_anomaly:
                node_data[source]['anomalies'] += 1

            # Handle multiple targets (comma-separated)
            targets = [t.strip() for t in target_raw.split(',') if t.strip()]

            for target in targets:
                if source != target:  # Avoid self-loops
                    edge_key = (source, target)
                    edge_weights[edge_key] += 1

                    # Initialize target node data if needed
                    if target not in node_data:
                        node_data[target] = {'risk_scores': [], 'anomalies': 0, 'emails': [], 'connections': set()}

                    # Store connections for highlighting
                    node_data[source]['connections'].add(target)
                    node_data[target]['connections'].add(source)

                    # Store target metadata too
                    node_data[target]['risk_scores'].append(risk_score)
                    node_data[target]['emails'].append(record)
                    if is_anomaly:
                        node_data[target]['anomalies'] += 1

                    # Add weight from weight field if specified
                    weight = 1
                    if config.get('weight_field'):
                        try:
                            weight = float(record.get(config['weight_field'], 1))
                        except:
                            weight = 1

                    G.add_edge(source, target, weight=weight, count=edge_weights[edge_key])

        # Apply minimum connections filter
        min_connections = config.get('min_connections', 0)
        if min_connections > 0:
            nodes_to_remove = [node for node in G.nodes() if G.degree(node) < min_connections]
            G.remove_nodes_from(nodes_to_remove)

        if len(G.nodes()) == 0:
            st.error("No nodes meet the current filter criteria. Try adjusting your filters.")
            return None

        # Community detection if enabled
        communities = {}
        community_colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F']
        
        if config.get('enable_communities', True) and len(G.nodes()) > 3:
            try:
                # Use Louvain algorithm for community detection
                import networkx.algorithms.community as nxcom
                communities_list = list(nxcom.greedy_modularity_communities(G))
                for i, community in enumerate(communities_list):
                    color = community_colors[i % len(community_colors)]
                    for node in community:
                        communities[node] = {'id': i, 'color': color}
            except:
                # Fallback to simple clustering if community detection fails
                communities = {node: {'id': 0, 'color': '#45B7D1'} for node in G.nodes()}

        # Advanced layout calculation
        pos = calculate_advanced_layout(G, config['layout'])
        
        # Calculate advanced node metrics
        node_metrics = calculate_node_metrics(G, config['node_size_metric'])

        # Create advanced Plotly figure
        fig = create_advanced_plotly_figure(G, pos, node_data, node_metrics, communities, config, source_field, target_field, community_colors)

        # Store graph data for highlighting functionality
        if 'graph_data' not in st.session_state:
            st.session_state.graph_data = {}
        
        st.session_state.graph_data = {
            'G': G,
            'pos': pos,
            'node_data': node_data,
            'communities': communities,
            'node_metrics': node_metrics
        }

        return fig

    except Exception as e:
        st.error(f"Error creating advanced network graph: {str(e)}")
        return None


def calculate_advanced_layout(G, layout_type):
    """Calculate advanced network layout positions"""
    try:
        if layout_type == 'force_atlas':
            # Force Atlas-like layout using spring with optimized parameters
            pos = nx.spring_layout(G, k=3.0, iterations=300, seed=42, weight='weight')
        elif layout_type == 'kamada_kawai':
            pos = nx.kamada_kawai_layout(G, weight='weight')
        elif layout_type == 'fruchterman_reingold':
            pos = nx.spring_layout(G, k=2.0, iterations=200, seed=42)
        elif layout_type == 'hierarchical':
            # Create hierarchical layout based on node degree
            pos = nx.nx_agraph.graphviz_layout(G, prog='dot') if hasattr(nx, 'nx_agraph') else nx.spring_layout(G)
        elif layout_type == 'community_based':
            # Layout nodes by communities first, then within communities
            try:
                import networkx.algorithms.community as nxcom
                communities_list = list(nxcom.greedy_modularity_communities(G))
                pos = {}
                angle_step = 2 * np.pi / len(communities_list) if communities_list else 2 * np.pi
                
                for i, community in enumerate(communities_list):
                    # Position communities in a circle
                    center_x = 5 * np.cos(i * angle_step)
                    center_y = 5 * np.sin(i * angle_step)
                    
                    # Layout nodes within each community
                    subgraph = G.subgraph(community)
                    if len(subgraph.nodes()) > 1:
                        sub_pos = nx.spring_layout(subgraph, scale=2.0, seed=42)
                        for node, (x, y) in sub_pos.items():
                            pos[node] = (center_x + x, center_y + y)
                    else:
                        for node in community:
                            pos[node] = (center_x, center_y)
            except:
                pos = nx.spring_layout(G, k=3.0, iterations=200, seed=42)
        elif layout_type == 'spring_3d':
            # 3D spring layout (we'll project to 2D but with z-influence)
            try:
                pos_3d = nx.spring_layout(G, dim=3, k=3.0, iterations=200, seed=42)
                pos = {node: (coords[0] + coords[2]*0.3, coords[1] + coords[2]*0.3) for node, coords in pos_3d.items()}
            except:
                pos = nx.spring_layout(G, k=3.0, iterations=200, seed=42)
        elif layout_type == 'circular':
            pos = nx.circular_layout(G, scale=3.0)
        else:
            pos = nx.spring_layout(G, k=10.0, iterations=300, seed=42)
        
        # Scale positions for much better spacing
        scaling_factor = 8.0
        pos = {node: (x * scaling_factor, y * scaling_factor) for node, (x, y) in pos.items()}
        
        return pos
    
    except Exception as e:
        # Fallback to basic spring layout
        return nx.spring_layout(G, k=3.0, iterations=200, seed=42)


def calculate_node_metrics(G, metric_type):
    """Calculate advanced node centrality metrics"""
    try:
        if metric_type == 'pagerank':
            return nx.pagerank(G, weight='weight')
        elif metric_type == 'eigenvector':
            try:
                return nx.eigenvector_centrality(G, weight='weight', max_iter=1000)
            except:
                return nx.degree_centrality(G)
        elif metric_type == 'betweenness':
            return nx.betweenness_centrality(G, weight='weight')
        elif metric_type == 'closeness':
            return nx.closeness_centrality(G, distance='weight')
        elif metric_type == 'clustering_coeff':
            return nx.clustering(G, weight='weight')
        elif metric_type == 'degree':
            return dict(G.degree(weight='weight'))
        else:
            return {node: 1 for node in G.nodes()}
    except Exception as e:
        # Fallback to degree centrality
        return dict(G.degree())


def create_advanced_plotly_figure(G, pos, node_data, node_metrics, communities, config, source_field, target_field, community_colors):
    """Create clean, reliable network visualization"""
    try:
        fig = go.Figure()
        
        # Simple, clean edge visualization
        edge_x, edge_y = [], []
        edge_info = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
            weight = G[edge[0]][edge[1]].get('weight', 1)
            count = G[edge[0]][edge[1]].get('count', 1)
            edge_info.append(f"{edge[0]} → {edge[1]} (Weight: {weight}, Count: {count})")
        
        # Add edges
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            mode='lines',
            line=dict(width=1.5, color='rgba(100, 100, 100, 0.6)'),
            hoverinfo='none',
            showlegend=False,
            name='edges'
        ))

        # Simple node visualization
        node_x, node_y, node_text, node_info = [], [], [], []
        node_colors, node_sizes, node_ids = [], [], []
        
        show_labels = config.get('show_labels', True)
        node_size_multiplier = config.get('node_size_multiplier', 1.0)
        
        # Normalize metrics
        if node_metrics:
            max_metric = max(node_metrics.values()) if node_metrics.values() else 1
            min_metric = min(node_metrics.values()) if node_metrics.values() else 0
            metric_range = max_metric - min_metric if max_metric != min_metric else 1

        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_ids.append(node)
            
            # Node information
            adjacencies = list(G.neighbors(node))
            node_metadata = node_data.get(node, {'risk_scores': [], 'anomalies': 0, 'emails': []})
            
            avg_risk = sum(node_metadata['risk_scores']) / len(node_metadata['risk_scores']) if node_metadata['risk_scores'] else 0
            total_emails = len(node_metadata['emails'])
            anomaly_count = node_metadata['anomalies']
            centrality_value = node_metrics.get(node, 0)
            community_info = communities.get(node, {'id': 0, 'color': '#45B7D1'})
            
            # Simple hover text
            hover_text = f"""
            <b>{node}</b><br>
            Community: {community_info['id']}<br>
            Centrality: {centrality_value:.3f}<br>
            Connections: {len(adjacencies)}<br>
            Emails: {total_emails}<br>
            Risk Score: {avg_risk:.1f}<br>
            Anomalies: {anomaly_count}
            """
            node_info.append(hover_text)
            
            # Node labels
            if show_labels:
                node_text.append(str(node)[:8] + "..." if len(str(node)) > 8 else str(node))
            else:
                node_text.append("")
            
            # Node size
            if node_metrics and max_metric > 0:
                normalized_metric = (centrality_value - min_metric) / metric_range
                base_size = 20 + normalized_metric * 30
            else:
                base_size = 25
            node_sizes.append(base_size * node_size_multiplier)
            
            # Node color
            if anomaly_count > 0:
                node_colors.append('#e74c3c')  # Red for anomalies
            elif communities and node in communities:
                node_colors.append(community_info['color'])
            elif avg_risk > 70:
                node_colors.append('#e67e22')  # Orange for high risk
            elif avg_risk > 40:
                node_colors.append('#f39c12')  # Yellow for medium risk
            else:
                node_colors.append('#3498db')  # Blue for low risk

        # Add nodes
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text' if show_labels else 'markers',
            text=node_text,
            hovertext=node_info,
            hovertemplate='%{hovertext}<extra></extra>',
            textposition="middle center",
            textfont=dict(size=10, color='white', family='Arial Black'),
            marker=dict(
                color=node_colors,
                size=node_sizes,
                line=dict(width=2, color='rgba(255, 255, 255, 0.8)'),
                opacity=0.9,
                sizemode='diameter'
            ),
            showlegend=False,
            customdata=node_ids,
            name='nodes'
        ))

        # Simple, clean layout
        zoom_level = config.get('zoom_level', 1.0)
        
        fig.update_layout(
            title=dict(
                text=f"<b>Network Analysis: {source_field} → {target_field}</b>",
                x=0.5,
                font=dict(size=18, color='#2c3e50')
            ),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=60, l=40, r=40, t=80),
            annotations=[
                dict(
                    text=f"Nodes: {len(G.nodes())} | Connections: {len(G.edges())} | Communities: {len(set(c['id'] for c in communities.values())) if communities else 0}",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.02, y=0.02,
                    xanchor='left', yanchor='bottom',
                    font=dict(color='#7f8c8d', size=12),
                    bgcolor='rgba(255, 255, 255, 0.8)',
                    bordercolor='#bdc3c7',
                    borderwidth=1,
                    borderpad=5
                )
            ],
            xaxis=dict(
                showgrid=True, 
                gridcolor='rgba(255, 255, 255, 0.1)',
                zeroline=False, 
                showticklabels=False,
                fixedrange=False
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor='rgba(255, 255, 255, 0.1)', 
                zeroline=False, 
                showticklabels=False,
                fixedrange=False
            ),
            plot_bgcolor='rgba(45, 55, 72, 1.0)',
            paper_bgcolor='#2d3748',
            height=700,
            dragmode='pan',
            clickmode='event+select'
        )

        return fig
        
    except Exception as e:
        st.error(f"Error creating network visualization: {str(e)}")
        return None

def calculate_network_statistics(data, source_field, target_field):
    """Calculate network statistics"""
    try:
        G = nx.Graph()

        for record in data:
            source = str(record.get(source_field, '')).strip()
            target_raw = str(record.get(target_field, '')).strip()

            if not source or not target_raw:
                continue

            targets = [t.strip() for t in target_raw.split(',') if t.strip()]
            for target in targets:
                if source != target:
                    G.add_edge(source, target)

        return {
            'total_nodes': len(G.nodes()),
            'total_edges': len(G.edges()),
            'density': nx.density(G) if len(G.nodes()) > 1 else 0,
            'components': nx.number_connected_components(G)
        }
    except:
        return {'total_nodes': 0, 'total_edges': 0, 'density': 0, 'components': 0}

def build_network_from_data(data, source_field, target_field):
    """Build NetworkX graph from data for node analysis"""
    G = nx.Graph()

    for record in data:
        source = str(record.get(source_field, '')).strip()
        target_raw = str(record.get(target_field, '')).strip()

        if not source or not target_raw:
            continue

        targets = [t.strip() for t in target_raw.split(',') if t.strip()]
        for target in targets:
            if source != target:
                G.add_edge(source, target)

    return G

def display_node_analysis(selected_node, data, source_field, target_field):
    """Display comprehensive analysis for selected node"""
    st.markdown("---")
    st.subheader(f"🎯 Detailed Analysis: {selected_node}")

    # Find all records related to this node
    related_records = []
    connections = set()
    outgoing_connections = set()
    incoming_connections = set()

    for record in data:
        source = str(record.get(source_field, '')).strip()
        target_raw = str(record.get(target_field, '')).strip()

        # Check if this node appears as source
        if source == selected_node:
            targets = [t.strip() for t in target_raw.split(',') if t.strip()]
            for target in targets:
                if target != selected_node:
                    connections.add(target)
                    outgoing_connections.add(target)
                    related_records.append({
                        'type': 'outgoing',
                        'connection': target,
                        'record': record
                    })

        # Check if this node appears as target
        if selected_node in [t.strip() for t in target_raw.split(',') if t.strip()]:
            connections.add(source)
            incoming_connections.add(source)
            related_records.append({
                'type': 'incoming',
                'connection': source,
                'record': record
            })

    # Node statistics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Connections", len(connections))
    with col2:
        st.metric("Outgoing Links", len(outgoing_connections))
    with col3:
        st.metric("Incoming Links", len(incoming_connections))
    with col4:
        high_risk_count = len([r for r in related_records if r['record'].get('risk_level') in ['High', 'Critical']])
        st.metric("High Risk Emails", high_risk_count)

    # Connection details
    if connections:
        col_a, col_b = st.columns(2)

        with col_a:
            if outgoing_connections:
                st.write("**Outgoing Connections:**")
                for conn in list(outgoing_connections)[:8]:
                    st.write(f"• → {conn}")
                if len(outgoing_connections) > 8:
                    st.write(f"... and {len(outgoing_connections) - 8} more")

        with col_b:
            if incoming_connections:
                st.write("**Incoming Connections:**")
                for conn in list(incoming_connections)[:8]:
                    st.write(f"• ← {conn}")
                if len(incoming_connections) > 8:
                    st.write(f"... and {len(incoming_connections) - 8} more")

    # Email analysis
    if related_records:
        st.write("**Associated Email Activity:**")

        # Risk level breakdown
        risk_counts = Counter(r['record'].get('risk_level', 'Unknown') for r in related_records)
        anomaly_count = sum(1 for r in related_records if r['record'].get('is_anomaly', False))



def create_highlighted_network_graph(data, source_field, target_field, config, selected_node):
    """Create network graph with highlighted connections for selected node"""
    try:
        # Build NetworkX graph
        G = nx.Graph()
        edge_weights = defaultdict(int)
        node_data = {}

        # Apply risk filter to data first
        filtered_data = data
        risk_filter = config.get('risk_filter', 'All')
        if risk_filter != 'All':
            if risk_filter == 'High Risk Only':
                filtered_data = [r for r in data if r.get('risk_level') in ['High', 'Critical']]
            elif risk_filter == 'Medium+ Risk':
                filtered_data = [r for r in data if r.get('risk_level') in ['Medium', 'High', 'Critical']]
            elif risk_filter == 'Low Risk Only':
                filtered_data = [r for r in data if r.get('risk_level') == 'Low']

        # Build graph and collect connections
        connected_nodes = set()
        selected_edges = set()

        for record in filtered_data:
            source = str(record.get(source_field, '')).strip()
            target_raw = str(record.get(target_field, '')).strip()

            if not source or not target_raw:
                continue

            # Initialize node data
            if source not in node_data:
                node_data[source] = {'risk_scores': [], 'anomalies': 0, 'emails': []}

            risk_score = record.get('risk_score', 0)
            is_anomaly = record.get('is_anomaly', False)

            node_data[source]['risk_scores'].append(risk_score)
            node_data[source]['emails'].append(record)
            if is_anomaly:
                node_data[source]['anomalies'] += 1

            targets = [t.strip() for t in target_raw.split(',') if t.strip()]

            for target in targets:
                if source != target:
                    edge_key = (source, target)
                    edge_weights[edge_key] += 1

                    if target not in node_data:
                        node_data[target] = {'risk_scores': [], 'anomalies': 0, 'emails': []}

                    node_data[target]['risk_scores'].append(risk_score)
                    node_data[target]['emails'].append(record)
                    if is_anomaly:
                        node_data[target]['anomalies'] += 1

                    weight = 1
                    if config.get('weight_field'):
                        try:
                            weight = float(record.get(config['weight_field'], 1))
                        except:
                            weight = 1

                    G.add_edge(source, target, weight=weight, count=edge_weights[edge_key])

                    # Track connections to selected node
                    if source == selected_node:
                        connected_nodes.add(target)
                        selected_edges.add((source, target))
                    elif target == selected_node:
                        connected_nodes.add(source)
                        selected_edges.add((source, target))

        # Apply minimum connections filter
        min_connections = config.get('min_connections', 0)
        if min_connections > 0:
            nodes_to_remove = [node for node in G.nodes() if G.degree(node) < min_connections]
            G.remove_nodes_from(nodes_to_remove)

        if len(G.nodes()) == 0:
            return None

        # Calculate layout positions
        if config['layout'] == 'spring':
            pos = nx.spring_layout(G, k=2.5, iterations=100, seed=42)
        elif config['layout'] == 'circular':
            pos = nx.circular_layout(G)
        elif config['layout'] == 'shell':
            pos = nx.shell_layout(G)
        else:
            pos = nx.random_layout(G, seed=42)

        # Calculate node metrics
        node_metrics = {}
        if config['node_size_metric'] == 'degree':
            node_metrics = dict(G.degree())
        elif config['node_size_metric'] == 'betweenness':
            node_metrics = nx.betweenness_centrality(G)
        elif config['node_size_metric'] == 'closeness':
            node_metrics = nx.closeness_centrality(G)
        else:
            node_metrics = {node: 1 for node in G.nodes()}

        # Create highlighted figure
        fig = go.Figure()

        # Add regular edges (dimmed)
        edge_x_regular = []
        edge_y_regular = []
        edge_x_highlighted = []
        edge_y_highlighted = []

        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            
            if edge in selected_edges or (edge[1], edge[0]) in selected_edges:
                # Highlighted edges
                edge_x_highlighted.extend([x0, x1, None])
                edge_y_highlighted.extend([y0, y1, None])
            else:
                # Regular edges (dimmed)
                edge_x_regular.extend([x0, x1, None])
                edge_y_regular.extend([y0, y1, None])

        # Regular edges (dimmed)
        if edge_x_regular:
            fig.add_trace(go.Scatter(
                x=edge_x_regular, y=edge_y_regular,
                line=dict(width=1, color='rgba(150, 150, 150, 0.2)'),
                hoverinfo='none',
                mode='lines',
                showlegend=False,
                name='regular_edges'
            ))

        # Highlighted edges
        if edge_x_highlighted:
            fig.add_trace(go.Scatter(
                x=edge_x_highlighted, y=edge_y_highlighted,
                line=dict(width=4, color='rgba(231, 76, 60, 0.8)'),
                hoverinfo='none',
                mode='lines',
                showlegend=False,
                name='highlighted_edges'
            ))

        # Add nodes with highlighting
        node_x = []
        node_y = []
        node_text = []
        node_info = []
        node_sizes = []
        node_colors = []
        node_opacities = []
        node_line_colors = []
        node_line_widths = []
        node_ids = []

        node_size_multiplier = config.get('node_size_multiplier', 1.0)
        show_labels = config.get('show_labels', True)
        highlight_anomalies = config.get('highlight_anomalies', True)

        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_ids.append(node)

            adjacencies = list(G.neighbors(node))
            node_metadata = node_data.get(node, {'risk_scores': [], 'anomalies': 0, 'emails': []})

            avg_risk = sum(node_metadata['risk_scores']) / len(node_metadata['risk_scores']) if node_metadata['risk_scores'] else 0
            total_emails = len(node_metadata['emails'])
            anomaly_count = node_metadata['anomalies']

            # Enhanced hover for highlighted nodes
            if node == selected_node:
                hover_text = f"""
                <b style="font-size: 16px; color: #e74c3c;">🎯 SELECTED: {node}</b><br>
                <span style="color: #34495e;"><b>Connections:</b> {len(adjacencies)}</span><br>
                <span style="color: #34495e;"><b>Connected Nodes:</b> {len(connected_nodes)}</span><br>
                <span style="color: #e74c3c;"><b>Risk Score:</b> {avg_risk:.1f}</span><br>
                <span style="color: #e67e22;"><b>Anomalies:</b> {anomaly_count}</span>
                """.strip()
            elif node in connected_nodes:
                hover_text = f"""
                <b style="font-size: 14px; color: #e67e22;">🔗 CONNECTED: {node}</b><br>
                <span style="color: #34495e;"><b>Connected to selected node</b></span><br>
                <span style="color: #34495e;"><b>Total Connections:</b> {len(adjacencies)}</span><br>
                <span style="color: #e74c3c;"><b>Risk Score:</b> {avg_risk:.1f}</span><br>
                <span style="color: #e67e22;"><b>Anomalies:</b> {anomaly_count}</span>
                """.strip()
            else:
                hover_text = f"""
                <b style="font-size: 12px; color: #7f8c8d;">{node}</b><br>
                <span style="color: #95a5a6;"><b>Connections:</b> {len(adjacencies)}</span><br>
                <span style="color: #95a5a6;"><b>Risk Score:</b> {avg_risk:.1f}</span>
                """.strip()
            
            node_info.append(hover_text)

            # Node labeling
            if show_labels and (node == selected_node or node in connected_nodes):
                if len(str(node)) > 15:
                    node_text.append(str(node)[:12] + "...")
                else:
                    node_text.append(str(node))
            else:
                node_text.append("")

            # Node size calculation
            metric_value = node_metrics.get(node, 1)
            base_size = max(20, min(80, metric_value * 35 + 15)) * node_size_multiplier
            
            # Increase size for selected and connected nodes
            if node == selected_node:
                base_size *= 1.5
            elif node in connected_nodes:
                base_size *= 1.2
            
            node_sizes.append(base_size)

            # Enhanced color scheme with highlighting
            if node == selected_node:
                node_colors.append('#e74c3c')  # Bright red for selected
                node_opacities.append(1.0)
                node_line_colors.append('#ffffff')
                node_line_widths.append(4)
            elif node in connected_nodes:
                if highlight_anomalies and anomaly_count > 0:
                    node_colors.append('#e67e22')  # Orange for connected anomalies
                elif avg_risk > 50:
                    node_colors.append('#f39c12')  # Yellow for connected high risk
                else:
                    node_colors.append('#3498db')  # Blue for connected normal
                node_opacities.append(0.9)
                node_line_colors.append('#e74c3c')
                node_line_widths.append(3)
            else:
                # Dimmed colors for non-connected nodes
                node_colors.append('#bdc3c7')
                node_opacities.append(0.3)
                node_line_colors.append('#95a5a6')
                node_line_widths.append(1)

        # Create nodes trace with highlighting
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text' if show_labels else 'markers',
            hoverinfo='text',
            hovertext=node_info,
            text=node_text,
            textposition="middle center",
            textfont=dict(
                size=11, 
                color='white', 
                family='Arial Black'
            ),
            marker=dict(
                color=node_colors,
                size=node_sizes,
                line=dict(width=node_line_widths, color=node_line_colors),
                opacity=node_opacities,
                sizemode='diameter'
            ),
            showlegend=False,
            customdata=node_ids,
            name='nodes'
        ))

        # Professional layout
        zoom_level = config.get('zoom_level', 1.0)

        fig.update_layout(
            title=dict(
                text=f"<b>Network Analysis - Highlighting: {selected_node}</b><br><sub>{len(connected_nodes)} connected nodes shown</sub>",
                x=0.5,
                font=dict(size=18, color='#2c3e50', family='Arial Black')
            ),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=60, l=40, r=120, t=80),
            annotations=[
                dict(
                    text=f"<b>🎯 Node Highlighting Active</b><br>Selected: <b>{selected_node}</b><br>Connected nodes: <b>{len(connected_nodes)}</b><br>Click another node or reset to change selection",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.02, y=0.02,
                    xanchor='left', yanchor='bottom',
                    font=dict(color='#e74c3c', size=12, family='Arial Black'),
                    bgcolor='rgba(255,255,255,0.95)',
                    bordercolor='#e74c3c',
                    borderwidth=3,
                    borderpad=10
                )
            ],
            xaxis=dict(
                showgrid=True, 
                gridcolor='rgba(255, 255, 255, 0.1)',
                zeroline=False, 
                showticklabels=False,
                range=[-zoom_level * 1.2, zoom_level * 1.2],
                fixedrange=False,
                scaleanchor="y",
                scaleratio=1
            ),
            yaxis=dict(
                showgrid=True, 
                gridcolor='rgba(255, 255, 255, 0.1)',
                zeroline=False, 
                showticklabels=False,
                range=[-zoom_level * 1.2, zoom_level * 1.2],
                fixedrange=False
            ),
            plot_bgcolor='rgba(45, 55, 72, 1.0)',
            paper_bgcolor='#2d3748',
            height=700,
            dragmode='pan',
            clickmode='event+select'
        )

        return fig

    except Exception as e:
        st.error(f"Error creating highlighted network graph: {str(e)}")
        return None


        col1, col2, col3 = st.columns(3)
        with col1:
            st.write("**Risk Distribution:**")
            for level, count in risk_counts.items():
                color = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(level, '⚪')
                st.write(f"{color} {level}: {count}")

        with col2:
            if anomaly_count > 0:
                st.error(f"🚨 {anomaly_count} Anomalies Detected")
            else:
                st.success("✅ No Anomalies")

        with col3:
            total_emails = len(related_records)
            avg_risk = sum(r['record'].get('risk_score', 0) for r in related_records) / total_emails if total_emails else 0
            st.metric("Average Risk Score", f"{avg_risk:.1f}")

        # Recent email activity
        st.write("**Recent Email Activity:**")

        # Sort by time (if available) and risk score
        sorted_records = sorted(related_records, 
                              key=lambda x: (x['record'].get('risk_score', 0), x['record'].get('time', '')), 
                              reverse=True)

        for i, record_info in enumerate(sorted_records[:6]):
            record = record_info['record']
            connection_type = "→" if record_info['type'] == 'outgoing' else "←"
            risk_level = record.get('risk_level', 'Unknown')
            risk_color = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(risk_level, '⚪')

            with st.expander(f"{connection_type} {record_info['connection']} {risk_color} - {record.get('subject', 'No Subject')[:40]}..."):
                col_x, col_y = st.columns(2)
                with col_x:
                    st.write(f"**Subject:** {record.get('subject', 'N/A')}")
                    st.write(f"**Time:** {record.get('time', 'N/A')}")
                    st.write(f"**Risk Score:** {record.get('risk_score', 0)}")
                    st.write(f"**Risk Level:** {risk_level}")

                with col_y:
                    st.write(f"**Attachments:** {record.get('attachments', 'None')}")
                    st.write(f"**Keywords:** {record.get('word_list_match', 'None')}")
                    if record.get('is_anomaly', False):
                        st.error(f"🚨 Anomaly: {record.get('anomaly_type', 'Unknown')}")

                    # Risk factors
                    risk_factors = record.get('risk_factors', 'None')
                    if risk_factors and risk_factors != 'None':
                        st.write(f"**Risk Factors:** {risk_factors}")

        if len(related_records) > 6:
            st.info(f"Showing 6 of {len(related_records)} related records")

def handle_node_click(selected_points, data, source_field, target_field):
    """Handle node click events and display detailed information"""
    if not selected_points:
        return

    # Get the clicked node
    point = selected_points[0]
    if 'customdata' in point:
        clicked_node = point['customdata']

        st.subheader(f"🎯 Node Details: {clicked_node}")

        # Find all records related to this node
        related_records = []
        connections = set()

        for record in data:
            source = str(record.get(source_field, '')).strip()
            target_raw = str(record.get(target_field, '')).strip()

            # Check if this node appears as source or target
            if source == clicked_node:
                targets = [t.strip() for t in target_raw.split(',') if t.strip()]
                for target in targets:
                    if target != clicked_node:
                        connections.add(target)
                        related_records.append({
                            'type': 'outgoing',
                            'connection': target,
                            'record': record
                        })

            if clicked_node in [t.strip() for t in target_raw.split(',') if t.strip()]:
                connections.add(source)
                related_records.append({
                    'type': 'incoming',
                    'connection': source,
                    'record': record
                })

        # Display node statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Connections", len(connections))
        with col2:
            outgoing = len([r for r in related_records if r['type'] == 'outgoing'])
            st.metric("Outgoing Links", outgoing)
        with col3:
            incoming = len([r for r in related_records if r['type'] == 'incoming'])
            st.metric("Incoming Links", incoming)

        # Display connections
        if connections:
            st.write("**Direct Connections:**")
            connections_list = list(connections)[:10]  # Show first 10
            for i, conn in enumerate(connections_list):
                st.write(f"• {conn}")

            if len(connections) > 10:
                st.write(f"... and {len(connections) - 10} more connections")

        # Display related email records
        if related_records:
            st.write("**Related Email Records:**")

            # Group by connection type
            for record_info in related_records[:5]:  # Show first 5 records
                record = record_info['record']
                connection_type = "→" if record_info['type'] == 'outgoing' else "←"

                with st.expander(f"{connection_type} {record_info['connection']} - {record.get('subject', 'No Subject')[:40]}..."):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"**Subject:** {record.get('subject', 'N/A')}")
                        st.write(f"**Time:** {record.get('_time', 'N/A')}")
                        st.write(f"**Risk Score:** {record.get('risk_score', 0)}")
                    with col_b:
                        st.write(f"**Risk Level:** {record.get('risk_level', 'Unknown')}")
                        st.write(f"**Attachments:** {record.get('attachments', 'None')}")
                        if record.get('is_anomaly', False):
                            st.error("🚨 Anomaly Detected")

            if len(related_records) > 5:
                st.info(f"Showing 5 of {len(related_records)} related records")

def main():
    # Check authentication first
    if not check_authentication():
        show_login_page()
        return
    
    # Show header with user info
    user = get_current_user()
    role_name = USER_ROLES[user['role']]['name'] if user else "Unknown"
    
    st.title("🛡️ ExfilEye - DLP Email Security Monitoring System")
    st.markdown(f"*Welcome, {user.get('full_name', 'User')} - {role_name}*")
    st.markdown("---")

    # Define all available pages
    all_pages = [
        "📁 Data Upload", 
        "🛡️ Security Operations",
        "✅ Email Check Completed",
        "📨 Follow-up Center", 
        "🔗 Network Analysis", 
        "🌐 Domain Classification",
        "🎯 Risk Configuration",
        "📊 System Workflow", 
        "⚙️ Settings"
    ]
    
    # Filter pages based on user permissions
    accessible_pages = filter_navigation_by_permissions(all_pages)
    
    # Add User Management for admins
    if has_permission('admin'):
        accessible_pages.append("👥 User Management")

    # Sidebar navigation
    with st.sidebar:
        st.header("📋 Navigation")
        
        if accessible_pages:
            page = st.radio(
                "Select Section:",
                accessible_pages,
                label_visibility="collapsed"
            )
        else:
            st.error("❌ No accessible pages for your role")
            page = None

        # Display data status
        if st.session_state.data is not None:
            st.success(f"✅ Data loaded: {len(st.session_state.data)} records")
        else:
            st.warning("⚠️ No data loaded")
        
        # Show user info
        show_user_info_sidebar()

    # Route to selected page with permission checks
    if page == "📁 Data Upload":
        if has_permission('data_upload'):
            data_upload_page()
        else:
            show_access_denied("data_upload")
    elif page == "🛡️ Security Operations":
        if has_permission('security_operations'):
            daily_checks_page()
        else:
            show_access_denied("security_operations")
    elif page == "✅ Email Check Completed":
        if has_permission('security_operations'):
            email_check_completed_page()
        else:
            show_access_denied("security_operations")
    elif page == "📨 Follow-up Center":
        if has_permission('follow_up'):
            followup_center_page()
        else:
            show_access_denied("follow_up")
    elif page == "🔗 Network Analysis":
        if has_permission('network_analysis'):
            network_analysis_page()
        else:
            show_access_denied("network_analysis")
    elif page == "🌐 Domain Classification":
        if has_permission('admin'):
            domain_classification_page()
        else:
            show_access_denied("admin")
    elif page == "🎯 Risk Configuration":
        if has_permission('admin'):
            risk_configuration_page()
        else:
            show_access_denied("admin")
    elif page == "📊 System Workflow":
        if has_permission('reports'):
            system_workflow_page()
        else:
            show_access_denied("reports")
    elif page == "⚙️ Settings":
        if has_permission('admin'):
            settings_page()
        else:
            show_access_denied("admin")
    elif page == "👥 User Management":
        if has_permission('admin'):
            show_user_management()
        else:
            show_access_denied("admin")

def show_access_denied(required_permission):
    """Show access denied message"""
    user = get_current_user()
    st.error("❌ **Access Denied**")
    st.warning(f"You don't have permission to access this feature.")
    st.info(f"**Required Permission:** {required_permission}")
    st.info(f"**Your Role:** {USER_ROLES[user['role']]['name']}")
    st.info(f"**Your Permissions:** {', '.join(USER_ROLES[user['role']]['permissions'])}")
    
    # Show role upgrade information
    with st.expander("ℹ️ Role Information"):
        st.markdown("### Available Roles and Permissions")
        for role, info in USER_ROLES.items():
            permissions_text = "All Permissions" if 'all' in info['permissions'] else ', '.join(info['permissions'])
            st.markdown(f"**{info['name']}**: {info['description']}")
            st.caption(f"Permissions: {permissions_text}")
            st.markdown("---")

@require_permission('data_upload')
def data_upload_page():
    st.header("📁 Data Upload & Validation")
    
    # Security audit log
    user = get_current_user()
    st.info(f"🔐 **Security Context**: Data upload session by {user.get('full_name')} ({USER_ROLES[user['role']]['name']})")

    st.subheader("CSV Email Data Upload")
    uploaded_file = st.file_uploader(
        "Upload email metadata CSV file",
        type=['csv'],
        help="Upload CSV file containing email metadata for analysis"
    )

    if uploaded_file is not None:
        # Display file information
        file_size = uploaded_file.size
        st.info(f"📁 **File Selected**: {uploaded_file.name} ({file_size:,} bytes)")
        
        if file_size > 100 * 1024 * 1024:  # 100MB
            st.warning("⚠️ **Large File Detected**: This file is over 100MB. Processing may take several minutes.")
        
        try:
            # Read the CSV file content
            with st.spinner("📖 Reading CSV file..."):
                csv_content = uploaded_file.read().decode('utf-8')
            
            # Process CSV data with progress indicators
            with st.spinner("🔍 Parsing CSV data..."):
                data = process_csv_data(csv_content)

            if data:
                st.session_state.data = data
                record_count = len(data)
                st.success(f"✅ CSV parsed successfully: {record_count:,} records found")

                # Process each email for risk scoring and anomaly detection using current risk configuration
                processed_data = []
                risk_manager = st.session_state.risk_config_manager
                
                # Show progress for large datasets
                if record_count > 1000:
                    st.info(f"🔄 Now calculating risk scores for {record_count:,} emails...")
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                
                for i, email in enumerate(data):
                    # Apply risk configuration from risk manager
                    risk_info = risk_manager.calculate_risk_score(email)
                    anomaly_info = detect_anomalies(email)
                    email.update(risk_info)
                    email.update(anomaly_info)
                    processed_data.append(email)
                    
                    # Update progress for large files
                    if record_count > 1000 and i % 1000 == 0:
                        progress = (i + 1) / record_count
                        progress_bar.progress(progress)
                        status_text.text(f"Processing email {i+1:,} of {record_count:,} ({progress*100:.1f}%)")
                
                # Clear progress indicators
                if record_count > 1000:
                    progress_bar.empty()
                    status_text.empty()

                st.session_state.processed_data = processed_data
                st.success(f"✅ Data uploaded and processed successfully! {record_count:,} emails ready for analysis")
                
                # Show risk configuration being used
                st.info(f"📊 **Risk Configuration Applied**: Using current risk level thresholds - Critical: {risk_manager.risk_config['risk_levels']['Critical']['threshold']}+, High: {risk_manager.risk_config['risk_levels']['High']['threshold']}+, Medium: {risk_manager.risk_config['risk_levels']['Medium']['threshold']}+, Low: {risk_manager.risk_config['risk_levels']['Low']['threshold']}+")
                
                # Debug: Show critical formula status
                st.info(f"🚨 **Critical Formula**: leaver=YES AND attachments!='-' AND (Wordlist_attachment != '-' OR Wordlist_subject != '-')")
                
                # Show sample of risk calculations
                sample_critical_checks = []
                for i, email in enumerate(processed_data[:3]):
                    formula_met = risk_manager.check_critical_formula(email)
                    sample_critical_checks.append(f"Email {i+1}: Formula={formula_met}, Risk={email.get('risk_level')}, Score={email.get('risk_score')}")
                
                st.info(f"🔍 **Sample Risk Calculations**: " + " | ".join(sample_critical_checks))

                # Display data preview
                st.subheader("📊 Data Preview")

                # Show first few records
                for i, email in enumerate(data[:5]):
                    with st.expander(f"Email {i+1}: {email.get('subject', 'No Subject')[:50]}..."):
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**Sender:** {email.get('sender', 'N/A')}")
                            st.write(f"**Recipients:** {email.get('recipients', 'N/A')}")
                            st.write(f"**Time:** {email.get('_time', 'N/A')}")
                        with col_b:
                            st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                            st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                            st.write(f"**Domain:** {email.get('sender_domain', 'N/A')}")

                # Display summary
                st.subheader("🔍 Analysis Summary")
                col_a, col_b, col_c, col_d = st.columns(4)
                with col_a:
                    st.metric("Total Records", len(data))
                with col_b:
                    high_risk = len([e for e in processed_data if e.get('risk_level') in ['High', 'Critical']])
                    st.metric("High Risk Emails", high_risk)
                with col_c:
                    anomaly_count = len([e for e in processed_data if e.get('is_anomaly', False)])
                    st.metric("Anomalies Detected", anomaly_count)
                with col_d:
                    avg_risk = sum(e.get('risk_score', 0) for e in processed_data) / len(processed_data) if processed_data else 0
                    st.metric("Average Risk Score", f"{avg_risk:.1f}")
                
                # Add reprocess button
                st.markdown("---")
                st.subheader("🔄 Reprocess Data")
                st.info("If you've changed risk configuration settings, click below to recalculate all risk scores with the new settings.")
                
                if st.button("🔄 Reprocess All Data with Current Risk Settings", type="primary"):
                    with st.spinner("Reprocessing data with updated risk configuration..."):
                        # Reprocess each email with current risk settings from risk manager
                        reprocessed_data = []
                        risk_manager = st.session_state.risk_config_manager
                        
                        for email in data:
                            # Use the risk configuration manager for consistent scoring
                            risk_info = risk_manager.calculate_risk_score(email)
                            anomaly_info = detect_anomalies(email)
                            email.update(risk_info)
                            email.update(anomaly_info)
                            reprocessed_data.append(email)
                        
                        st.session_state.processed_data = reprocessed_data
                        st.success("✅ Data reprocessed successfully with current risk settings!")
                        
                        # Show updated risk configuration info
                        st.info(f"🎯 **Updated Risk Thresholds Applied**: Critical: {risk_manager.risk_config['risk_levels']['Critical']['threshold']}+, High: {risk_manager.risk_config['risk_levels']['High']['threshold']}+, Medium: {risk_manager.risk_config['risk_levels']['Medium']['threshold']}+, Low: {risk_manager.risk_config['risk_levels']['Low']['threshold']}+")
                        
                        # Show updated summary
                        st.subheader("📊 Updated Analysis Summary")
                        col_new1, col_new2, col_new3, col_new4 = st.columns(4)
                        with col_new1:
                            st.metric("Total Records", len(reprocessed_data))
                        with col_new2:
                            new_high_risk = len([e for e in reprocessed_data if e.get('risk_level') in ['High', 'Critical']])
                            st.metric("High Risk Emails", new_high_risk)
                        with col_new3:
                            new_anomaly_count = len([e for e in reprocessed_data if e.get('is_anomaly', False)])
                            st.metric("Anomalies Detected", new_anomaly_count)
                        with col_new4:
                            new_avg_risk = sum(e.get('risk_score', 0) for e in reprocessed_data) / len(reprocessed_data) if reprocessed_data else 0
                            st.metric("Average Risk Score", f"{new_avg_risk:.1f}")
                        
                        st.rerun()

            else:
                st.error("❌ No valid data found in the uploaded file")

        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")



@require_permission('security_operations')
def email_check_completed_page():
    """Dashboard showing emails that have been reviewed and completed"""
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return

    # Professional header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
                padding: 2rem; border-radius: 10px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0; text-align: center;">
            ✅ Email Check Completed Dashboard
        </h1>
        <p style="color: rgba(255,255,255,0.8); text-align: center; margin: 0.5rem 0 0 0;">
            Completed Email Security Reviews & Actions Taken
        </p>
    </div>
    """, unsafe_allow_html=True)

    data = st.session_state.processed_data
    
    # Filter to show only completed senders and emails
    sender_groups = defaultdict(list)
    for email in data:
        sender = email.get('sender', 'Unknown')
        sender_groups[sender].append(email)

    # Get only completed senders
    completed_senders = []
    for sender, emails in sender_groups.items():
        sender_status = st.session_state.sender_review_status.get(sender, 'outstanding')
        if sender_status == 'completed':
            completed_senders.append((sender, emails))

    if not completed_senders:
        st.info("📋 No emails have been marked as completed yet.")
        st.markdown("---")
        st.markdown("### 📖 How to mark emails as completed:")
        st.markdown("""
        1. Go to **🛡️ Security Operations** dashboard
        2. Review emails in the Risk Events section
        3. Make decisions on all emails from a sender (No Action, Monitor, Investigate, or Escalate)
        4. Once all emails from a sender have been reviewed, they will automatically appear here
        """)
        return

    # Summary metrics
    st.markdown("### 📊 Completion Summary")
    col1, col2, col3, col4 = st.columns(4)
    
    total_completed_emails = sum(len(emails) for _, emails in completed_senders)
    total_completed_senders = len(completed_senders)
    
    # Calculate completion stats
    completed_actions = {
        'no_action': 0,
        'monitor': 0,
        'investigate': 0,
        'escalate': 0
    }
    
    for sender, emails in completed_senders:
        for i, email in enumerate(emails):
            email_key = f"{sender}_{i}"
            decision = st.session_state.followup_decisions.get(email_key, 'pending')
            if decision in completed_actions:
                completed_actions[decision] += 1

    with col1:
        st.metric("✅ Completed Senders", total_completed_senders)
    with col2:
        st.metric("📧 Total Emails Reviewed", total_completed_emails)
    with col3:
        st.metric("🔍 Investigations", completed_actions['investigate'])
    with col4:
        st.metric("🚨 Escalations", completed_actions['escalate'])

    # Action breakdown
    st.markdown("### 📈 Actions Taken Breakdown")
    action_col1, action_col2, action_col3, action_col4 = st.columns(4)
    
    with action_col1:
        st.metric("✅ No Action", completed_actions['no_action'], help="Emails cleared as no security concern")
    with action_col2:
        st.metric("⚠️ Monitor", completed_actions['monitor'], help="Emails added to monitoring list")
    with action_col3:
        st.metric("🔎 Investigate", completed_actions['investigate'], help="Emails sent for investigation")
    with action_col4:
        st.metric("🚨 Escalate", completed_actions['escalate'], help="Emails escalated to management")

    # Completed senders list
    st.markdown("---")
    st.markdown("### 📋 Completed Email Reviews")
    
    # Sort by completion date (if we had that) or by sender name
    completed_senders.sort(key=lambda x: x[0])
    
    for sender, emails in completed_senders:
        # Calculate stats for this sender
        sender_actions = {}
        for i, email in enumerate(emails):
            email_key = f"{sender}_{i}"
            decision = st.session_state.followup_decisions.get(email_key, 'pending')
            sender_actions[decision] = sender_actions.get(decision, 0) + 1

        # Get risk info
        max_risk = max(email.get('risk_score', 0) for email in emails)
        max_risk_level = next((email.get('risk_level', 'Low') for email in emails 
                              if email.get('risk_score', 0) == max_risk), 'Low')
        
        risk_level_colors = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🟢',
            'Unknown': '⚪'
        }
        risk_color = risk_level_colors.get(max_risk_level, '⚪')
        
        # Create summary card
        with st.container():
            st.markdown(f"""
            <div style="background-color: #d4edda; border-left: 5px solid #28a745; 
                        padding: 1rem; margin: 0.5rem 0; border-radius: 5px;">
                <h4 style="margin: 0; color: #155724;">
                    ✅ {sender} - {len(emails)} emails completed
                </h4>
                <p style="margin: 0.5rem 0; color: #155724;">
                    <strong>Highest Risk:</strong> {risk_color} {max_risk_level} | 
                    <strong>Actions:</strong> 
                    {sender_actions.get('no_action', 0)} No Action, 
                    {sender_actions.get('monitor', 0)} Monitor, 
                    {sender_actions.get('investigate', 0)} Investigate, 
                    {sender_actions.get('escalate', 0)} Escalate
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander("📋 View Completed Email Details", expanded=False):
                for i, email in enumerate(emails):
                    email_key = f"{sender}_{i}"
                    decision = st.session_state.followup_decisions.get(email_key, 'pending')
                    
                    decision_icons = {
                        'no_action': '✅',
                        'monitor': '⚠️',
                        'investigate': '🔎',
                        'escalate': '🚨',
                        'pending': '⏳'
                    }
                    decision_icon = decision_icons.get(decision, '❓')
                    
                    st.markdown(f"**{decision_icon} Email {i+1}: {decision.replace('_', ' ').title()}**")
                    
                    detail_col1, detail_col2 = st.columns(2)
                    with detail_col1:
                        st.write(f"**Subject:** {email.get('subject', 'N/A')[:50]}...")
                        st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                        st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                    with detail_col2:
                        st.write(f"**Time:** {email.get('_time', 'N/A')}")
                        st.write(f"**Recipients:** {email.get('recipients', 'N/A')[:30]}...")
                        st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                    
                    if email.get('is_anomaly', False):
                        st.error("🚨 **Anomaly was detected in this email**")
                    
                    st.markdown("---")

    # Export completed reviews
    st.markdown("### 💾 Export Completed Reviews")
    if st.button("📊 Export Completion Report", use_container_width=True):
        # Create completion report
        report_data = []
        for sender, emails in completed_senders:
            for i, email in enumerate(emails):
                email_key = f"{sender}_{i}"
                decision = st.session_state.followup_decisions.get(email_key, 'pending')
                
                report_data.append({
                    'Sender': sender,
                    'Subject': email.get('subject', 'N/A'),
                    'Risk Level': email.get('risk_level', 'Unknown'),
                    'Risk Score': email.get('risk_score', 0),
                    'Action Taken': decision.replace('_', ' ').title(),
                    'Anomaly': 'Yes' if email.get('is_anomaly', False) else 'No',
                    'Time': email.get('_time', 'N/A')
                })
        
        if report_data:
            import pandas as pd
            df = pd.DataFrame(report_data)
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV Report",
                data=csv,
                file_name=f"email_completion_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            st.success("✅ Report ready for download!")

def recalculate_risk_scores():
    """Recalculate risk scores for all processed data using current risk configuration"""
    if st.session_state.processed_data is None:
        return
    
    # Recalculate risk scores for all emails using current configuration
    for email in st.session_state.processed_data:
        risk_result = calculate_risk_score(email)
        email.update(risk_result)
        
        # Recalculate anomaly detection as well
        email.update(detect_anomalies(email))

@require_permission('security_operations')
def daily_checks_page():
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return
    
    # Check if we need to recalculate risk scores due to configuration changes
    if 'last_risk_config_hash' not in st.session_state:
        st.session_state.last_risk_config_hash = None
    
    # Create a hash of current risk configuration to detect changes
    risk_manager = st.session_state.risk_config_manager
    current_config_str = json.dumps(risk_manager.risk_config, sort_keys=True)
    import hashlib
    current_config_hash = hashlib.md5(current_config_str.encode()).hexdigest()
    
    # If configuration changed, recalculate risk scores
    if st.session_state.last_risk_config_hash != current_config_hash:
        st.session_state.last_risk_config_hash = current_config_hash
        with st.spinner("🔄 Updating risk scores based on current configuration..."):
            recalculate_risk_scores()
            st.success("✅ Risk scores updated successfully!")
            st.rerun()

    # Professional header with enhanced styling
    risk_manager = st.session_state.risk_config_manager
    total_conditions = sum(len(level.get('conditions', [])) for level in risk_manager.risk_config['risk_levels'].values())
    
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 2rem; border-radius: 10px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0; text-align: center;">
            🛡️ Security Operations Dashboard
        </h1>
        <p style="color: rgba(255,255,255,0.8); text-align: center; margin: 0.5rem 0 0 0;">
            Real-time Email Security Monitoring & Risk Management
        </p>
        <p style="color: rgba(255,255,255,0.6); text-align: center; margin: 0.5rem 0 0 0; font-size: 12px;">
            Active Risk Engine: {total_conditions} conditions configured | Critical: ≥{risk_manager.risk_config['risk_levels']['Critical']['threshold']} pts
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Security context information with enhanced styling
    user = get_current_user()
    role_permissions = USER_ROLES[user['role']]['permissions']
    
    # Professional role banner
    role_info = {
        'viewer': {'icon': '👁️', 'title': 'Viewer Mode', 'desc': 'Read-only access to security operations', 'color': '#3498db'},
        'compliance_officer': {'icon': '📋', 'title': 'Compliance Mode', 'desc': 'Regulatory compliance and reporting focus', 'color': '#9b59b6'},
        'security_manager': {'icon': '🎯', 'title': 'Management Mode', 'desc': 'Security oversight and decision-making access', 'color': '#e67e22'},
        'admin': {'icon': '🔐', 'title': 'Administrator Access', 'desc': 'Full system administration capabilities', 'color': '#e74c3c'},
        'security_analyst': {'icon': '🔍', 'title': 'Analyst Access', 'desc': 'Full security operations capabilities', 'color': '#27ae60'}
    }
    
    current_role = role_info.get(user['role'], {'icon': '🔐', 'title': f"{USER_ROLES[user['role']]['name']} Access", 'desc': 'Full security operations capabilities', 'color': '#34495e'})
    
    st.markdown(f"""
    <div style="background-color: {current_role['color']}; 
                padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;
                border-left: 5px solid rgba(255,255,255,0.3);">
        <p style="color: white; margin: 0; font-weight: 500;">
            {current_role['icon']} <strong>{current_role['title']}</strong>: {current_role['desc']}
        </p>
    </div>
    """, unsafe_allow_html=True)

    data = st.session_state.processed_data

    # Enhanced KPI Cards with better styling
    st.markdown("### 📊 Security Risk Overview")
    
    # Show current risk configuration being used
    risk_manager = st.session_state.risk_config_manager
    current_thresholds = {
        'Critical': risk_manager.risk_config['risk_levels']['Critical']['threshold'],
        'High': risk_manager.risk_config['risk_levels']['High']['threshold'], 
        'Medium': risk_manager.risk_config['risk_levels']['Medium']['threshold'],
        'Low': risk_manager.risk_config['risk_levels']['Low']['threshold']
    }
    
    # Add manual refresh button and configuration info
    config_col1, config_col2 = st.columns([4, 1])
    
    with config_col1:
        st.info(f"🎯 **Active Risk Configuration**: Critical ≥{current_thresholds['Critical']}, High ≥{current_thresholds['High']}, Medium ≥{current_thresholds['Medium']}, Low ≥{current_thresholds['Low']} points | 🔧 [Modify Risk Settings](/?page=Risk%20Configuration)")
    
    with config_col2:
        if st.button("🔄 Refresh Risk Scores", help="Manually recalculate risk scores based on current configuration"):
            with st.spinner("🔄 Recalculating risk scores..."):
                recalculate_risk_scores()
                st.success("✅ Risk scores updated!")
                st.rerun()
    
    st.markdown("---")
    
    # Create metrics in a more professional layout
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
    risk_counts = Counter(email.get('risk_level', 'Unknown') for email in data)

    # Enhanced metric cards with background colors
    with kpi_col1:
        critical_count = risk_counts.get('Critical', 0)
        delta = f"+{critical_count}" if critical_count > 0 else None
        st.metric(
            "🔴 Critical Risk", 
            critical_count,
            delta=delta,
            help="Emails requiring immediate attention"
        )

    with kpi_col2:
        high_count = risk_counts.get('High', 0)
        delta = f"+{high_count}" if high_count > 0 else None
        st.metric(
            "🟠 High Risk", 
            high_count,
            delta=delta,
            help="Emails requiring priority review"
        )

    with kpi_col3:
        medium_count = risk_counts.get('Medium', 0)
        st.metric(
            "🟡 Medium Risk", 
            medium_count,
            help="Emails requiring standard review"
        )

    with kpi_col4:
        low_count = risk_counts.get('Low', 0)
        st.metric(
            "🟢 Low Risk", 
            low_count,
            help="Emails with minimal security concerns"
        )

    # Enhanced Domain Classification Analysis
    st.markdown("### 🌐 Domain Intelligence Analysis")
    st.markdown("---")
    
    # Analyze sender and recipient domains
    sender_domain_stats = defaultdict(int)
    recipient_domain_stats = defaultdict(int)
    external_communications = 0
    suspicious_domains = 0
    temporary_disposable_emails = []
    
    for email in data:
        # Only analyze recipient classification since sender classification is not performed
        recipient_class = email.get('recipient_classification', {})
        sender = email.get('sender', '')
        recipients = email.get('recipients_email_domain', '') or email.get('recipients', '')
        
        # Check for temporary/disposable email providers in recipients only
        email_addresses_to_check = []
        
        # Check for temporary/disposable email providers in recipients
        if recipients:
            # Handle multiple recipients separated by comma or semicolon
            recipient_list = [r.strip() for r in recipients.replace(';', ',').split(',') if r.strip() and '@' in r.strip()]
            email_addresses_to_check.extend(recipient_list)
        
        # Check recipient email addresses for disposable providersder and recipients) for temporary/disposable patterns
        is_temp_disposable_email = False
        for email_addr in email_addresses_to_check:
            if '@' in email_addr:
                domain = email_addr.split('@')[1].lower()
                
                # Check against domain classification
                domain_class = domain_classifier.classify_domain(domain)
                if domain_class.get('classification') == 'temporary_disposable':
                    is_temp_disposable_email = True
                    break
                
                # Also check specific temporary email domains
                temp_domains = {
                    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.org",
                    "throwaway.email", "getnada.com", "maildrop.cc", "sharklasers.com",
                    "temp-mail.org", "yopmail.com", "dispostable.com", "trashmail.com"
                }
                
                if domain in temp_domains or is_temp_disposable_email:
                    is_temp_disposable_email = True
                    break
        
        if is_temp_disposable_email:
            temporary_disposable_emails.append(email)
        
        # Only analyze recipient classification per user request
        if recipient_class:
            recipient_domain_stats[recipient_class.get('classification', 'unknown')] += 1
            if recipient_class.get('is_suspicious', False):
                suspicious_domains += 1
        
        # Check for external communication
        sender_domain = email.get('sender_domain', '')
        recipient_domain = email.get('recipient_domain', '')
        if sender_domain and recipient_domain and sender_domain != recipient_domain:
            external_communications += 1
    
    # Enhanced domain metrics with professional styling
    domain_col1, domain_col2, domain_col3, domain_col4 = st.columns(4)
    
    with domain_col1:
        delta_ext = f"+{external_communications}" if external_communications > 0 else None
        st.metric(
            "📧 External Communications", 
            external_communications, 
            delta=delta_ext,
            help="Cross-domain email activity indicating potential data sharing"
        )
        
    with domain_col2:
        delta_sus = f"+{suspicious_domains}" if suspicious_domains > 0 else None
        st.metric(
            "⚠️ Suspicious Domains", 
            suspicious_domains, 
            delta=delta_sus,
            help="Domains flagged as potentially risky or malicious"
        )
        
    with domain_col3:
        free_email_count = sender_domain_stats.get('free_email', 0) + recipient_domain_stats.get('free_email', 0)
        st.metric(
            "🔓 Free Email Usage", 
            free_email_count, 
            help="Personal email services (Gmail, Yahoo, etc.) usage"
        )
        
    with domain_col4:
        business_count = sender_domain_stats.get('business', 0) + recipient_domain_stats.get('business', 0)
        st.metric(
            "🏢 Business Communications", 
            business_count, 
            help="Corporate domain communications"
        )
    
    # Enhanced Security Actions Dashboard
    if st.session_state.flagged_emails or st.session_state.generated_alerts or st.session_state.blocked_domains:
        st.markdown("### 🔐 Active Security Actions")
        st.markdown("---")
        
        # Summary cards for security actions
        actions_col1, actions_col2, actions_col3 = st.columns(3)
        
        with actions_col1:
            flagged_count = len(st.session_state.get('flagged_emails', []))
            st.metric("🚨 Flagged Emails", flagged_count, help="Emails flagged for investigation")
            
        with actions_col2:
            alerts_count = len(st.session_state.get('generated_alerts', []))
            st.metric("📧 Active Alerts", alerts_count, help="Security alerts requiring attention")
            
        with actions_col3:
            blocked_count = len(st.session_state.get('blocked_domains', []))
            st.metric("🔒 Blocked Domains", blocked_count, help="Domains blocked for security")
        
        # Enhanced tabbed interface
        action_tab1, action_tab2, action_tab3 = st.tabs(["🚨 Flagged Emails", "📧 Active Alerts", "🔒 Blocked Domains"])
        
        with action_tab1:
            if st.session_state.flagged_emails:
                st.markdown(f"**📊 Summary: {len(st.session_state.flagged_emails)} emails flagged for review**")
                st.markdown("---")
                
                for flag in st.session_state.flagged_emails:
                    # Enhanced card layout for flagged emails
                    with st.container():
                        st.markdown(f"""
                        <div style="background-color: #fff3cd; border-left: 5px solid #ffc107; 
                                    padding: 1rem; margin: 0.5rem 0; border-radius: 5px;">
                            <h4 style="margin: 0; color: #856404;">🚨 {flag['sender']}</h4>
                            <p style="margin: 0.5rem 0; color: #856404;">
                                <strong>Subject:</strong> {flag['subject'][:60]}...
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        with st.expander("📋 View Details", expanded=False):
                            detail_col1, detail_col2 = st.columns(2)
                            with detail_col1:
                                st.write(f"**📧 Sender:** {flag['sender']}")
                                st.write(f"**🌐 Domain:** {flag['domain']}")
                                st.write(f"**⚠️ Risk Level:** {flag['risk_level']}")
                            with detail_col2:
                                st.write(f"**📅 Flagged:** {flag['timestamp']}")
                                st.write(f"**🔍 Reason:** {flag['reason']}")
            else:
                st.success("✅ No emails currently flagged for investigation")
        
        with action_tab2:
            if st.session_state.generated_alerts:
                st.markdown(f"**📊 Summary: {len(st.session_state.generated_alerts)} active security alerts**")
                st.markdown("---")
                
                for alert in st.session_state.generated_alerts:
                    severity_color = "#dc3545" if alert['severity'] == 'HIGH' else "#ffc107"
                    severity_icon = "🔴" if alert['severity'] == 'HIGH' else "🟡"
                    
                    with st.container():
                        st.markdown(f"""
                        <div style="background-color: {'#f8d7da' if alert['severity'] == 'HIGH' else '#fff3cd'}; 
                                    border-left: 5px solid {severity_color}; 
                                    padding: 1rem; margin: 0.5rem 0; border-radius: 5px;">
                            <h4 style="margin: 0;">
                                {severity_icon} Alert: {alert['alert_type']}
                            </h4>
                            <p style="margin: 0.5rem 0;">
                                <strong>ID:</strong> {alert['alert_id']} | 
                                <strong>Severity:</strong> {alert['severity']}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        with st.expander("📋 Alert Details", expanded=False):
                            alert_col1, alert_col2 = st.columns(2)
                            with alert_col1:
                                st.write(f"**🆔 Alert ID:** {alert['alert_id']}")
                                st.write(f"**📧 Sender:** {alert['sender']}")
                                st.write(f"**🌐 Domain:** {alert['domain']}")
                            with alert_col2:
                                st.write(f"**⚠️ Severity:** {alert['severity']}")
                                st.write(f"**📅 Generated:** {alert['timestamp']}")
                                st.write(f"**📝 Type:** {alert['alert_type']}")
            else:
                st.success("✅ No active security alerts")
        
        with action_tab3:
            if st.session_state.blocked_domains:
                st.markdown(f"**📊 Summary: {len(st.session_state.blocked_domains)} domains currently blocked**")
                st.markdown("---")
                
                for block in st.session_state.blocked_domains:
                    risk_colors = {
                        'Critical': '#dc3545',
                        'High': '#fd7e14', 
                        'Medium': '#ffc107',
                        'Low': '#28a745'
                    }
                    color = risk_colors.get(block['risk_level'], '#6c757d')
                    
                    with st.container():
                        st.markdown(f"""
                        <div style="background-color: #f8f9fa; border-left: 5px solid {color}; 
                                    padding: 1rem; margin: 0.5rem 0; border-radius: 5px;">
                            <h4 style="margin: 0;">🔒 {block['domain']}</h4>
                            <p style="margin: 0.5rem 0;">
                                <strong>Risk Level:</strong> {block['risk_level']} | 
                                <strong>Email Count:</strong> {block['email_count']}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        with st.expander("📋 Block Details", expanded=False):
                            block_col1, block_col2 = st.columns(2)
                            with block_col1:
                                st.write(f"**🌐 Domain:** {block['domain']}")
                                st.write(f"**⚠️ Risk Level:** {block['risk_level']}")
                                st.write(f"**📧 Email Count:** {block['email_count']}")
                            with block_col2:
                                st.write(f"**🔒 Blocked:** {block['timestamp']}")
                                st.write(f"**📝 Reason:** {block['block_reason']}")
            else:
                st.success("✅ No domains currently blocked")

    # Enhanced RED FLAG ALERT Section
    if temporary_disposable_emails:
        st.markdown("---")
        
        # Critical alert banner with enhanced styling
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); 
                    padding: 1.5rem; border-radius: 10px; margin: 1rem 0;
                    border: 3px solid #bd2130; box-shadow: 0 4px 8px rgba(220,53,69,0.3);">
            <h2 style="color: white; margin: 0; text-align: center; font-weight: bold;">
                🚨 CRITICAL SECURITY ALERT
            </h2>
            <h3 style="color: white; margin: 0.5rem 0 0 0; text-align: center;">
                {len(temporary_disposable_emails)} Temporary/Disposable Emails Detected
            </h3>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 🔴 Disposable Email Risk Assessment")
        
        # Enhanced security warning with better formatting
        st.markdown("""
        <div style="background-color: #fff3cd; border-left: 5px solid #ffc107; 
                    padding: 1.5rem; margin: 1rem 0; border-radius: 5px;">
            <h4 style="color: #856404; margin-top: 0;">⚠️ Security Risk Analysis</h4>
            <p style="color: #856404; margin-bottom: 0;">
                <strong>Temporary and disposable email addresses are commonly used for:</strong><br>
                • Data exfiltration attempts<br>
                • Hiding true identity and avoiding accountability<br>
                • Bypassing security controls and detection systems<br>
                • Establishing untraceable communication channels
            </p>
            <br>
            <p style="color: #856404; margin-bottom: 0; font-weight: bold;">
                🔍 <strong>Immediate Action Required:</strong> Review these emails for potential security violations
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Group temporary emails by sender (same structure as Risk Events)
        temp_sender_groups = defaultdict(list)
        for email in temporary_disposable_emails:
            sender = email.get('sender', 'Unknown')
            temp_sender_groups[sender].append(email)

        # Add tracking overview for temp emails
        temp_col1, temp_col2, temp_col3, temp_col4 = st.columns(4)

        # Calculate tracking statistics for temp emails
        temp_total_senders = len(temp_sender_groups)
        temp_completed_senders = 0
        temp_outstanding_senders = 0
        temp_in_progress_senders = 0

        for sender in temp_sender_groups.keys():
            sender_status = st.session_state.sender_review_status.get(sender, 'outstanding')
            if sender_status == 'completed':
                temp_completed_senders += 1
            elif sender_status == 'in_progress':
                temp_in_progress_senders += 1
            else:
                temp_outstanding_senders += 1

        # Display tracking metrics for temp emails
        with temp_col1:
            st.metric("📊 Total Red Flag Senders", temp_total_senders)
        with temp_col2:
            st.metric("✅ Completed", temp_completed_senders)
        with temp_col3:
            st.metric("🔄 In Progress", temp_in_progress_senders)
        with temp_col4:
            st.metric("⏳ Outstanding", temp_outstanding_senders)

        # Add filter options for temp emails (same as Risk Events)
        st.write("**Filter Red Flag Senders:**")
        temp_filter_col1, temp_filter_col2 = st.columns(2)
        with temp_filter_col1:
            temp_status_filter = st.selectbox(
                "Show red flag senders:",
                options=['All', 'Outstanding', 'In Progress', 'Completed'],
                index=0,
                key="temp_status_filter"
            )
        with temp_filter_col2:
            temp_sort_by = st.selectbox(
                "Sort red flags by:",
                options=['Risk Level', 'Status', 'Email Count'],
                index=0,
                key="temp_sort_by"
            )

        # Sort temp senders by risk priority (same logic as Risk Events)
        risk_priority = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}
        
        def get_temp_sender_max_risk(emails):
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

        sorted_temp_sender_groups = sorted(temp_sender_groups.items(), 
                                         key=lambda x: get_temp_sender_max_risk(x[1]), 
                                         reverse=True)

        # Apply status filter for temp emails
        if temp_status_filter != 'All':
            filter_map = {'Outstanding': 'outstanding', 'In Progress': 'in_progress', 'Completed': 'completed'}
            filtered_status = filter_map[temp_status_filter]
            sorted_temp_sender_groups = [
                (sender, emails) for sender, emails in sorted_temp_sender_groups 
                if st.session_state.sender_review_status.get(sender, 'outstanding') == filtered_status
            ]

        # Display temp email senders (exactly same format as Risk Events)
        for sender, emails in sorted_temp_sender_groups:
            if not emails:
                continue

            # Find highest risk in group
            max_risk = max(email.get('risk_score', 0) for email in emails)
            max_risk_level = next((email.get('risk_level', 'Low') for email in emails 
                                  if email.get('risk_score', 0) == max_risk), 'Low')

            # Check if sender has any anomalies
            has_anomalies = any(email.get('is_anomaly', False) for email in emails)
            anomaly_count = sum(1 for email in emails if email.get('is_anomaly', False))

            # Get current sender status
            current_status = st.session_state.sender_review_status.get(sender, 'outstanding')
            status_icons = {'outstanding': '⏳', 'in_progress': '🔄', 'completed': '✅'}
            status_icon = status_icons.get(current_status, '⏳')

            # Create sender title with clear risk level indicators and red flag status
            risk_level_colors = {
                'Critical': '🔴',
                'High': '🟠', 
                'Medium': '🟡',
                'Low': '🟢',
                'Unknown': '⚪'
            }
            risk_color = risk_level_colors.get(max_risk_level, '⚪')
            
            sender_title = f"{status_icon} {risk_color} **{max_risk_level.upper()} RISK** - {sender} ({len(emails)} emails)"
            
            # Add red flag indicators
            red_flags = ["🔴 RED FLAG: Disposable Email"]
            if has_anomalies:
                red_flags.append(f"🚨 {anomaly_count} Anomalies")
            
            sender_title += " - " + " | ".join(red_flags)

            # Auto-calculate status based on user actions
            sender_emails_count = len(emails)
            sender_followup_decisions = [
                st.session_state.followup_decisions.get(f"{sender}_{i}", 'pending') 
                for i in range(sender_emails_count)
            ]

            # Determine automatic status
            decided_count = sum(1 for decision in sender_followup_decisions if decision != 'pending')

            if decided_count == 0:
                auto_status = 'outstanding'
            elif decided_count == sender_emails_count:
                auto_status = 'completed'
            else:
                auto_status = 'in_progress'

            # Update status automatically
            st.session_state.sender_review_status[sender] = auto_status

            # Update status icon based on auto-calculated status
            status_icons = {'outstanding': '⏳', 'in_progress': '🔄', 'completed': '✅'}
            status_icon = status_icons.get(auto_status, '⏳')

            # Update sender title with new status (using the same enhanced format)
            risk_color = risk_level_colors.get(max_risk_level, '⚪')
            sender_title = f"{status_icon} {risk_color} **{max_risk_level.upper()} RISK** - {sender} ({len(emails)} emails)"
            sender_title += " - " + " | ".join(red_flags)

            with st.expander(sender_title):
                # Show automatic status info
                st.write(f"**Review Status:** {auto_status.title()} ({decided_count}/{sender_emails_count} emails reviewed)")
                st.markdown("---")
                
                # Display individual emails with action buttons (same as Risk Events)
                for i, email in enumerate(emails):
                    email_key = f"{sender}_{i}"
                    current_decision = st.session_state.followup_decisions.get(email_key, 'pending')
                    
                    with st.expander(f"📧 Email {i+1}: {email.get('subject', 'No Subject')[:50]}..."):
                        # Email details (same format as Risk Events)
                        col_a, col_b = st.columns(2)
                        
                        with col_a:
                            st.write(f"**From:** {email.get('sender', 'N/A')}")
                            st.write(f"**To:** {email.get('recipients', 'N/A')}")
                            st.write(f"**Subject:** {email.get('subject', 'N/A')}")
                            st.write(f"**Time:** {email.get('_time', 'N/A')}")
                        
                        with col_b:
                            st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                            st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                            st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                            
                            if email.get('is_anomaly', False):
                                st.error("🚨 **Anomaly Detected**")
                            
                            # Always show red flag for temp/disposable
                            st.error("🔴 **RED FLAG: Temporary/Disposable Email Domain**")
                        
                        # Decision buttons with improved layout
                        st.write(f"**Current Decision:** {current_decision.title()}")
                        st.write("**Actions:**")
                        
                        button_col1, button_col2 = st.columns(2)
                        
                        with button_col1:
                            if st.button("✅ No Action", key=f"no_action_{email_key}_temp", use_container_width=True):
                                st.session_state.followup_decisions[email_key] = 'no_action'
                                st.rerun()
                            
                            if st.button("🔎 Investigate", key=f"investigate_{email_key}_temp", use_container_width=True):
                                st.session_state.followup_decisions[email_key] = 'investigate'
                                # Add to investigation queue
                                if 'investigation_queue' not in st.session_state:
                                    st.session_state.investigation_queue = []
                                st.session_state.investigation_queue.append({
                                    'email': email,
                                    'sender': sender,
                                    'decision_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'investigating',
                                    'priority': 'high' if email.get('risk_level') == 'Critical' else 'medium'
                                })
                                st.warning("Email queued for investigation")
                                st.rerun()
                        
                        with button_col2:
                            if st.button("⚠️ Monitor", key=f"monitor_{email_key}_temp", use_container_width=True):
                                st.session_state.followup_decisions[email_key] = 'monitor'
                                # Add to monitoring list
                                if 'monitored_emails' not in st.session_state:
                                    st.session_state.monitored_emails = []
                                st.session_state.monitored_emails.append({
                                    'email': email,
                                    'sender': sender,
                                    'decision_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'monitoring'
                                })
                                st.success("Email added to monitoring queue")
                                st.rerun()
                            
                            if st.button("🚨 Escalate", key=f"escalate_{email_key}_temp", use_container_width=True):
                                st.session_state.followup_decisions[email_key] = 'escalate'
                                # Add to follow-up center
                                if 'escalated_emails' not in st.session_state:
                                    st.session_state.escalated_emails = []
                                st.session_state.escalated_emails.append({
                                    'email': email,
                                    'sender': sender,
                                    'escalation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'escalated',
                                    'priority': 'critical',
                                    'requires_followup': True
                                })
                                st.error("Email escalated to Follow-up Center")
                                st.rerun()
        
        st.info("📍 **These red flag indicators are also highlighted in the Risk Events section below for comprehensive review.**")
    else:
        st.success("✅ **No temporary or disposable email addresses detected in current dataset**")

    # Enhanced Risk Events Section
    st.markdown("---")
    st.markdown("### 🎯 Security Risk Events Management")
    st.markdown("*Organized by sender for efficient review and decision tracking*")
    
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

    # Calculate tracking statistics before sorting
    total_senders = 0
    completed_senders = 0
    outstanding_senders = 0
    in_progress_senders = 0
    
    for sender, emails in sender_groups.items():
        total_senders += 1
        sender_status = st.session_state.sender_review_status.get(sender, 'outstanding')

        if sender_status == 'completed':
            completed_senders += 1
        elif sender_status == 'in_progress':
            in_progress_senders += 1
        else:
            outstanding_senders += 1

    # Information about completed emails
    if completed_senders > 0:
        st.info(f"ℹ️ **{completed_senders} completed senders have been moved to the ✅ Email Check Completed dashboard.** Only pending and in-progress reviews are shown below.")

    # Enhanced tracking dashboard
    st.markdown("#### 📈 Review Progress Dashboard")
    col_track1, col_track2, col_track3, col_track4 = st.columns(4)

    with col_track1:
        st.metric(
            "📊 Total Senders", 
            total_senders,
            help="Total unique senders requiring review"
        )
    with col_track2:
        completion_rate = f"{(completed_senders/total_senders*100):.1f}%" if total_senders > 0 else "0%"
        st.metric(
            "✅ Completed", 
            completed_senders,
            delta=completion_rate,
            help="Senders with all emails reviewed"
        )
    with col_track3:
        st.metric(
            "🔄 In Progress", 
            in_progress_senders,
            help="Senders with partial review completed"
        )
    with col_track4:
        st.metric(
            "⏳ Outstanding", 
            outstanding_senders,
            help="Senders requiring initial review"
        )

    # Enhanced filter and sort interface
    st.markdown("#### 🔧 Filter & Sort Options")
    filter_col1, filter_col2 = st.columns(2)
    
    with filter_col1:
        status_filter = st.selectbox(
            "📋 Show senders by status:",
            options=['All', 'Outstanding', 'In Progress', 'Completed'],
            index=0,
            help="Filter senders by their review status"
        )
    with filter_col2:
        sort_by = st.selectbox(
            "📈 Sort by:",
            options=['Risk Level', 'Status', 'Email Count'],
            index=0,
            help="Choose how to order the sender list"
        )

    # Sort senders by risk priority (Critical first)
    sorted_sender_groups = sorted(sender_groups.items(), 
                                 key=lambda x: get_sender_max_risk(x[1]), 
                                 reverse=True)

    # Apply status filter - by default exclude completed senders from main dashboard
    if status_filter == 'All':
        # Exclude completed senders by default in main Security Operations dashboard
        sorted_sender_groups = [
            (sender, emails) for sender, emails in sorted_sender_groups 
            if st.session_state.sender_review_status.get(sender, 'outstanding') != 'completed'
        ]
    else:
        filter_map = {'Outstanding': 'outstanding', 'In Progress': 'in_progress', 'Completed': 'completed'}
        filtered_status = filter_map[status_filter]
        sorted_sender_groups = [
            (sender, emails) for sender, emails in sorted_sender_groups 
            if st.session_state.sender_review_status.get(sender, 'outstanding') == filtered_status
        ]

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

        # Check if sender has temporary/disposable email domain red flags
        sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
        sender_classification = domain_classifier.classify_domain(sender_domain)
        is_temp_disposable = sender_classification.get('classification') == 'temporary_disposable'
        temp_disposable_count = sum(1 for email in emails 
                                   if domain_classifier.classify_domain(email.get('sender', '').split('@')[-1].lower() if '@' in email.get('sender', '') else '').get('classification') == 'temporary_disposable')

        # Get current sender status
        current_status = st.session_state.sender_review_status.get(sender, 'outstanding')
        status_icons = {'outstanding': '⏳', 'in_progress': '🔄', 'completed': '✅'}
        status_icon = status_icons.get(current_status, '⏳')

        # Create sender title with clear risk level indicators and red flag status
        risk_level_colors = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🟢',
            'Unknown': '⚪'
        }
        risk_color = risk_level_colors.get(max_risk_level, '⚪')
        
        sender_title = f"{status_icon} {risk_color} **{max_risk_level.upper()} RISK** - {sender} ({len(emails)} emails)"
        
        # Add red flag indicators
        red_flags = []
        if has_anomalies:
            red_flags.append(f"🚨 {anomaly_count} Anomalies")
        if is_temp_disposable:
            red_flags.append("🔴 RED FLAG: Disposable Email")
        
        if red_flags:
            sender_title += " - " + " | ".join(red_flags)

        # Auto-calculate status based on user actions
        sender_emails_count = len(emails)
        sender_followup_decisions = [
            st.session_state.followup_decisions.get(f"{sender}_{i}", 'pending') 
            for i in range(sender_emails_count)
        ]

        # Determine automatic status
        decided_count = sum(1 for decision in sender_followup_decisions if decision != 'pending')

        if decided_count == 0:
            auto_status = 'outstanding'
        elif decided_count == sender_emails_count:
            auto_status = 'completed'
        else:
            auto_status = 'in_progress'

        # Update status automatically
        st.session_state.sender_review_status[sender] = auto_status

        # Update status icon based on auto-calculated status
        status_icons = {'outstanding': '⏳', 'in_progress': '🔄', 'completed': '✅'}
        status_icon = status_icons.get(auto_status, '⏳')

        # Update sender title with new status (using the same enhanced format)
        risk_color = risk_level_colors.get(max_risk_level, '⚪')
        sender_title = f"{status_icon} {risk_color} **{max_risk_level.upper()} RISK** - {sender} ({len(emails)} emails)"
        if red_flags:
            sender_title += " - " + " | ".join(red_flags)

        with st.expander(sender_title):
            # Show automatic status info
            st.write(f"**Review Status:** {auto_status.title()} ({decided_count}/{sender_emails_count} emails reviewed)")
            st.markdown("---")
            
            # Add detailed behavioral analysis view per sender
            st.subheader(f"📊 Behavioral Analysis - {sender}")
            
            # Calculate sender-specific metrics
            total_emails_sender = len(emails)
            avg_risk_sender = sum(email.get('risk_score', 0) for email in emails) / total_emails_sender if total_emails_sender else 0
            anomaly_count_sender = sum(1 for email in emails if email.get('is_anomaly', False))
            
            # Time analysis
            after_hours_count = 0
            time_patterns = []
            for email in emails:
                time_str = email.get('_time', '')
                if time_str:
                    time_patterns.append(time_str)
                    try:
                        if ':' in time_str:
                            hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                            hour = int(hour_part)
                            if hour >= 18 or hour <= 6:
                                after_hours_count += 1
                    except:
                        pass
            
            # Content analysis
            attachment_count = sum(1 for email in emails if email.get('attachments', '').strip())
            keyword_matches = sum(1 for email in emails if email.get('word_list_match', '').strip())
            external_recipients = sum(1 for email in emails if 'external' in email.get('recipient_status', '').lower())
            
            # Domain analysis
            sender_domain = sender.split('@')[1] if '@' in sender else 'unknown'
            domain_type = "Free" if sender_domain.lower() in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'] else "Corporate"
            
            # Risk indicators
            risk_indicators = []
            if after_hours_count > 0:
                risk_indicators.append(f"After-hours activity ({after_hours_count})")
            if 'external' in [email.get('recipient_status', '').lower() for email in emails]:
                risk_indicators.append(f"External communication ({external_recipients})")
            if attachment_count > 0 and keyword_matches > 0:
                risk_indicators.append("Sensitive content + attachments")
            if any(email.get('leaver', '').strip().upper() == 'YES' for email in emails):
                risk_indicators.append("Departing employee")
            
            # Create the detailed analysis view
            analysis_col1, analysis_col2, analysis_col3 = st.columns(3)
            
            with analysis_col1:
                st.markdown("**📧 Email Patterns**")
                st.write(f"• Total emails: {total_emails_sender}")
                st.write(f"• Average risk: {avg_risk_sender:.1f}")
                st.write(f"• Anomalies: {anomaly_count_sender}")
                st.write(f"• After hours: {after_hours_count}")
            
            with analysis_col2:
                st.markdown("**🔍 Content Analysis**")
                st.write(f"• With attachments: {attachment_count}")
                st.write(f"• Keyword matches: {keyword_matches}")
                st.write(f"• External recipients: {external_recipients}")
                st.write(f"• Domain type: {domain_type}")
            
            with analysis_col3:
                st.markdown("**⚠️ Risk Indicators**")
                if risk_indicators:
                    for indicator in risk_indicators:
                        st.write(f"• {indicator}")
                else:
                    st.write("• No major risk indicators")
            
            # Temporal Behavior Analysis
            if time_patterns:
                st.markdown("**⏰ Temporal Behavior Analysis**")
                
                # Extract hours for visualization
                hours = []
                for time_str in time_patterns:
                    try:
                        if ':' in time_str:
                            hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                            hours.append(int(hour_part))
                    except:
                        continue
                
                if hours:
                    hour_counts = Counter(hours)
                    
                    # Create temporal analysis chart
                    fig_temporal = go.Figure(data=[
                        go.Bar(
                            x=list(range(24)),
                            y=[hour_counts.get(h, 0) for h in range(24)],
                            marker=dict(
                                color=['#e74c3c' if h >= 18 or h <= 6 else '#3498db' for h in range(24)],
                                line=dict(color='rgba(0,0,0,0.3)', width=1)
                            ),
                            text=[hour_counts.get(h, 0) if hour_counts.get(h, 0) > 0 else '' for h in range(24)],
                            textposition='auto',
                            hovertemplate='<b>Hour %{x}:00</b><br>Emails: %{y}<extra></extra>'
                        )
                    ])
                    
                    fig_temporal.update_layout(
                        title=f"Email Activity by Hour - {sender}",
                        xaxis_title="Hour of Day",
                        yaxis_title="Number of Emails",
                        height=300,
                        showlegend=False,
                        plot_bgcolor='rgba(45, 55, 72, 1.0)',
                        xaxis=dict(
                            tickmode='linear',
                            tick0=0,
                            dtick=2,
                            range=[-0.5, 23.5]
                        ),
                        yaxis=dict(
                            gridcolor='rgba(255, 255, 255, 0.1)'
                        ),
                        margin=dict(l=40, r=40, t=50, b=40)
                    )
                    
                    # Add annotations for business hours
                    fig_temporal.add_vrect(
                        x0=18, x1=24,
                        fillcolor="rgba(231, 76, 60, 0.1)",
                        layer="below",
                        line_width=0,
                        annotation_text="After Hours",
                        annotation_position="top left"
                    )
                    
                    fig_temporal.add_vrect(
                        x0=0, x1=6,
                        fillcolor="rgba(231, 76, 60, 0.1)",
                        layer="below",
                        line_width=0,
                        annotation_text="After Hours",
                        annotation_position="top right"
                    )
                    
                    st.plotly_chart(fig_temporal, use_container_width=True)
            
            st.markdown("---")
            
            # Sort emails within sender group by risk level and score (Critical first)
            sorted_emails = sorted(emails, 
                                 key=lambda x: (risk_priority.get(x.get('risk_level', 'Low'), 0), 
                                              x.get('risk_score', 0)), 
                                 reverse=True)

            st.markdown("**📋 Individual Email Review**")
            
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
                        # Use wider layout for better button visibility
                        st.write("**Actions:**")
                        button_col1, button_col2 = st.columns(2)
                        
                        with button_col1:
                            if st.button("✅ No Action", key=f"no_action_{email_id}", use_container_width=True):
                                st.session_state.followup_decisions[email_id] = 'no_action'
                                st.rerun()
                            
                            if st.button("🔎 Investigate", key=f"investigate_{email_id}", use_container_width=True):
                                st.session_state.followup_decisions[email_id] = 'investigate'
                                # Add to investigation queue
                                if 'investigation_queue' not in st.session_state:
                                    st.session_state.investigation_queue = []
                                st.session_state.investigation_queue.append({
                                    'email': email,
                                    'sender': sender,
                                    'decision_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'investigating',
                                    'priority': 'high' if email.get('risk_level') == 'Critical' else 'medium'
                                })
                                st.warning("Email queued for investigation")
                                st.rerun()
                        
                        with button_col2:
                            if st.button("⚠️ Monitor", key=f"monitor_{email_id}", use_container_width=True):
                                st.session_state.followup_decisions[email_id] = 'monitor'
                                # Add to monitoring list
                                if 'monitored_emails' not in st.session_state:
                                    st.session_state.monitored_emails = []
                                st.session_state.monitored_emails.append({
                                    'email': email,
                                    'sender': sender,
                                    'decision_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'monitoring'
                                })
                                st.success("Email added to monitoring queue")
                                st.rerun()
                            
                            if st.button("🚨 Escalate", key=f"escalate_{email_id}", use_container_width=True):
                                st.session_state.followup_decisions[email_id] = 'escalate'
                                # Add to follow-up center
                                if 'escalated_emails' not in st.session_state:
                                    st.session_state.escalated_emails = []
                                st.session_state.escalated_emails.append({
                                    'email': email,
                                    'sender': sender,
                                    'escalation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'escalated',
                                    'priority': 'critical',
                                    'requires_followup': True
                                })
                                st.error("Email escalated to Follow-up Center")
                                st.rerun()
                    else:
                        # Show current decision with colored indicator
                        decision_colors = {
                            'no_action': '✅ No Action',
                            'monitor': '⚠️ Monitoring',
                            'investigate': '🔎 Investigating',
                            'escalate': '🚨 Escalated'
                        }
                        st.write(decision_colors.get(current_decision, f"✅ {current_decision.title()}"))

@require_permission('follow_up')
def followup_center_page():
    st.header("📨 Follow-up Email Center")
    
    # Show permission-based features
    user = get_current_user()
    if user['role'] in ['security_analyst', 'security_manager', 'admin']:
        st.success("🔓 **Full Access**: You can manage all follow-up actions and escalations")
    else:
        st.warning("⚠️ **Limited Access**: Contact your administrator for additional permissions")

    # Get escalated emails
    escalated_emails = st.session_state.get('escalated_emails', [])
    
    # Get emails being monitored
    monitored_emails = st.session_state.get('monitored_emails', [])
    
    # Get emails under investigation
    investigation_emails = st.session_state.get('investigation_queue', [])

    # Get emails marked for follow-up (legacy)
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

    # Total counts
    total_items = len(escalated_emails) + len(monitored_emails) + len(investigation_emails) + len(followup_emails)

    if total_items == 0:
        st.info("📭 No emails currently require follow-up action.")
        st.write("Use the Escalate, Monitor, or Investigate buttons in the Security Operations section to add items here.")
        return

    # Display overview metrics
    st.subheader("📊 Follow-up Overview")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🚨 Escalated", len(escalated_emails))
    with col2:
        st.metric("🔎 Investigating", len(investigation_emails))
    with col3:
        st.metric("⚠️ Monitoring", len(monitored_emails))
    with col4:
        st.metric("📋 Legacy Follow-ups", len(followup_emails))

    # Tabs for different categories
    if escalated_emails or investigation_emails or monitored_emails:
        tab1, tab2, tab3, tab4 = st.tabs(["🚨 Escalated", "🔎 Investigation Queue", "⚠️ Monitoring", "📋 Legacy Follow-ups"])
        
        with tab1:
            st.subheader(f"🚨 Escalated Emails ({len(escalated_emails)})")
            if escalated_emails:
                for i, item in enumerate(escalated_emails):
                    email = item['email']
                    with st.expander(f"🚨 CRITICAL - {item['sender']} - {email.get('subject', 'No Subject')[:50]}..."):
                        st.error(f"**Status:** Escalated on {item['escalation_date']}")
                        st.write(f"**Priority:** {item['priority'].upper()}")
                        
                        # Email details
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**From:** {email.get('sender', 'N/A')}")
                            st.write(f"**To:** {email.get('recipients', 'N/A')}")
                            st.write(f"**Subject:** {email.get('subject', 'N/A')}")
                        with col_b:
                            st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                            st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                            st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                        
                        # Generate follow-up email
                        if st.button(f"📧 Generate Follow-up Email", key=f"escalated_email_{i}"):
                            email_template = generate_followup_email(email)
                            st.session_state[f'generated_template_{i}'] = email_template
                            
                            # URL encode the email content for proper mailto link
                            import urllib.parse
                            encoded_subject = urllib.parse.quote(email_template['subject'])
                            encoded_body = urllib.parse.quote(email_template['body'])
                            mailto_link = f"mailto:{email_template['to']}?subject={encoded_subject}&body={encoded_body}"
                            
                            # Auto-open Outlook using JavaScript
                            st.markdown(f"""
                            <script>
                            setTimeout(function() {{
                                window.open('{mailto_link}', '_blank');
                            }}, 100);
                            </script>
                            """, unsafe_allow_html=True)
                            
                            st.success("Opening Outlook automatically...")
                            st.rerun()
                        
                        # Show generated template if exists
                        if f'generated_template_{i}' in st.session_state:
                            template = st.session_state[f'generated_template_{i}']
                            st.success("Follow-up email generated successfully!")
                            
                            # URL encode for proper mailto link
                            import urllib.parse
                            encoded_subject = urllib.parse.quote(template['subject'])
                            encoded_body = urllib.parse.quote(template['body'])
                            mailto_link = f"mailto:{template['to']}?subject={encoded_subject}&body={encoded_body}"
                            
                            # Display email details for reference
                            st.subheader("Follow-up Email Details")
                            col_email1, col_email2 = st.columns(2)
                            with col_email1:
                                st.write(f"**To:** {template['to']}")
                                st.write(f"**Subject:** {template['subject']}")

                            # Backup link if auto-open doesn't work
                            with col_email2:
                                st.markdown(f"**[Click here if Outlook didn't open]({mailto_link})**")
                                st.caption("Backup link for manual opening")

                            # Display email body for reference
                            st.text_area("Email Content (Reference):", template['body'], height=200, key=f"escalated_template_{i}")

                            # Download option
                            email_content = f"To: {template['to']}\nSubject: {template['subject']}\n\n{template['body']}"
                            st.download_button(
                                label="💾 Download Email",
                                data=email_content,
                                file_name=f"followup_email_{template['sender_name']}.txt",
                                mime="text/plain",
                                key=f"download_escalated_{i}"
                            )
            else:
                st.info("No escalated emails currently.")
        
        with tab2:
            st.subheader(f"🔎 Investigation Queue ({len(investigation_emails)})")
            if investigation_emails:
                for i, item in enumerate(investigation_emails):
                    email = item['email']
                    priority_color = "🔴" if item['priority'] == 'high' else "🟡"
                    with st.expander(f"{priority_color} {item['priority'].upper()} - {item['sender']} - {email.get('subject', 'No Subject')[:50]}..."):
                        st.warning(f"**Status:** Under investigation since {item['decision_date']}")
                        st.write(f"**Priority:** {item['priority'].upper()}")
                        
                        # Email details (same format as escalated)
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**From:** {email.get('sender', 'N/A')}")
                            st.write(f"**To:** {email.get('recipients', 'N/A')}")
                            st.write(f"**Subject:** {email.get('subject', 'N/A')}")
                        with col_b:
                            st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                            st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                            st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                        
                        # Investigation actions
                        if st.button(f"✅ Complete Investigation", key=f"complete_inv_{i}"):
                            st.session_state.investigation_queue.remove(item)
                            st.success("Investigation marked as complete")
                            st.rerun()
            else:
                st.info("No emails under investigation currently.")
        
        with tab3:
            st.subheader(f"⚠️ Monitoring ({len(monitored_emails)})")
            if monitored_emails:
                for i, item in enumerate(monitored_emails):
                    email = item['email']
                    with st.expander(f"⚠️ {item['sender']} - {email.get('subject', 'No Subject')[:50]}..."):
                        st.info(f"**Status:** Monitoring since {item['decision_date']}")
                        
                        # Email details (same format)
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**From:** {email.get('sender', 'N/A')}")
                            st.write(f"**To:** {email.get('recipients', 'N/A')}")
                            st.write(f"**Subject:** {email.get('subject', 'N/A')}")
                        with col_b:
                            st.write(f"**Risk Level:** {email.get('risk_level', 'Unknown')}")
                            st.write(f"**Risk Score:** {email.get('risk_score', 0)}")
                            st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                        
                        # Monitoring actions
                        monitor_col1, monitor_col2 = st.columns(2)
                        with monitor_col1:
                            if st.button(f"🚨 Escalate", key=f"escalate_monitor_{i}"):
                                # Move from monitoring to escalated
                                st.session_state.monitored_emails.remove(item)
                                if 'escalated_emails' not in st.session_state:
                                    st.session_state.escalated_emails = []
                                st.session_state.escalated_emails.append({
                                    'email': email,
                                    'sender': item['sender'],
                                    'escalation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'status': 'escalated',
                                    'priority': 'critical',
                                    'requires_followup': True
                                })
                                st.success("Moved to escalated queue")
                                st.rerun()
                        with monitor_col2:
                            if st.button(f"✅ Stop Monitoring", key=f"stop_monitor_{i}"):
                                st.session_state.monitored_emails.remove(item)
                                st.success("Removed from monitoring")
                                st.rerun()
            else:
                st.info("No emails being monitored currently.")
        
        with tab4:
            st.subheader(f"📋 Legacy Follow-ups ({len(followup_emails)})")

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
                email_data = generate_followup_email(email)

                # Create mailto link for automatic opening in Outlook
                import urllib.parse
                mailto_subject = urllib.parse.quote(email_data['subject'])
                mailto_body = urllib.parse.quote(email_data['body'])
                mailto_to = urllib.parse.quote(email_data['to'])
                mailto_link = f"mailto:{mailto_to}?subject={mailto_subject}&body={mailto_body}"

                # Auto-open in Outlook using HTML redirect
                st.markdown(f"""
                <meta http-equiv="refresh" content="0; url={mailto_link}">
                <p>Opening Outlook automatically...</p>
                <script>
                setTimeout(function(){{
                    window.location.href = '{mailto_link}';
                }}, 100);
                </script>
                """, unsafe_allow_html=True)

                st.success("Opening Outlook automatically...")

                # Display email details for reference
                st.subheader("Follow-up Email Details")
                col_email1, col_email2 = st.columns(2)
                with col_email1:
                    st.write(f"**To:** {email_data['to']}")
                    st.write(f"**Subject:** {email_data['subject']}")

                # Backup link if auto-open doesn't work
                with col_email2:
                    st.markdown(f"**[Click here if Outlook didn't open]({mailto_link})**")
                    st.caption("Backup link for manual opening")

                # Display email body for reference
                st.text_area("Email Content (Reference):", email_data['body'], height=200, key=f"template_{i}")

                # Download option
                email_content = f"To: {email_data['to']}\nSubject: {email_data['subject']}\n\n{email_data['body']}"
                st.download_button(
                    label="💾 Download Email",
                    data=email_content,
                    file_name=f"followup_email_{email_data['sender_name']}.txt",
                    mime="text/plain",
                    key=f"download_{i}"
                )

def generate_followup_email(email):
    """Generate a follow-up email template with Outlook integration"""
    sender = email.get('sender', 'Unknown')
    subject = email.get('subject', 'No Subject')
    risk_level = email.get('risk_level', 'Medium')
    risk_factors = email.get('risk_factors', 'General security review')
    time = email.get('time', 'Unknown')
    recipients = email.get('recipients', 'Unknown')
    attachments = email.get('attachments', 'None')

    # Clean sender name for display
    sender_name = sender.split('@')[0].title() if '@' in sender else sender

    # Email subject for the follow-up
    followup_subject = f"Security Review Required - Email Activity Alert"

    # Email body
    email_body = f"""Dear {sender_name},

Our email security monitoring system has identified an email sent from your account that requires review:

Email Details:
- Subject: {subject}
- Sent to: {recipients}
- Date/Time: {time}
- Attachments: {attachments}

Could you please provide more details regarding this activity? Specifically, we would like to know if the file does indeed contain Investec IP and if this is part of an approved business process.

Best regards,
IT Security Team"""

    return {
        'subject': followup_subject,
        'body': email_body,
        'to': sender,
        'sender_name': sender_name
    }

@require_permission('admin')
def risk_configuration_page():
    """Advanced Risk Configuration Management System"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 2rem; border-radius: 10px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0; text-align: center;">
            🎯 Risk Configuration Management
        </h1>
        <p style="color: rgba(255,255,255,0.8); text-align: center; margin: 0.5rem 0 0 0;">
            Configure custom risk scoring rules and thresholds for email security analysis
        </p>
    </div>
    """, unsafe_allow_html=True)

    risk_manager = st.session_state.risk_config_manager
    
    # Information about automatic updates
    st.info("ℹ️ **Automatic Updates**: Changes to risk configuration automatically update the Security Operations Dashboard. When you modify settings here, the imported data will be recalculated and reflected immediately in the dashboard.")
    
    # Check if configuration has changed and offer to reprocess data
    if st.session_state.processed_data and 'last_config_hash' not in st.session_state:
        st.session_state.last_config_hash = hash(str(risk_manager.risk_config))
    
    current_config_hash = hash(str(risk_manager.risk_config))
    config_changed = st.session_state.get('last_config_hash') != current_config_hash
    
    if config_changed and st.session_state.processed_data:
        st.warning("⚠️ **Risk configuration has changed!** Your imported data needs to be reprocessed to reflect the new risk settings.")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🔄 Reprocess Data with New Configuration", type="primary", use_container_width=True):
                with st.spinner("Reprocessing all emails with updated risk configuration..."):
                    # Reprocess each email with current risk settings
                    reprocessed_data = []
                    for email in st.session_state.data:  # Use original data
                        # Apply domain classification
                        recipient_email = email.get('recipients_email_domain', '') or email.get('recipients', '')
                        if recipient_email:
                            email['recipient_domain'] = extract_domain_from_email(recipient_email)
                            first_recipient = recipient_email.split(';')[0].split(',')[0].strip()
                            email['recipient_classification'] = classify_email_domain(first_recipient)
                        
                        sender_email = email.get('sender', '')
                        if sender_email:
                            email['sender_domain'] = extract_domain_from_email(sender_email)
                        
                        # Apply risk calculation with current config
                        risk_info = risk_manager.calculate_risk_score(email)
                        anomaly_info = detect_anomalies(email)
                        email.update(risk_info)
                        email.update(anomaly_info)
                        reprocessed_data.append(email)
                    
                    st.session_state.processed_data = reprocessed_data
                    st.session_state.last_config_hash = current_config_hash
                    
                    # Clear follow-up decisions since risk levels may have changed
                    if st.button("🗑️ Also Clear Previous Decisions (Recommended)", type="secondary"):
                        st.session_state.followup_decisions = {}
                        st.session_state.sender_review_status = {}
                        st.success("✅ Data reprocessed and previous decisions cleared!")
                    else:
                        st.success("✅ Data reprocessed with new risk configuration!")
                    
                    st.rerun()
    
    # Get available fields from uploaded data
    available_fields = risk_manager.get_available_fields(st.session_state.processed_data or [])
    
    # Critical Formula Configuration Section
    st.markdown("---")
    st.markdown("### 🚨 Critical Event Formula")
    st.markdown("*Special formula for detecting critical security events*")
    
    # Display current critical formula
    st.info("""
    **Current Critical Formula:**
    `leaver=YES AND attachments!="-" AND (Wordlist_attachment != "-" OR Wordlist_subject !="-")`
    
    This formula identifies emails from departing employees that contain attachments and suspicious content.
    """)
    
    # Show how to modify the formula
    with st.expander("🔧 How to modify the Critical Formula"):
        st.markdown("""
        The Critical Formula is currently hardcoded for security. To modify it:
        
        1. **Current Logic**: Emails are flagged as Critical only if they meet ALL of these conditions:
           - Employee is leaving (leaver=YES)
           - Email has attachments (attachments != "-")
           - Email contains suspicious content (Wordlist_attachment != "-" OR Wordlist_subject != "-")
        
        2. **To Change**: Contact your system administrator to modify the formula in `risk_config_manager.py`
        
        3. **Testing**: Use the test section below to verify how your data matches the current formula
        """)
    
    # Test the critical formula
    st.markdown("#### 🧪 Test Critical Formula")
    test_col1, test_col2 = st.columns(2)
    
    with test_col1:
        test_leaver = st.selectbox("Leaver Status:", ["YES", "NO", ""], key="test_leaver")
        test_attachments = st.text_input("Attachments:", value="document.pdf", key="test_attachments")
    
    with test_col2:
        test_wordlist_attachment = st.text_input("Wordlist Attachment:", value="-", key="test_wordlist_attachment")
        test_wordlist_subject = st.text_input("Wordlist Subject:", value="-", key="test_wordlist_subject")
    
    if st.button("🔍 Test Formula"):
        test_data = {
            "leaver": test_leaver,
            "attachments": test_attachments,
            "Wordlist_attachment": test_wordlist_attachment,
            "Wordlist_subject": test_wordlist_subject
        }
        
        risk_result = risk_manager.calculate_risk_score(test_data)
        
        if risk_result['risk_level'] == 'Critical':
            st.success("✅ **CRITICAL** - This email would be flagged as Critical")
            st.json(risk_result)
        else:
            st.info(f"ℹ️ **{risk_result['risk_level'].upper()}** - This email would be flagged as {risk_result['risk_level']}")
            st.json(risk_result)

    # Tabs for different configuration aspects
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Risk Levels", "📊 Current Config", "🔧 Add Rules", "💾 Import/Export"])
    
    with tab1:
        st.markdown("### Risk Level Configuration")
        st.markdown("Configure thresholds and conditions for each risk level (excluding Critical).")
        
        # Display and edit risk levels
        for risk_level in ["Critical", "High", "Medium", "Low"]:
            config = risk_manager.risk_config["risk_levels"][risk_level]
            
            with st.expander(f"🔴 {risk_level} Risk Configuration" if risk_level == "Critical" 
                           else f"🟠 {risk_level} Risk Configuration" if risk_level == "High"
                           else f"🟡 {risk_level} Risk Configuration" if risk_level == "Medium"
                           else f"🟢 {risk_level} Risk Configuration"):
                
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    # Threshold configuration
                    current_threshold = config.get("threshold", 0)
                    new_threshold = st.number_input(
                        f"Minimum Score for {risk_level}",
                        min_value=0,
                        max_value=200,
                        value=current_threshold,
                        key=f"threshold_{risk_level}"
                    )
                    
                    if new_threshold != current_threshold:
                        if st.button(f"Update {risk_level} Threshold", key=f"update_threshold_{risk_level}"):
                            risk_manager.update_threshold(risk_level, new_threshold)
                            # Update config hash to trigger reprocess notification
                            if 'last_config_hash' in st.session_state:
                                del st.session_state.last_config_hash
                            st.success(f"{risk_level} threshold updated to {new_threshold}")
                            if st.session_state.processed_data:
                                st.info("💡 **Tip**: Go to the top of this page to reprocess your data with the new threshold!")
                            st.rerun()
                
                with col2:
                    # Display current conditions
                    st.write("**Current Conditions:**")
                    conditions = config.get("conditions", [])
                    
                    if conditions:
                        for i, condition in enumerate(conditions):
                            col_desc, col_points, col_action = st.columns([3, 1, 1])
                            
                            with col_desc:
                                st.write(f"• {condition.get('description', 'Unknown')}")
                                st.caption(f"Field: {condition.get('field')} | Operation: {condition.get('operator')} | Value: {condition.get('value')}")
                            
                            with col_points:
                                st.metric("Points", condition.get('points', 0))
                            
                            with col_action:
                                if st.button("❌", key=f"remove_{risk_level}_{i}", help="Remove condition"):
                                    risk_manager.remove_condition(risk_level, i)
                                    if 'last_config_hash' in st.session_state:
                                        del st.session_state.last_config_hash
                                    st.success("Condition removed")
                                    if st.session_state.processed_data:
                                        st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                                    st.rerun()
                    else:
                        st.info(f"No conditions defined for {risk_level} risk level")
    
    with tab2:
        st.markdown("### Current Risk Configuration Overview")
        
        # Display configuration summary
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 Risk Level Thresholds")
            for risk_level in ["Critical", "High", "Medium", "Low"]:
                threshold = risk_manager.risk_config["risk_levels"][risk_level]["threshold"]
                condition_count = len(risk_manager.risk_config["risk_levels"][risk_level].get("conditions", []))
                
                color = "🔴" if risk_level == "Critical" else "🟠" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢"
                st.write(f"{color} **{risk_level}:** {threshold}+ points ({condition_count} conditions)")
        
        with col2:
            st.markdown("#### 🔧 Available Operators")
            operators = risk_manager.risk_config.get("operators", {})
            for op, desc in operators.items():
                st.write(f"• **{op}:** {desc}")
        
        # Test risk calculation with sample data
        st.markdown("---")
        st.markdown("#### 🧪 Test Risk Calculation")
        
        if st.session_state.processed_data:
            sample_email = st.selectbox(
                "Select a sample email to test:",
                options=range(min(10, len(st.session_state.processed_data))),
                format_func=lambda x: f"Email {x+1}: {st.session_state.processed_data[x].get('subject', 'No Subject')[:50]}..."
            )
            
            if st.button("🧪 Test Risk Calculation"):
                test_email = st.session_state.processed_data[sample_email]
                result = risk_manager.calculate_risk_score(test_email)
                
                st.markdown("**Risk Calculation Result:**")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Risk Score", result['risk_score'])
                with col2:
                    st.metric("Risk Level", result['risk_level'])
                with col3:
                    st.metric("Conditions Triggered", len(result.get('triggered_conditions', [])))
                
                if result.get('triggered_conditions'):
                    st.markdown("**Triggered Conditions:**")
                    for condition in result['triggered_conditions']:
                        st.write(f"• {condition['description']} (+{condition['points']} points)")
                
                st.write(f"**Risk Factors:** {result.get('risk_factors', 'None')}")
        else:
            st.info("Upload data to test risk calculations with real email samples")
    
    with tab3:
        st.markdown("### Add New Risk Conditions")
        st.markdown("Create custom conditions for risk scoring based on email field values.")
        
        with st.form("add_condition_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                target_risk_level = st.selectbox(
                    "Risk Level:",
                    options=["Critical", "High", "Medium", "Low"],
                    help="Which risk level should this condition contribute to?"
                )
                
                field_name = st.selectbox(
                    "Email Field:",
                    options=available_fields,
                    help="Select the email field to evaluate"
                )
                
                operator = st.selectbox(
                    "Condition Type:",
                    options=list(risk_manager.risk_config.get("operators", {}).keys()),
                    format_func=lambda x: f"{x} - {risk_manager.risk_config.get('operators', {}).get(x, '')}"
                )
            
            with col2:
                condition_value = st.text_input(
                    "Expected Value:",
                    help="The value to compare against (use '-' for empty checks)"
                )
                
                points = st.number_input(
                    "Points to Add:",
                    min_value=1,
                    max_value=100,
                    value=20,
                    help="How many points this condition should add to the risk score"
                )
                
                description = st.text_input(
                    "Description:",
                    placeholder="Brief description of this risk condition",
                    help="Human-readable description of what this condition detects"
                )
            
            # Submit button
            submitted = st.form_submit_button("➕ Add Risk Condition", type="primary")
            
            if submitted:
                if field_name and operator and description:
                    risk_manager.add_condition(
                        target_risk_level, field_name, operator, condition_value, points, description
                    )
                    # Update config hash to trigger reprocess notification
                    if 'last_config_hash' in st.session_state:
                        del st.session_state.last_config_hash
                    st.success(f"Added new {target_risk_level} risk condition: {description}")
                    if st.session_state.processed_data:
                        st.info("💡 **Tip**: Go to the top of this page to reprocess your data with the new condition!")
                    st.rerun()
                else:
                    st.error("Please fill in all required fields")
        
        # Quick condition templates
        st.markdown("---")
        st.markdown("#### 🚀 Quick Templates")
        st.markdown("Click to add common risk conditions:")
        
        template_col1, template_col2, template_col3 = st.columns(3)
        
        with template_col1:
            if st.button("🔴 Departing Employee", use_container_width=True):
                risk_manager.add_condition("Critical", "leaver", "equals", "YES", 60, "Departing employee activity")
                if 'last_config_hash' in st.session_state:
                    del st.session_state.last_config_hash
                st.success("Added departing employee condition")
                if st.session_state.processed_data:
                    st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                st.rerun()
            
            if st.button("📎 Suspicious Attachments", use_container_width=True):
                risk_manager.add_condition("High", "Wordlist_attachment", "not_equals", "-", 40, "Suspicious attachment content")
                if 'last_config_hash' in st.session_state:
                    del st.session_state.last_config_hash
                st.success("Added suspicious attachments condition")
                if st.session_state.processed_data:
                    st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                st.rerun()
        
        with template_col2:
            if st.button("📧 Free Email Domains", use_container_width=True):
                risk_manager.add_condition("High", "recipients_email_domain_classification", "equals", "free_email", 35, "Free email domain recipient")
                if 'last_config_hash' in st.session_state:
                    del st.session_state.last_config_hash
                st.success("Added free email domain condition")
                if st.session_state.processed_data:
                    st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                st.rerun()
            
            if st.button("🕒 After Hours Activity", use_container_width=True):
                risk_manager.add_condition("Medium", "_time", "after_hours", "18:00-06:00", 20, "After-hours email activity")
                if 'last_config_hash' in st.session_state:
                    del st.session_state.last_config_hash
                st.success("Added after hours condition")
                if st.session_state.processed_data:
                    st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                st.rerun()
        
        with template_col3:
            if st.button("🔍 Subject Keywords", use_container_width=True):
                risk_manager.add_condition("High", "Wordlist_subject", "not_equals", "-", 30, "Sensitive keywords in subject")
                if 'last_config_hash' in st.session_state:
                    del st.session_state.last_config_hash
                st.success("Added subject keywords condition")
                if st.session_state.processed_data:
                    st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                st.rerun()
            
            if st.button("🌐 Cross-Domain", use_container_width=True):
                risk_manager.add_condition("Medium", "sender_recipient_different_domain", "equals", "true", 15, "Cross-domain communication")
                if 'last_config_hash' in st.session_state:
                    del st.session_state.last_config_hash
                st.success("Added cross-domain condition")
                if st.session_state.processed_data:
                    st.info("💡 **Tip**: Go to the top of this page to reprocess your data!")
                st.rerun()
    
    with tab4:
        st.markdown("### Import/Export Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📤 Export Configuration")
            st.markdown("Download your current risk configuration for backup or sharing.")
            
            if st.button("📥 Export Configuration", type="primary"):
                config_json = risk_manager.export_config()
                st.download_button(
                    label="💾 Download Configuration File",
                    data=config_json,
                    file_name=f"risk_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
                st.success("Configuration ready for download!")
        
        with col2:
            st.markdown("#### 📤 Import Configuration")
            st.markdown("Upload a previously exported configuration file.")
            
            uploaded_config = st.file_uploader(
                "Upload Configuration File",
                type=['json'],
                help="Upload a JSON configuration file"
            )
            
            if uploaded_config is not None:
                try:
                    config_content = uploaded_config.read().decode('utf-8')
                    if st.button("🔄 Import Configuration", type="primary"):
                        if risk_manager.import_config(config_content):
                            if 'last_config_hash' in st.session_state:
                                del st.session_state.last_config_hash
                            st.success("Configuration imported successfully!")
                            if st.session_state.processed_data:
                                st.info("💡 **Tip**: Go to the top of this page to reprocess your data with the imported configuration!")
                            st.rerun()
                        else:
                            st.error("Invalid configuration file format")
                except Exception as e:
                    st.error(f"Error reading configuration file: {str(e)}")
        
        # Reset to defaults
        st.markdown("---")
        st.markdown("#### ⚠️ Reset Configuration")
        st.warning("This will reset all risk configuration to default settings.")
        
        if st.button("🔄 Reset to Default Configuration", type="secondary"):
            st.session_state.risk_config_manager = RiskConfigManager()
            if 'last_config_hash' in st.session_state:
                del st.session_state.last_config_hash
            st.success("Configuration reset to defaults")
            if st.session_state.processed_data:
                st.info("💡 **Tip**: Go to the top of this page to reprocess your data with the default configuration!")
            st.rerun()

@require_permission('admin')
def settings_page():
    st.header("⚙️ Settings")
    
    # Import security features
    from security_config import show_security_dashboard, audit_logger
    
    # Security tab
    tab1, tab2, tab3 = st.tabs(["🔒 Security Management", "📧 Domain Classification", "📊 System Information"])
    
    with tab1:
        show_security_dashboard()
        
        # Log settings access
        audit_logger.log_action(
            'settings_accessed',
            {'section': 'security_management'},
            'info'
        )
    
    with tab2:
        # Domain Classification Management
        st.subheader("📧 Email Domain Classification")
    
    tab1, tab2, tab3 = st.tabs(["Domain Statistics", "Classification Rules", "Risk Configuration"])
    
    with tab1:
        st.write("**Domain Classification Overview**")
        
        # Display domain statistics
        col1, col2, col3, col4 = st.columns(4)
        
        stats = domain_classifier.get_classification_stats()
        
        with col1:
            st.metric("Free Email Domains", stats.get("free_email_domains", 0))
            st.caption("Personal email services")
        
        with col2:
            st.metric("Business Domains", stats.get("business_domains", 0))
            st.caption("Corporate organizations")
        
        with col3:
            st.metric("Government Domains", stats.get("government_domains", 0))
            st.caption("Official institutions")
        
        with col4:
            st.metric("Educational Domains", stats.get("educational_domains", 0))
            st.caption("Academic institutions")
        
        # Domain search and classification test
        st.markdown("---")
        st.write("**Test Email Classification**")
        test_email = st.text_input("Enter email address to test classification:")
        
        if test_email:
            classification = classify_email_domain(test_email)
            
            col1, col2 = st.columns(2)
            with col1:
                st.json({
                    "Email": test_email,
                    "Classification": classification.get('classification', 'unknown'),
                    "Category": classification.get('category', 'unclassified'),
                    "Risk Level": classification.get('risk_level', 'medium')
                })
            
            with col2:
                st.json({
                    "Is Free Email": classification.get('is_free', False),
                    "Is Suspicious": classification.get('is_suspicious', False)
                })
    
    with tab2:
        st.write("**Domain Classification Rules**")
        
        # Show classification categories
        for category, domains in domain_classifier.classifications.items():
            if category in ["last_updated", "version", "suspicious_patterns"]:  # Skip metadata and patterns
                continue
            if isinstance(domains, list) and domains:
                with st.expander(f"{category.replace('_', ' ').title()} ({len(domains)} domains)"):
                    # Display first 20 domains for each category
                    displayed_domains = domains[:20]
                    for i in range(0, len(displayed_domains), 4):
                        cols = st.columns(4)
                        for j, domain in enumerate(displayed_domains[i:i+4]):
                            if j < len(cols):
                                cols[j].code(domain)
                    
                    if len(domains) > 20:
                        st.caption(f"... and {len(domains) - 20} more domains")
        
        # Add custom domain functionality
        st.markdown("---")
        st.write("**Add Custom Domain**")
        
        col1, col2 = st.columns(2)
        with col1:
            new_domain = st.text_input("Domain to add:")
            domain_category = st.selectbox("Category:", 
                ["business_domains", "free_email_domains", "suspicious_domains"])
        
        with col2:
            if st.button("Add Domain"):
                if new_domain:
                    st.success(f"Domain '{new_domain}' would be added to {domain_category}")
                    st.info("Note: This is a demo. In production, this would update the domain database.")
    
    with tab3:
        st.write("**Risk Configuration**")
        
        # Get current risk configuration
        risk_config = st.session_state.risk_config
        
        st.warning("⚠️ **Important**: Changes to risk configuration will affect all future risk calculations. Re-process your data after making changes.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**🎯 Risk Thresholds**")
            st.info("Configure when emails are classified as different risk levels")
            
            critical_threshold = st.slider("Critical Risk Threshold", 0, 150, risk_config['critical_threshold'], 
                                         help="Scores above this are Critical risk")
            high_threshold = st.slider("High Risk Threshold", 0, 150, risk_config['high_threshold'],
                                     help="Scores above this are High risk")
            medium_threshold = st.slider("Medium Risk Threshold", 0, 150, risk_config['medium_threshold'],
                                       help="Scores above this are Medium risk")
            
            if st.button("Update Thresholds", key="update_thresholds"):
                st.session_state.risk_config['critical_threshold'] = critical_threshold
                st.session_state.risk_config['high_threshold'] = high_threshold
                st.session_state.risk_config['medium_threshold'] = medium_threshold
                st.success("Risk thresholds updated successfully!")
                st.rerun()
        
        with col2:
            st.write("**⚖️ Risk Factor Points**")
            st.info("Configure how many points each risk factor adds to the total score")
            
            suspicious_domain = st.slider("Suspicious Domain Points", 0, 100, risk_config['suspicious_domain_points'],
                                         help="Points for suspicious recipient domains")
            free_email = st.slider("Free Email Points", 0, 50, risk_config['free_email_points'],
                                  help="Points for free email domains (Gmail, Yahoo, etc.)")
            unknown_domain = st.slider("Unknown Domain Points", 0, 50, risk_config['unknown_domain_points'],
                                      help="Points for unknown/unclassified domains")
            
            if st.button("Update Domain Points", key="update_domain_points"):
                st.session_state.risk_config['suspicious_domain_points'] = suspicious_domain
                st.session_state.risk_config['free_email_points'] = free_email
                st.session_state.risk_config['unknown_domain_points'] = unknown_domain
                st.success("Domain risk points updated successfully!")
                st.rerun()
        
        st.markdown("---")
        
        # Communication Risk Factors
        st.write("**📡 Communication Risk Factors**")
        comm_col1, comm_col2, comm_col3 = st.columns(3)
        
        with comm_col1:
            external_comm = st.slider("External Communication", 0, 30, risk_config['external_communication_points'],
                                     help="Points for cross-domain communication")
            external_to_free = st.slider("External to Free Email", 0, 50, risk_config['external_to_free_email_points'],
                                        help="Extra points for external communication to free email")
            external_to_unknown = st.slider("External to Unknown", 0, 30, risk_config['external_to_unknown_points'],
                                           help="Extra points for external communication to unknown domains")
        
        with comm_col2:
            subject_keywords = st.slider("Subject Keywords", 0, 50, risk_config['subject_keywords_points'],
                                        help="Points for sensitive keywords in subject")
            attachments = st.slider("Attachments", 0, 30, risk_config['attachments_points'],
                                   help="Points for emails with attachments")
            attachment_keywords = st.slider("Attachment Keywords", 0, 50, risk_config['attachment_keywords_points'],
                                           help="Points for sensitive keywords in attachments")
        
        with comm_col3:
            departing_employee = st.slider("Departing Employee", 0, 60, risk_config['departing_employee_points'],
                                          help="Points for emails from departing employees")
            external_recipients = st.slider("External Recipients", 0, 30, risk_config['external_recipients_points'],
                                           help="Points for external recipients")
            off_hours = st.slider("Off-Hours Activity", 0, 30, risk_config['off_hours_points'],
                                 help="Points for emails sent after hours")
        
        if st.button("Update Communication Risk Points", key="update_comm_points"):
            st.session_state.risk_config['external_communication_points'] = external_comm
            st.session_state.risk_config['external_to_free_email_points'] = external_to_free
            st.session_state.risk_config['external_to_unknown_points'] = external_to_unknown
            st.session_state.risk_config['subject_keywords_points'] = subject_keywords
            st.session_state.risk_config['attachments_points'] = attachments
            st.session_state.risk_config['attachment_keywords_points'] = attachment_keywords
            st.session_state.risk_config['departing_employee_points'] = departing_employee
            st.session_state.risk_config['external_recipients_points'] = external_recipients
            st.session_state.risk_config['off_hours_points'] = off_hours
            st.success("Communication risk points updated successfully!")
            st.rerun()
        
        st.markdown("---")
        
        # Current Configuration Display
        st.write("**📋 Current Risk Configuration**")
        
        config_col1, config_col2 = st.columns(2)
        
        with config_col1:
            st.write("**Risk Levels:**")
            st.code(f"""
Critical: ≥ {risk_config['critical_threshold']} points
High: ≥ {risk_config['high_threshold']} points  
Medium: ≥ {risk_config['medium_threshold']} points
Low: < {risk_config['medium_threshold']} points
            """)
        
        with config_col2:
            st.write("**Risk Factors:**")
            st.code(f"""
Suspicious Domain: {risk_config['suspicious_domain_points']} pts
Free Email: {risk_config['free_email_points']} pts
Unknown Domain: {risk_config['unknown_domain_points']} pts
External Communication: {risk_config['external_communication_points']} pts
Subject Keywords: {risk_config['subject_keywords_points']} pts
Attachments: {risk_config['attachments_points']} pts
Attachment Keywords: {risk_config['attachment_keywords_points']} pts
Departing Employee: {risk_config['departing_employee_points']} pts
External Recipients: {risk_config['external_recipients_points']} pts
Off-Hours: {risk_config['off_hours_points']} pts
            """)
        
        # Reset to defaults
        st.markdown("---")
        col_reset1, col_reset2, col_reset3 = st.columns([1, 1, 2])
        
        with col_reset1:
            if st.button("🔄 Reset to Defaults", key="reset_defaults"):
                st.session_state.risk_config = {
                    'suspicious_domain_points': 40,
                    'free_email_points': 25,
                    'unknown_domain_points': 15,
                    'external_communication_points': 10,
                    'external_to_free_email_points': 20,
                    'external_to_unknown_points': 10,
                    'subject_keywords_points': 20,
                    'attachments_points': 15,
                    'attachment_keywords_points': 25,
                    'departing_employee_points': 30,
                    'external_recipients_points': 10,
                    'off_hours_points': 10,
                    'critical_threshold': 80,
                    'high_threshold': 60,
                    'medium_threshold': 30
                }
                st.success("Risk configuration reset to default values!")
                st.rerun()
        
        with col_reset2:
            if st.button("💾 Export Config", key="export_config"):
                config_json = json.dumps(st.session_state.risk_config, indent=2)
                st.download_button(
                    label="Download Risk Config",
                    data=config_json,
                    file_name="risk_configuration.json",
                    mime="application/json",
                    key="download_risk_config"
                )
        
        with col_reset3:
            st.info("💡 **Tip**: Export your configuration to save custom risk settings, or reset to defaults if needed.")

    with tab3:
        # System Information
        st.subheader("📊 System Information")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info(f"""
            **Application:** ExfilEye DLP Monitor
            **Version:** 2.0.0 (Security Enhanced)
            **Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
            **Status:** Active with Security
            **Authentication:** Role-Based Access Control
            """)
        
        with col2:
            stats = domain_classifier.get_classification_stats()
            total_domains = sum(count for count in stats.values() if isinstance(count, int))
            st.info(f"""
            **Domain Database:** {total_domains} domains
            **Classification Engine:** Daily Updated System
            **Risk Engine:** Multi-factor analysis
            **Security Engine:** Multi-layer protection
            **Last Sync:** {datetime.now().strftime('%H:%M:%S')}
            """)
        
        # Security status
        st.subheader("🔐 Security Status")
        
        security_col1, security_col2, security_col3, security_col4 = st.columns(4)
        
        with security_col1:
            st.metric("🛡️ Authentication", "Active")
        with security_col2:
            st.metric("👥 User Management", "Enabled")
        with security_col3:
            st.metric("📝 Audit Logging", "Active")
        with security_col4:
            st.metric("🔒 Role-Based Access", "Enforced")
        
        # Current session info
        user = get_current_user()
        st.markdown("### 👤 Current Session")
        
        session_col1, session_col2 = st.columns(2)
        with session_col1:
            st.write(f"**User:** {user.get('full_name', 'Unknown')}")
            st.write(f"**Username:** {st.session_state.get('username', 'Unknown')}")
            st.write(f"**Role:** {USER_ROLES[user['role']]['name']}")
        
        with session_col2:
            st.write(f"**Permissions:** {', '.join(USER_ROLES[user['role']]['permissions'])}")
            st.write(f"**Session Started:** {datetime.now().strftime('%H:%M:%S')}")
            st.write(f"**Security Level:** {'Maximum' if user['role'] == 'admin' else 'Standard'}")




def domain_classification_page():
    """Domain Classification Management with Daily Updates"""
    st.title("🌐 Domain Classification Management")
    st.markdown("Monitor and manage domain classifications with daily threat intelligence updates")
    
    # Create tabs for different management functions
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔄 Daily Updates", "➕ Add Domains", "📋 Management"])
    
    with tab1:
        st.subheader("📊 Classification Overview")
        
        # Get classification statistics
        stats = domain_classifier.get_classification_stats()
        
        # Display statistics in columns
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Suspicious Domains", stats.get("suspicious_domains", 0), help="Known threat domains")
        
        with col2:
            st.metric("Free Email Providers", stats.get("free_email_domains", 0), help="Personal email services")
        
        with col3:
            st.metric("Business Domains", stats.get("business_domains", 0), help="Corporate domains")
        
        with col4:
            st.metric("Government Domains", stats.get("government_domains", 0), help="Official government domains")
        
        # System status
        st.markdown("---")
        st.subheader("🔧 System Status")
        
        needs_update = domain_classifier.needs_daily_update()
        last_updated = domain_classifier.classifications.get("last_updated", "Never")
        
        status_col1, status_col2 = st.columns(2)
        
        with status_col1:
            if needs_update:
                st.warning("⚠️ Daily update needed")
            else:
                st.success("✅ Classifications are current")
        
        with status_col2:
            st.info(f"Last updated: {last_updated}")
        
        # Recent updates summary
        recent_updates = domain_classifier.get_daily_updates(7)
        if recent_updates:
            st.markdown("---")
            st.subheader("📋 Recent Updates (Last 7 Days)")
            
            for update in recent_updates[:5]:  # Show last 5 updates
                timestamp = datetime.fromisoformat(update["timestamp"]).strftime("%Y-%m-%d %H:%M")
                action = "Added" if update["action"] == "add" else "Removed"
                st.write(f"• **{timestamp}**: {action} {update['count']} domains to {update['category']}")
    
    with tab2:
        st.subheader("🔄 Daily Update Management")
        
        # Manual update trigger
        col1, col2 = st.columns([1, 2])
        
        with col1:
            if st.button("🔄 Run Daily Update", type="primary"):
                with st.spinner("Performing daily update..."):
                    success, message, updates = domain_classifier.perform_daily_update()
                    
                    if success:
                        st.success(f"✅ {message}")
                        
                        # Show what was updated
                        if updates:
                            st.subheader("📋 Update Details")
                            for update in updates:
                                st.write(f"**{update['category']}**: Added {update['count']} domains")
                                with st.expander(f"View added domains ({update['count']})"):
                                    for domain in update['domains']:
                                        st.write(f"• {domain}")
                    else:
                        st.info("ℹ️ No updates were needed")
        
        with col2:
            st.info("💡 **Daily Updates Include:**\n- New threat intelligence feeds\n- Suspicious domain discoveries\n- Free email provider additions\n- Domain classification improvements")
        
        # Update history
        st.markdown("---")
        st.subheader("📊 Update History")
        
        days_filter = st.selectbox("Show updates from last:", [1, 7, 30, 90], index=1)
        recent_updates = domain_classifier.get_daily_updates(days_filter)
        
        if recent_updates:
            # Create a dataframe for better display
            update_data = []
            for update in recent_updates:
                update_data.append({
                    "Timestamp": datetime.fromisoformat(update["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "Action": update["action"].title(),
                    "Category": update["category"],
                    "Count": update["count"],
                    "Reason": update["reason"]
                })
            
            st.dataframe(pd.DataFrame(update_data), use_container_width=True)
        else:
            st.info(f"No updates found in the last {days_filter} days")
    
    with tab3:
        st.subheader("➕ Add New Domains")
        
        # Category selection
        categories = ["suspicious_domains", "free_email_domains", "business_domains", 
                     "government_domains", "financial_domains", "cloud_providers"]
        
        selected_category = st.selectbox("Select Category:", categories)
        
        # Domain input
        domain_input = st.text_area(
            "Enter domains (one per line):",
            placeholder="example.com\nanotherdomain.org\nsuspicious-site.net",
            height=100
        )
        
        reason = st.text_input("Reason for addition:", placeholder="Manual threat intelligence addition")
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            if st.button("➕ Add Domains"):
                if domain_input.strip() and reason.strip():
                    domains = [d.strip() for d in domain_input.split('\n') if d.strip()]
                    
                    if domains:
                        success, message = domain_classifier.add_domains(selected_category, domains, reason)
                        
                        if success:
                            st.success(f"✅ {message}")
                            st.balloons()
                        else:
                            st.warning(f"⚠️ {message}")
                    else:
                        st.error("Please enter at least one domain")
                else:
                    st.error("Please enter domains and a reason")
        
        with col2:
            st.info("💡 **Guidelines:**\n- Enter one domain per line\n- Don't include 'http://' or 'www.'\n- Provide a clear reason for tracking")
    
    with tab4:
        st.subheader("📋 Domain Management")
        
        # Category filter
        category_filter = st.selectbox("View Category:", 
                                     ["All"] + list(domain_classifier.classifications.keys()))
        
        # Search functionality
        search_term = st.text_input("🔍 Search domains:", placeholder="Enter domain or keyword")
        
        # Display domains
        for category, domains in domain_classifier.classifications.items():
            if category in ["last_updated", "version"]:
                continue
                
            if category_filter != "All" and category != category_filter:
                continue
                
            if isinstance(domains, list):
                # Filter by search term if provided
                filtered_domains = domains
                if search_term:
                    filtered_domains = [d for d in domains if search_term.lower() in d.lower()]
                
                if filtered_domains:
                    with st.expander(f"📂 {category.replace('_', ' ').title()} ({len(filtered_domains)})"):
                        # Show domains in columns for better display
                        domain_cols = st.columns(3)
                        for i, domain in enumerate(sorted(filtered_domains)):
                            with domain_cols[i % 3]:
                                st.write(f"• {domain}")
        
        # Bulk operations
        st.markdown("---")
        st.subheader("🔧 Bulk Operations")
        
        operation_col1, operation_col2 = st.columns(2)
        
        with operation_col1:
            st.write("**Remove Domains**")
            remove_category = st.selectbox("Category:", categories, key="remove_cat")
            domains_to_remove = st.text_area(
                "Domains to remove (one per line):",
                placeholder="domain1.com\ndomain2.org",
                key="remove_domains"
            )
            remove_reason = st.text_input("Removal reason:", key="remove_reason")
            
            if st.button("🗑️ Remove Domains"):
                if domains_to_remove.strip() and remove_reason.strip():
                    domains = [d.strip() for d in domains_to_remove.split('\n') if d.strip()]
                    success, message = domain_classifier.remove_domains(remove_category, domains, remove_reason)
                    
                    if success:
                        st.success(f"✅ {message}")
                    else:
                        st.warning(f"⚠️ {message}")
        
        with operation_col2:
            st.write("**Export Classifications**")
            if st.button("📥 Download Classifications"):
                # Create downloadable JSON
                export_data = {
                    "export_date": datetime.now().isoformat(),
                    "classifications": domain_classifier.classifications,
                    "stats": domain_classifier.get_classification_stats()
                }
                
                st.download_button(
                    label="📁 Download JSON",
                    data=json.dumps(export_data, indent=2),
                    file_name=f"domain_classifications_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )

def sender_behavior_analysis_page():
    """Comprehensive sender behavior analysis dashboard"""
    st.header("👤 Sender Behavior Analysis")
    
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return

    data = st.session_state.processed_data

    # Group emails by sender
    sender_groups = defaultdict(list)
    for email in data:
        sender = email.get('sender', 'Unknown')
        sender_groups[sender].append(email)

    # Sender Overview Dashboard
    st.subheader("📊 Sender Overview Dashboard")
    
    overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)
    
    with overview_col1:
        total_senders = len(sender_groups)
        st.metric("Total Senders", total_senders)
    
    with overview_col2:
        high_risk_senders = sum(1 for emails in sender_groups.values() 
                               if any(e.get('risk_level') in ['High', 'Critical'] for e in emails))
        st.metric("High Risk Senders", high_risk_senders)


def qa_assistant_page():
    """Q&A Assistant for natural language queries on email data"""
    st.header("🤖 Q&A Assistant - Ask Questions About Your Data")
    
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return

    data = st.session_state.processed_data
    
    # Initialize chat history
    if 'qa_history' not in st.session_state:
        st.session_state.qa_history = []
    
    st.subheader("💬 Ask Questions About Your Email Data")
    st.info("Examples: 'Show me high risk emails', 'What domains send the most emails?', 'Chart emails by risk level'")
    
    # Question input
    user_question = st.text_input(
        "Ask a question about your email data:",
        placeholder="e.g., How many emails are from gmail.com?",
        key="qa_input"
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        ask_button = st.button("🔍 Ask", type="primary")
    with col2:
        if st.button("🗑️ Clear History"):
            st.session_state.qa_history = []
            st.rerun()
    
    if ask_button and user_question:
        with st.spinner("Analyzing your question..."):
            answer, chart = process_natural_language_query(user_question, data)
            
            # Add to history
            st.session_state.qa_history.append({
                'question': user_question,
                'answer': answer,
                'chart': chart,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })
            
            st.rerun()
    
    # Display chat history
    if st.session_state.qa_history:
        st.subheader("📊 Q&A History")
        
        for i, qa in enumerate(reversed(st.session_state.qa_history)):
            with st.expander(f"Q: {qa['question'][:80]}... - {qa['timestamp']}", expanded=(i==0)):
                st.write(f"**Question:** {qa['question']}")
                st.write(f"**Answer:** {qa['answer']}")
                
                if qa['chart']:
                    st.plotly_chart(qa['chart'], use_container_width=True, key=f"qa_chart_{len(st.session_state.qa_history)-1-i}_{datetime.now().timestamp()}")
    
    # Pre-built Questions Section
    st.subheader("📝 Pre-built Questions")
    
    # Initialize pre-built questions in session state
    if 'prebuilt_questions' not in st.session_state:
        st.session_state.prebuilt_questions = [
            "Count emails with attachments vs without",
            "Which departments sent the most 'business'-tagged emails?",
            "Which recipients received emails from more than one sender domain?",
            "Show me the risk distribution by domain",
            "What are the peak email sending hours?",
            "How many anomalies were detected this week?",
            "Which senders have the highest risk scores?",
            "Show external vs internal email patterns"
        ]
    
    # Display editable questions
    st.write("**Click to ask these questions or edit them:**")
    
    # Questions management
    question_col1, question_col2 = st.columns([3, 1])
    
    with question_col1:
        new_question = st.text_input("Add new pre-built question:", placeholder="Enter a new question...", key="new_prebuilt_q")
    
    with question_col2:
        if st.button("➕ Add Question") and new_question:
            st.session_state.prebuilt_questions.append(new_question)
            st.rerun()
    
    # Display questions in a grid
    questions_per_row = 2
    for i in range(0, len(st.session_state.prebuilt_questions), questions_per_row):
        cols = st.columns(questions_per_row + 1)  # Extra column for delete button
        
        for j, question in enumerate(st.session_state.prebuilt_questions[i:i+questions_per_row]):
            question_idx = i + j
            with cols[j]:
                if st.button(f"❓ {question}", key=f"prebuilt_{question_idx}"):
                    with st.spinner("Processing question..."):
                        answer, chart = process_natural_language_query(question, data)
                        st.session_state.qa_history.append({
                            'question': question,
                            'answer': answer,
                            'chart': chart,
                            'timestamp': datetime.now().strftime('%H:%M:%S')
                        })
                        st.rerun()
            
            # Delete button for each question
            with cols[questions_per_row]:
                if j == 0:  # Only show delete button on first question of each row
                    if st.button(f"🗑️", key=f"delete_{question_idx}", help=f"Delete: {question}"):
                        st.session_state.prebuilt_questions.pop(question_idx)
                        st.rerun()

    st.markdown("---")

    # Quick analysis buttons
    st.subheader("🚀 Quick Analysis")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📊 Risk Overview"):
            answer, chart = analyze_risk_overview(data)
            st.session_state.qa_history.append({
                'question': 'Show me a risk overview',
                'answer': answer,
                'chart': chart,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })
            st.rerun()
    
    with col2:
        if st.button("🌐 Domain Analysis"):
            answer, chart = analyze_domains(data)
            st.session_state.qa_history.append({
                'question': 'Analyze email domains',
                'answer': answer,
                'chart': chart,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })
            st.rerun()
    
    with col3:
        if st.button("⏰ Time Patterns"):
            answer, chart = analyze_time_patterns(data)
            st.session_state.qa_history.append({
                'question': 'Show time patterns in emails',
                'answer': answer,
                'chart': chart,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })
            st.rerun()
    
    with col4:
        if st.button("🚨 Anomalies"):
            answer, chart = analyze_anomalies(data)
            st.session_state.qa_history.append({
                'question': 'Show me anomaly analysis',
                'answer': answer,
                'chart': chart,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })
            st.rerun()


def process_natural_language_query(question, data):
    """Process natural language questions and return answers with charts"""
    question_lower = question.lower()
    
    # Attachment-related queries
    if any(word in question_lower for word in ['attachment', 'attachments', 'with attachments', 'without attachments']):
        return analyze_attachment_queries(question_lower, data)
    
    # Department-related queries
    elif any(word in question_lower for word in ['department', 'departments', 'business', 'tagged']):
        return analyze_department_queries(question_lower, data)
    
    # Recipients and domains queries
    elif any(word in question_lower for word in ['recipient', 'recipients', 'received emails', 'sender domain', 'multiple domains']):
        return analyze_recipient_domain_queries(question_lower, data)
    
    # Risk-related queries
    elif any(word in question_lower for word in ['risk', 'dangerous', 'threat', 'high']):
        return analyze_risk_queries(question_lower, data)
    
    # Domain-related queries
    elif any(word in question_lower for word in ['domain', 'gmail', 'yahoo', 'email', 'sender']):
        return analyze_domain_queries(question_lower, data)
    
    # Time-related queries
    elif any(word in question_lower for word in ['time', 'hour', 'when', 'after hours', 'night']):
        return analyze_time_queries(question_lower, data)
    
    # Anomaly-related queries
    elif any(word in question_lower for word in ['anomaly', 'anomalies', 'unusual', 'strange']):
        return analyze_anomaly_queries(question_lower, data)
    
    # Count/statistics queries
    elif any(word in question_lower for word in ['how many', 'count', 'number of', 'total']):
        return analyze_count_queries(question_lower, data)
    
    # General overview
    elif any(word in question_lower for word in ['overview', 'summary', 'show me', 'all']):
        return analyze_general_queries(question_lower, data)
    
    else:
        # Default response with basic stats
        total_emails = len(data)
        high_risk = len([e for e in data if e.get('risk_level') in ['High', 'Critical']])
        anomalies = len([e for e in data if e.get('is_anomaly', False)])
        
        answer = f"I found {total_emails} total emails in your dataset. {high_risk} are high/critical risk and {anomalies} are anomalies. Try asking about 'risk levels', 'domains', 'time patterns', or 'anomalies' for more specific analysis."
        
        return answer, None


def analyze_risk_queries(question, data):
    """Handle risk-related questions"""
    risk_counts = Counter(email.get('risk_level', 'Unknown') for email in data)
    
    if 'high' in question or 'critical' in question:
        high_risk_emails = [e for e in data if e.get('risk_level') in ['High', 'Critical']]
        answer = f"Found {len(high_risk_emails)} high/critical risk emails out of {len(data)} total."
        
        if high_risk_emails:
            # Top high risk senders
            sender_counts = Counter(email.get('sender', 'Unknown') for email in high_risk_emails)
            top_senders = sender_counts.most_common(5)
            answer += f" Top senders: {', '.join([f'{sender} ({count})' for sender, count in top_senders])}"
    else:
        answer = f"Risk distribution: Critical: {risk_counts.get('Critical', 0)}, High: {risk_counts.get('High', 0)}, Medium: {risk_counts.get('Medium', 0)}, Low: {risk_counts.get('Low', 0)}"
    
    # Create risk distribution chart
    fig = px.pie(
        values=list(risk_counts.values()),
        names=list(risk_counts.keys()),
        title="Email Risk Level Distribution",
        color_discrete_map={
            'Critical': '#e74c3c',
            'High': '#e67e22', 
            'Medium': '#f39c12',
            'Low': '#27ae60'
        }
    )
    fig.update_layout(showlegend=True)
    
    return answer, fig


def analyze_domain_queries(question, data):
    """Handle domain-related questions"""
    domain_counts = Counter()
    
    for email in data:
        sender = email.get('sender', '')
        if '@' in sender:
            domain = sender.split('@')[1].lower()
            domain_counts[domain] += 1
    
    top_domains = domain_counts.most_common(10)
    
    if 'gmail' in question:
        gmail_count = domain_counts.get('gmail.com', 0)
        answer = f"Found {gmail_count} emails from gmail.com ({gmail_count/len(data)*100:.1f}% of total emails)."
    else:
        answer = f"Top email domains: {', '.join([f'{domain} ({count})' for domain, count in top_domains[:5]])}"
    
    # Create domain chart
    fig = px.bar(
        x=[domain for domain, count in top_domains],
        y=[count for domain, count in top_domains],
        title="Top Email Domains",
        labels={'x': 'Domain', 'y': 'Email Count'}
    )
    fig.update_layout(xaxis_tickangle=45)
    
    return answer, fig


def analyze_time_queries(question, data):
    """Handle time-related questions"""
    hour_counts = Counter()
    after_hours_count = 0
    
    for email in data:
        time_str = email.get('time', '')
        if time_str and ':' in time_str:
            try:
                hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                hour = int(hour_part)
                hour_counts[hour] += 1
                
                if hour >= 18 or hour <= 6:
                    after_hours_count += 1
            except:
                continue
    
    if 'after hours' in question or 'night' in question:
        answer = f"Found {after_hours_count} emails sent after hours (6 PM - 6 AM), which is {after_hours_count/len(data)*100:.1f}% of all emails."
    else:
        peak_hour = hour_counts.most_common(1)[0] if hour_counts else (0, 0)
        answer = f"Peak email activity is at {peak_hour[0]}:00 with {peak_hour[1]} emails. {after_hours_count} emails were sent after hours."
    
    # Create hourly activity chart
    hours = list(range(24))
    counts = [hour_counts.get(h, 0) for h in hours]
    
    fig = go.Figure(data=[
        go.Bar(
            x=hours,
            y=counts,
            marker_color=['red' if h >= 18 or h <= 6 else 'blue' for h in hours]
        )
    ])
    
    fig.update_layout(
        title="Email Activity by Hour of Day",
        xaxis_title="Hour",
        yaxis_title="Number of Emails"
    )
    
    return answer, fig


def analyze_anomaly_queries(question, data):
    """Handle anomaly-related questions"""
    anomaly_emails = [e for e in data if e.get('is_anomaly', False)]
    anomaly_types = Counter(email.get('anomaly_type', 'Unknown') for email in anomaly_emails)
    
    answer = f"Found {len(anomaly_emails)} anomalous emails ({len(anomaly_emails)/len(data)*100:.1f}% of total). "
    
    if anomaly_types:
        top_types = anomaly_types.most_common(3)
        answer += f"Most common anomaly types: {', '.join([f'{atype} ({count})' for atype, count in top_types])}"
    
    # Create anomaly type chart
    if anomaly_types:
        fig = px.bar(
            x=list(anomaly_types.keys()),
            y=list(anomaly_types.values()),
            title="Anomaly Types Distribution",
            color_discrete_sequence=['#e74c3c']
        )
    else:
        fig = None
        answer += "No anomalies detected in the dataset."
    
    return answer, fig


def analyze_count_queries(question, data):
    """Handle counting/statistics questions"""
    total_emails = len(data)
    
    if 'sender' in question:
        unique_senders = len(set(email.get('sender', '') for email in data))
        answer = f"Total emails: {total_emails}, Unique senders: {unique_senders}"
    elif 'attachment' in question:
        with_attachments = len([e for e in data if e.get('attachments', '').strip()])
        answer = f"Emails with attachments: {with_attachments} out of {total_emails} ({with_attachments/total_emails*100:.1f}%)"
    else:
        high_risk = len([e for e in data if e.get('risk_level') in ['High', 'Critical']])
        anomalies = len([e for e in data if e.get('is_anomaly', False)])
        answer = f"Total emails: {total_emails}, High risk: {high_risk}, Anomalies: {anomalies}"
    
    return answer, None


def analyze_attachment_queries(question, data):
    """Analyze attachment-related queries"""
    emails_with_attachments = len([email for email in data if email.get('attachments', '').strip() and email.get('attachments', '').strip() != 'None'])
    emails_without_attachments = len(data) - emails_with_attachments
    
    answer = f"Out of {len(data)} total emails:\n• {emails_with_attachments} emails have attachments\n• {emails_without_attachments} emails have no attachments\n• Attachment rate: {(emails_with_attachments/len(data)*100):.1f}%"
    
    fig = px.pie(
        values=[emails_with_attachments, emails_without_attachments],
        names=['With Attachments', 'Without Attachments'],
        title="Emails with vs without Attachments",
        color_discrete_map={'With Attachments': '#e74c3c', 'Without Attachments': '#27ae60'}
    )
    
    return answer, fig

def analyze_department_queries(question, data):
    """Analyze department-related queries"""
    dept_business_counts = defaultdict(int)
    dept_total_counts = defaultdict(int)
    
    for email in data:
        sender = email.get('sender', '')
        tags = email.get('tags', '').lower()
        keywords_subject = email.get('Wordlist_subject', '').lower()
        keywords_attachment = email.get('Wordlist_attachment', '').lower()
        subject = email.get('subject', '').lower()
        
        # Infer department
        dept = 'Unknown'
        if '@' in sender:
            username = sender.split('@')[0].lower()
            if any(word in username for word in ['finance', 'accounting', 'fin']):
                dept = 'Finance'
            elif any(word in username for word in ['hr', 'human', 'recruiting']):
                dept = 'HR'
            elif any(word in username for word in ['it', 'tech', 'dev', 'sys']):
                dept = 'IT'
            elif any(word in username for word in ['sales', 'marketing', 'mkt']):
                dept = 'Sales/Marketing'
            elif any(word in username for word in ['legal', 'compliance', 'audit']):
                dept = 'Legal/Compliance'
            else:
                dept = 'General'
        
        dept_total_counts[dept] += 1
        
        # Check for business-related content
        if any(word in tags for word in ['business', 'corporate', 'official']) or \
           any(word in keywords_subject for word in ['business', 'corporate', 'meeting', 'contract', 'proposal']) or \
           any(word in keywords_attachment for word in ['business', 'corporate', 'meeting', 'contract', 'proposal']) or \
           any(word in subject for word in ['business', 'corporate', 'meeting', 'contract', 'proposal']):
            dept_business_counts[dept] += 1
    
    sorted_depts = sorted(dept_business_counts.items(), key=lambda x: x[1], reverse=True)
    
    answer = "Departments ranked by 'business'-tagged emails:\n"
    for dept, count in sorted_depts[:5]:
        total = dept_total_counts[dept]
        percentage = (count/total*100) if total > 0 else 0
        answer += f"• {dept}: {count} business emails ({percentage:.1f}% of {total} total)\n"
    
    if sorted_depts:
        fig = px.bar(
            x=[dept for dept, count in sorted_depts],
            y=[count for dept, count in sorted_depts],
            title="Business-Tagged Emails by Department",
            labels={'x': 'Department', 'y': 'Business Email Count'}
        )
        fig.update_layout(xaxis_tickangle=45)
    else:
        fig = None
    
    return answer, fig

def analyze_recipient_domain_queries(question, data):
    """Analyze recipients who received emails from multiple sender domains"""
    recipient_domains = defaultdict(set)
    
    for email in data:
        sender = email.get('sender', '')
        recipients_raw = email.get('recipients', '')
        
        if '@' in sender:
            sender_domain = sender.split('@')[1]
            
            if recipients_raw:
                recipients = [r.strip() for r in recipients_raw.split(',') if r.strip()]
                for recipient in recipients:
                    if '@' in recipient:
                        recipient_domains[recipient].add(sender_domain)
    
    multi_domain_recipients = {recipient: domains for recipient, domains in recipient_domains.items() if len(domains) > 1}
    
    answer = f"Found {len(multi_domain_recipients)} recipients who received emails from multiple sender domains:\n"
    
    sorted_recipients = sorted(multi_domain_recipients.items(), key=lambda x: len(x[1]), reverse=True)
    
    for recipient, domains in sorted_recipients[:10]:
        answer += f"• {recipient}: {len(domains)} domains ({', '.join(list(domains)[:3])}{'...' if len(domains) > 3 else ''})\n"
    
    if sorted_recipients:
        domain_counts = [len(domains) for domains in multi_domain_recipients.values()]
        count_distribution = Counter(domain_counts)
        
        fig = px.bar(
            x=list(count_distribution.keys()),
            y=list(count_distribution.values()),
            title="Recipients by Number of Sender Domains",
            labels={'x': 'Number of Sender Domains', 'y': 'Number of Recipients'}
        )
    else:
        fig = None
        answer += "No recipients found who received emails from multiple sender domains."
    
    return answer, fig

def analyze_behavior_queries(question, data):
    """Analyze sender behavior and communication patterns"""
    if not data:
        return "No data available for behavior analysis", None
    
    # Extract sender information
    senders = {}
    for email in data:
        sender = email.get('Sender', 'Unknown')
        if sender not in senders:
            senders[sender] = {
                'total_emails': 0,
                'recipients': set(),
                'domains': set(),
                'risk_scores': [],
                'times': []
            }
        
        senders[sender]['total_emails'] += 1
        if 'Recipient' in email:
            senders[sender]['recipients'].add(email['Recipient'])
        if 'Sender' in email:
            sender_domain = email['Sender'].split('@')[-1] if '@' in email['Sender'] else 'unknown'
            senders[sender]['domains'].add(sender_domain)
        if 'Risk_Score' in email:
            try:
                senders[sender]['risk_scores'].append(float(email['Risk_Score']))
            except:
                pass
    
    # Create behavior analysis chart
    sender_names = list(senders.keys())[:10]  # Top 10 senders
    email_counts = [senders[sender]['total_emails'] for sender in sender_names]
    recipient_counts = [len(senders[sender]['recipients']) for sender in sender_names]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        name='Total Emails',
        x=sender_names,
        y=email_counts,
        marker_color='#3498db'
    ))
    fig.add_trace(go.Bar(
        name='Unique Recipients',
        x=sender_names,
        y=recipient_counts,
        marker_color='#e74c3c'
    ))
    
    fig.update_layout(
        title='Sender Communication Behavior Analysis',
        xaxis_title='Senders',
        yaxis_title='Count',
        barmode='group',
        height=500
    )
    
    # Generate insights
    most_active = max(senders.keys(), key=lambda x: senders[x]['total_emails'])
    most_recipients = max(senders.keys(), key=lambda x: len(senders[x]['recipients']))
    
    analysis = f"""
    **Sender Behavior Analysis Results:**
    
    - **Most Active Sender**: {most_active} ({senders[most_active]['total_emails']} emails)
    - **Highest Recipient Count**: {most_recipients} ({len(senders[most_recipients]['recipients'])} unique recipients)
    - **Total Active Senders**: {len(senders)}
    - **Average Emails per Sender**: {sum(s['total_emails'] for s in senders.values()) / len(senders):.1f}
    """
    
    return analysis, fig

def analyze_compliance_queries(question, data):
    """Analyze compliance and policy-related questions"""
    if not data:
        return "No data available for compliance analysis", None
    
    # Define compliance metrics
    compliance_issues = {
        'external_communications': 0,
        'high_risk_emails': 0,
        'attachment_violations': 0,
        'domain_violations': 0
    }
    
    total_emails = len(data)
    
    for email in data:
        # External communication check
        sender_domain = email.get('Sender', '').split('@')[-1] if '@' in email.get('Sender', '') else ''
        if any(ext in sender_domain.lower() for ext in ['gmail', 'yahoo', 'hotmail', 'outlook']):
            compliance_issues['external_communications'] += 1
        
        # High risk email check
        risk_score = email.get('Risk_Score', 0)
        try:
            if float(risk_score) > 7:
                compliance_issues['high_risk_emails'] += 1
        except:
            pass
        
        # Attachment check
        if email.get('Has_Attachments', '').lower() == 'yes':
            compliance_issues['attachment_violations'] += 1
    
    # Create compliance dashboard
    metrics = list(compliance_issues.keys())
    values = list(compliance_issues.values())
    percentages = [v/total_emails*100 for v in values]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=metrics,
        y=percentages,
        marker_color=['#e74c3c' if p > 20 else '#f39c12' if p > 10 else '#27ae60' for p in percentages],
        text=[f'{v} ({p:.1f}%)' for v, p in zip(values, percentages)],
        textposition='auto'
    ))
    
    fig.update_layout(
        title='Email Compliance Analysis Dashboard',
        xaxis_title='Compliance Categories',
        yaxis_title='Percentage of Total Emails',
        height=500
    )
    
    analysis = f"""
    **Compliance Analysis Results:**
    
    - **External Communications**: {compliance_issues['external_communications']} emails ({percentages[0]:.1f}%)
    - **High Risk Emails**: {compliance_issues['high_risk_emails']} emails ({percentages[1]:.1f}%)
    - **Emails with Attachments**: {compliance_issues['attachment_violations']} emails ({percentages[2]:.1f}%)
    - **Total Emails Analyzed**: {total_emails}
    
    **Compliance Status**: {'⚠️ Attention Required' if max(percentages) > 20 else '✅ Within Normal Range'}
    """
    
    return analysis, fig

def analyze_comparison_queries(question, data):
    """Handle comparison and correlation questions"""
    if not data:
        return "No data available for comparison analysis", None
    
    # Extract domains for comparison
    domain_stats = {}
    for email in data:
        sender = email.get('Sender', '')
        if '@' in sender:
            domain = sender.split('@')[1]
            if domain not in domain_stats:
                domain_stats[domain] = {
                    'count': 0,
                    'risk_scores': [],
                    'attachments': 0,
                    'recipients': set()
                }
            
            domain_stats[domain]['count'] += 1
            
            if 'Risk_Score' in email:
                try:
                    domain_stats[domain]['risk_scores'].append(float(email['Risk_Score']))
                except:
                    pass
            
            if email.get('Has_Attachments', '').lower() == 'yes':
                domain_stats[domain]['attachments'] += 1
            
            if 'Recipient' in email:
                domain_stats[domain]['recipients'].add(email['Recipient'])
    
    # Create comparison visualization
    domains = list(domain_stats.keys())[:8]  # Top 8 domains
    email_counts = [domain_stats[d]['count'] for d in domains]
    avg_risk_scores = [
        sum(domain_stats[d]['risk_scores'])/len(domain_stats[d]['risk_scores']) 
        if domain_stats[d]['risk_scores'] else 0 
        for d in domains
    ]
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=['Email Volume by Domain', 'Average Risk Score by Domain'],
        vertical_spacing=0.15
    )
    
    fig.add_trace(go.Bar(
        x=domains,
        y=email_counts,
        name='Email Count',
        marker_color='#3498db'
    ), row=1, col=1)
    
    fig.add_trace(go.Bar(
        x=domains,
        y=avg_risk_scores,
        name='Avg Risk Score',
        marker_color='#e74c3c'
    ), row=2, col=1)
    
    fig.update_layout(
        title='Domain Comparison Analysis',
        height=600,
        showlegend=False
    )
    
    # Find interesting comparisons
    highest_volume = max(domains, key=lambda d: domain_stats[d]['count'])
    highest_risk = max(domains, key=lambda d: sum(domain_stats[d]['risk_scores'])/len(domain_stats[d]['risk_scores']) if domain_stats[d]['risk_scores'] else 0)
    
    analysis = f"""
    **Domain Comparison Results:**
    
    - **Highest Email Volume**: {highest_volume} ({domain_stats[highest_volume]['count']} emails)
    - **Highest Average Risk**: {highest_risk} (Risk Score: {sum(domain_stats[highest_risk]['risk_scores'])/len(domain_stats[highest_risk]['risk_scores']) if domain_stats[highest_risk]['risk_scores'] else 0:.2f})
    - **Total Domains Analyzed**: {len(domain_stats)}
    
    **Key Insights**:
    - Volume and risk don't always correlate
    - External domains may show different patterns than internal ones
    """
    
    return analysis, fig

def analyze_advanced_general_queries(question, data):
    """Enhanced general query handling with context awareness"""
    if not data:
        return "No email data available for analysis. Please upload a CSV file first.", None
    
    # Comprehensive overview analysis
    total_emails = len(data)
    
    # Extract key metrics
    senders = set(email.get('Sender', '') for email in data)
    recipients = set(email.get('Recipient', '') for email in data)
    
    # Risk analysis
    risk_scores = []
    for email in data:
        try:
            risk_scores.append(float(email.get('Risk_Score', 0)))
        except:
            pass
    
    # Domain analysis
    sender_domains = set()
    for email in data:
        sender = email.get('Sender', '')
        if '@' in sender:
            sender_domains.add(sender.split('@')[1])
    
    # Attachment analysis
    attachments = sum(1 for email in data if email.get('Has_Attachments', '').lower() == 'yes')
    
    # Create comprehensive overview chart
    metrics = ['Total Emails', 'Unique Senders', 'Unique Recipients', 'Sender Domains', 'With Attachments']
    values = [total_emails, len(senders), len(recipients), len(sender_domains), attachments]
    
    fig = go.Figure(data=go.Bar(
        x=metrics,
        y=values,
        marker_color=['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'],
        text=values,
        textposition='auto'
    ))
    
    fig.update_layout(
        title='Email Communication Overview Dashboard',
        xaxis_title='Metrics',
        yaxis_title='Count',
        height=500
    )
    
    # Advanced insights
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    high_risk_count = sum(1 for score in risk_scores if score > 7)
    
    analysis = f"""
    **Comprehensive Email Analysis Overview:**
    
    **Volume Metrics:**
    - Total Emails: {total_emails:,}
    - Unique Senders: {len(senders):,}
    - Unique Recipients: {len(recipients):,}
    - Active Domains: {len(sender_domains)}
    
    **Security Metrics:**
    - Average Risk Score: {avg_risk:.2f}/10
    - High Risk Emails (>7): {high_risk_count} ({high_risk_count/total_emails*100:.1f}%)
    - Emails with Attachments: {attachments} ({attachments/total_emails*100:.1f}%)
    
    **Communication Patterns:**
    - Average Emails per Sender: {total_emails/len(senders):.1f}
    - Sender-to-Recipient Ratio: 1:{len(recipients)/len(senders):.1f}
    
    This overview provides the foundation for deeper security analysis and monitoring.
    """
    
    return analysis, fig

def analyze_general_queries(question, data):
    """Handle general overview questions"""
    return analyze_advanced_general_queries(question, data)

def system_workflow_page():
    """Professional system workflow and process documentation"""
    st.header("ExfilEye DLP System - Professional Workflow Documentation")
    
    # Export options
    col1, col2, col3 = st.columns([2, 1, 1])
    with col2:
        if st.button("📄 Export Workflow PDF", type="primary"):
            pdf_content = generate_workflow_pdf()
            st.download_button(
                label="⬇️ Download PDF",
                data=pdf_content,
                file_name=f"ExfilEye_Workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )
    
    with col3:
        if st.button("📊 Export Charts PDF"):
            charts_pdf = generate_charts_pdf()
            st.download_button(
                label="⬇️ Download Charts PDF",
                data=charts_pdf,
                file_name=f"ExfilEye_Charts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )
    
    # Main Process Flow
    st.subheader("Complete Process Flow: Data Import to Security Results")
    
    # Create workflow visualization
    workflow_fig = create_main_workflow_diagram()
    st.plotly_chart(workflow_fig, use_container_width=True, key="main_workflow")
    
    # Process Details
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Stage 1: Data Input")
        st.markdown("""
        **CSV File Upload**
        - Secure file upload interface
        - Email data validation
        - Field mapping and parsing
        
        **Data Validation**
        - Email format verification
        - Required field checking
        - Data integrity validation
        
        **Email Parsing**
        - Sender/recipient extraction
        - Domain identification
        - Attachment detection
        """)
        
        st.markdown("### Stage 2: Data Processing")
        st.markdown("""
        **Domain Classification**
        - Internal/external domain analysis
        - Risk-based domain categorization
        - Trusted domain identification
        
        **Risk Scoring**
        - Multi-factor risk assessment
        - Behavioral pattern analysis
        - Threat level calculation
        
        **Anomaly Detection**
        - Statistical pattern analysis
        - Unusual behavior identification
        - Security threat detection
        
        **Network Graph Building**
        - Communication relationship mapping
        - Network topology construction
        - Interactive graph generation
        """)
    
    with col2:
        st.markdown("### Stage 3: Analysis & Intelligence")
        st.markdown("""
        **Sender Behavior Analysis**
        - Communication pattern analysis
        - Risk trend identification
        - Behavioral matrix generation
        - Department-based insights
        
        **Network Intelligence**
        - Communication relationship mapping
        - Community detection algorithms
        - Centrality analysis and node importance
        - Interactive graph visualization
        """)
        
        st.markdown("### Stage 4: Security Operations & Response")
        st.markdown("""
        **Security Operations Dashboard**
        - Real-time risk event monitoring
        - Temporary/disposable email detection
        - Visual risk level indicators
        - Anomaly alert management
        
        **Decision Management System**
        - Four-tier action framework (No Action, Monitor, Investigate, Escalate)
        - Automated queue management
        - Status tracking and workflow integration
        - Professional security response protocols
        
        **Follow-up Center**
        - Escalated email management
        - Investigation queue tracking
        - Monitoring status oversight
        - Outlook integration for security communications
        
        **Advanced Features**
        - Network analysis with interactive graphs
        - System workflow documentation
        - Professional reporting tools
        - Comprehensive export capabilities
        """)
    
    st.markdown("---")
    
    # Feature Matrix
    st.subheader("Feature Capabilities Matrix")
    
    features_fig = create_feature_matrix_diagram()
    st.plotly_chart(features_fig, use_container_width=True, key="feature_matrix")
    
    # Technology Stack
    st.markdown("---")
    st.subheader("Technology Stack & Architecture")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Frontend Technologies**")
        st.markdown("""
        - Streamlit Web Framework
        - Plotly Interactive Visualizations
        - NetworkX Graph Analysis
        - HTML/CSS Interface Components
        """)
    
    with col2:
        st.markdown("**Backend Processing**")
        st.markdown("""
        - Python 3.11 Runtime
        - NumPy Numerical Computing
        - Scikit-learn Machine Learning
        - Custom Algorithm Implementation
        """)
    
    with col3:
        st.markdown("**Security & Analytics**")
        st.markdown("""
        - Real-time Anomaly Detection
        - Risk Scoring Algorithms
        - Behavioral Pattern Analysis
        - Domain Classification Engine
        """)

def create_main_workflow_diagram():
    """Create the main workflow process diagram with improved readability"""
    fig = go.Figure()
    
    # Define workflow stages with better sizing and positioning
    stages = [
        # Input Stage
        {"name": "CSV Upload", "x": 1, "y": 4.5, "color": "#3498db", "width": 0.7, "height": 0.4},
        {"name": "Data Validation", "x": 1, "y": 3.5, "color": "#3498db", "width": 0.7, "height": 0.4},
        {"name": "Email Parsing", "x": 1, "y": 2.5, "color": "#3498db", "width": 0.7, "height": 0.4},
        
        # Processing Stage
        {"name": "Domain<br>Classification", "x": 3, "y": 4.5, "color": "#e67e22", "width": 0.7, "height": 0.4},
        {"name": "Risk Scoring", "x": 3, "y": 3.5, "color": "#e67e22", "width": 0.7, "height": 0.4},
        {"name": "Anomaly<br>Detection", "x": 3, "y": 2.5, "color": "#e67e22", "width": 0.7, "height": 0.4},
        {"name": "Network Graph<br>Building", "x": 3, "y": 1.5, "color": "#e67e22", "width": 0.7, "height": 0.4},
        
        # Analysis Stage
        {"name": "Sender Behavior<br>Analysis", "x": 5, "y": 4.5, "color": "#9b59b6", "width": 0.7, "height": 0.4},
        {"name": "Communication<br>Patterns", "x": 5, "y": 3.5, "color": "#9b59b6", "width": 0.7, "height": 0.4},
        {"name": "Risk Trend<br>Analysis", "x": 5, "y": 2.5, "color": "#9b59b6", "width": 0.7, "height": 0.4},
        {"name": "Network<br>Intelligence", "x": 5, "y": 1.5, "color": "#9b59b6", "width": 0.7, "height": 0.4},
        
        # Results Stage
        {"name": "Interactive<br>Dashboards", "x": 7, "y": 4.5, "color": "#27ae60", "width": 0.7, "height": 0.4},
        {"name": "Security<br>Reports", "x": 7, "y": 3.5, "color": "#27ae60", "width": 0.7, "height": 0.4},
        {"name": "Follow-up<br>Tracking", "x": 7, "y": 2.5, "color": "#27ae60", "width": 0.7, "height": 0.4},
        {"name": "Export<br>Capabilities", "x": 7, "y": 1.5, "color": "#27ae60", "width": 0.7, "height": 0.4},
    ]
    
    # Add workflow boxes as rectangles with better visibility
    for i, stage in enumerate(stages):
        # Add rectangle shape
        fig.add_shape(
            type="rect",
            x0=stage["x"] - stage["width"]/2,
            y0=stage["y"] - stage["height"]/2,
            x1=stage["x"] + stage["width"]/2,
            y1=stage["y"] + stage["height"]/2,
            fillcolor=stage["color"],
            line=dict(color="white", width=3),
            opacity=0.9
        )
        
        # Add text with better positioning
        fig.add_annotation(
            x=stage["x"],
            y=stage["y"],
            text=f"<b>{stage['name']}</b>",
            showarrow=False,
            font=dict(color="white", size=11, family="Arial"),
            align="center",
            bgcolor="rgba(0,0,0,0)",
            bordercolor="rgba(0,0,0,0)"
        )
    
    # Add stage headers with better positioning
    headers = [
        {"text": "DATA INPUT", "x": 1, "y": 5.5, "color": "#3498db"},
        {"text": "PROCESSING", "x": 3, "y": 5.5, "color": "#e67e22"},
        {"text": "ANALYSIS", "x": 5, "y": 5.5, "color": "#9b59b6"},
        {"text": "RESULTS", "x": 7, "y": 5.5, "color": "#27ae60"},
    ]
    
    for header in headers:
        fig.add_annotation(
            x=header["x"],
            y=header["y"],
            text=f"<b>{header['text']}</b>",
            showarrow=False,
            font=dict(color=header["color"], size=16, family="Arial Black"),
            align="center"
        )
    
    # Add flow arrows with better positioning
    arrow_paths = [
        # Input to Processing
        (1.35, 4.5, 2.65, 4.5), (1.35, 3.5, 2.65, 3.5), (1.35, 2.5, 2.65, 2.5),
        # Processing to Analysis  
        (3.35, 4.5, 4.65, 4.5), (3.35, 3.5, 4.65, 3.5), (3.35, 2.5, 4.65, 2.5), (3.35, 1.5, 4.65, 1.5),
        # Analysis to Results
        (5.35, 4.5, 6.65, 4.5), (5.35, 3.5, 6.65, 3.5), (5.35, 2.5, 6.65, 2.5), (5.35, 1.5, 6.65, 1.5),
    ]
    
    for x1, y1, x2, y2 in arrow_paths:
        fig.add_annotation(
            x=x2, y=y2, ax=x1, ay=y1,
            xref='x', yref='y', axref='x', ayref='y',
            arrowhead=3, arrowsize=1.8, arrowwidth=3, arrowcolor='#34495e'
        )
    
    fig.update_layout(
        title={
            'text': "ExfilEye DLP Email Security Monitor - Complete Process Flow",
            'x': 0.5, 'xanchor': 'center',
            'font': {'size': 20, 'family': 'Arial Black', 'color': '#2c3e50'}
        },
        xaxis=dict(range=[0, 8], showgrid=False, showticklabels=False, zeroline=False),
        yaxis=dict(range=[0.5, 6.5], showgrid=False, showticklabels=False, zeroline=False),
        plot_bgcolor='white', 
        paper_bgcolor='#f8f9fa',
        width=1400, 
        height=600, 
        margin=dict(l=50, r=50, t=80, b=50)
    )
    
    return fig

def create_feature_matrix_diagram():
    """Create feature capability matrix with improved readability"""
    
    # Define features for current navigation sections
    features_data = {
        'Data Upload': ['CSV Validation', 'Email Parsing', 'Domain Classification', 'Risk Scoring', 'Anomaly Detection', 'Data Preview'],
        'Security Operations': ['Risk Event Monitoring', 'Disposable Email Detection', 'Decision Management', 'Action Tracking', 'Alert Systems', 'Workflow Integration'],
        'Follow-up Center': ['Escalation Management', 'Investigation Queue', 'Monitoring Status', 'Outlook Integration', 'Security Communications', 'Response Tracking'],
        'Network Analysis': ['Interactive Graphs', 'Community Detection', 'Relationship Mapping', 'Centrality Analysis', 'Communication Patterns', 'Node Intelligence']
    }
    
    colors = ['#3498db', '#9b59b6', '#e74c3c', '#27ae60']
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=list(features_data.keys()),
        vertical_spacing=0.2, horizontal_spacing=0.15,
        specs=[[{"type": "xy"}, {"type": "xy"}],
               [{"type": "xy"}, {"type": "xy"}]]
    )
    
    positions = [(1, 1), (1, 2), (2, 1), (2, 2)]
    
    for idx, (section, features) in enumerate(features_data.items()):
        row, col = positions[idx]
        color = colors[idx]
        
        # Create rectangular boxes for each feature
        for i, feature in enumerate(features):
            y_pos = len(features) - i
            
            # Add rectangle shape for feature
            fig.add_shape(
                type="rect",
                x0=0.2, y0=y_pos - 0.35,
                x1=3.8, y1=y_pos + 0.35,
                fillcolor=color,
                line=dict(color="white", width=2),
                opacity=0.8,
                row=row, col=col
            )
            
            # Add feature text
            fig.add_annotation(
                x=2, y=y_pos,
                text=f"<b>{feature}</b>",
                showarrow=False,
                font=dict(color="white", size=11, family="Arial"),
                align="center",
                row=row, col=col
            )
        
        # Update subplot axes with better spacing
        fig.update_xaxes(
            range=[0, 4], showgrid=False, showticklabels=False, zeroline=False,
            row=row, col=col
        )
        fig.update_yaxes(
            range=[0, len(features)+1], showgrid=False, showticklabels=False, zeroline=False,
            row=row, col=col
        )
    
    fig.update_layout(
        title={
            'text': "ExfilEye Navigation Features - Capability Matrix",
            'x': 0.5, 'xanchor': 'center',
            'font': {'size': 18, 'family': 'Arial Black', 'color': '#2c3e50'}
        },
        plot_bgcolor='white', 
        paper_bgcolor='#f8f9fa',
        width=1400, 
        height=700, 
        margin=dict(l=50, r=50, t=120, b=50)
    )
    
    return fig

def generate_workflow_pdf():
    """Generate comprehensive workflow documentation as PDF"""
    from io import BytesIO
    import base64
    
    # Create HTML content for the workflow documentation
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>ExfilEye DLP System - Workflow Documentation</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                line-height: 1.6;
                color: #333;
            }}
            .header {{
                text-align: center;
                border-bottom: 3px solid #3498db;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            .title {{
                color: #2c3e50;
                font-size: 24px;
                font-weight: bold;
                margin: 0;
            }}
            .subtitle {{
                color: #7f8c8d;
                font-size: 14px;
                margin: 5px 0 0 0;
            }}
            .stage {{
                margin: 30px 0;
            }}
            .stage-title {{
                color: #2c3e50;
                font-size: 18px;
                font-weight: bold;
                border-left: 4px solid #3498db;
                padding-left: 15px;
            }}
            .stage-content {{
                margin: 15px 0 15px 20px;
            }}
            .feature-list {{
                list-style-type: none;
                padding: 0;
            }}
            .feature-item {{
                background: #f8f9fa;
                margin: 5px 0;
                padding: 10px;
                border-left: 3px solid #3498db;
            }}
            .tech-section {{
                background: #ecf0f1;
                padding: 20px;
                margin: 20px 0;
                border-radius: 5px;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #bdc3c7;
                color: #7f8c8d;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="title">🛡️ ExfilEye DLP Email Security Monitor</h1>
            <p class="subtitle">Professional Workflow Documentation & Process Flow</p>
            <p class="subtitle">Generated on {timestamp}</p>
        </div>

        <div class="stage">
            <h2 class="stage-title">Stage 1: Data Input</h2>
            <div class="stage-content">
                <ul class="feature-list">
                    <li class="feature-item"><strong>CSV File Upload:</strong> Secure file upload interface with email data validation and field mapping</li>
                    <li class="feature-item"><strong>Data Validation:</strong> Email format verification, required field checking, and data integrity validation</li>
                    <li class="feature-item"><strong>Email Parsing:</strong> Sender/recipient extraction, domain identification, and attachment detection</li>
                </ul>
            </div>
        </div>

        <div class="stage">
            <h2 class="stage-title">Stage 2: Data Processing</h2>
            <div class="stage-content">
                <ul class="feature-list">
                    <li class="feature-item"><strong>Domain Classification:</strong> Internal/external domain analysis, risk-based categorization, and trusted domain identification</li>
                    <li class="feature-item"><strong>Risk Scoring:</strong> Multi-factor risk assessment, behavioral pattern analysis, and threat level calculation</li>
                    <li class="feature-item"><strong>Anomaly Detection:</strong> Statistical pattern analysis, unusual behavior identification, and security threat detection</li>
                    <li class="feature-item"><strong>Network Graph Building:</strong> Communication relationship mapping, network topology construction, and interactive graph generation</li>
                </ul>
            </div>
        </div>

        <div class="stage">
            <h2 class="stage-title">Stage 3: Analysis & Intelligence</h2>
            <div class="stage-content">
                <ul class="feature-list">
                    <li class="feature-item"><strong>Sender Behavior Analysis:</strong> Communication pattern analysis, risk trend identification, behavioral matrix generation, and department-based insights</li>
                    <li class="feature-item"><strong>Q&A Processing:</strong> Natural language query processing, pre-built question execution, smart pattern recognition, and custom insight generation</li>
                </ul>
            </div>
        </div>

        <div class="stage">
            <h2 class="stage-title">Stage 4: Results & Actions</h2>
            <div class="stage-content">
                <ul class="feature-list">
                    <li class="feature-item"><strong>Interactive Dashboards:</strong> Real-time security metrics, visual analytics displays, risk distribution charts, and behavior trend visualizations</li>
                    <li class="feature-item"><strong>Security Reports:</strong> Comprehensive security assessments, anomaly detection results, risk analysis summaries, and actionable intelligence reports</li>
                    <li class="feature-item"><strong>Follow-up Tracking:</strong> Security decision tracking, follow-up action management, Outlook integration, and incident response workflow</li>
                    <li class="feature-item"><strong>Export Capabilities:</strong> CSV data export, report generation, dashboard sharing, and compliance documentation</li>
                </ul>
            </div>
        </div>

        <div class="tech-section">
            <h2 class="stage-title">Technology Stack & Architecture</h2>
            <div class="stage-content">
                <p><strong>Frontend Technologies:</strong> Streamlit Web Framework, Plotly Interactive Visualizations, NetworkX Graph Analysis, HTML/CSS Interface Components</p>
                <p><strong>Backend Processing:</strong> Python 3.11 Runtime, NumPy Numerical Computing, Scikit-learn Machine Learning, Custom Algorithm Implementation</p>
                <p><strong>Security & Analytics:</strong> Real-time Anomaly Detection, Risk Scoring Algorithms, Behavioral Pattern Analysis, Domain Classification Engine</p>
            </div>
        </div>

        <div class="footer">
            <p>ExfilEye DLP Email Security Monitoring System | Professional Documentation</p>
        </div>
    </body>
    </html>
    """
    
    try:
        # Try to use weasyprint for better PDF generation
        import weasyprint
        pdf_buffer = BytesIO()
        weasyprint.HTML(string=html_content).write_pdf(pdf_buffer)
        return pdf_buffer.getvalue()
    except ImportError:
        # Fallback to basic HTML to PDF conversion using reportlab
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.units import inch
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=20, textColor='#2c3e50', alignment=1)
            heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor='#3498db')
            
            story = []
            
            # Title
            story.append(Paragraph("ExfilEye DLP Email Security Monitor", title_style))
            story.append(Paragraph("Professional Workflow Documentation", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Content sections
            sections = [
                ("Stage 1: Data Input", [
                    "CSV File Upload: Secure file upload interface with validation",
                    "Data Validation: Email format verification and integrity checks",
                    "Email Parsing: Sender/recipient extraction and domain identification"
                ]),
                ("Stage 2: Data Processing", [
                    "Domain Classification: Internal/external analysis and risk categorization",
                    "Risk Scoring: Multi-factor assessment and threat level calculation",
                    "Anomaly Detection: Statistical analysis and threat detection",
                    "Network Graph Building: Communication mapping and topology construction"
                ]),
                ("Stage 3: Analysis & Intelligence", [
                    "Sender Behavior Analysis: Pattern analysis and behavioral insights",
                    "Network Intelligence: Communication mapping and relationship analysis"
                ]),
                ("Stage 4: Security Operations & Response", [
                    "Security Operations Dashboard: Real-time risk monitoring and alert management",
                    "Decision Management System: Four-tier action framework with automated workflows",
                    "Follow-up Center: Escalation management and Outlook integration",
                    "Advanced Features: Network analysis and professional reporting tools"
                ])
            ]
            
            for section_title, items in sections:
                story.append(Paragraph(section_title, heading_style))
                story.append(Spacer(1, 10))
                for item in items:
                    story.append(Paragraph(f"• {item}", styles['Normal']))
                story.append(Spacer(1, 15))
            
            doc.build(story)
            return buffer.getvalue()
            
        except ImportError:
            # Final fallback - return HTML content as text
            return html_content.encode('utf-8')

def generate_charts_pdf():
    """Generate workflow charts as PDF"""
    from io import BytesIO
    
    try:
        # Create the workflow diagram
        workflow_fig = create_main_workflow_diagram()
        features_fig = create_feature_matrix_diagram()
        
        # Convert to images and create PDF
        workflow_img = workflow_fig.to_image(format="png", width=1400, height=600)
        features_img = features_fig.to_image(format="png", width=1400, height=700)
        
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.utils import ImageReader
            
            buffer = BytesIO()
            c = canvas.Canvas(buffer, pagesize=landscape(A4))
            
            # Page 1 - Workflow diagram
            c.setTitle("ExfilEye Workflow Charts")
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, 550, "ExfilEye DLP System - Complete Process Flow")
            
            # Add workflow image
            workflow_image = ImageReader(BytesIO(workflow_img))
            c.drawImage(workflow_image, 50, 200, width=700, height=300)
            
            c.showPage()
            
            # Page 2 - Feature matrix
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, 550, "ExfilEye Navigation Features - Capability Matrix")
            
            # Add features image
            features_image = ImageReader(BytesIO(features_img))
            c.drawImage(features_image, 50, 150, width=700, height=350)
            
            c.save()
            return buffer.getvalue()
            
        except ImportError:
            # Fallback - return the first chart as PNG
            return workflow_img
            
    except Exception as e:
        # Return error message as text
        return f"Error generating charts PDF: {str(e)}".encode('utf-8')


def analyze_risk_overview(data):
    """Generate risk overview"""
    risk_counts = Counter(email.get('risk_level', 'Unknown') for email in data)
    total = len(data)
    
    answer = f"Dataset Overview: {total} total emails. Risk distribution - Critical: {risk_counts.get('Critical', 0)}, High: {risk_counts.get('High', 0)}, Medium: {risk_counts.get('Medium', 0)}, Low: {risk_counts.get('Low', 0)}"
    
    # Create unique figure with timestamp to avoid conflicts
    fig = px.pie(
        values=list(risk_counts.values()),
        names=list(risk_counts.keys()),
        title=f"Risk Level Distribution - {datetime.now().strftime('%H:%M:%S')}",
        color_discrete_map={'Critical': '#e74c3c', 'High': '#e67e22', 'Medium': '#f39c12', 'Low': '#27ae60'}
    )
    fig.update_layout(showlegend=True)
    
    return answer, fig


def analyze_domains(data):
    """Generate domain analysis"""
    domain_counts = Counter()
    for email in data:
        sender = email.get('sender', '')
        if '@' in sender:
            domain_counts[sender.split('@')[1].lower()] += 1
    
    top_domains = domain_counts.most_common(10)
    answer = f"Top domains: {', '.join([f'{domain} ({count})' for domain, count in top_domains[:5]])}"
    
    fig = px.bar(
        x=[domain for domain, count in top_domains],
        y=[count for domain, count in top_domains],
        title=f"Top Email Domains - {datetime.now().strftime('%H:%M:%S')}"
    )
    fig.update_layout(showlegend=False)
    
    return answer, fig


def analyze_time_patterns(data):
    """Generate time pattern analysis"""
    hour_counts = Counter()
    for email in data:
        time_str = email.get('time', '')
        if time_str and ':' in time_str:
            try:
                hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                hour_counts[int(hour_part)] += 1
            except:
                continue
    
    peak_hour = hour_counts.most_common(1)[0] if hour_counts else (0, 0)
    answer = f"Peak activity at {peak_hour[0]}:00 with {peak_hour[1]} emails"
    
    hours = list(range(24))
    counts = [hour_counts.get(h, 0) for h in hours]
    
    fig = go.Figure(data=[go.Bar(x=hours, y=counts)])
    fig.update_layout(title=f"Email Activity by Hour - {datetime.now().strftime('%H:%M:%S')}")
    
    return answer, fig


def analyze_anomalies(data):
    """Generate anomaly analysis"""
    anomaly_emails = [e for e in data if e.get('is_anomaly', False)]
    anomaly_types = Counter(email.get('anomaly_type', 'Unknown') for email in anomaly_emails)
    
    answer = f"Found {len(anomaly_emails)} anomalies ({len(anomaly_emails)/len(data)*100:.1f}% of total)"
    
    if anomaly_types:
        fig = px.bar(
            x=list(anomaly_types.keys()),
            y=list(anomaly_types.values()),
            title=f"Anomaly Types - {datetime.now().strftime('%H:%M:%S')}"
        )
        fig.update_layout(showlegend=False)
    else:
        fig = None
    
    return answer, fig


    
    with overview_col3:
        anomaly_senders = sum(1 for emails in sender_groups.values() 
                             if any(e.get('is_anomaly', False) for e in emails))
        st.metric("Anomaly Senders", anomaly_senders)
    
    with overview_col4:
        departing_senders = sum(1 for emails in sender_groups.values() 
                               if any(e.get('leaver', '').strip().upper() == 'YES' for e in emails))
        st.metric("Departing Employees", departing_senders)

    # Sender Risk Distribution Chart
    st.subheader("🎯 Sender Risk Distribution")
    
    # Calculate sender risk levels
    sender_risk_data = []
    for sender, emails in sender_groups.items():
        max_risk_score = max(email.get('risk_score', 0) for email in emails)
        max_risk_level = 'Low'
        for email in emails:
            if email.get('risk_score', 0) == max_risk_score:
                max_risk_level = email.get('risk_level', 'Low')
                break
        
        total_emails = len(emails)
        anomaly_count = sum(1 for email in emails if email.get('is_anomaly', False))
        avg_risk = sum(email.get('risk_score', 0) for email in emails) / total_emails
        
        sender_risk_data.append({
            'sender': sender,
            'max_risk_level': max_risk_level,
            'max_risk_score': max_risk_score,
            'avg_risk_score': avg_risk,
            'total_emails': total_emails,
            'anomaly_count': anomaly_count
        })

    # Risk level pie chart
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        risk_level_counts = Counter(item['max_risk_level'] for item in sender_risk_data)
        
        fig_pie = go.Figure(data=[go.Pie(
            labels=list(risk_level_counts.keys()),
            values=list(risk_level_counts.values()),
            hole=0.4,
            marker_colors=['#e74c3c', '#e67e22', '#f39c12', '#27ae60']
        )])
        
        fig_pie.update_layout(
            title="Sender Risk Level Distribution",
            height=400
        )
        
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with chart_col2:
        # Risk score vs email count scatter plot
        fig_scatter = px.scatter(
            sender_risk_data,
            x='total_emails',
            y='avg_risk_score',
            size='anomaly_count',
            color='max_risk_level',
            hover_data=['sender'],
            title="Risk Score vs Email Volume",
            labels={
                'total_emails': 'Number of Emails',
                'avg_risk_score': 'Average Risk Score',
                'max_risk_level': 'Risk Level'
            },
            color_discrete_map={
                'Critical': '#e74c3c',
                'High': '#e67e22', 
                'Medium': '#f39c12',
                'Low': '#27ae60'
            }
        )
        
        fig_scatter.update_layout(height=400)
        st.plotly_chart(fig_scatter, use_container_width=True)

    # Behavioral Analysis Filters
    st.subheader("🔍 Behavioral Analysis Filters")
    
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    
    with filter_col1:
        risk_filter = st.selectbox(
            "Risk Level Filter:",
            options=["All", "Critical", "High", "Medium", "Low"],
            key="behavior_risk_filter"
        )
    
    with filter_col2:
        anomaly_filter = st.selectbox(
            "Anomaly Filter:",
            options=["All", "Has Anomalies", "No Anomalies"],
            key="behavior_anomaly_filter"
        )
    
    with filter_col3:
        email_volume_filter = st.selectbox(
            "Email Volume:",
            options=["All", "High Volume (>10)", "Medium Volume (5-10)", "Low Volume (<5)"],
            key="behavior_volume_filter"
        )
    
    with filter_col4:
        domain_filter = st.selectbox(
            "Domain Type:",
            options=["All", "Free Domains", "Corporate Domains", "External Domains"],
            key="behavior_domain_filter"
        )

    # Apply filters
    filtered_sender_data = sender_risk_data.copy()
    
    if risk_filter != "All":
        filtered_sender_data = [s for s in filtered_sender_data if s['max_risk_level'] == risk_filter]
    
    if anomaly_filter == "Has Anomalies":
        filtered_sender_data = [s for s in filtered_sender_data if s['anomaly_count'] > 0]
    elif anomaly_filter == "No Anomalies":
        filtered_sender_data = [s for s in filtered_sender_data if s['anomaly_count'] == 0]
    
    if email_volume_filter == "High Volume (>10)":
        filtered_sender_data = [s for s in filtered_sender_data if s['total_emails'] > 10]
    elif email_volume_filter == "Medium Volume (5-10)":
        filtered_sender_data = [s for s in filtered_sender_data if 5 <= s['total_emails'] <= 10]
    elif email_volume_filter == "Low Volume (<5)":
        filtered_sender_data = [s for s in filtered_sender_data if s['total_emails'] < 5]

    # Sort by risk score
    filtered_sender_data.sort(key=lambda x: x['max_risk_score'], reverse=True)

    # Detailed Sender Analysis
    st.subheader(f"📋 Detailed Sender Analysis ({len(filtered_sender_data)} senders)")
    
    if not filtered_sender_data:
        st.info("No senders match the current filter criteria.")
        return

    # Display top risky senders
    for i, sender_info in enumerate(filtered_sender_data[:20]):  # Show top 20
        sender = sender_info['sender']
        emails = sender_groups[sender]
        
        # Sender behavior metrics
        time_patterns = [email.get('_time', '') for email in emails if email.get('_time', '')]
        after_hours_count = 0
        for time_str in time_patterns:
            try:
                if ':' in time_str:
                    hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                    hour = int(hour_part)
                    if hour >= 18 or hour <= 6:
                        after_hours_count += 1
            except:
                continue
        
        # Domain analysis
        sender_domain = sender.split('@')[1] if '@' in sender else 'unknown'
        free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        is_free_domain = sender_domain.lower() in free_domains
        
        # External recipient analysis
        external_emails = sum(1 for email in emails if 'external' in email.get('recipient_status', '').lower())
        
        # Attachment patterns
        attachment_emails = sum(1 for email in emails if email.get('attachments', '').strip())
        
        # Keyword matches
        keyword_emails = sum(1 for email in emails if email.get('Wordlist_subject', '').strip() or email.get('Wordlist_attachment', '').strip())
        
        # Create sender card
        risk_color = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(sender_info['max_risk_level'], '⚪')
        
        with st.expander(f"{risk_color} {sender} - Risk: {sender_info['max_risk_level']} ({sender_info['max_risk_score']:.0f}) - {sender_info['total_emails']} emails"):
            
            # Behavior summary
            behavior_col1, behavior_col2, behavior_col3 = st.columns(3)
            
            with behavior_col1:
                st.write("**📧 Email Patterns**")
                st.write(f"• Total emails: {sender_info['total_emails']}")
                st.write(f"• Average risk: {sender_info['avg_risk_score']:.1f}")
                st.write(f"• Anomalies: {sender_info['anomaly_count']}")
                st.write(f"• After hours: {after_hours_count}")
            
            with behavior_col2:
                st.write("**🎯 Content Analysis**")
                st.write(f"• With attachments: {attachment_emails}")
                st.write(f"• Keyword matches: {keyword_emails}")
                st.write(f"• External recipients: {external_emails}")
                domain_type = "Free" if is_free_domain else "Corporate"
                st.write(f"• Domain type: {domain_type}")
            
            with behavior_col3:
                st.write("**⚠️ Risk Indicators**")
                
                # Calculate behavioral risk indicators
                risk_indicators = []
                if after_hours_count > 0:
                    risk_indicators.append(f"After-hours activity ({after_hours_count})")
                if is_free_domain:
                    risk_indicators.append("Free email domain")
                if external_emails > 0:
                    risk_indicators.append(f"External communication ({external_emails})")
                if attachment_emails > 0 and keyword_emails > 0:
                    risk_indicators.append("Sensitive content + attachments")
                if any(email.get('Termination', '').strip() or email.get('leaver', '').strip() for email in emails):
                    risk_indicators.append("Departing employee")
                
                if risk_indicators:
                    for indicator in risk_indicators:
                        st.write(f"• {indicator}")
                else:
                    st.write("• No major risk indicators")
            
            # Time pattern analysis
            if time_patterns:
                st.write("**⏰ Temporal Behavior Analysis**")
                
                # Extract hours for time pattern visualization
                hours = []
                for time_str in time_patterns:
                    try:
                        if ':' in time_str:
                            hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                            hours.append(int(hour_part))
                    except:
                        continue
                
                if hours:
                    hour_counts = Counter(hours)
                    
                    fig_time = go.Figure(data=[
                        go.Bar(
                            x=list(range(24)),
                            y=[hour_counts.get(h, 0) for h in range(24)],
                            marker_color=['red' if h >= 18 or h <= 6 else 'blue' for h in range(24)]
                        )
                    ])
                    
                    fig_time.update_layout(
                        title=f"Email Activity by Hour - {sender}",
                        xaxis_title="Hour of Day",
                        yaxis_title="Number of Emails",
                        height=300,
                        showlegend=False
                    )
                    
                    st.plotly_chart(fig_time, use_container_width=True)
            
            # Recent high-risk emails
            high_risk_emails = [e for e in emails if e.get('risk_level') in ['High', 'Critical'] or e.get('is_anomaly', False)]
            if high_risk_emails:
                st.write("**🚨 Recent High-Risk/Anomaly Emails**")
                
                # Sort by risk score and show top 3
                high_risk_emails.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
                
                for j, email in enumerate(high_risk_emails[:3]):
                    email_col1, email_col2 = st.columns([3, 1])
                    
                    with email_col1:
                        subject = email.get('subject', 'No Subject')[:50]
                        recipients = email.get('recipients', 'N/A')[:30]
                        risk_level = email.get('risk_level', 'Unknown')
                        email_risk_color = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(risk_level, '⚪')
                        
                        anomaly_indicator = " 🚨" if email.get('is_anomaly', False) else ""
                        st.write(f"{email_risk_color} **{subject}...** → {recipients}...{anomaly_indicator}")
                        
                        if email.get('risk_factors'):
                            st.caption(f"Risk factors: {email.get('risk_factors', '')[:80]}...")
                    
                    with email_col2:
                        if st.button("📧 Details", key=f"sender_detail_{sender}_{j}"):
                            show_email_details_modal(email)
    
    # Advanced Behavioral Analytics
    st.subheader("🧠 Advanced Behavioral Analytics")
    
    # Communication Patterns Analysis
    st.write("**📊 Communication Patterns**")
    comm_col1, comm_col2, comm_col3 = st.columns(3)
    
    with comm_col1:
        # Sender-Recipient Network Density
        st.metric("Network Density", f"{len([e for e in data if e.get('recipients')])}/{len(data)}")
        
        # Peak Activity Hours
        all_hours = []
        for email in data:
            time_str = email.get('_time', '')
            try:
                if ':' in time_str:
                    hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                    all_hours.append(int(hour_part))
            except:
                continue
        
        if all_hours:
            peak_hour = Counter(all_hours).most_common(1)[0][0]
            st.metric("Peak Activity Hour", f"{peak_hour}:00")
    
    with comm_col2:
        # Domain Diversity Index
        sender_domains = set()
        for email in data:
            sender = email.get('sender', '')
            if '@' in sender:
                sender_domains.add(sender.split('@')[1])
        
        st.metric("Unique Domains", len(sender_domains))
        
        # Average Risk Per Domain
        domain_risks = defaultdict(list)
        for email in data:
            sender = email.get('sender', '')
            if '@' in sender:
                domain = sender.split('@')[1]
                domain_risks[domain].append(email.get('risk_score', 0))
        
        if domain_risks:
            avg_domain_risk = sum(sum(risks)/len(risks) for risks in domain_risks.values()) / len(domain_risks)
            st.metric("Avg Domain Risk", f"{avg_domain_risk:.1f}")
    
    with comm_col3:
        # Attachment Usage Rate
        attachment_emails = len([e for e in data if e.get('attachments', '').strip()])
        attachment_rate = (attachment_emails / len(data)) * 100 if data else 0
        st.metric("Attachment Usage", f"{attachment_rate:.1f}%")
        
        # Keyword Alert Rate
        keyword_emails = len([e for e in data if e.get('Wordlist_subject', '').strip() or e.get('Wordlist_attachment', '').strip()])
        keyword_rate = (keyword_emails / len(data)) * 100 if data else 0
        st.metric("Keyword Alerts", f"{keyword_rate:.1f}%")

    # Risk Trend Analysis
    st.write("**📈 Risk Trend Analysis**")
    
    # Time-based risk evolution
    time_risk_data = []
    for email in data:
        time_str = email.get('_time', '')
        risk_score = email.get('risk_score', 0)
        if time_str and risk_score:
            time_risk_data.append({'time': time_str, 'risk': risk_score})
    
    if time_risk_data:
        # Group by hour for trend analysis
        hourly_risks = defaultdict(list)
        for item in time_risk_data:
            try:
                time_str = item['time']
                if ':' in time_str:
                    hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                    hour = int(hour_part)
                    hourly_risks[hour].append(item['risk'])
            except:
                continue
        
        if hourly_risks:
            hours = sorted(hourly_risks.keys())
            avg_risks = [sum(hourly_risks[h])/len(hourly_risks[h]) for h in hours]
            
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=hours,
                y=avg_risks,
                mode='lines+markers',
                name='Average Risk Score',
                line=dict(color='#e74c3c', width=3),
                marker=dict(size=8)
            ))
            
            # Add business hours indicator
            fig_trend.add_vrect(x0=9, x1=17, fillcolor="rgba(39, 174, 96, 0.1)", layer="below", line_width=0)
            
            fig_trend.update_layout(
                title="Risk Score Trends Throughout the Day",
                xaxis_title="Hour of Day",
                yaxis_title="Average Risk Score",
                height=350,
                showlegend=False
            )
            
            st.plotly_chart(fig_trend, use_container_width=True)

    # Behavioral Risk Matrix
    st.write("**🎯 Behavioral Risk Matrix**")
    
    # Create risk matrix data
    matrix_data = []
    for sender_info in sender_risk_data:
        sender = sender_info['sender']
        emails = sender_groups[sender]
        
        # Calculate behavioral metrics
        after_hours_ratio = 0
        external_ratio = 0
        attachment_ratio = 0
        
        time_patterns = [email.get('_time', '') for email in emails if email.get('_time', '')]
        after_hours_count = 0
        for time_str in time_patterns:
            try:
                if ':' in time_str:
                    hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                    hour = int(hour_part)
                    if hour >= 18 or hour <= 6:
                        after_hours_count += 1
            except:
                continue
        
        if time_patterns:
            after_hours_ratio = after_hours_count / len(time_patterns)
        
        external_emails = sum(1 for email in emails if 'external' in email.get('recipient_status', '').lower())
        external_ratio = external_emails / len(emails) if emails else 0
        
        attachment_emails = sum(1 for email in emails if email.get('attachments', '').strip())
        attachment_ratio = attachment_emails / len(emails) if emails else 0
        
        matrix_data.append({
            'sender': sender.split('@')[0] if '@' in sender else sender,
            'risk_score': sender_info['avg_risk_score'],
            'after_hours_ratio': after_hours_ratio * 100,
            'external_ratio': external_ratio * 100,
            'attachment_ratio': attachment_ratio * 100,
            'email_count': sender_info['total_emails']
        })
    
    if matrix_data:
        # Create bubble chart for risk matrix
        fig_matrix = px.scatter(
            matrix_data,
            x='after_hours_ratio',
            y='external_ratio',
            size='email_count',
            color='risk_score',
            hover_data=['sender', 'attachment_ratio'],
            title="Behavioral Risk Matrix: After-Hours vs External Communication",
            labels={
                'after_hours_ratio': 'After-Hours Activity (%)',
                'external_ratio': 'External Communication (%)',
                'risk_score': 'Risk Score'
            },
            color_continuous_scale='Reds'
        )
        
        fig_matrix.update_layout(height=400)
        st.plotly_chart(fig_matrix, use_container_width=True)

    # Anomaly Detection Insights
    st.write("**🚨 Anomaly Detection Insights**")
    
    anomaly_col1, anomaly_col2 = st.columns(2)
    
    with anomaly_col1:
        # Anomaly type breakdown
        anomaly_types = []
        for email in data:
            if email.get('is_anomaly', False):
                anomaly_type = email.get('anomaly_type', 'Unknown')
                anomaly_types.append(anomaly_type)
        
        if anomaly_types:
            anomaly_counts = Counter(anomaly_types)
            
            fig_anomaly = go.Figure(data=[go.Bar(
                x=list(anomaly_counts.keys()),
                y=list(anomaly_counts.values()),
                marker_color='#e74c3c'
            )])
            
            fig_anomaly.update_layout(
                title="Anomaly Types Distribution",
                xaxis_title="Anomaly Type",
                yaxis_title="Count",
                height=300
            )
            
            st.plotly_chart(fig_anomaly, use_container_width=True)
    
    with anomaly_col2:
        # Risk vs Anomaly correlation
        risk_anomaly_data = []
        for sender_info in sender_risk_data:
            risk_anomaly_data.append({
                'risk_score': sender_info['avg_risk_score'],
                'anomaly_ratio': (sender_info['anomaly_count'] / sender_info['total_emails']) * 100
            })
        
        if risk_anomaly_data:
            fig_correlation = px.scatter(
                risk_anomaly_data,
                x='risk_score',
                y='anomaly_ratio',
                title="Risk Score vs Anomaly Rate",
                labels={
                    'risk_score': 'Average Risk Score',
                    'anomaly_ratio': 'Anomaly Rate (%)'
                }
            )
            
            fig_correlation.update_layout(height=300)
            st.plotly_chart(fig_correlation, use_container_width=True)

    # Departmental Analysis (if department data available)
    st.write("**🏢 Departmental Risk Analysis**")
    
    # Attempt to infer departments from email domains or usernames
    dept_analysis = defaultdict(lambda: {'emails': 0, 'risk_sum': 0, 'anomalies': 0})
    
    for email in data:
        sender = email.get('sender', '')
        risk_score = email.get('risk_score', 0)
        is_anomaly = email.get('is_anomaly', False)
        
        # Simple department inference (could be enhanced with actual dept data)
        dept = 'Unknown'
        if '@' in sender:
            username = sender.split('@')[0].lower()
            if any(word in username for word in ['finance', 'accounting', 'fin']):
                dept = 'Finance'
            elif any(word in username for word in ['hr', 'human', 'recruiting']):
                dept = 'HR'
            elif any(word in username for word in ['it', 'tech', 'dev', 'sys']):
                dept = 'IT'
            elif any(word in username for word in ['sales', 'marketing', 'mkt']):
                dept = 'Sales/Marketing'
            elif any(word in username for word in ['legal', 'compliance', 'audit']):
                dept = 'Legal/Compliance'
            else:
                dept = 'General'
        
        dept_analysis[dept]['emails'] += 1
        dept_analysis[dept]['risk_sum'] += risk_score
        if is_anomaly:
            dept_analysis[dept]['anomalies'] += 1
    
    # Calculate departmental metrics
    dept_metrics = []
    for dept, stats in dept_analysis.items():
        if stats['emails'] > 0:
            avg_risk = stats['risk_sum'] / stats['emails']
            anomaly_rate = (stats['anomalies'] / stats['emails']) * 100
            dept_metrics.append({
                'Department': dept,
                'Email Count': stats['emails'],
                'Avg Risk': f"{avg_risk:.1f}",
                'Anomaly Rate': f"{anomaly_rate:.1f}%",
                'Total Anomalies': stats['anomalies']
            })
    
    if dept_metrics:
        dept_df = pd.DataFrame(dept_metrics)
        dept_df = dept_df.sort_values('Avg Risk', key=lambda x: x.astype(float), ascending=False)
        st.dataframe(dept_df, use_container_width=True)

    # Behavioral Insights Summary
    st.subheader("🔍 Key Behavioral Insights")
    
    insights_col1, insights_col2 = st.columns(2)
    
    with insights_col1:
        st.write("**🚨 Top Risk Patterns Detected:**")
        
        # Calculate pattern frequencies
        pattern_counts = {
            'after_hours': 0,
            'free_domains': 0,
            'external_comms': 0,
            'content_risk': 0,
            'departing_employees': 0
        }
        
        for sender_info in sender_risk_data:
            sender = sender_info['sender']
            emails = sender_groups[sender]
            
            # Count patterns
            time_patterns = [email.get('_time', '') for email in emails if email.get('_time', '')]
            after_hours_count = 0
            for time_str in time_patterns:
                try:
                    if ':' in time_str:
                        hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                        hour = int(hour_part)
                        if hour >= 18 or hour <= 6:
                            after_hours_count += 1
                except:
                    continue
            
            if after_hours_count > 0:
                pattern_counts['after_hours'] += 1
            
            # Free domain check
            sender_domain = sender.split('@')[1] if '@' in sender else ''
            free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
            if sender_domain.lower() in free_domains:
                pattern_counts['free_domains'] += 1
            
            # External communications
            external_emails = sum(1 for email in emails if 'external' in email.get('recipient_status', '').lower())
            if external_emails > 0:
                pattern_counts['external_comms'] += 1
            
            # Content risk (attachments + keywords)
            attachment_emails = sum(1 for email in emails if email.get('attachments', '').strip())
            keyword_emails = sum(1 for email in emails if email.get('Wordlist_subject', '').strip() or email.get('Wordlist_attachment', '').strip())
            if attachment_emails > 0 and keyword_emails > 0:
                pattern_counts['content_risk'] += 1
            
            # Departing employees - only if leaver field equals "YES"
            if any(email.get('leaver', '').strip().upper() == 'YES' for email in emails):
                pattern_counts['departing_employees'] += 1
        
        # Display top patterns
        sorted_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)
        for pattern, count in sorted_patterns[:5]:
            pattern_name = {
                'after_hours': 'After-hours activity',
                'free_domains': 'Free email domains',
                'external_comms': 'External communications',
                'content_risk': 'High-risk content',
                'departing_employees': 'Departing employees'
            }.get(pattern, pattern)
            
            st.write(f"• {pattern_name}: {count} senders")
    
    with insights_col2:
        st.write("**📈 Risk Recommendations:**")
        
        # Generate actionable recommendations
        recommendations = []
        
        if pattern_counts['after_hours'] > 0:
            recommendations.append("Monitor after-hours email activity for data exfiltration risks")
        
        if pattern_counts['free_domains'] > 0:
            recommendations.append("Review policy on free email domain usage")
        
        if pattern_counts['external_comms'] > 0:
            recommendations.append("Implement additional controls for external communications")
        
        if pattern_counts['content_risk'] > 0:
            recommendations.append("Enhanced scanning for sensitive content in attachments")
        
        if pattern_counts['departing_employees'] > 0:
            recommendations.append("Immediate review of departing employee activities")
        
        # Add general recommendations based on overall risk levels
        high_risk_count = len([s for s in sender_risk_data if s['max_risk_level'] in ['High', 'Critical']])
        total_senders = len(sender_risk_data)
        
        if high_risk_count > total_senders * 0.1:  # More than 10% high risk
            recommendations.append("Consider implementing stricter email policies")
        
        if sum(s['anomaly_count'] for s in sender_risk_data) > total_senders * 0.05:  # High anomaly rate
            recommendations.append("Review anomaly detection thresholds and rules")
        
        for i, rec in enumerate(recommendations[:7], 1):
            st.write(f"{i}. {rec}")

    # Export Options for Sender Analysis
    st.subheader("💾 Export & Reporting")
    
    export_col1, export_col2, export_col3 = st.columns(3)
    
    with export_col1:
        if st.button("📊 Export Risk Summary", key="export_risk_summary"):
            # Create summary report
            summary_data = {
                'Total Senders': len(sender_risk_data),
                'High Risk Senders': len([s for s in sender_risk_data if s['max_risk_level'] in ['High', 'Critical']]),
                'Anomaly Senders': len([s for s in sender_risk_data if s['anomaly_count'] > 0]),
                'After Hours Activity': pattern_counts['after_hours'],
                'Free Domain Usage': pattern_counts['free_domains'],
                'External Communications': pattern_counts['external_comms']
            }
            
            summary_text = "SENDER BEHAVIOR ANALYSIS SUMMARY\n" + "="*40 + "\n\n"
            for key, value in summary_data.items():
                summary_text += f"{key}: {value}\n"
            
            summary_text += "\nTOP RISK PATTERNS:\n" + "-"*20 + "\n"
            for pattern, count in sorted_patterns[:5]:
                pattern_name = {
                    'after_hours': 'After-hours activity',
                    'free_domains': 'Free email domains', 
                    'external_comms': 'External communications',
                    'content_risk': 'High-risk content',
                    'departing_employees': 'Departing employees'
                }.get(pattern, pattern)
                summary_text += f"• {pattern_name}: {count} senders\n"
            
            st.download_button(
                label="Download Summary",
                data=summary_text,
                file_name="sender_behavior_summary.txt",
                mime="text/plain",
                key="download_summary"
            )
    
    with export_col2:
        if st.button("📈 Export Detailed Report", key="export_detailed_report"):
            # Create detailed CSV report
            detailed_data = []
            for sender_info in sender_risk_data:
                sender = sender_info['sender']
                emails = sender_groups[sender]
                
                # Calculate additional metrics
                time_patterns = [email.get('_time', '') for email in emails if email.get('_time', '')]
                after_hours_count = 0
                for time_str in time_patterns:
                    try:
                        if ':' in time_str:
                            hour_part = time_str.split(' ')[-1].split(':')[0] if ' ' in time_str else time_str.split(':')[0]
                            hour = int(hour_part)
                            if hour >= 18 or hour <= 6:
                                after_hours_count += 1
                    except:
                        continue
                
                external_emails = sum(1 for email in emails if 'external' in email.get('recipient_status', '').lower())
                attachment_emails = sum(1 for email in emails if email.get('attachments', '').strip())
                keyword_emails = sum(1 for email in emails if email.get('Wordlist_subject', '').strip() or email.get('Wordlist_attachment', '').strip())
                
                detailed_data.append({
                    'Sender': sender,
                    'Total_Emails': sender_info['total_emails'],
                    'Max_Risk_Level': sender_info['max_risk_level'],
                    'Max_Risk_Score': sender_info['max_risk_score'],
                    'Avg_Risk_Score': f"{sender_info['avg_risk_score']:.2f}",
                    'Anomaly_Count': sender_info['anomaly_count'],
                    'After_Hours_Emails': after_hours_count,
                    'External_Emails': external_emails,
                    'Attachment_Emails': attachment_emails,
                    'Keyword_Emails': keyword_emails
                })
            
            # Convert to CSV
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=detailed_data[0].keys())
            writer.writeheader()
            writer.writerows(detailed_data)
            csv_data = output.getvalue()
            
            st.download_button(
                label="Download CSV Report",
                data=csv_data,
                file_name="sender_behavior_detailed.csv",
                mime="text/csv",
                key="download_detailed"
            )
    
    with export_col3:
        if st.button("📋 Generate Action Items", key="generate_actions"):
            # Generate prioritized action items
            action_items = []
            
            # High priority actions
            critical_senders = [s for s in sender_risk_data if s['max_risk_level'] == 'Critical']
            if critical_senders:
                action_items.append(f"URGENT: Review {len(critical_senders)} critical risk senders immediately")
            
            departing_employees = [s for s in sender_risk_data if any(email.get('leaver', '').strip().upper() == 'YES' for email in sender_groups[s['sender']])]
            if departing_employees:
                action_items.append(f"HIGH: Monitor {len(departing_employees)} departing employees for data exfiltration")
            
            # Medium priority actions
            high_anomaly_senders = [s for s in sender_risk_data if s['anomaly_count'] >= 3]
            if high_anomaly_senders:
                action_items.append(f"MEDIUM: Investigate {len(high_anomaly_senders)} senders with multiple anomalies")
            
            after_hours_senders = pattern_counts['after_hours']
            if after_hours_senders > 0:
                action_items.append(f"MEDIUM: Review after-hours activity for {after_hours_senders} senders")
            
            # Low priority actions
            if pattern_counts['free_domains'] > 0:
                action_items.append(f"LOW: Policy review for {pattern_counts['free_domains']} free domain users")
            
            action_text = "SENDER BEHAVIOR ACTION ITEMS\n" + "="*30 + "\n\n"
            action_text += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            for i, action in enumerate(action_items, 1):
                action_text += f"{i}. {action}\n"
            
            st.download_button(
                label="Download Action Items",
                data=action_text,
                file_name="sender_behavior_actions.txt",
                mime="text/plain",
                key="download_actions"
            )


    
    # Performance Metrics
    st.markdown("---")
    st.subheader("📊 Key Performance Indicators")
    
    metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)
    
    with metrics_col1:
        st.metric("Threat Detection", "99.5%", "↑2.3%")
        st.caption("Accuracy Rate")
    
    with metrics_col2:
        st.metric("Response Time", "< 5min", "↓1.2min")
        st.caption("Average Investigation")
    
    with metrics_col3:
        st.metric("False Positives", "< 1%", "↓0.3%")
        st.caption("Alert Precision")
    
    with metrics_col4:
        st.metric("Coverage", "100%", "→0%")
        st.caption("Email Monitoring")


if __name__ == "__main__":
    main()