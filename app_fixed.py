import streamlit as st
import json
import io
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

def detect_anomalies(email_data):
    """Detect anomalies in email behavior"""
    is_anomaly = False
    anomaly_reasons = []
    anomaly_score = 0
    anomaly_type = 'None'

    # Check for time-based anomalies (after hours)
    time_str = email_data.get('time', '')
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
    recipients = email_data.get('recipients', '')
    if recipients:
        recipient_count = len([r.strip() for r in recipients.split(',') if r.strip()])
        if recipient_count > 10:
            is_anomaly = True
            anomaly_reasons.append(f'Unusual high recipient count ({recipient_count})')
            anomaly_score += 0.4
            anomaly_type = 'Behavioral'

    # Check for content anomalies (sensitive keywords + attachments)
    has_keywords = email_data.get('word_list_match', '').strip()
    has_attachments = email_data.get('attachments', '').strip()
    if has_keywords and has_attachments:
        is_anomaly = True
        anomaly_reasons.append('Combination of sensitive keywords and attachments')
        anomaly_score += 0.5
        anomaly_type = 'Content'

    # Check for departing employee anomaly
    last_working_day = email_data.get('last_working_day', '')
    if last_working_day and last_working_day.strip():
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

    # High-risk combination anomaly
    if (last_working_day and has_attachments and has_keywords and sender_domain in free_domains):
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

def network_analysis_page():
    """Interactive network analysis page with field selection and visualization"""
    st.header("🔗 Network Analysis")

    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload data first in the Data Upload section.")
        return

    data = st.session_state.processed_data

    # Automatically detect available columns
    if data:
        available_fields = list(data[0].keys())
        st.subheader("📊 Available Fields")

        # Filter out internal fields and show user-friendly field names
        display_fields = [field for field in available_fields if not field.startswith('_')]

        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Total Fields:** {len(display_fields)}")
            st.write("**Available Fields:**")
            for field in display_fields[:10]:  # Show first 10 fields
                sample_value = str(data[0].get(field, 'N/A'))[:30]
                st.write(f"• `{field}`: {sample_value}...")

        with col2:
            if len(display_fields) > 10:
                st.write("**Additional Fields:**")
                for field in display_fields[10:]:
                    sample_value = str(data[0].get(field, 'N/A'))[:30]
                    st.write(f"• `{field}`: {sample_value}...")

    st.markdown("---")

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
            pos = nx.spring_layout(G, k=3.0, iterations=200, seed=42)
        
        # Scale positions for better spacing
        scaling_factor = 4.0
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
    """Create professional interactive network figure with enhanced styling"""
    fig = go.Figure()
    
    # Professional edge styling with gradients and transparency
    edge_traces = []
    edge_weights = []
    
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        weight = G[edge[0]][edge[1]].get('weight', 1)
        count = G[edge[0]][edge[1]].get('count', 1)
        edge_weights.append(weight)
        
        # Determine edge color based on communities and weight
        if communities and edge[0] in communities and edge[1] in communities:
            if communities[edge[0]]['id'] == communities[edge[1]]['id']:
                # Same community - use community color with transparency
                base_color = communities[edge[0]]['color']
                edge_color = f"rgba({int(base_color[1:3], 16)}, {int(base_color[3:5], 16)}, {int(base_color[5:7], 16)}, {0.3 + weight * 0.3})"
            else:
                # Different communities - neutral color
                edge_color = f"rgba(99, 110, 114, {0.2 + weight * 0.2})"
        else:
            edge_color = f"rgba(99, 110, 114, {0.2 + weight * 0.2})"
        
        # Calculate edge width based on weight
        edge_width = max(0.5, min(6.0, weight * config.get('edge_width', 1.0) + 0.5))
        
        # Create individual edge trace for better control
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode='lines',
            line=dict(
                width=edge_width,
                color=edge_color,
                shape='spline',
                smoothing=0.3
            ),
            hovertemplate=f"<b>Connection</b><br>{edge[0]} ↔ {edge[1]}<br><b>Weight:</b> {weight}<br><b>Messages:</b> {count}<extra></extra>",
            showlegend=False,
            name=f'edge_{edge[0]}_{edge[1]}'
        ))

    # Professional nodes with enhanced interactivity and styling
    show_labels = config.get('show_labels', True)
    show_centrality = config.get('show_centrality', False)
    node_size_multiplier = config.get('node_size_multiplier', 1.0)
    
    # Normalize metrics for better visualization
    if node_metrics:
        max_metric = max(node_metrics.values()) if node_metrics.values() else 1
        min_metric = min(node_metrics.values()) if node_metrics.values() else 0
        metric_range = max_metric - min_metric if max_metric != min_metric else 1

    # Create separate traces for different node types for better interaction
    high_risk_nodes = {'x': [], 'y': [], 'text': [], 'info': [], 'size': [], 'ids': []}
    community_nodes = {}
    normal_nodes = {'x': [], 'y': [], 'text': [], 'info': [], 'size': [], 'color': [], 'ids': []}

    for node in G.nodes():
        x, y = pos[node]
        adjacencies = list(G.neighbors(node))
        node_metadata = node_data.get(node, {'risk_scores': [], 'anomalies': 0, 'emails': []})
        
        avg_risk = sum(node_metadata['risk_scores']) / len(node_metadata['risk_scores']) if node_metadata['risk_scores'] else 0
        total_emails = len(node_metadata['emails'])
        anomaly_count = node_metadata['anomalies']
        centrality_value = node_metrics.get(node, 0)
        community_info = communities.get(node, {'id': 0, 'color': '#45B7D1'})
        
        # Professional hover template with rich formatting
        hover_text = f"""
        <b style="font-size: 18px; color: #2c3e50; text-shadow: 1px 1px 2px rgba(0,0,0,0.1);">{node}</b><br>
        <div style="background: linear-gradient(135deg, #f8f9fa, #e9ecef); padding: 8px; border-radius: 6px; margin: 4px 0;">
        <span style="color: #8e44ad; font-weight: bold;">🏘️ Community:</span> <span style="color: {community_info['color']}; font-weight: bold;">Group {community_info['id']}</span><br>
        <span style="color: #27ae60; font-weight: bold;">⭐ Centrality:</span> <span style="color: #2c3e50;">{centrality_value:.3f}</span><br>
        <span style="color: #3498db; font-weight: bold;">🔗 Connections:</span> <span style="color: #2c3e50;">{len(adjacencies)}</span><br>
        <span style="color: #34495e; font-weight: bold;">📧 Total Emails:</span> <span style="color: #2c3e50;">{total_emails}</span><br>
        <span style="color: #e74c3c; font-weight: bold;">⚠️ Risk Score:</span> <span style="color: #2c3e50;">{avg_risk:.1f}</span><br>
        <span style="color: #e67e22; font-weight: bold;">🚨 Anomalies:</span> <span style="color: #2c3e50;">{anomaly_count}</span><br>
        </div>
        <span style="color: #95a5a6; font-size: 12px;">Click to analyze • Drag to reposition</span>
        """.strip()

        # Enhanced node labeling
        if show_labels:
            label = str(node)[:15] + "..." if len(str(node)) > 15 else str(node)
            if show_centrality:
                label += f"\n★{centrality_value:.2f}"
        else:
            label = ""

        # Advanced node size with minimum and maximum bounds
        if node_metrics and max_metric > 0:
            normalized_metric = (centrality_value - min_metric) / metric_range
            base_size = 30 + normalized_metric * 50
        else:
            base_size = 40
        
        final_size = max(25, min(80, base_size * node_size_multiplier))

        # Categorize nodes for different traces
        if anomaly_count > 0:
            # High risk/anomaly nodes
            high_risk_nodes['x'].append(x)
            high_risk_nodes['y'].append(y)
            high_risk_nodes['text'].append(label)
            high_risk_nodes['info'].append(hover_text)
            high_risk_nodes['size'].append(final_size + 5)
            high_risk_nodes['ids'].append(node)
        elif communities and node in communities:
            # Community-based nodes
            comm_id = community_info['id']
            if comm_id not in community_nodes:
                community_nodes[comm_id] = {
                    'x': [], 'y': [], 'text': [], 'info': [], 'size': [], 
                    'color': community_info['color'], 'ids': []
                }
            community_nodes[comm_id]['x'].append(x)
            community_nodes[comm_id]['y'].append(y)
            community_nodes[comm_id]['text'].append(label)
            community_nodes[comm_id]['info'].append(hover_text)
            community_nodes[comm_id]['size'].append(final_size)
            community_nodes[comm_id]['ids'].append(node)
        else:
            # Normal nodes
            normal_nodes['x'].append(x)
            normal_nodes['y'].append(y)
            normal_nodes['text'].append(label)
            normal_nodes['info'].append(hover_text)
            normal_nodes['size'].append(final_size)
            normal_nodes['ids'].append(node)
            if avg_risk > 70:
                normal_nodes['color'].append('#e67e22')
            elif avg_risk > 40:
                normal_nodes['color'].append('#f39c12')
            else:
                normal_nodes['color'].append('#3498db')

    # Add high-risk nodes with special styling
    if high_risk_nodes['x']:
        fig.add_trace(go.Scatter(
            x=high_risk_nodes['x'], y=high_risk_nodes['y'],
            mode='markers+text' if show_labels else 'markers',
            text=high_risk_nodes['text'],
            hovertemplate='%{hovertext}<extra></extra>',
            hovertext=high_risk_nodes['info'],
            textposition="middle center",
            textfont=dict(size=11, color='white', family='Arial Black'),
            marker=dict(
                color='#e74c3c',
                size=high_risk_nodes['size'],
                line=dict(width=3, color='rgba(231, 76, 60, 0.8)'),
                opacity=0.95,
                symbol='diamond',
                sizemode='diameter'
            ),
            name='High Risk Nodes',
            customdata=high_risk_nodes['ids']
        ))

    # Add community-based nodes
    for comm_id, comm_data in community_nodes.items():
        if comm_data['x']:
            fig.add_trace(go.Scatter(
                x=comm_data['x'], y=comm_data['y'],
                mode='markers+text' if show_labels else 'markers',
                text=comm_data['text'],
                hovertemplate='%{hovertext}<extra></extra>',
                hovertext=comm_data['info'],
                textposition="middle center",
                textfont=dict(size=10, color='white', family='Arial Black'),
                marker=dict(
                    color=comm_data['color'],
                    size=comm_data['size'],
                    line=dict(width=2, color='rgba(255,255,255,0.9)'),
                    opacity=0.9,
                    sizemode='diameter'
                ),
                name=f'Community {comm_id}',
                customdata=comm_data['ids']
            ))

    # Add normal nodes
    if normal_nodes['x']:
        fig.add_trace(go.Scatter(
            x=normal_nodes['x'], y=normal_nodes['y'],
            mode='markers+text' if show_labels else 'markers',
            text=normal_nodes['text'],
            hovertemplate='%{hovertext}<extra></extra>',
            hovertext=normal_nodes['info'],
            textposition="middle center",
            textfont=dict(size=10, color='white', family='Arial Black'),
            marker=dict(
                color=normal_nodes['color'],
                size=normal_nodes['size'],
                line=dict(width=2, color='rgba(255,255,255,0.9)'),
                opacity=0.85,
                sizemode='diameter'
            ),
            name='Other Nodes',
            customdata=normal_nodes['ids']
        ))

    # Enhanced layout with community legend
    zoom_level = config.get('zoom_level', 1.0)
    
    # Create community legend if communities exist
    legend_text = ""
    if communities:
        community_counts = {}
        for node, comm_info in communities.items():
            comm_id = comm_info['id']
            community_counts[comm_id] = community_counts.get(comm_id, 0) + 1
        
        legend_text = "<b>Communities</b><br>" + "<br>".join([
            f"<span style='color:{community_colors[i % len(community_colors)]};'>● Community {i}</span> ({count} nodes)" 
            for i, count in community_counts.items()
        ])

    # Professional layout with enhanced styling
    zoom_level = config.get('zoom_level', 1.0)
    
    fig.update_layout(
        title=dict(
            text=f"<b style='color: #2c3e50; text-shadow: 2px 2px 4px rgba(0,0,0,0.1);'>Professional Network Analysis</b><br><sub style='color: #7f8c8d;'>{source_field} → {target_field} • Interactive Communities • Advanced Metrics</sub>",
            x=0.5,
            y=0.95,
            font=dict(size=20, family='Arial Black')
        ),
        showlegend=True,
        legend=dict(
            x=0.02, y=0.98,
            bgcolor='rgba(255,255,255,0.9)',
            bordercolor='#bdc3c7',
            borderwidth=1,
            font=dict(size=10)
        ),
        hovermode='closest',
        margin=dict(b=60, l=40, r=40, t=120),
        annotations=[
            dict(
                text=f"""<b style='color: #2c3e50;'>📊 Network Overview</b><br>
                <span style='color: #34495e;'>🔸 <b>{len(G.nodes())}</b> nodes • <b>{len(G.edges())}</b> connections</span><br>
                <span style='color: #8e44ad;'>🏘️ <b>{len(set(c['id'] for c in communities.values())) if communities else 0}</b> communities detected</span><br>
                <span style='color: #27ae60;'>⚙️ Layout: <b>{config['layout'].replace('_', ' ').title()}</b></span><br>
                <span style='color: #e67e22;'>📏 Metric: <b>{config['node_size_metric'].replace('_', ' ').title()}</b></span><br>
                <br><span style='color: #95a5a6; font-size: 10px;'>💡 Click nodes to analyze • Drag to reposition • Use toolbar for advanced controls</span>""",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.02, y=0.02,
                xanchor='left', yanchor='bottom',
                font=dict(color='#2c3e50', size=11, family='Arial'),
                bgcolor='rgba(255,255,255,0.95)',
                bordercolor='#3498db',
                borderwidth=2,
                borderpad=10
            )
        ],
        xaxis=dict(
            showgrid=True, 
            gridcolor='rgba(189, 195, 199, 0.3)',
            gridwidth=1,
            zeroline=False, 
            showticklabels=False,
            range=[-zoom_level * 12, zoom_level * 12],
            fixedrange=False,
            scaleanchor="y",
            scaleratio=1
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor='rgba(189, 195, 199, 0.3)',
            gridwidth=1,
            zeroline=False, 
            showticklabels=False,
            range=[-zoom_level * 12, zoom_level * 12],
            fixedrange=False
        ),
        plot_bgcolor='rgba(248, 249, 250, 0.95)',
        paper_bgcolor='#ffffff',
        height=900,
        dragmode='pan',
        clickmode='event+select',
        transition=dict(duration=500, easing='cubic-in-out')
    )

    return fig

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
                showgrid=False, 
                zeroline=False, 
                showticklabels=False,
                range=[-zoom_level * 1.2, zoom_level * 1.2],
                fixedrange=False,
                scaleanchor="y",
                scaleratio=1
            ),
            yaxis=dict(
                showgrid=False, 
                zeroline=False, 
                showticklabels=False,
                range=[-zoom_level * 1.2, zoom_level * 1.2],
                fixedrange=False
            ),
            plot_bgcolor='#f8f9fa',
            paper_bgcolor='#ffffff',
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
                        st.write(f"**Time:** {record.get('time', 'N/A')}")
                        st.write(f"**Risk Score:** {record.get('risk_score', 0)}")
                    with col_b:
                        st.write(f"**Risk Level:** {record.get('risk_level', 'Unknown')}")
                        st.write(f"**Attachments:** {record.get('attachments', 'None')}")
                        if record.get('is_anomaly', False):
                            st.error("🚨 Anomaly Detected")

            if len(related_records) > 5:
                st.info(f"Showing 5 of {len(related_records)} related records")

def main():
    st.title("🛡️ ExfilEye - DLP Email Security Monitoring System")
    st.markdown("---")

    # Sidebar navigation
    with st.sidebar:
        st.header("📋 Navigation")
        page = st.selectbox(
            "Select Section:",
            ["📁 Data Upload", "📆 Daily Checks", "📨 Follow-up Center", "🔗 Network Analysis", "⚙️ Settings"]
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
    elif page == "🔗 Network Analysis":
        network_analysis_page()
    elif page == "⚙️ Settings":
        settings_page()

def data_upload_page():
    st.header("📁 Data Upload & Validation")

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

                # Process each email for risk scoring and anomaly detection
                processed_data = []
                for email in data:
                    risk_info = calculate_risk_score(email)
                    anomaly_info = detect_anomalies(email)
                    email.update(risk_info)
                    email.update(anomaly_info)
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

            else:
                st.error("❌ No valid data found in the uploaded file")

        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")



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

    # Risk Events by Sender with Tracking
    st.subheader("🎯 Risk Events (Grouped by Sender)")

    # Add tracking overview
    col_track1, col_track2, col_track3, col_track4 = st.columns(4)

    # Calculate tracking statistics
    total_senders = 0
    completed_senders = 0
    outstanding_senders = 0
    in_progress_senders = 0

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
    for sender, emails in sender_groups.items():
        total_senders += 1
        sender_status = st.session_state.sender_review_status.get(sender, 'outstanding')

        if sender_status == 'completed':
            completed_senders += 1
        elif sender_status == 'in_progress':
            in_progress_senders += 1
        else:
            outstanding_senders += 1

    # Display tracking metrics
    with col_track1:
        st.metric("📊 Total Senders", total_senders)
    with col_track2:
        st.metric("✅ Completed", completed_senders)
    with col_track3:
        st.metric("🔄 In Progress", in_progress_senders)
    with col_track4:
        st.metric("⏳ Outstanding", outstanding_senders)

    # Add filter options
    st.write("**Filter by Status:**")
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        status_filter = st.selectbox(
            "Show senders:",
            options=['All', 'Outstanding', 'In Progress', 'Completed'],
            index=0
        )
    with filter_col2:
        sort_by = st.selectbox(
            "Sort by:",
            options=['Risk Level', 'Status', 'Email Count'],
            index=0
        )

    # Sort senders by risk priority (Critical first)
    sorted_sender_groups = sorted(sender_groups.items(), 
                                 key=lambda x: get_sender_max_risk(x[1]), 
                                 reverse=True)

    # Apply status filter
    if status_filter != 'All':
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

        # Get current sender status
        current_status = st.session_state.sender_review_status.get(sender, 'outstanding')
        status_icons = {'outstanding': '⏳', 'in_progress': '🔄', 'completed': '✅'}
        status_icon = status_icons.get(current_status, '⏳')

        # Create sender title with status and anomaly indicator
        sender_title = f"{status_icon} {sender} - {len(emails)} emails - Risk: {max_risk_level} ({max_risk})"
        if has_anomalies:
            sender_title += f" 🚨 {anomaly_count} Anomalies"

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

        # Update sender title with new status
        sender_title = f"{status_icon} {sender} - {len(emails)} emails - Risk: {max_risk_level} ({max_risk})"
        if has_anomalies:
            sender_title += f" 🚨 {anomaly_count} Anomalies"

        with st.expander(sender_title):
            # Show automatic status info
            st.write(f"**Review Status:** {auto_status.title()} ({decided_count}/{sender_emails_count} emails reviewed)")
            st.markdown("---")
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
IT Security Team"""

    return {
        'subject': followup_subject,
        'body': email_body,
        'to': sender,
        'sender_name': sender_name
    }

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