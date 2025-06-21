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
                options=['spring', 'circular', 'random', 'shell'],
                index=0,
                help="Choose the network layout algorithm"
            )
            st.session_state.network_config['layout'] = layout_type
            
            node_size_metric = st.selectbox(
                "Node Size Based On:",
                options=['degree', 'betweenness', 'closeness', 'uniform'],
                help="Choose what determines node size"
            )
            st.session_state.network_config['node_size_metric'] = node_size_metric
        
        with col2:
            # Filters
            st.write("**Filters**")
            date_filter = st.checkbox("Enable Date Filter", help="Filter by date range if time field exists")
            
            if date_filter and 'time' in display_fields:
                st.date_input("Date Range", value=datetime.now().date())
            
            domain_filter = st.checkbox("Enable Domain Filter", help="Filter by specific domains")
            if domain_filter:
                domain_field = st.selectbox("Domain Field:", [f for f in display_fields if 'domain' in f.lower()])
    
    # Generate Network Button
    if st.button("🔗 Generate Network Graph", type="primary", key="generate_network_btn"):
        st.session_state.selected_node = None  # Reset selection
        st.session_state.show_network = True
    
    # Display network graph
    if st.session_state.get('show_network', False):
        st.session_state.show_network = True
        
        with st.spinner("Building network graph..."):
            network_graph = create_network_graph(data, source_field, target_field, st.session_state.network_config)
            if network_graph:
                # Enhanced clickable network with selection handling
                event = st.plotly_chart(
                    network_graph, 
                    use_container_width=True, 
                    on_select="rerun",
                    selection_mode="points",
                    key="network_chart"
                )
                
                # Node selection interface
                st.subheader("🎯 Node Interaction")
                
                # Manual node selection dropdown
                G = build_network_from_data(data, source_field, target_field)
                if len(G.nodes()) > 0:
                    all_nodes = sorted(list(G.nodes()))
                    
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        selected_node = st.selectbox(
                            "Click on a node in the graph above or select manually:",
                            options=["None"] + all_nodes,
                            index=0,
                            key="manual_node_select"
                        )
                    
                    with col2:
                        if selected_node != "None":
                            if st.button("🔍 Analyze Node", key="analyze_button"):
                                st.session_state.selected_node = selected_node
                                st.rerun()
                    
                    # Clear selection button
                    if st.session_state.selected_node:
                        if st.button("❌ Clear Selection", key="clear_selection_btn"):
                            st.session_state.selected_node = None
                            st.rerun()
                
                # Display selected node details
                if st.session_state.selected_node:
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
    """Create interactive network graph using Plotly and NetworkX"""
    try:
        # Build NetworkX graph
        G = nx.Graph()
        edge_weights = defaultdict(int)
        
        # Add edges from data
        for record in data:
            source = str(record.get(source_field, '')).strip()
            target_raw = str(record.get(target_field, '')).strip()
            
            if not source or not target_raw:
                continue
            
            # Handle multiple targets (comma-separated)
            targets = [t.strip() for t in target_raw.split(',') if t.strip()]
            
            for target in targets:
                if source != target:  # Avoid self-loops
                    edge_key = (source, target)
                    edge_weights[edge_key] += 1
                    
                    # Add weight from weight field if specified
                    weight = 1
                    if config.get('weight_field'):
                        try:
                            weight = float(record.get(config['weight_field'], 1))
                        except:
                            weight = 1
                    
                    G.add_edge(source, target, weight=weight, count=edge_weights[edge_key])
        
        if len(G.nodes()) == 0:
            st.error("No valid network connections found. Please check your field selections.")
            return None
        
        # Calculate layout positions
        if config['layout'] == 'spring':
            pos = nx.spring_layout(G, k=1, iterations=50)
        elif config['layout'] == 'circular':
            pos = nx.circular_layout(G)
        elif config['layout'] == 'shell':
            pos = nx.shell_layout(G)
        else:
            pos = nx.random_layout(G)
        
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
        
        # Create Plotly figure
        fig = go.Figure()
        
        # Add edges
        edge_x = []
        edge_y = []
        edge_info = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
            weight = G[edge[0]][edge[1]].get('weight', 1)
            count = G[edge[0]][edge[1]].get('count', 1)
            edge_info.append(f"Connection: {edge[0]} ↔ {edge[1]}<br>Weight: {weight}<br>Count: {count}")
        
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='rgba(125,125,125,0.5)'),
            hoverinfo='none',
            mode='lines',
            showlegend=False
        ))
        
        # Add nodes
        node_x = []
        node_y = []
        node_text = []
        node_info = []
        node_sizes = []
        node_colors = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            # Node information
            adjacencies = list(G.neighbors(node))
            node_info.append(f"Node: {node}<br>Connections: {len(adjacencies)}<br>Neighbors: {', '.join(adjacencies[:5])}")
            node_text.append(str(node))
            
            # Node size based on metric
            metric_value = node_metrics.get(node, 1)
            node_sizes.append(max(10, min(50, metric_value * 30)))
            
            # Node color based on degree
            degree = G.degree(node)
            node_colors.append(degree)
        
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            hovertext=node_info,
            text=node_text,
            textposition="middle center",
            marker=dict(
                showscale=True,
                colorscale='Viridis',
                reversescale=True,
                color=node_colors,
                size=node_sizes,
                colorbar=dict(
                    thickness=15,
                    len=0.5,
                    x=1.02,
                    title="Node Degree"
                ),
                line=dict(width=2, color='white')
            ),
            showlegend=False,
            customdata=node_text,  # Store node names for click handling
            selectedpoints=[]
        ))
        
        # Update layout for dark theme
        fig.update_layout(
            title=dict(
                text=f"Network Analysis: {source_field} → {target_field}",
                x=0.5,
                font=dict(size=20, color='white')
            ),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=60),
            annotations=[
                dict(
                    text=f"Nodes: {len(G.nodes())} | Edges: {len(G.edges())}",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(color='white', size=12)
                )
            ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0.8)',
            height=700
        )
        
        return fig
        
    except Exception as e:
        st.error(f"Error creating network graph: {str(e)}")
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