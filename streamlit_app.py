import streamlit as st
import pandas as pd
import concurrent.futures
import smtplib
import plotly.express as px
import csv
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import time
from dotenv import load_dotenv

# Import functions from the vulnerability scanner module
from vulnerability_scanner import (
    setup_database, 
    scan_source, 
    OEM_SOURCES, 
    get_vulnerabilities,
    add_recipient,
    get_recipients,
    delete_recipient,
    save_vulnerability_to_db as save_vulnerability
)

# Import AI integration functions
from gemini_integration import (
    analyze_single_vulnerability,
    batch_analyze_vulnerabilities,
    generate_mitigation_plan,
    get_vulnerability_explanation,
    prioritize_vulnerability_list,
    get_threat_intelligence
)

# Email configuration

# Load environment variables from .env file
load_dotenv()

# Email configuration from environment variables with fallbacks
EMAIL_CONFIG = {
    "sender_email": os.getenv("EMAIL_SENDER"),
    "smtp_server": os.getenv("SMTP_SERVER"),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "username": os.getenv("EMAIL_USERNAME"),
    "password": os.getenv("EMAIL_PASSWORD")
}

# Define sources with their configurations
SOURCES = {
    "NVD": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20",
        "type": "api",
        "description": "National Vulnerability Database - Official US government repository of vulnerability data"
    },
    "CISA": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "api",
        "description": "CISA Known Exploited Vulnerabilities Catalog - Actively exploited vulnerabilities"
    },
    "Microsoft Security": {
        "url": "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
        "type": "api",
        "description": "Microsoft Security Update Guide"
    },
    "Cisco": {
        "url": "https://tools.cisco.com/security/center/publicationListing.x",
        "type": "web",
        "description": "Cisco Security Advisories"
    },
     "IBM": {
        "url": "https://tools.cisco.com/security/center/publicationListing.x",
        "type": "web",
        "description": "IBM Security Advisories"
    },
    "Google": {
        "url": "https://cloud.google.com/support/bulletins",
        "type": "web",
        "description": "Google Cloud Security Bulletins"
    }
}

def format_vulnerability_for_email(vulnerability):
    """Format vulnerability details for email"""
    # Handle CISA-specific information
    is_cisa = vulnerability.get('oem_name') == 'CISA'
    
    # Helper function to safely handle strings for display in HTML
    def safe_str(value):
        if value is None:
            return 'N/A'
        if not isinstance(value, str):
            value = str(value)
        # Replace problematic HTML characters
        value = value.replace('<', '&lt;').replace('>', '&gt;')
        return value
    
    html = f'''
<tr>
  <td><strong>Product Name:</strong></td>
  <td>{safe_str(vulnerability.get('product_name', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>Product Version:</strong></td>
  <td>{safe_str(vulnerability.get('product_version', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>OEM Name:</strong></td>
  <td>{safe_str(vulnerability.get('oem_name', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>Severity Level:</strong></td>
  <td>{safe_str(vulnerability.get('severity_level', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>Vulnerability:</strong></td>
  <td>{safe_str(vulnerability.get('vulnerability_description', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>Mitigation Strategy:</strong></td>
  <td>{safe_str(vulnerability.get('mitigation_strategy', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>Published Date:</strong></td>
  <td>{safe_str(vulnerability.get('published_date', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>CVE ID:</strong></td>
  <td>{safe_str(vulnerability.get('cve_id', 'N/A'))}</td>
</tr>
<tr>
  <td><strong>Reference:</strong></td>
  <td><a href="{safe_str(vulnerability.get('url', '#'))}">{safe_str(vulnerability.get('url', 'N/A'))}</a></td>
</tr>'''

    # Add CISA-specific information if available
    if is_cisa:
        html += f'''
<tr>
  <td><strong>Source:</strong></td>
  <td>CISA Known Exploited Vulnerabilities Catalog</td>
</tr>
<tr>
  <td><strong>Status:</strong></td>
  <td>Actively Exploited in the Wild</td>
</tr>'''

    html += '''
<tr>
  <td colspan="2"><hr></td>
</tr>
'''
    return html

def send_email_notification(vulnerabilities, recipients, include_ai_insights=False):
    """Send email notification for new vulnerabilities"""
    if not vulnerabilities:
        st.info("No new vulnerabilities to notify about")
        return False
    
    if not recipients:
        st.warning("No recipients configured for email notifications")
        return False
    
    try:
        # Debug information
        st.info(f"Attempting to send email using SMTP server: {EMAIL_CONFIG['smtp_server']}")
        st.info(f"Using sender email: {EMAIL_CONFIG['sender_email']}")
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG["sender_email"]
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = f"CRITICAL/HIGH ALERT: {len(vulnerabilities)} New Vulnerability Notifications"
        
        # Clean vulnerability data to handle encoding issues
        cleaned_vulnerabilities = []
        for vuln in vulnerabilities:
            cleaned_vuln = {}
            for key, value in vuln.items():
                if isinstance(value, str):
                    # Replace problematic characters with their closest ASCII equivalents
                    cleaned_value = value.encode('ascii', 'replace').decode('ascii')
                    cleaned_vuln[key] = cleaned_value
                else:
                    cleaned_vuln[key] = value
            cleaned_vulnerabilities.append(cleaned_vuln)
        
        # Optionally enhance vulnerabilities with AI insights
        if include_ai_insights:
            st.info("Generating AI insights for email content...")
            # Limit to first 3 vulnerabilities to avoid overloading the API
            vulns_to_analyze = cleaned_vulnerabilities[:3]
            try:
                enhanced_vulns = batch_analyze_vulnerabilities(vulns_to_analyze)
                email_body = generate_ai_enhanced_email_content(enhanced_vulns, len(cleaned_vulnerabilities))
            except Exception as e:
                st.warning(f"Could not generate AI insights: {str(e)}. Falling back to standard email format.")
                email_body = generate_standard_email_content(cleaned_vulnerabilities)
        else:
            email_body = generate_standard_email_content(cleaned_vulnerabilities)
        
        # Attach HTML content
        msg.attach(MIMEText(email_body, 'html', 'utf-8'))
        
        # Export vulnerabilities to CSV and attach
        csv_file = "new_vulnerabilities.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'product_name', 'product_version', 'oem_name', 'severity_level',
                'vulnerability_description', 'mitigation_strategy', 'published_date',
                'cve_id', 'url'
            ])
            writer.writeheader()
            writer.writerows(cleaned_vulnerabilities)
        
        # Attach CSV file
        with open(csv_file, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{csv_file}"')
            msg.attach(part)
        
        # Connect to SMTP server and send email with detailed error handling
        try:
            st.info("Connecting to SMTP server...")
            server = smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"])
            server.set_debuglevel(1)  # Enable debug output
            
            st.info("Starting TLS...")
            server.starttls()
            
            st.info("Attempting login...")
            server.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
            
            st.info("Sending email...")
            server.send_message(msg)
            
            st.success(f"Email notification sent to {len(recipients)} recipients")
            
            # Clean up
            server.quit()
            os.remove(csv_file)
            return True
        
        except smtplib.SMTPAuthenticationError as e:
            st.error(f"""
            Gmail Authentication Error: {str(e)}
            
            Please check the following:
            1. Make sure you're using an App Password, not your regular Gmail password
            2. Verify that 2-Step Verification is enabled on your Google Account
            3. Check that the sender email matches the username ({EMAIL_CONFIG["username"]})
            4. Ensure there are no extra spaces in the email or password
            
            To get a new App Password:
            1. Go to https://myaccount.google.com/security
            2. Enable 2-Step Verification if not already enabled
            3. Go to App Passwords
            4. Generate a new app password for 'Mail'
            5. Copy the 16-character password and update it in the Settings
            """)
            return False
            
        except smtplib.SMTPException as e:
            st.error(f"""
            SMTP Error: {str(e)}
            
            Please check:
            1. SMTP server: {EMAIL_CONFIG["smtp_server"]}
            2. SMTP port: {EMAIL_CONFIG["smtp_port"]}
            3. Sender email: {EMAIL_CONFIG["sender_email"]}
            4. Network connectivity to the SMTP server
            """)
            return False
            
        except Exception as e:
            st.error(f"""
            Unexpected Error: {str(e)}
            
            Please check:
            1. Email configuration settings
            2. Internet connectivity
            3. Firewall settings that might block SMTP traffic
            """)
            return False
    
    except Exception as e:
        st.error(f"Error sending email notification: {str(e)}")
        return False

def generate_standard_email_content(vulnerabilities):
    """Generate standard email content without AI insights"""
    email_body = f'''
<html>
<head>
  <style>
    body {{ font-family: Arial, sans-serif; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td {{ padding: 8px; vertical-align: top; }}
    tr:nth-child(even) {{ background-color: #f2f2f2; }}
  </style>
</head>
<body>
  <h2>Critical/High Severity Vulnerability Alert</h2>
  <p>The following {len(vulnerabilities)} new critical or high severity vulnerabilities have been detected:</p>
  <table>
'''
    
    # Add each vulnerability to the email body
    for vuln in vulnerabilities:
        email_body += format_vulnerability_for_email(vuln)
    
    email_body += '''
  </table>
  <p>Please take immediate action to address these vulnerabilities.</p>
</body>
</html>
'''
    return email_body

def generate_ai_enhanced_email_content(enhanced_vulnerabilities, total_count):
    """Generate enhanced email content with AI insights"""
    email_body = f'''
<html>
<head>
  <style>
    body {{ font-family: Arial, sans-serif; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td {{ padding: 8px; vertical-align: top; }}
    tr:nth-child(even) {{ background-color: #f2f2f2; }}
    .ai-insights {{ background-color: #f0f7ff; padding: 15px; margin: 10px 0; border-left: 5px solid #0078d4; }}
    .ai-summary {{ font-style: italic; color: #333; }}
    .ai-impact {{ color: #d83b01; }}
    .ai-actions {{ color: #107c10; }}
  </style>
</head>
<body>
  <h2>AI-Enhanced Critical/High Severity Vulnerability Alert</h2>
  <p>The following {total_count} new critical or high severity vulnerabilities have been detected. 
  AI analysis has been provided for the most critical items below:</p>
'''
    
    # Add enhanced vulnerabilities with AI insights
    for vuln in enhanced_vulnerabilities:
        # Get AI insights if available
        ai_insights = vuln.get("ai_insights", {})
        has_insights = "error" not in ai_insights and ai_insights
        
        email_body += f'''
<div style="margin: 20px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
  <h3>{vuln.get('cve_id', 'Unknown CVE')} - {vuln.get('product_name', 'Unknown Product')}</h3>
  <table width="100%">
    <tr>
      <td width="150"><strong>Severity:</strong></td>
      <td>{vuln.get('severity_level', 'Unknown')}</td>
    </tr>
    <tr>
      <td><strong>Product:</strong></td>
      <td>{vuln.get('product_name', 'N/A')} {vuln.get('product_version', '')}</td>
    </tr>
    <tr>
      <td><strong>Vendor:</strong></td>
      <td>{vuln.get('oem_name', 'N/A')}</td>
    </tr>
    <tr>
      <td><strong>Published:</strong></td>
      <td>{vuln.get('published_date', 'N/A')}</td>
    </tr>
    <tr>
      <td><strong>Description:</strong></td>
      <td>{vuln.get('vulnerability_description', 'N/A')}</td>
    </tr>
'''

        # Add AI insights if available
        if has_insights:
            summary = ai_insights.get("summary", "No AI summary available")
            business_impact = ai_insights.get("business_impact", "No business impact analysis available")
            recommended_actions = ai_insights.get("recommended_actions", "No recommended actions available")
            
            email_body += f'''
    <tr>
      <td colspan="2">
        <div class="ai-insights">
          <h4>AI Analysis</h4>
          <p class="ai-summary"><strong>Summary:</strong> {summary}</p>
          <p class="ai-impact"><strong>Business Impact:</strong> {business_impact}</p>
          <p class="ai-actions"><strong>Recommended Actions:</strong> {recommended_actions}</p>
        </div>
      </td>
    </tr>
'''
        
        email_body += f'''
    <tr>
      <td><strong>Reference:</strong></td>
      <td><a href="{vuln.get('url', '#')}">{vuln.get('url', 'N/A')}</a></td>
    </tr>
  </table>
</div>
'''
    
    # Add note about remaining vulnerabilities if there are more
    if total_count > len(enhanced_vulnerabilities):
        email_body += f'''
<p>Plus {total_count - len(enhanced_vulnerabilities)} additional vulnerabilities. See the attached CSV file for complete details.</p>
'''
    
    email_body += '''
  <p>Please prioritize these vulnerabilities based on the AI-provided insights and your specific environment.</p>
</body>
</html>
'''
    return email_body

def export_to_csv(vulnerabilities, filename="vulnerabilities.csv"):
    """Export vulnerabilities to CSV file"""
    try:
        df = pd.DataFrame(vulnerabilities)
        df.to_csv(filename, index=False)
        return df
    except Exception as e:
        st.error(f"Error exporting to CSV: {str(e)}")
        return None

def plot_severity_distribution(vulnerabilities):
    """Create a pie chart of vulnerability severity levels"""
    df = pd.DataFrame(vulnerabilities)
    severity_counts = df['severity_level'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    
    fig = px.pie(
        severity_counts, 
        values='Count', 
        names='Severity', 
        title='Vulnerability Severity Distribution',
        color='Severity',
        color_discrete_map={
            'Critical': '#FF0000',
            'High': '#FFA500',
            'Medium': '#FFFF00',
            'Low': '#00FF00'
        }
    )
    return fig

def plot_oem_distribution(vulnerabilities):
    """Create a bar chart of vulnerabilities by OEM"""
    df = pd.DataFrame(vulnerabilities)
    oem_counts = df['oem_name'].value_counts().reset_index()
    oem_counts.columns = ['OEM', 'Count']
    
    fig = px.bar(
        oem_counts, 
        x='OEM', 
        y='Count', 
        title='Vulnerabilities by OEM',
        color='Count',
        color_continuous_scale=px.colors.sequential.Reds
    )
    return fig

def plot_time_series(vulnerabilities):
    """Create a time series line chart of vulnerabilities discovered over time"""
    df = pd.DataFrame(vulnerabilities)
    if 'published_date' not in df.columns:
        return None
    # Parse dates
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
    # Drop NaT
    df = df.dropna(subset=['published_date'])
    # Group by date
    time_counts = df.groupby(df['published_date'].dt.date).size().reset_index(name='Count')
    fig = px.line(
        time_counts,
        x='published_date',
        y='Count',
        title='Vulnerabilities Discovered Over Time',
        markers=True
    )
    fig.update_xaxes(title='Date')
    fig.update_yaxes(title='Number of Vulnerabilities')
    return fig

def plot_oem_severity_heatmap(vulnerabilities):
    """Create a heatmap of vulnerabilities by OEM and severity"""
    df = pd.DataFrame(vulnerabilities)
    if 'oem_name' not in df.columns or 'severity_level' not in df.columns:
        return None
    pivot = pd.pivot_table(df, index='oem_name', columns='severity_level', aggfunc='size', fill_value=0)
    fig = px.imshow(
        pivot,
        labels=dict(x="Severity", y="OEM", color="Count"),
        title="OEM vs. Severity Heatmap",
        aspect="auto",
        color_continuous_scale=px.colors.sequential.Blues
    )
    return fig

def main():
    st.set_page_config(
        page_title="OEM Vulnerability Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize session state for storing scan results
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = []
    if 'has_new_results' not in st.session_state:
        st.session_state.has_new_results = False
    if 'last_page' not in st.session_state:
        st.session_state.last_page = None
    
    st.title("🔒 OEM Vulnerability Scanner")
    st.subheader("Real-time Critical Vulnerability Detection & Notification")
    
    # Initialize database
    setup_database()
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    pages = ["Dashboard", "Scanner", "Email Notifications", "Settings", "AI Analysis"]
    selection = st.sidebar.radio("Go to", pages)
    
    # Reset scan results when changing from Scanner to another page
    if st.session_state.last_page == "Scanner" and selection != "Scanner":
        st.session_state.scan_results = []
        st.session_state.has_new_results = False
    
    # Store current page for next check
    st.session_state.last_page = selection
    
    if selection == "Dashboard":
        st.header("Vulnerability Dashboard")
        
        # Get vulnerabilities from database
        all_vulnerabilities = get_vulnerabilities()
        
        if all_vulnerabilities:
            # Show stats
            col1, col2, col3, col4 = st.columns(4)
            
            all_vulns_count = len(all_vulnerabilities)
            critical_vulns = sum(1 for v in all_vulnerabilities if v['severity_level'] == 'Critical')
            high_vulns = sum(1 for v in all_vulnerabilities if v['severity_level'] == 'High')
            oem_count = len(set(v['oem_name'] for v in all_vulnerabilities))
            
            col1.metric("Total Vulnerabilities", all_vulns_count)
            col2.metric("Critical Vulnerabilities", critical_vulns)
            col3.metric("High Vulnerabilities", high_vulns)
            col4.metric("OEMs Affected", oem_count)
            
            # Charts
            col1, col2 = st.columns(2)
            
            with col1:
                severity_chart = plot_severity_distribution(all_vulnerabilities)
                st.plotly_chart(severity_chart, use_container_width=True)
            
            with col2:
                oem_chart = plot_oem_distribution(all_vulnerabilities)
                st.plotly_chart(oem_chart, use_container_width=True)
            
            # --- New analytics row ---
            col3, col4 = st.columns(2)
            with col3:
                time_series_chart = plot_time_series(all_vulnerabilities)
                if time_series_chart:
                    st.plotly_chart(time_series_chart, use_container_width=True)
                else:
                    st.info("Not enough date data for time series chart.")
            with col4:
                heatmap_chart = plot_oem_severity_heatmap(all_vulnerabilities)
                if heatmap_chart:
                    st.plotly_chart(heatmap_chart, use_container_width=True)
                else:
                    st.info("Not enough data for OEM vs. Severity heatmap.")
            
            # Filter vulnerabilities
            st.subheader("Filter Vulnerabilities")
            
            # Create filters
            col1, col2, col3 = st.columns(3)
            
            df = pd.DataFrame(all_vulnerabilities)
            
            with col1:
                severity_options = sorted(df['severity_level'].unique())
                # Make sure default values are in options
                severity_defaults = [level for level in ["Critical", "High"] if level in severity_options]
                severity_filter = st.multiselect(
                    "Severity Level",
                    options=severity_options,
                    default=severity_defaults
                )
            
            with col2:
                oem_filter = st.multiselect(
                    "OEM",
                    options=sorted(df['oem_name'].unique())
                )
            
            with col3:
                cve_search = st.text_input("Search by CVE ID")
            
            # Apply filters
            filtered_df = df.copy()
            
            if severity_filter:
                filtered_df = filtered_df[filtered_df['severity_level'].isin(severity_filter)]
            
            if oem_filter:
                filtered_df = filtered_df[filtered_df['oem_name'].isin(oem_filter)]
            
            if cve_search:
                filtered_df = filtered_df[filtered_df['cve_id'].str.contains(cve_search, case=False, na=False)]
            
            # Display filtered vulnerabilities
            st.subheader(f"Vulnerabilities ({len(filtered_df)} results)")
            
            # Add columns to display additional CISA-specific information if available
            if not filtered_df.empty:
                # Check if any of the filtered results are from CISA
                has_cisa = any(filtered_df['oem_name'] == 'CISA')
                
                # Add a custom view for CISA entries with additional context if needed
                if has_cisa:
                    st.info("CISA Known Exploited Vulnerabilities are critical vulnerabilities with evidence of active exploitation.")
                    
                # Add a display option toggle
                display_option = st.radio(
                    "Display Format",
                    ["Table View", "Detailed View"],
                    index=0
                )
                
                # Enhanced table view
                if display_option == "Table View":
                    st.dataframe(filtered_df, use_container_width=True)
                else:
                    # Detailed view with more context
                    for index, vuln in filtered_df.iterrows():
                        with st.expander(f"{vuln['cve_id']} - {vuln['product_name']} ({vuln['severity_level']})"):
                            # Create tabs for standard info and AI insights
                            standard_tab, ai_tab = st.tabs(["Standard Information", "AI Insights"])
                            
                            with standard_tab:
                                cols = st.columns(2)
                                with cols[0]:
                                    st.markdown("**Vendor/OEM:**")
                                    st.write(vuln['oem_name'])
                                    st.markdown("**Severity:**")
                                    st.write(vuln['severity_level'])
                                    st.markdown("**Published Date:**")
                                    st.write(vuln['published_date'])
                                with cols[1]:
                                    st.markdown("**Product:**")
                                    st.write(f"{vuln['product_name']} {vuln['product_version']}")
                                    st.markdown("**CVE ID:**")
                                    st.write(vuln['cve_id'])
                                
                                st.markdown("**Description:**")
                                st.write(vuln['vulnerability_description'])
                                
                                st.markdown("**Mitigation Strategy:**")
                                st.write(vuln['mitigation_strategy'])
                                
                                st.markdown("**Reference:**")
                                st.write(vuln['url'])
                            
                            with ai_tab:
                                # Add AI insights section
                                if st.button("Generate AI Insights", key=f"ai_insights_{vuln['cve_id']}"):
                                    with st.spinner("Analyzing vulnerability with AI..."):
                                        try:
                                            # Get AI analysis
                                            enhanced_vuln = analyze_single_vulnerability(vuln.to_dict())
                                            
                                            if "ai_insights" in enhanced_vuln and "error" not in enhanced_vuln["ai_insights"]:
                                                insights = enhanced_vuln["ai_insights"]
                                                
                                                # Display insights
                                                if "summary" in insights:
                                                    st.subheader("AI Summary")
                                                    st.markdown(insights["summary"])
                                                
                                                col1, col2 = st.columns(2)
                                                
                                                with col1:
                                                    if "technical_impact" in insights:
                                                        st.subheader("Technical Impact")
                                                        st.markdown(insights["technical_impact"])
                                                    
                                                    if "attack_vectors" in insights:
                                                        st.subheader("Attack Vectors")
                                                        st.markdown(insights["attack_vectors"])
                                                
                                                with col2:
                                                    if "business_impact" in insights:
                                                        st.subheader("Business Impact")
                                                        st.markdown(insights["business_impact"])
                                                    
                                                    if "ease_of_exploitation" in insights:
                                                        st.subheader("Exploitation Difficulty")
                                                        st.markdown(insights["ease_of_exploitation"])
                                                
                                                if "recommended_actions" in insights:
                                                    st.subheader("Recommended Actions")
                                                    st.markdown(insights["recommended_actions"])
                                            else:
                                                error_message = enhanced_vuln.get("ai_insights", {}).get("error", "Unknown error occurred")
                                                st.error(f"Could not generate AI insights: {error_message}")
                                        
                                        except Exception as e:
                                            st.error(f"Error generating AI insights: {str(e)}")
                                
                                # Add mitigation plan section
                                if st.button("Generate Mitigation Plan", key=f"mitigation_{vuln['cve_id']}"):
                                    with st.spinner("Generating mitigation plan..."):
                                        try:
                                            # Generate a mitigation plan
                                            mitigation_plan = generate_mitigation_plan(vuln.to_dict())
                                            
                                            # Display the plan
                                            st.subheader("AI-Generated Mitigation Plan")
                                            st.markdown(mitigation_plan)
                                            
                                            # Add download button
                                            st.download_button(
                                                "Download Mitigation Plan",
                                                mitigation_plan,
                                                file_name=f"mitigation_{vuln['cve_id']}.txt",
                                                mime="text/plain",
                                                key=f"download_mitigation_{vuln['cve_id']}"
                                            )
                                        except Exception as e:
                                            st.error(f"Error generating mitigation plan: {str(e)}")
            
            # Export functionality
            if st.button("Export Filtered Results to CSV"):
                export_df = export_to_csv(filtered_df.to_dict('records'))
                if export_df is not None:
                    st.download_button(
                        "Download CSV",
                        data=export_df.to_csv(index=False).encode('utf-8'),
                        file_name="filtered_vulnerabilities.csv",
                        mime="text/csv"
                    )
            
            # Add AI prioritization option
            st.subheader("AI Prioritization")
            if st.checkbox("Use AI to prioritize these vulnerabilities"):
                # Get organization context
                org_context = st.text_area(
                    "Organization Context",
                    value="Enterprise with Windows servers, cloud infrastructure, and customer data",
                    height=100
                )
                
                # Button to trigger prioritization
                if st.button("Prioritize with AI"):
                    with st.spinner("Prioritizing vulnerabilities with AI..."):
                        try:
                            # Convert DataFrame to list of dictionaries
                            vulns_list = filtered_df.to_dict('records')
                            
                            # Get up to 20 vulnerabilities to avoid overloading the API
                            vulns_to_prioritize = vulns_list[:20]
                            
                            # Prioritize vulnerabilities
                            prioritized_vulns = prioritize_vulnerability_list(vulns_to_prioritize, org_context)
                            
                            # Extract priority information
                            priority_data = []
                            for vuln in prioritized_vulns:
                                if "ai_priority" in vuln and "error" not in vuln["ai_priority"]:
                                    priority_info = {
                                        "cve_id": vuln.get("cve_id", "N/A"),
                                        "product_name": vuln.get("product_name", "N/A"),
                                        "severity_level": vuln.get("severity_level", "N/A"),
                                        "ai_priority_score": vuln["ai_priority"].get("priority_score", "N/A"),
                                        "ai_rationale": vuln["ai_priority"].get("rationale", "N/A"),
                                        "recommended_timeframe": vuln["ai_priority"].get("recommended_timeframe", "N/A")
                                    }
                                    priority_data.append(priority_info)
                            
                            if priority_data:
                                # Create DataFrame for display
                                priority_df = pd.DataFrame(priority_data)
                                
                                # Sort by priority score
                                try:
                                    priority_df["ai_priority_score"] = pd.to_numeric(priority_df["ai_priority_score"])
                                    priority_df = priority_df.sort_values("ai_priority_score", ascending=False)
                                except:
                                    pass
                                
                                # Display prioritized vulnerabilities
                                st.subheader("AI-Prioritized Vulnerabilities")
                                st.dataframe(priority_df)
                                
                                # Show detailed view of top vulnerabilities
                                st.subheader("Top Priority Vulnerabilities - Detailed Analysis")
                                for _, vuln in priority_df.head(3).iterrows():
                                    with st.expander(f"{vuln['cve_id']} - Priority Score: {vuln['ai_priority_score']}"):
                                        st.markdown(f"**Product:** {vuln['product_name']}")
                                        st.markdown(f"**Severity:** {vuln['severity_level']}")
                                        st.markdown(f"**Recommended Timeframe:** {vuln['recommended_timeframe']}")
                                        st.markdown("**AI Rationale:**")
                                        st.markdown(f"{vuln['ai_rationale']}")
                            else:
                                st.warning("Could not prioritize vulnerabilities. Please try again.")
                                
                        except Exception as e:
                            st.error(f"Error during AI prioritization: {str(e)}")
            else:
                st.info("No vulnerabilities match your selected filters.")
        else:
            st.info("No vulnerabilities found in the database. Use the Scanner to find vulnerabilities.")
            
    elif selection == "Scanner":
        st.header("Vulnerability Scanner")
        
        # Select sources to scan
        st.subheader("Select Sources to Scan")
        # Updated to include Google Cloud Security Bulletins as a source option
        selected_sources = st.multiselect(
            "Sources",
            ["NVD", "CISA", "Cisco", "Google"],  # Added Google Cloud as a supported source
            default=["NVD", "CISA"]
        )
        
        # Severity filter
        severity_filter = st.multiselect(
            "Severity Levels",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High"]
        )
        
        # Define columns for actions
        col1, col2 = st.columns(2)
        
        # Scan button
        if col1.button("Start Scanning"):
            if not selected_sources:
                st.warning("Please select at least one source to scan")
            else:
                with st.spinner("Scanning for vulnerabilities..."):
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    all_new_vulnerabilities = []
                    
                    try:
                        for idx, source in enumerate(selected_sources):
                            status_text.text(f"Scanning {source}...")
                            progress = (idx + 1) / len(selected_sources)
                            progress_bar.progress(progress)
                            
                            
                            try:
                                vulnerabilities = scan_source(source)
                                
                                # Log information about the scan results
                                st.info(f"Found {len(vulnerabilities)} vulnerabilities from {source}")
                                
                                if source == "Google" and len(vulnerabilities) > 0:
                                    st.success(f"Successfully scanned Google Cloud Security Bulletins and found {len(vulnerabilities)} vulnerabilities")
                                
                                # Filter by severity
                                filtered_vulns = [v for v in vulnerabilities if v['severity_level'] in severity_filter]
                                if len(filtered_vulns) < len(vulnerabilities):
                                    st.info(f"Filtered to {len(filtered_vulns)} {', '.join(severity_filter)} vulnerabilities from {source}")
                                
                                all_new_vulnerabilities.extend(filtered_vulns)
                            except Exception as e:
                                st.error(f"Error scanning {source}: {str(e)}")
                                continue
                        
                        progress_bar.empty()
                        status_text.empty()
                        
                        # Store scan results in session state
                        st.session_state.scan_results = all_new_vulnerabilities
                        st.session_state.has_new_results = True
                        
                        if all_new_vulnerabilities:
                            st.success(f"Found {len(all_new_vulnerabilities)} new vulnerabilities")
                            
                            # Show new vulnerabilities
                            st.subheader("Newly Discovered Vulnerabilities")
                            df = pd.DataFrame(all_new_vulnerabilities)
                            st.dataframe(df)
                            st.session_state.has_new_results = True
                        else:
                            st.info("No new vulnerabilities found matching your criteria")
                            st.session_state.has_new_results = False
                    
                    except Exception as e:
                        st.error(f"Error during scan: {str(e)}")
                        st.session_state.has_new_results = False
        
        # Email notification button (separate from scan action)
        # Add AI enhancement option for email
        use_ai = st.checkbox("Use AI to enhance email notifications", help="Add AI-generated insights to email notifications (may take longer to send)")
        
        if col2.button("Send Email Notification", disabled=not st.session_state.has_new_results):
            recipients = get_recipients()
            if recipients and st.session_state.scan_results:
                if send_email_notification(st.session_state.scan_results, recipients, include_ai_insights=use_ai):
                    st.success("Email notification sent successfully")
            elif not recipients:
                st.warning("No email recipients configured. Add recipients in the Email Notifications section.")
            elif not st.session_state.scan_results:
                st.warning("No vulnerabilities to send. Please scan first.")
        
        # Show existing vulnerabilities
        st.subheader("Current Critical & High Vulnerabilities")
        critical_high_vulns = get_vulnerabilities(severity_filter=["Critical", "High"])
        
        if critical_high_vulns:
            df = pd.DataFrame(critical_high_vulns)
            st.dataframe(df)
            
            # Export option
            if st.button("Export to CSV"):
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "Download CSV",
                    csv,
                    "vulnerabilities.csv",
                    "text/csv",
                    key='download-csv'
                )
        else:
            st.info("No critical or high vulnerabilities in the database")
    
    elif selection == "Email Notifications":
        st.header("Email Notification Settings")
        
        # Show current recipients
        st.subheader("Current Recipients")
        recipients = get_recipients()
        
        if recipients:
            for email in recipients:
                col1, col2 = st.columns([3, 1])
                col1.text(email)
                if col2.button("Delete", key=f"delete_{email}"):
                    if delete_recipient(email):
                        st.rerun()
        else:
            st.info("No recipients configured")
        
        # Add new recipient
        st.subheader("Add New Recipient")
        
        with st.form("add_recipient_form"):
            new_email = st.text_input("Email Address")
            submitted = st.form_submit_button("Add Recipient")
            
            if submitted:
                if new_email:
                    if add_recipient(new_email):
                        st.success(f"Added {new_email} to recipients")
                        time.sleep(1)
                        st.rerun()
                else:
                    st.warning("Please enter an email address")
        
        # Test email
        st.subheader("Test Email Notification")
        
        use_ai_test = st.checkbox("Include AI insights in test email", help="Add AI-generated insights to the test email (may take longer to send)")
        
        if st.button("Send Test Email"):
            recipients = get_recipients()
            if recipients:
                # Create a test vulnerability
                test_vuln = {
                    "product_name": "Test Product",
                    "product_version": "1.0",
                    "oem_name": "Test OEM",
                    "severity_level": "Critical",
                    "vulnerability_description": "This is a test vulnerability for email notification",
                    "mitigation_strategy": "This is just a test, no mitigation needed",
                    "published_date": datetime.now().strftime("%b %Y"),
                    "cve_id": "TEST-2023-0000",
                    "url": "https://example.com/test"
                }
                
                if send_email_notification([test_vuln], recipients, include_ai_insights=use_ai_test):
                    st.success("Test email sent successfully")
            else:
                st.warning("No recipients configured. Please add at least one recipient.")
    
    elif selection == "Settings":
        st.header("Settings")
        
        # Email Configuration
        st.subheader("Email Configuration")
        st.warning("Note: These settings are for demonstration only. In a production environment, use secure methods for storing credentials.")
        
        with st.form("email_settings_form"):
            sender_email = st.text_input("Sender Email", value=EMAIL_CONFIG["sender_email"])
            smtp_server = st.text_input("SMTP Server", value=EMAIL_CONFIG["smtp_server"])
            smtp_port = st.number_input("SMTP Port", value=EMAIL_CONFIG["smtp_port"])
            username = st.text_input("SMTP Username", value=EMAIL_CONFIG["username"])
            password = st.text_input("SMTP Password", value=EMAIL_CONFIG["password"], type="password")
            
            if st.form_submit_button("Save Email Settings"):
                EMAIL_CONFIG["sender_email"] = sender_email
                EMAIL_CONFIG["smtp_server"] = smtp_server
                EMAIL_CONFIG["smtp_port"] = int(smtp_port)
                EMAIL_CONFIG["username"] = username
                EMAIL_CONFIG["password"] = password
                
                st.success("Email settings saved")
        
        # Test SMTP connection
        if st.button("Test SMTP Connection"):
            try:
                with st.spinner("Testing SMTP connection..."):
                    st.info(f"Connecting to {EMAIL_CONFIG['smtp_server']}:{EMAIL_CONFIG['smtp_port']}...")
                    server = smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"])
                    server.set_debuglevel(1)
                    
                    st.info("Starting TLS...")
                    server.starttls()
                    
                    st.info(f"Logging in with username: {EMAIL_CONFIG['username']}...")
                    server.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
                    
                    st.success("SMTP connection successful! Your email settings are working.")
                    server.quit()
            except Exception as e:
                st.error(f"Connection failed: {str(e)}")
                st.info("Please check your email settings and try again.")
        
        # OEM Sources
        st.subheader("Vulnerability Sources")
        st.info("The following OEM sources are configured for vulnerability scanning:")
        
        for oem, config in OEM_SOURCES.items():
            with st.expander(f"{oem} - {config['url']}"):
                st.json(config)
        
        st.warning("To add or modify OEM sources, edit the OEM_SOURCES dictionary in the vulnerability_scanner.py file.")
    
    elif selection == "AI Analysis":
        render_ai_analysis_page()

def render_ai_analysis_page():
    """Render the AI Analysis page content"""
    st.header("AI-Powered Vulnerability Analysis")
    
    # Get vulnerabilities from database
    vulnerabilities = get_vulnerabilities()

    if not vulnerabilities:
        st.info("No vulnerabilities found in the database. Please use the Scanner to find vulnerabilities first.")
        return

    # Create tabs for different AI features
    tabs = st.tabs([
        "Smart Prioritization", 
        "AI Insights", 
        "Mitigation Planning",
        "Audience-Specific Reports",
        "Threat Intelligence"
    ])

    # Tab 1: Smart Prioritization
    with tabs[0]:
        st.subheader("Smart AI-Driven Vulnerability Prioritization")
        
        # Context input for organization
        org_context = st.text_area(
            "Organization Context (helps AI prioritize based on your environment)",
            value="Enterprise environment with Windows servers, Linux web servers, and cloud infrastructure in AWS.",
            height=100
        )
        
        # Number of vulnerabilities to prioritize
        num_vulnerabilities = st.slider(
            "Number of vulnerabilities to prioritize",
            min_value=5,
            max_value=min(50, len(vulnerabilities)),
            value=min(20, len(vulnerabilities))
        )
        
        # Button to trigger prioritization
        if st.button("Prioritize Vulnerabilities"):
            with st.spinner("AI is analyzing and prioritizing vulnerabilities..."):
                # Get a subset of vulnerabilities for prioritization
                vulns_to_prioritize = vulnerabilities[:num_vulnerabilities]
                
                # Prioritize vulnerabilities
                prioritized_vulns = prioritize_vulnerability_list(vulns_to_prioritize, org_context)
                
                # Create a DataFrame for display
                df = pd.DataFrame(prioritized_vulns)
                
                # Extract AI priority info into separate columns
                priority_data = []
                for vuln in prioritized_vulns:
                    if "ai_priority" in vuln and "error" not in vuln["ai_priority"]:
                        priority_info = {
                            "cve_id": vuln.get("cve_id", "N/A"),
                            "product_name": vuln.get("product_name", "N/A"),
                            "severity_level": vuln.get("severity_level", "N/A"),
                            "ai_priority_score": vuln["ai_priority"].get("priority_score", "N/A"),
                            "ai_rationale": vuln["ai_priority"].get("rationale", "N/A"),
                            "recommended_timeframe": vuln["ai_priority"].get("recommended_timeframe", "N/A")
                        }
                        priority_data.append(priority_info)
                
                if priority_data:
                    priority_df = pd.DataFrame(priority_data)
                    
                    # Sort by AI priority score (descending)
                    try:
                        priority_df["ai_priority_score"] = pd.to_numeric(priority_df["ai_priority_score"])
                        priority_df = priority_df.sort_values("ai_priority_score", ascending=False)
                    except:
                        # If conversion fails, just show as is
                        pass
                    
                    # Display the prioritized vulnerabilities
                    st.subheader("AI-Prioritized Vulnerabilities")
                    st.dataframe(priority_df)
                    
                    # Show detailed view of top vulnerabilities
                    st.subheader("Top Priority Vulnerabilities - Detailed Analysis")
                    for _, vuln in priority_df.head(5).iterrows():
                        with st.expander(f"{vuln['cve_id']} - Priority Score: {vuln['ai_priority_score']}"):
                            st.markdown(f"**Product:** {vuln['product_name']}")
                            st.markdown(f"**Severity:** {vuln['severity_level']}")
                            st.markdown(f"**Recommended Timeframe:** {vuln['recommended_timeframe']}")
                            st.markdown("**AI Rationale:**")
                            st.markdown(f"{vuln['ai_rationale']}")
                else:
                    st.error("Could not generate priority data. Please try again.")

    # Tab 2: AI Insights
    with tabs[1]:
        st.subheader("Deep AI Insights on Vulnerabilities")
        
        # Select a vulnerability to analyze
        df = pd.DataFrame(vulnerabilities)
        selected_index = st.selectbox(
            "Select a vulnerability to analyze:",
            options=df.index,
            format_func=lambda x: f"{df.iloc[x]['cve_id']} - {df.iloc[x]['product_name']}"
        )
        
        selected_vuln = df.iloc[selected_index].to_dict()
        
        # Button to trigger analysis
        if st.button("Generate AI Insights"):
            with st.spinner("AI is analyzing the vulnerability..."):
                # Get AI insights
                enhanced_vuln = analyze_single_vulnerability(selected_vuln)
                
                if "ai_insights" in enhanced_vuln:
                    insights = enhanced_vuln["ai_insights"]
                    
                    # Check if we got a text response or structured data
                    if "text_response" in insights:
                        st.markdown(insights["text_response"])
                    else:
                        # Display structured insights
                        st.subheader("AI Summary")
                        st.markdown(insights.get("summary", "No summary available"))
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.subheader("Technical Impact")
                            st.markdown(insights.get("technical_impact", "No technical impact available"))
                            
                            st.subheader("Attack Vectors")
                            st.markdown(insights.get("attack_vectors", "No attack vectors available"))
                        
                        with col2:
                            st.subheader("Business Impact")
                            st.markdown(insights.get("business_impact", "No business impact available"))
                            
                            st.subheader("Ease of Exploitation")
                            st.markdown(insights.get("ease_of_exploitation", "No exploitation info available"))
                        
                        st.subheader("Recommended Actions")
                        st.markdown(insights.get("recommended_actions", "No recommended actions available"))
                        
                        st.subheader("Detection Methods")
                        st.markdown(insights.get("detection_methods", "No detection methods available"))
                        
                        if "related_vulnerabilities" in insights and insights["related_vulnerabilities"]:
                            st.subheader("Related Vulnerabilities")
                            st.markdown(insights.get("related_vulnerabilities", "None identified"))
                else:
                    st.error("Could not generate AI insights. Please try again.")

    # Tab 3: Mitigation Planning
    with tabs[2]:
        st.subheader("AI-Generated Mitigation Plans")
        
        # Select a vulnerability for mitigation planning
        df = pd.DataFrame(vulnerabilities)
        selected_index = st.selectbox(
            "Select a vulnerability for mitigation planning:",
            options=df.index,
            format_func=lambda x: f"{df.iloc[x]['cve_id']} - {df.iloc[x]['product_name']}",
            key="mitigation_selector"
        )
        
        selected_vuln = df.iloc[selected_index].to_dict()
        
        # System context input
        system_context = st.text_area(
            "System Context (describe your environment for tailored mitigation)",
            value="Windows-based infrastructure with Active Directory, Exchange Server, SQL Server, and various web applications. Compliance requirements include PCI-DSS and HIPAA.",
            height=100
        )
        
        # Button to trigger mitigation plan generation
        if st.button("Generate Mitigation Plan"):
            with st.spinner("AI is generating a detailed mitigation plan..."):
                # Generate mitigation plan
                mitigation_plan = generate_mitigation_plan(selected_vuln, system_context)
                
                # Display the plan
                st.subheader(f"Mitigation Plan for {selected_vuln.get('cve_id', 'Unknown')}")
                st.markdown(mitigation_plan)
                
                # Add download button for the plan
                st.download_button(
                    "Download Mitigation Plan",
                    mitigation_plan,
                    file_name=f"mitigation_plan_{selected_vuln.get('cve_id', 'vulnerability')}.txt",
                    mime="text/plain"
                )

    # Tab 4: Audience-Specific Reports
    with tabs[3]:
        st.subheader("Audience-Specific Vulnerability Reports")
        
        # Select a vulnerability for reporting
        df = pd.DataFrame(vulnerabilities)
        selected_index = st.selectbox(
            "Select a vulnerability to explain:",
            options=df.index,
            format_func=lambda x: f"{df.iloc[x]['cve_id']} - {df.iloc[x]['product_name']}",
            key="report_selector"
        )
        
        selected_vuln = df.iloc[selected_index].to_dict()
        
        # Select audience type
        audience = st.radio(
            "Select target audience:",
            ["Technical", "Executive", "Compliance"]
        )
        
        # Button to generate audience-specific explanation
        if st.button("Generate Report"):
            with st.spinner(f"Generating {audience}-focused report..."):
                # Generate explanation
                explanation = get_vulnerability_explanation(selected_vuln, audience.lower())
                
                # Display the explanation
                st.subheader(f"{audience} Report for {selected_vuln.get('cve_id', 'Unknown')}")
                st.markdown(explanation)
                
                # Add download button for the report
                st.download_button(
                    "Download Report",
                    explanation,
                    file_name=f"{audience.lower()}_report_{selected_vuln.get('cve_id', 'vulnerability')}.txt",
                    mime="text/plain"
                )

    # Tab 5: Threat Intelligence
    with tabs[4]:
        st.subheader("Enhanced Threat Intelligence")
        
        # Input for CVE ID
        cve_options = [vuln.get('cve_id', 'Unknown') for vuln in vulnerabilities if vuln.get('cve_id')]
        selected_cve = st.selectbox("Select or type a CVE ID:", options=cve_options)
        
        # Button to generate threat intelligence
        if st.button("Get Threat Intelligence"):
            with st.spinner("Gathering enhanced threat intelligence..."):
                # Get threat intelligence
                threat_intel = get_threat_intelligence(selected_cve)
                
                # Display the threat intelligence
                st.subheader(f"Threat Intelligence for {selected_cve}")
                
                # Check for error or text response
                if "error" in threat_intel:
                    st.error(threat_intel["error"])
                elif "text_response" in threat_intel:
                    st.markdown(threat_intel["text_response"])
                else:
                    # Display structured threat intelligence
                    for section, content in threat_intel.items():
                        st.subheader(section.replace("_", " ").title())
                        if isinstance(content, list):
                            for item in content:
                                st.markdown(f"- {item}")
                        else:
                            st.markdown(content)

if __name__ == "__main__":
    main()