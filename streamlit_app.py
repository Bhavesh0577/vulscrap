import os
from dotenv import load_dotenv

# Load .env FIRST, before any project imports that read env vars at module level
load_dotenv()

import streamlit as st
import pandas as pd
import concurrent.futures
import smtplib
import plotly.express as px
import csv
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import time

# Import functions from the vulnerability scanner module
from vulnerability_scanner import (
    setup_database,
    scan_source,
    OEM_SOURCES,
    get_vulnerabilities,
    add_recipient,
    get_recipients,
    delete_recipient,
    save_vulnerability_to_db as save_vulnerability,
    openvas_supported,
    scan_openvas_targets,
)

try:
    from openvas_integration import OpenVASConfig
except ImportError:  # pragma: no cover - optional dependency
    OpenVASConfig = None  # type: ignore

# Import AI integration functions
from gemini_integration import (
    analyze_single_vulnerability,
    batch_analyze_vulnerabilities,
    generate_mitigation_plan,
    get_vulnerability_explanation,
    prioritize_vulnerability_list,
    get_threat_intelligence,
    batch_generate_mitigation_plans,
)

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
    "Microsoft": {
        "url": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "type": "api",
        "description": "Microsoft Security Response Center (MSRC) - Patch Tuesday updates"
    },
    "Cisco": {
        "url": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
        "type": "web",
        "description": "Cisco Security Advisories - Network equipment vulnerabilities"
    },
    "Google": {
        "url": "https://cloud.google.com/support/bulletins",
        "type": "web",
        "description": "Google Cloud & Android Security Bulletins"
    },
    "Fortinet": {
        "url": "https://www.fortiguard.com/psirt",
        "type": "web",
        "description": "Fortinet FortiGuard PSIRT - FortiGate/FortiOS advisories"
    },
    "Palo Alto": {
        "url": "https://security.paloaltonetworks.com/",
        "type": "web",
        "description": "Palo Alto Networks Security Advisories - PAN-OS vulnerabilities"
    },
    "Adobe": {
        "url": "https://helpx.adobe.com/security.html",
        "type": "web",
        "description": "Adobe Security Bulletins - Acrobat, Reader, ColdFusion, etc."
    },
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
        # Log connection attempt without exposing credentials
        st.info("Connecting to SMTP server...")
        
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
        
        # --- Generate Gemini AI remediation strategies in ONE batch request ---
        st.info(f"Generating AI remediation strategies via Gemini for {len(cleaned_vulnerabilities)} vulnerabilities (single batch request)...")
        ai_strategies = {}  # cve_id -> strategy text
        try:
            ai_strategies = batch_generate_mitigation_plans(cleaned_vulnerabilities)
            st.success(f"AI strategies generated for {len(ai_strategies)} vulnerabilities in a single batch.")
        except Exception as e:
            st.warning(f"AI batch strategy generation encountered an error: {e}")
        
        # Optionally enhance vulnerabilities with deeper AI insights
        if include_ai_insights:
            st.info("Generating additional AI insights for email content...")
            vulns_to_analyze = cleaned_vulnerabilities[:5]
            try:
                enhanced_vulns = batch_analyze_vulnerabilities(vulns_to_analyze)
                email_body = generate_ai_enhanced_email_content(enhanced_vulns, len(cleaned_vulnerabilities), ai_strategies)
            except Exception as e:
                st.warning(f"Could not generate AI insights: {str(e)}. Falling back to standard email format.")
                email_body = generate_standard_email_content(cleaned_vulnerabilities, ai_strategies)
        else:
            email_body = generate_standard_email_content(cleaned_vulnerabilities, ai_strategies)
        
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

def _build_summary_table_html(vulnerabilities):
    """Build an at-a-glance HTML summary table of all reported vulnerabilities."""
    severity_colors = {
        'Critical': '#d32f2f', 'High': '#e65100',
        'Medium': '#f9a825', 'Low': '#388e3c',
    }
    rows = ''
    for idx, v in enumerate(vulnerabilities, 1):
        sev = v.get('severity_level', 'N/A')
        color = severity_colors.get(sev, '#555')
        rows += (
            f'<tr>'
            f'<td style="padding:6px 10px;">{idx}</td>'
            f'<td style="padding:6px 10px;font-family:monospace;">{v.get("cve_id", "N/A")}</td>'
            f'<td style="padding:6px 10px;color:{color};font-weight:bold;">{sev}</td>'
            f'<td style="padding:6px 10px;">{v.get("oem_name", "N/A")}</td>'
            f'<td style="padding:6px 10px;">{v.get("product_name", "N/A")}</td>'
            f'<td style="padding:6px 10px;">{v.get("published_date", "N/A")}</td>'
            f'</tr>'
        )
    return f'''
    <h3 style="margin-top:30px;">Report Summary &mdash; All Vulnerabilities ({len(vulnerabilities)})</h3>
    <table style="border-collapse:collapse;width:100%;border:1px solid #ddd;">
      <thead>
        <tr style="background:#1a237e;color:#fff;">
          <th style="padding:8px 10px;text-align:left;">#</th>
          <th style="padding:8px 10px;text-align:left;">CVE ID</th>
          <th style="padding:8px 10px;text-align:left;">Severity</th>
          <th style="padding:8px 10px;text-align:left;">Vendor</th>
          <th style="padding:8px 10px;text-align:left;">Product</th>
          <th style="padding:8px 10px;text-align:left;">Published</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    '''


def generate_standard_email_content(vulnerabilities, ai_strategies=None):
    """Generate standard email content with Gemini AI remediation strategies."""
    ai_strategies = ai_strategies or {}

    email_body = f'''
<html>
<head>
  <style>
    body {{ font-family: Arial, sans-serif; color: #222; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td {{ padding: 8px; vertical-align: top; }}
    tr:nth-child(even) {{ background-color: #f2f2f2; }}
    .ai-strategy {{ background:#e8f5e9; padding:12px 15px; margin:8px 0; border-left:4px solid #2e7d32;
                     font-size:14px; white-space:pre-wrap; }}
    .vuln-card {{ border:1px solid #ccc; border-radius:6px; padding:16px; margin:18px 0;
                  box-shadow:0 2px 4px rgba(0,0,0,.08); }}
  </style>
</head>
<body>
  <h2 style="color:#c62828;">&#x1F6A8; Critical/High Severity Vulnerability Alert</h2>
  <p>The following <strong>{len(vulnerabilities)}</strong> new critical or high severity vulnerabilities have been detected.</p>
'''

    # --- Summary report table ---
    email_body += _build_summary_table_html(vulnerabilities)

    # --- Detailed section per vulnerability ---
    email_body += '<h3 style="margin-top:30px;">Detailed Findings &amp; AI Remediation Strategies</h3>'

    for vuln in vulnerabilities:
        cve = vuln.get('cve_id', 'N/A')
        strategy_html = ''
        strategy_text = ai_strategies.get(cve)
        if strategy_text:
            safe_strategy = (strategy_text
                             .replace('&', '&amp;')
                             .replace('<', '&lt;')
                             .replace('>', '&gt;'))
            strategy_html = f'''
        <tr>
          <td colspan="2">
            <div class="ai-strategy">
              <strong>&#x1F916; AI-Powered Remediation Strategy (Gemini):</strong><br/>
              {safe_strategy}
            </div>
          </td>
        </tr>'''

        email_body += f'<div class="vuln-card"><table width="100%">'
        email_body += format_vulnerability_for_email(vuln)
        email_body += strategy_html
        email_body += '</table></div>'

    email_body += '''
  <p style="margin-top:20px;">Please take immediate action to address these vulnerabilities.<br/>
  <em>AI strategies powered by Google Gemini.</em></p>
</body>
</html>
'''
    return email_body

def generate_ai_enhanced_email_content(enhanced_vulnerabilities, total_count, ai_strategies=None):
    """Generate enhanced email content with AI insights and Gemini remediation strategies."""
    ai_strategies = ai_strategies or {}

    # Build a combined list for the summary table (enhanced vulns may be a subset)
    email_body = f'''
<html>
<head>
  <style>
    body {{ font-family: Arial, sans-serif; color: #222; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td {{ padding: 8px; vertical-align: top; }}
    tr:nth-child(even) {{ background-color: #f2f2f2; }}
    .ai-insights {{ background-color: #f0f7ff; padding: 15px; margin: 10px 0; border-left: 5px solid #0078d4; }}
    .ai-strategy {{ background:#e8f5e9; padding:12px 15px; margin:8px 0; border-left:4px solid #2e7d32;
                     font-size:14px; white-space:pre-wrap; }}
    .ai-summary {{ font-style: italic; color: #333; }}
    .ai-impact {{ color: #d83b01; }}
    .ai-actions {{ color: #107c10; }}
    .vuln-card {{ border:1px solid #ccc; border-radius:6px; padding:16px; margin:18px 0;
                  box-shadow:0 2px 4px rgba(0,0,0,.08); }}
  </style>
</head>
<body>
  <h2 style="color:#c62828;">&#x1F916; AI-Enhanced Critical/High Severity Vulnerability Alert</h2>
  <p>The following <strong>{total_count}</strong> new critical or high severity vulnerabilities have been detected.
  AI analysis and Gemini-powered remediation strategies are included below.</p>
'''

    # --- Summary report table ---
    email_body += _build_summary_table_html(enhanced_vulnerabilities)

    email_body += '<h3 style="margin-top:30px;">Detailed Findings, AI Insights &amp; Remediation Strategies</h3>'

    # Add enhanced vulnerabilities with AI insights
    for vuln in enhanced_vulnerabilities:
        cve = vuln.get('cve_id', 'Unknown CVE')
        ai_insights = vuln.get("ai_insights", {})
        has_insights = "error" not in ai_insights and ai_insights

        email_body += f'<div class="vuln-card">'
        email_body += f'<h3>{cve} &mdash; {vuln.get("product_name", "Unknown Product")}</h3>'
        email_body += '<table width="100%">'
        email_body += f'''
    <tr><td width="150"><strong>Severity:</strong></td><td>{vuln.get('severity_level', 'Unknown')}</td></tr>
    <tr><td><strong>Product:</strong></td><td>{vuln.get('product_name', 'N/A')} {vuln.get('product_version', '')}</td></tr>
    <tr><td><strong>Vendor:</strong></td><td>{vuln.get('oem_name', 'N/A')}</td></tr>
    <tr><td><strong>Published:</strong></td><td>{vuln.get('published_date', 'N/A')}</td></tr>
    <tr><td><strong>Description:</strong></td><td>{vuln.get('vulnerability_description', 'N/A')}</td></tr>
'''

        # AI insights block
        if has_insights:
            summary = ai_insights.get("summary", "No AI summary available")
            business_impact = ai_insights.get("business_impact", "No business impact analysis available")
            recommended_actions = ai_insights.get("recommended_actions", "No recommended actions available")
            email_body += f'''
    <tr><td colspan="2">
      <div class="ai-insights">
        <h4>&#x1F4CA; AI Analysis</h4>
        <p class="ai-summary"><strong>Summary:</strong> {summary}</p>
        <p class="ai-impact"><strong>Business Impact:</strong> {business_impact}</p>
        <p class="ai-actions"><strong>Recommended Actions:</strong> {recommended_actions}</p>
      </div>
    </td></tr>
'''

        # Gemini remediation strategy block
        strategy_text = ai_strategies.get(cve)
        if strategy_text:
            safe_strategy = (strategy_text
                             .replace('&', '&amp;')
                             .replace('<', '&lt;')
                             .replace('>', '&gt;'))
            email_body += f'''
    <tr><td colspan="2">
      <div class="ai-strategy">
        <strong>&#x1F916; Gemini Remediation Strategy:</strong><br/>
        {safe_strategy}
      </div>
    </td></tr>
'''

        email_body += f'''
    <tr><td><strong>Reference:</strong></td>
      <td><a href="{vuln.get('url', '#')}">{vuln.get('url', 'N/A')}</a></td></tr>
  </table></div>
'''

    if total_count > len(enhanced_vulnerabilities):
        email_body += f'<p>Plus {total_count - len(enhanced_vulnerabilities)} additional vulnerabilities. See the attached CSV file for complete details.</p>'

    email_body += '''
  <p style="margin-top:20px;">Please prioritize these vulnerabilities based on the AI-provided insights and your specific environment.<br/>
  <em>Analysis powered by Google Gemini.</em></p>
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
    """Create a donut chart of vulnerability severity levels"""
    df = pd.DataFrame(vulnerabilities)
    # Normalize severity to valid values only
    valid_severities = {'Critical', 'High', 'Medium', 'Low'}
    sev_map = {
        'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low',
        'important': 'High', 'moderate': 'Medium', 'informational': 'Low',
    }
    df['severity_level'] = df['severity_level'].astype(str).str.strip().str.lower().map(
        lambda s: sev_map.get(s, next((v for k, v in sev_map.items() if k in s), 'Medium'))
    )
    severity_counts = df['severity_level'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    
    fig = px.pie(
        severity_counts, 
        values='Count', 
        names='Severity', 
        title='Severity Breakdown',
        color='Severity',
        color_discrete_map={
            'Critical': '#f85149',
            'High': '#d29922',
            'Medium': '#e3b341',
            'Low': '#3fb950'
        },
        hole=0.5,
    )
    fig.update_layout(
        margin=dict(t=36, b=16, l=16, r=16),
        legend=dict(orientation="h", yanchor="bottom", y=-0.18, xanchor="center", x=0.5,
                    font=dict(size=11, color="#8b949e")),
        font=dict(family="Inter, sans-serif", size=12, color="#e6edf3"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        title_font=dict(size=14, color="#e6edf3"),
    )
    fig.update_traces(textposition='inside', textinfo='percent+label',
                      marker=dict(line=dict(color='#161b22', width=2)))
    return fig

def plot_oem_distribution(vulnerabilities):
    """Create a horizontal bar chart of vulnerabilities by vendor"""
    df = pd.DataFrame(vulnerabilities)
    oem_counts = df['oem_name'].value_counts().reset_index()
    oem_counts.columns = ['Vendor', 'Count']
    oem_counts = oem_counts.sort_values('Count', ascending=True)
    
    fig = px.bar(
        oem_counts, 
        y='Vendor', 
        x='Count', 
        title='By Vendor',
        orientation='h',
        text='Count',
    )
    fig.update_traces(
        marker_color='#58a6ff',
        textposition='outside',
        textfont=dict(color="#8b949e", size=11),
    )
    fig.update_layout(
        margin=dict(t=36, b=16, l=16, r=30),
        showlegend=False,
        font=dict(family="Inter, sans-serif", size=12, color="#e6edf3"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        title_font=dict(size=14, color="#e6edf3"),
        xaxis=dict(showgrid=True, gridcolor="#21262d", zeroline=False),
        yaxis=dict(showgrid=False),
    )
    return fig

def plot_time_series(vulnerabilities):
    """Create an area chart of vulnerabilities over time"""
    df = pd.DataFrame(vulnerabilities)
    if 'published_date' not in df.columns:
        return None
    # Strip whitespace / empty strings before conversion so they become NaT
    df['published_date'] = df['published_date'].astype(str).str.strip().replace('', pd.NaT)
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce', utc=True)
    df['published_date'] = df['published_date'].dt.tz_localize(None)  # drop tz so groupby works cleanly
    df = df.dropna(subset=['published_date'])
    if df.empty:
        return None
    time_counts = df.groupby(df['published_date'].dt.normalize()).size().reset_index(name='Count')
    fig = px.area(
        time_counts,
        x='published_date',
        y='Count',
        title='Timeline',
        markers=True,
    )
    fig.update_traces(
        line_color='#58a6ff',
        fillcolor='rgba(56,139,253,.12)',
        marker=dict(size=5, color='#58a6ff'),
    )
    fig.update_layout(
        margin=dict(t=36, b=16, l=16, r=16),
        font=dict(family="Inter, sans-serif", size=12, color="#e6edf3"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        title_font=dict(size=14, color="#e6edf3"),
        xaxis=dict(title="", showgrid=True, gridcolor="#21262d"),
        yaxis=dict(title="Count", showgrid=True, gridcolor="#21262d"),
    )
    return fig

def plot_oem_severity_heatmap(vulnerabilities):
    """Create a heatmap of vulnerabilities by vendor and severity"""
    df = pd.DataFrame(vulnerabilities)
    if 'oem_name' not in df.columns or 'severity_level' not in df.columns:
        return None
    pivot = pd.pivot_table(df, index='oem_name', columns='severity_level', aggfunc='size', fill_value=0)
    if pivot.empty:
        return None
    fig = px.imshow(
        pivot,
        labels=dict(x="Severity", y="Vendor", color="Count"),
        title="Vendor / Severity",
        aspect="auto",
        color_continuous_scale=[[0, '#161b22'], [0.5, '#1f4a6f'], [1, '#58a6ff']],
    )
    fig.update_layout(
        margin=dict(t=36, b=16, l=16, r=16),
        font=dict(family="Inter, sans-serif", size=12, color="#e6edf3"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        title_font=dict(size=14, color="#e6edf3"),
        coloraxis_colorbar=dict(thickness=12, len=0.6),
    )
    return fig


def render_openvas_section():
    """Render the OpenVAS active scanning section on the Scanner page."""

    st.subheader("🛡️ OpenVAS Active Network Scan (Beta)")
    st.caption("Run authenticated OpenVAS/GVM scans directly from this dashboard.")

    if OpenVASConfig is None or not openvas_supported():
        st.info(
            "OpenVAS integration is unavailable. Install dependencies and configure the OpenVAS environment"
            " variables. On Windows, set OPENVAS_BACKEND=docker and ensure Docker Desktop is running."
        )
        return

    def _env_int(name: str, fallback: int) -> int:
        try:
            raw = os.getenv(name, "").strip()
            return int(raw) if raw else fallback
        except ValueError:
            return fallback

    default_scan_name = f"Streamlit Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    timeout_default = _env_int("OPENVAS_TIMEOUT_MINUTES", 45)
    poll_default = _env_int("OPENVAS_POLL_INTERVAL", 30)
    port_default = _env_int("OPENVAS_PORT", 9390)

    with st.form("openvas_scan_form"):
        targets_input = st.text_area(
            "Target hosts or IPs",
            placeholder="192.168.1.10\nweb.example.com",
            help="Specify one target per line. CIDR ranges are supported if enabled on your GVM server.",
        )
        scan_name = st.text_input("Scan name", value=default_scan_name)

        col1, col2 = st.columns(2)
        host = col1.text_input("OpenVAS host", value=os.getenv("OPENVAS_HOST", "127.0.0.1"))
        port = col2.number_input("GMP port", min_value=1, max_value=65535, value=port_default, step=1)

        col3, col4 = st.columns(2)
        username = col3.text_input("OpenVAS username", value=os.getenv("OPENVAS_USERNAME", ""))
        password = col4.text_input("OpenVAS password", value=os.getenv("OPENVAS_PASSWORD", ""), type="password")

        col5, col6 = st.columns(2)
        scan_config_id = col5.text_input(
            "Scan config ID",
            value=os.getenv("OPENVAS_SCAN_CONFIG_ID", ""),
            help="Use `gvm-cli --xml '<get_scan_configs/>'` to locate the ID for profiles such as Full and Fast.",
        )
        port_list_id = col6.text_input(
            "Port list ID",
            value=os.getenv("OPENVAS_PORT_LIST_ID", ""),
            help="List available port lists with `gvm-cli --xml '<get_port_lists/>'`.",
        )

        severity_filter = st.multiselect(
            "Keep severities",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High"],
        )
        verify_tls = st.checkbox(
            "Verify TLS certificates",
            value=os.getenv("OPENVAS_VERIFY_TLS", "false").lower() == "true",
        )
        timeout_minutes = st.slider(
            "Wait timeout (minutes)",
            min_value=5,
            max_value=120,
            value=timeout_default,
        )
        poll_interval = st.slider(
            "Status refresh interval (seconds)",
            min_value=10,
            max_value=120,
            value=poll_default,
        )

        submitted = st.form_submit_button("Run OpenVAS Scan")

    if not submitted:
        return

    targets = [line.strip() for line in targets_input.splitlines() if line.strip()]
    if not targets:
        st.error("Provide at least one host or IP address to scan.")
        return

    required_values = [host, username, password, scan_config_id, port_list_id]
    if any(not value.strip() for value in required_values):
        st.error("Host, credentials, scan config ID, and port list ID are required for OpenVAS scans.")
        return

    config = OpenVASConfig(
        host=host.strip(),
        port=int(port),
        username=username.strip(),
        password=password,
        scan_config_id=scan_config_id.strip(),
        port_list_id=port_list_id.strip(),
        verify_tls=verify_tls,
        timeout_seconds=timeout_minutes * 60,
        poll_interval=poll_interval,
    )

    with st.spinner("Running OpenVAS scan. This can take several minutes depending on the profile and targets..."):
        try:
            new_findings, scan_meta = scan_openvas_targets(
                targets,
                scan_name=scan_name.strip() or None,
                custom_config=config,
                severity_filter=severity_filter,
            )
        except Exception as exc:
            st.error(f"OpenVAS scan failed: {exc}")
            return

    persisted_count = len(new_findings)
    total_report_findings = len(scan_meta.vulnerabilities)
    if persisted_count:
        st.success(
            f"OpenVAS completed. {persisted_count} new finding(s) saved to the database "
            f"({total_report_findings} findings reported before filtering/deduplication)."
        )
        st.session_state.scan_results.extend(new_findings)
        st.session_state.has_new_results = True
        st.dataframe(pd.DataFrame(new_findings), use_container_width=True)
    else:
        st.info(
            "OpenVAS scan finished but no new findings met the selected severity filter or they already existed "
            "in the database."
        )

    with st.expander("OpenVAS scan metadata"):
        st.write(
            {
                "task_id": scan_meta.task_id,
                "report_id": scan_meta.report_id,
                "scan_name": scan_meta.scan_name,
                "duration_seconds": round(scan_meta.duration_seconds, 1),
                "targets": targets,
            }
        )

def main():
    st.set_page_config(
        page_title="VulnGuard — Vulnerability Management",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # ── Professional Dark Theme CSS ────────────────────────────────────
    st.markdown("""
    <style>
    /* ===== Imports ===== */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    /* ===== Root Variables ===== */
    :root {
        --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        --bg-primary: #0f1318;
        --bg-secondary: #161b22;
        --bg-card: #1c2128;
        --bg-elevated: #22272e;
        --border: #30363d;
        --border-subtle: #21262d;
        --text-primary: #e6edf3;
        --text-secondary: #8b949e;
        --text-muted: #6e7681;
        --accent: #58a6ff;
        --accent-subtle: rgba(56,139,253,.15);
        --red: #f85149;
        --red-subtle: rgba(248,81,73,.15);
        --orange: #d29922;
        --orange-subtle: rgba(210,153,34,.15);
        --green: #3fb950;
        --green-subtle: rgba(63,185,80,.15);
        --yellow: #e3b341;
        --yellow-subtle: rgba(227,179,65,.15);
        --purple: #bc8cff;
    }

    /* ===== Global Reset ===== */
    html, body, [class*="css"] {
        font-family: var(--font) !important;
    }
    .main .block-container {
        padding-top: 1.5rem;
        max-width: 1280px;
    }
    footer { visibility: hidden; }
    header[data-testid="stHeader"] {
        background: var(--bg-primary);
        border-bottom: 1px solid var(--border);
    }

    /* ===== Sidebar ===== */
    section[data-testid="stSidebar"] {
        background: var(--bg-secondary);
        border-right: 1px solid var(--border);
    }
    section[data-testid="stSidebar"] [data-testid="stSidebarContent"] {
        padding-top: 1.2rem;
    }
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: var(--text-primary) !important;
        font-weight: 600;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown span,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] .stRadio label {
        color: var(--text-secondary) !important;
    }
    section[data-testid="stSidebar"] hr {
        border-color: var(--border);
        margin: .8rem 0;
    }
    section[data-testid="stSidebar"] .stRadio > div {
        gap: 2px;
    }
    section[data-testid="stSidebar"] .stRadio label {
        padding: .55rem .8rem;
        border-radius: 6px;
        transition: background .15s;
        font-size: .9rem;
    }
    section[data-testid="stSidebar"] .stRadio label:hover {
        background: var(--bg-elevated);
    }
    section[data-testid="stSidebar"] .stRadio label[data-checked="true"],
    section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label[aria-checked="true"] {
        background: var(--accent-subtle);
        color: var(--accent) !important;
        font-weight: 500;
    }

    /* ===== Header Banner ===== */
    .vg-header {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .vg-header-icon {
        width: 48px; height: 48px;
        background: var(--accent-subtle);
        border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.5rem; flex-shrink: 0;
    }
    .vg-header h1 {
        margin: 0; font-size: 1.45rem; font-weight: 700;
        color: var(--text-primary); letter-spacing: -.3px;
    }
    .vg-header p {
        margin: .15rem 0 0 0; font-size: .85rem;
        color: var(--text-secondary); line-height: 1.3;
    }

    /* ===== KPI Metric Cards ===== */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: .85rem;
        margin-bottom: 1.5rem;
    }
    .kpi {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 1.1rem 1.3rem;
        display: flex;
        align-items: center;
        gap: .9rem;
        transition: border-color .15s;
    }
    .kpi:hover { border-color: var(--accent); }
    .kpi-dot {
        width: 40px; height: 40px;
        border-radius: 8px;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.1rem; flex-shrink: 0;
    }
    .kpi-dot-blue   { background: var(--accent-subtle); color: var(--accent); }
    .kpi-dot-red    { background: var(--red-subtle); color: var(--red); }
    .kpi-dot-orange { background: var(--orange-subtle); color: var(--orange); }
    .kpi-dot-green  { background: var(--green-subtle); color: var(--green); }
    .kpi-num {
        font-size: 1.55rem; font-weight: 700; line-height: 1;
        color: var(--text-primary);
    }
    .kpi-lbl {
        font-size: .73rem; font-weight: 500; text-transform: uppercase;
        letter-spacing: .6px; color: var(--text-muted); margin-top: 2px;
    }

    /* ===== Page Section Title ===== */
    .pg-title {
        font-size: 1.05rem;
        font-weight: 600;
        color: var(--text-primary);
        padding-bottom: .45rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid var(--border);
        display: flex;
        align-items: center;
        gap: .5rem;
    }
    .pg-title .pg-icon {
        width: 28px; height: 28px;
        border-radius: 6px;
        display: inline-flex; align-items: center; justify-content: center;
        font-size: .85rem;
        background: var(--accent-subtle);
    }

    /* ===== Empty State ===== */
    .empty-state {
        text-align: center;
        padding: 4rem 1rem;
        color: var(--text-secondary);
    }
    .empty-state .empty-icon {
        width: 56px; height: 56px;
        background: var(--bg-elevated);
        border-radius: 50%;
        display: inline-flex; align-items: center; justify-content: center;
        font-size: 1.5rem; margin-bottom: 1rem;
        border: 1px solid var(--border);
    }
    .empty-state h3 {
        color: var(--text-primary); margin: 0 0 .3rem 0; font-size: 1.05rem;
    }
    .empty-state p { font-size: .87rem; margin: 0; }

    /* ===== Data tables ===== */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 8px;
        overflow: hidden;
    }

    /* ===== Tabs ===== */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
        border-bottom: 1px solid var(--border);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px 6px 0 0;
        padding: .55rem 1.1rem;
        font-weight: 500;
        font-size: .88rem;
    }

    /* ===== Dividers ===== */
    hr {
        border-color: var(--border) !important;
        margin: 1.2rem 0 !important;
    }

    /* ===== Buttons ===== */
    .stButton > button {
        border-radius: 6px;
        font-weight: 500;
        font-size: .85rem;
        padding: .45rem 1rem;
        border: 1px solid var(--border);
        transition: all .15s;
    }
    .stButton > button:hover {
        border-color: var(--accent);
        color: var(--accent);
    }
    .stButton > button[kind="primary"],
    .stButton > button[data-testid="stFormSubmitButton"] {
        background: var(--accent);
        color: white;
        border-color: var(--accent);
    }

    /* ===== Forms / inputs ===== */
    .stTextInput > div > div > input,
    .stTextArea textarea,
    .stNumberInput > div > div > input {
        border-radius: 6px;
        border: 1px solid var(--border);
        font-size: .88rem;
    }
    .stMultiSelect > div {
        border-radius: 6px;
    }
    </style>
    """, unsafe_allow_html=True)

    # Initialize session state
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = []
    if 'has_new_results' not in st.session_state:
        st.session_state.has_new_results = False
    if 'last_page' not in st.session_state:
        st.session_state.last_page = None

    # ── Header ─────────────────────────────────────────────────────────
    st.markdown("""
    <div class="vg-header">
        <div class="vg-header-icon">🛡️</div>
        <div>
            <h1>VulnGuard</h1>
            <p>Enterprise Vulnerability Detection &amp; AI-Powered Analysis</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Initialize database
    setup_database()

    # ── Sidebar ────────────────────────────────────────────────────────
    st.sidebar.markdown("### Navigation")
    pages = ["Dashboard", "Scanner", "Email Notifications", "Settings", "AI Analysis"]
    _page_labels = {
        "Dashboard": "Dashboard",
        "Scanner": "Scanner",
        "Email Notifications": "Notifications",
        "Settings": "Settings",
        "AI Analysis": "AI Analysis",
    }
    selection = st.sidebar.radio(
        "Page",
        pages,
        format_func=lambda p: _page_labels[p],
        label_visibility="collapsed",
    )
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "<span style='font-size:.75rem;color:var(--text-muted);'>Gemini AI &middot; OpenVAS &middot; v2.0</span>",
        unsafe_allow_html=True,
    )
    
    # Reset scan results when changing from Scanner to another page
    if st.session_state.last_page == "Scanner" and selection != "Scanner":
        st.session_state.scan_results = []
        st.session_state.has_new_results = False
    
    # Store current page for next check
    st.session_state.last_page = selection
    
    if selection == "Dashboard":
        st.markdown('<div class="pg-title"><span class="pg-icon">📊</span> Dashboard</div>', unsafe_allow_html=True)
        
        # Get vulnerabilities from database
        all_vulnerabilities = get_vulnerabilities()
        
        if all_vulnerabilities:
            # Compute stats
            all_vulns_count = len(all_vulnerabilities)
            critical_vulns = sum(1 for v in all_vulnerabilities if v['severity_level'] == 'Critical')
            high_vulns = sum(1 for v in all_vulnerabilities if v['severity_level'] == 'High')
            medium_vulns = sum(1 for v in all_vulnerabilities if v['severity_level'] == 'Medium')
            oem_count = len(set(v['oem_name'] for v in all_vulnerabilities))

            # ── KPI Cards ──
            st.markdown(f"""
            <div class="kpi-grid">
                <div class="kpi">
                    <div class="kpi-dot kpi-dot-blue">■</div>
                    <div>
                        <div class="kpi-num">{all_vulns_count}</div>
                        <div class="kpi-lbl">Total</div>
                    </div>
                </div>
                <div class="kpi">
                    <div class="kpi-dot kpi-dot-red">●</div>
                    <div>
                        <div class="kpi-num">{critical_vulns}</div>
                        <div class="kpi-lbl">Critical</div>
                    </div>
                </div>
                <div class="kpi">
                    <div class="kpi-dot kpi-dot-orange">▲</div>
                    <div>
                        <div class="kpi-num">{high_vulns}</div>
                        <div class="kpi-lbl">High</div>
                    </div>
                </div>
                <div class="kpi">
                    <div class="kpi-dot kpi-dot-green">◆</div>
                    <div>
                        <div class="kpi-num">{oem_count}</div>
                        <div class="kpi-lbl">Vendors</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # ── Charts ──
            st.markdown("---")
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                with st.container():
                    severity_chart = plot_severity_distribution(all_vulnerabilities)
                    st.plotly_chart(severity_chart, use_container_width=True)
            
            with chart_col2:
                with st.container():
                    oem_chart = plot_oem_distribution(all_vulnerabilities)
                    st.plotly_chart(oem_chart, use_container_width=True)
            
            chart_col3, chart_col4 = st.columns(2)
            with chart_col3:
                with st.container():
                    time_series_chart = plot_time_series(all_vulnerabilities)
                    if time_series_chart:
                        st.plotly_chart(time_series_chart, use_container_width=True)
                    else:
                        st.info("Not enough date data for time series chart.")
            with chart_col4:
                with st.container():
                    heatmap_chart = plot_oem_severity_heatmap(all_vulnerabilities)
                    if heatmap_chart:
                        st.plotly_chart(heatmap_chart, use_container_width=True)
                    else:
                        st.info("Not enough data for OEM vs. Severity heatmap.")
            
            # ── Filter Section ──
            st.markdown("---")
            st.markdown('<div class="pg-title"><span class="pg-icon">🔎</span> Filter</div>', unsafe_allow_html=True)
            
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
            st.markdown(f'<div class="pg-title"><span class="pg-icon">📋</span> Results &mdash; {len(filtered_df)} found</div>', unsafe_allow_html=True)
            
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
            st.markdown("""
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <h3>No vulnerabilities found</h3>
                <p>Run a scan from the Scanner page to populate this dashboard.</p>
            </div>
            """, unsafe_allow_html=True)
            
    elif selection == "Scanner":
        st.markdown('<div class="pg-title"><span class="pg-icon">🔍</span> Scanner</div>', unsafe_allow_html=True)
        
        # Select sources to scan
        st.markdown("**Sources**")
        # Updated to include Google Cloud Security Bulletins as a source option
        selected_sources = st.multiselect(
            "Sources",
            ["NVD", "CISA", "Cisco", "Google", "Microsoft", "Fortinet", "Palo Alto", "Adobe"],
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
        
        st.divider()
        render_openvas_section()

        st.markdown("---")
        st.markdown("**Current Critical & High Vulnerabilities**")
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
        st.markdown('<div class="pg-title"><span class="pg-icon">📧</span> Notifications</div>', unsafe_allow_html=True)
        
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
        st.markdown('<div class="pg-title"><span class="pg-icon">⚙️</span> Settings</div>', unsafe_allow_html=True)
        
        # Email Configuration
        st.subheader("Email Configuration")
        st.warning("Note: These settings are for demonstration only. In a production environment, use secure methods for storing credentials.")
        
        with st.form("email_settings_form"):
            sender_email = st.text_input("Sender Email", value=EMAIL_CONFIG["sender_email"])
            smtp_server = st.text_input("SMTP Server", value=EMAIL_CONFIG["smtp_server"])
            smtp_port = st.number_input("SMTP Port", value=EMAIL_CONFIG["smtp_port"])
            username = st.text_input("SMTP Username", value=EMAIL_CONFIG["username"])
            password = st.text_input("SMTP Password", value="", type="password",
                                     placeholder="••••••••  (leave blank to keep current)",
                                     help="Stored securely. Leave blank to keep the existing password.")
            
            if st.form_submit_button("Save Email Settings"):
                EMAIL_CONFIG["sender_email"] = sender_email
                EMAIL_CONFIG["smtp_server"] = smtp_server
                EMAIL_CONFIG["smtp_port"] = int(smtp_port)
                EMAIL_CONFIG["username"] = username
                if password:  # only overwrite if user typed a new password
                    EMAIL_CONFIG["password"] = password
                
                st.success("Email settings saved")
        
        # Test SMTP connection
        if st.button("Test SMTP Connection"):
            try:
                with st.spinner("Testing SMTP connection..."):
                    server = smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"])
                    server.set_debuglevel(0)
                    server.starttls()
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
    st.markdown('<div class="pg-title"><span class="pg-icon">🤖</span> AI Analysis</div>', unsafe_allow_html=True)
    
    # Get vulnerabilities from database
    vulnerabilities = get_vulnerabilities()

    if not vulnerabilities:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-icon">🤖</div>
            <h3>No data available</h3>
            <p>Scan for vulnerabilities first to unlock AI analysis.</p>
        </div>
        """, unsafe_allow_html=True)
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