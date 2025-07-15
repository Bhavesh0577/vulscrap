# 🔒 OEM Vulnerability Scanner

A comprehensive, AI-powered vulnerability scanner that monitors multiple OEM sources for critical security vulnerabilities and provides intelligent analysis, prioritization, and automated notifications.

## 🚀 Features

### Core Scanning Capabilities

- **Multi-Source Vulnerability Detection**: Monitors 10+ OEM sources including:
  - National Vulnerability Database (NVD)
  - CISA Known Exploited Vulnerabilities Catalog
  - Microsoft Security Response Center
  - Cisco Security Advisories
  - Google Cloud Security Bulletins
  - Oracle Security Alerts
  - VMware Security Advisories
  - IBM Security Bulletins
  - Adobe Security Bulletins
  - HPE Security Bulletins

### AI-Powered Analysis

- **Google Gemini 2.0 Flash Integration**: Advanced AI analysis for vulnerabilities
- **Smart Prioritization**: AI-driven vulnerability prioritization based on organizational context
- **Automated Mitigation Planning**: Generate detailed remediation plans
- **Impact Assessment**: Technical and business impact analysis
- **Threat Intelligence**: Enhanced threat intelligence for CVEs
- **Audience-Specific Reports**: Tailored explanations for technical, executive, and compliance teams

### Real-Time Monitoring & Notifications

- **Email Notifications**: Automated email alerts for critical/high severity vulnerabilities
- **Customizable Recipients**: Manage email notification recipients
- **Rich Email Content**: HTML-formatted emails with vulnerability details and AI insights
- **CSV Export**: Export vulnerability data for further analysis

### Interactive Dashboard

- **Streamlit Web Interface**: Modern, responsive web application
- **Real-time Visualization**: Charts and graphs for vulnerability trends
- **Filtering & Search**: Advanced filtering by severity, OEM, date range
- **Data Export**: Export filtered results to CSV

## 🛠️ Technology Stack

- **Frontend**: Streamlit
- **Backend**: Python 3.8+
- **Database**: SQLite
- **AI Integration**: Google Gemini 2.0 Flash
- **Web Scraping**: Playwright, BeautifulSoup, Requests
- **Visualization**: Plotly
- **Email**: SMTP with HTML support

## 📋 Prerequisites

- Python 3.8 or higher
- Google Gemini API key
- Email server credentials (for notifications)
- Internet connection for vulnerability source monitoring

## 🔧 Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Bhavesh0577/vulscrap.git
   cd vulscrap
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Install Playwright browsers**:

   ```bash
   playwright install
   ```

4. **Set up environment variables**:
   Create a `.env` file in the project root:

   ```env
   # Google Gemini API Configuration
   GEMINI_API=your_gemini_api_key_here

   # Email Configuration
   EMAIL_SENDER=your_email@domain.com
   EMAIL_USERNAME=your_email@domain.com
   EMAIL_PASSWORD=your_app_password
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   ```

## 🚀 Usage

### Starting the Application

```bash
streamlit run streamlit_app.py
```

The application will be available at `http://localhost:8501`

### Application Navigation

#### 1. Dashboard

- Overview of all vulnerabilities
- Filtering options (severity, OEM, date range)
- Vulnerability statistics and visualizations
- AI-enhanced vulnerability details

#### 2. Scanner

- Select and scan multiple OEM sources
- Real-time scanning progress
- View newly discovered vulnerabilities
- Automated database storage

#### 3. Email Notifications

- Manage email recipients
- Configure notification settings
- Test email functionality
- Send alerts for critical/high vulnerabilities

#### 4. Settings

- Configure email server settings
- View and manage vulnerability sources
- System configuration options

#### 5. AI Analysis

- **Smart Prioritization**: AI-driven vulnerability ranking
- **AI Insights**: Detailed vulnerability analysis
- **Mitigation Planning**: Automated remediation strategies
- **Audience-Specific Reports**: Tailored explanations
- **Threat Intelligence**: Enhanced CVE information

### Command Line Usage

You can also run the scanner from the command line:

```bash
python vulnerability_scanner.py [source_name]
```

Available sources: NVD, CISA, Cisco, Microsoft, Google, Oracle, VMware, IBM, Adobe, HPE

## 📊 Database Schema

The application uses SQLite with the following tables:

### Vulnerabilities Table

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_name TEXT,
    product_version TEXT,
    oem_name TEXT,
    severity_level TEXT,
    vulnerability_description TEXT,
    mitigation_strategy TEXT,
    published_date TEXT,
    cve_id TEXT UNIQUE,
    url TEXT,
    discovered_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notified BOOLEAN DEFAULT FALSE
);
```

### Recipients Table

```sql
CREATE TABLE recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE
);
```

## 🤖 AI Features

### Vulnerability Analysis

- **Summary Generation**: Plain-language vulnerability explanations
- **Technical Impact**: Detailed technical analysis
- **Business Impact**: Potential business consequences
- **Exploitation Assessment**: Difficulty rating for exploitation
- **Attack Vectors**: Likely attack methods
- **Detection Methods**: Ways to detect exploitation

### Smart Prioritization

- **Context-Aware Ranking**: Considers organizational environment
- **Risk Scoring**: 1-10 priority scale with rationale
- **Remediation Timeframes**: Suggested action timelines

### Mitigation Planning

- **Immediate Actions**: Quick mitigation steps
- **Long-term Strategy**: Comprehensive remediation approach
- **Resource Requirements**: Effort and resource estimates
- **Compensating Controls**: Alternative security measures
- **Verification Steps**: Validation procedures

## 📧 Email Notifications

### Features

- **Automated Alerts**: Sends notifications for critical/high vulnerabilities
- **Rich HTML Content**: Formatted emails with vulnerability details
- **AI-Enhanced Emails**: Optional AI insights in notifications
- **CSV Attachments**: Vulnerability data export
- **Multiple Recipients**: Support for multiple email addresses

### Configuration

Configure email settings in the `.env` file or through the web interface.

## 🔍 Supported Vulnerability Sources

| Source    | Type | Description                             |
| --------- | ---- | --------------------------------------- |
| NVD       | API  | National Vulnerability Database         |
| CISA      | API  | Known Exploited Vulnerabilities Catalog |
| Microsoft | Web  | Security Response Center                |
| Cisco     | Web  | Security Advisories                     |
| Google    | Web  | Cloud Security Bulletins                |
| Oracle    | Web  | Security Alerts                         |
| VMware    | Web  | Security Advisories                     |
| IBM       | Web  | Security Bulletins                      |
| Adobe     | Web  | Security Bulletins                      |
| HPE       | Web  | Security Bulletins                      |

## 📈 Visualizations

The dashboard includes:

- **Severity Distribution**: Pie chart of vulnerability severities
- **OEM Distribution**: Bar chart of vulnerabilities by vendor
- **Time Series**: Vulnerability discovery trends
- **Heatmap**: OEM vs. Severity correlation

## 🔐 Security Considerations

- **API Key Security**: Store API keys in environment variables
- **Database Security**: SQLite database with proper permissions
- **Email Security**: Use app-specific passwords for email accounts
- **Input Validation**: Sanitized input handling for web scraping
- **Error Handling**: Comprehensive error handling and logging

## 🛡️ Error Handling & Logging

- **Comprehensive Logging**: All activities logged to `vulnerability_scraper.log`
- **Graceful Degradation**: Application continues working if some sources fail
- **Retry Mechanisms**: Automatic retry for network failures
- **User Feedback**: Clear error messages in the web interface

## 📝 Configuration

### Adding New Sources

To add new vulnerability sources, edit the `OEM_SOURCES` dictionary in `vulnerability_scanner.py`:

```python
OEM_SOURCES = {
    "NewSource": {
        "url": "https://example.com/security",
        "selector": "div.vulnerability-item",
        "requires_js": True,
        "mapping": {
            "product_name": {"selector": "h3.product", "attribute": "text"},
            "severity": {"selector": "span.severity", "attribute": "text"},
            # ... other mappings
        }
    }
}
```

### Customizing AI Prompts

AI prompts can be customized in the `gemini_integration.py` file for different analysis needs.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## 👥 Author

**Bhavesh** - [GitHub](https://github.com/Bhavesh0577)

## 🆘 Support

For support, please open an issue on GitHub or contact the development team.


**⚠️ Disclaimer**: This tool is for educational and security research purposes. Always follow responsible disclosure practices and comply with applicable laws and regulations when using this software.
