# HellSuite v4.2 - Pentesting Orchestration Platform

**Professional Security Testing Suite with Web Dashboard, Automated Scanning, and Reporting**

![Version](https://img.shields.io/badge/version-4.2-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![Flask](https://img.shields.io/badge/flask-2.3.3-lightgrey)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

- **Role-Based Access Control** (Viewer, Analyst, Admin)
- **Web Dashboard** - Modern Flask interface with unified design
- **Automated Scanning** - Reconnaissance, Fuzzing, Vulnerability Scanning
- **Professional Reporting** - HTML, PDF, and Pwndoc JSON exports
- **Orchestration Engine** - Coordinate multiple security tools
- **Logging & Monitoring** - Professional logging with rotation and redaction
- **Security First** - Input validation, error handling, secure defaults

## Quick Start

### Prerequisites
- Python 3.9+
- Git
- Modern web browser

### Installation

```bash

# Clone the repository
git clone https://github.com/yourusername/hellsuite.git
cd hellsuite

# Install dependencies
pip install -r requirements.txt

# Install Playwright for PDF generation
python -m playwright install

# Setup environment
cp .env.example .env
# Edit .env with your configuration


### Configuration

Edit `.env` file:

<- INICIO BLOQUE BASH
HELLSUITE_SECRET_KEY=your-super-secret-key-change-this
HELLSUITE_DEBUG=False
HELLSUITE_ALLOW_REGISTER=False  # Disable in production!
HELLSUITE_DEFAULT_PASS=your-strong-password-here
<- FIN BLOQUE BASH

### Running

<- INICIO BLOQUE BASH
# Start the dashboard
cd hellSsus/dashboard
python app.py

# Access the dashboard at: http://localhost:5000
# Default credentials: admin / (password from HELLSUITE_DEFAULT_PASS)
<- FIN BLOQUE BASH

### Running Scans

<- INICIO BLOQUE BASH
# Full scan
cd hellSsus
python orchestrate.py http://example.com --project "MyProject" --tools all

# Specific tools only
python orchestrate.py http://example.com --project "Test" --tools recon,fuzz
<- FIN BLOQUE BASH

## Project Structure
hellSuite/
├── hellSsus/ # Main application
│ ├── dashboard/ # Flask web interface
│ ├── config/ # Configuration and logging
│ ├── database/ # SQLite database
│ ├── integrations/ # Tool adapters
│ ├── utils/ # Utilities and helpers
│ └── orchestrate.py # Main orchestrator
├── tools/ # Security tools
│ ├── hellRecon/ # Reconnaissance
│ ├── hellFuzzer/ # Fuzzing engine
│ └── hellScanner/ # Vulnerability scanner
├── shared_data/ # Scans, reports, wordlists
└── logs/ # Application logs (auto-generated)


## Dashboard Features

- **Dashboard Overview** - Statistics and recent projects
- **Project Management** - Create, view, and manage security projects
- **Asset Discovery** - View discovered assets and technologies
- **Vulnerability Management** - Categorized by severity (Critical, High, Medium, Low)
- **Endpoint Analysis** - Discovered endpoints with methods and status codes
- **Reporting** - Generate professional HTML, PDF, and Pwndoc-compatible reports

## Tools Integration

### HellRecon
- Subdomain enumeration
- Technology detection
- Port scanning
- Screenshot capture

### HellFuzzer
- Directory and file discovery
- Parameter fuzzing
- Status code analysis
- Custom wordlist support

### HellScanner
- Common vulnerability detection
- Security header analysis
- Misconfiguration detection
- CVSS scoring

## Reporting

HellSuite generates three types of reports:

1. **HTML Report** - Interactive web report with dashboard design
2. **PDF Report** - Printable professional report
3. **Pwndoc JSON** - Import directly into Pwndoc for client reporting

## User Roles

- **Viewer** - Read-only access to projects and reports
- **Analyst** - Can run scans and view all data
- **Admin** - Full access including user management

## Security Features

- Password hashing with PBKDF2
- Session management with Flask
- Input validation and sanitization
- Secure logging with data redaction
- Environment-based configuration
- SQL injection protection

## Troubleshooting

### Common Issues

1. **"ModuleNotFoundError: No module named 'config'"**
   - Use `hellconfig.py` instead of `config.py`
   - All imports should be `from hellconfig import ...`

2. **PDF generation fails**
   - Install Playwright: `python -m playwright install`
   - Ensure Chrome/Chromium is available

3. **Database errors**
   - Check write permissions in database directory
   - Run database init: `python hellSsus/database/init_database.py`

4. **"Missing required keyword argument" error**
   - The `@require_kwargs` decorator has been removed in v4.2
   - Update your code if using custom integrations

### Logs
Check `hellSsus/logs/` directory for detailed error information:
- `dashboard.log` - Web interface logs
- `hellsuite.log` - Application logs
- `errors.log` - Error-only logs
- Module-specific logs (`orchestrate.log`, `scanner.log`, etc.)

## Roadmap

- [ ] Nuclei integration for advanced vulnerability scanning
- [ ] REST API for automation
- [ ] Docker containerization
- [ ] CI/CD pipeline integration
- [ ] Multi-user collaboration features
- [ ] Advanced reporting templates

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

HellSuite is for **authorized security testing only**. Use only on systems you own or have explicit permission to test. The developers are not responsible for any misuse or damage caused by this tool.

## Acknowledgments

- The HellSuite development team
- Security community contributors
- Open source tools that make this possible

---

**Happy (ethical) hacking!** 🔐