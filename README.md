# hellSuite - Unified Security Assessment Platform
**Current Version:
beta 0.9**

**One suite to orchestrate them all...**

*A professional, modular platform that unifies reconnaissance, vulnerability scanning, fuzzing, and asset management into a single, automated workflow with a centralized dashboard.*

---

## Table of Contents
- [Features](#features)
- [Dashboard Overview](#dashboard-overview)
- [Quick Start](#quick-start)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Your First Scan](#your-first-scan)
- [Orchestrator Usage](#orchestrator-usage)
- [Integrated Tools](#integrated-tools)
    - [HellRecon: Technology Intelligence Scanner](#hellrecon-technology-intelligence-scanner)
    - [HellFuzzer: Directory and File Fuzzer](#hellfuzzer-directory-and-file-fuzzer)
    - [HellScanner: Vulnerability Scanner](#hellscanner-vulnerability-scanner)
    - [Nuclei Scanner: Vulnerability Scanning Engine](#nuclei-scanner-vulnerability-scanning-engine)
- [Project Structure](#project-structure)
- [Database & Reporting](#database--reporting)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [Security Policy](#security-policy)
- [License](#license)

---

## Features

hellSuite is designed for security professionals and red teams who need efficiency and consistency. It integrates multiple scanning phases into a cohesive system.

*   **Unified Dashboard**: Web-based interface (Flask) for real-time project, asset, and vulnerability management.
*   **Intelligent Orchestration**: The `orchestrate.py` script coordinates the entire assessment lifecycle from a single command.
*   **Modular Tool Integration**:
    *   **HellRecon**: Active and passive technology intelligence gathering.
    *   **HellFuzzer**: High-speed directory and endpoint discovery.
    *   **HellScanner**: Custom vulnerability detection and logic flaw testing.
    *   **Nuclei Scanner**: Integration with the powerful Nuclei engine for scanning with thousands of templates.
*   **Centralized SQLite Database**: All findings from all tools are aggregated, deduplicated, and stored in a single source of truth.
*   **Automated Reporting**: Generate consolidated HTML and JSON reports from the dashboard.
*   **Security-First Design**: Built with OWASP Top 10 principles in mind, featuring input validation and safe command execution.

---

## Dashboard Overview

The dashboard provides a central hub for all security assessment activities.

| View | Description |
| :--- | :--- |
| **Projects** | Create and manage different assessment engagements. |
| **Assets** | View all discovered hosts, URLs, and associated technologies. |
| **Vulnerabilities** | Review all findings categorized by tool, severity (Critical, High, Medium, Low, Info), and type. |
| **Endpoints** | Browse directories and files discovered by HellFuzzer. |
| **Reports** | Generate and download professional HTML reports for stakeholders. |

Access it at `http://localhost:5000` after starting the Flask server.

---

## Quick Start

### Prerequisites
*   **Python 3.9+**
*   **Git**
*   **Go** (Required for Nuclei)
*   A modern web browser (for the dashboard)

### Installation

1.  **Clone the repository:**

```
git clone https://github.com/akil3s79/hellSuite.git --depth 1
cd hellSuite
```

2.  **(Recommended) Create a virtual environment:**

```
python -m venv venv
# On Windows
venv\Scripts\activate
# On Linux/macOS
source venv/bin/activate
```

3.  **Install Python dependencies:**

```
pip install -r requirements.txt
```

4.  **Install and configure Nuclei:**

```
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Ensure the Go binary directory is in your PATH
# Update Nuclei templates (first run may take a few minutes)
nuclei -ut
```

5.  **Initialize the database:**

```
cd hellSsus
python dashboard/app.py
```

On first run, the database and necessary tables will be created. You can register a new user via the web interface at `http://localhost:5000/register`.

### Your First Scan
Run a comprehensive scan against a test target using all integrated tools:

```
python orchestrate.py http://testphp.vulnweb.com --project "Initial Assessment" --tools all
```

Results will be automatically imported and visible in the dashboard.

---

## Orchestrator Usage

The `orchestrate.py` script is the command center for automated scans.

### Basic Syntax:

```
python orchestrate.py <TARGET_URL> --project "<PROJECT_NAME>" [--tools TOOL_LIST] [OPTIONS]
```

### Common Examples:

| Command | Purpose |
|--------|---------|
| `python orchestrate.py http://example.com --project "Test" --tools all` | Run all tools (Recon, Fuzzer, Scanner, Nuclei). |
| `python orchestrate.py http://example.com --project "Recon Only" --tools recon` | Run only technology reconnaissance. |
| `python orchestrate.py http://example.com --project "Vuln Scan" --tools scanner,nuclei` | Run only vulnerability-focused tools. |
| `python orchestrate.py -l targets.txt --project "Batch Scan" --tools all` | Scan a list of URLs from a file. |

### Full Options:

```
usage: orchestrate.py [-h] [-l PATH] [--tools TOOLS] --project PROJECT [--verbose]

HellSuite Orchestrator - Executes and coordinates all security tools.

optional arguments:
  -h, --help            show this help message and exit
  -l PATH, --urls-file PATH
                        File containing a list of target URLs (one per line).
  --tools TOOLS         Comma-separated list of tools to run. Options: recon, fuzz, scanner, nuclei, all (default: all).
  --project PROJECT     Name of the project for organizing results (required).
  --verbose, -v         Enable verbose output for debugging.
```

---

## Integrated Tools

### HellRecon: Technology Intelligence Scanner
Discovers technologies, frameworks, and services running on the target.

**Usage:**  
```python tools/hellRecon/hellRecon.py <TARGET> --report-format json -o output.json```

**Key Features**: Identifies web servers, CMS, JavaScript libraries, and security headers.

---

### HellFuzzer: Directory and File Fuzzer
Discovers hidden directories, files, and endpoints using wordlists.

**Usage:**  
```python tools/hellFuzzer/hellFuzzer.py <TARGET> <WORDLIST> --format json --ci```

**Key Features**: Multi-threaded, recursive scanning, configurable filters for status codes and response sizes.

**Wordlists**: Uses common lists from the `shared_data/wordlists/` directory. The `common.txt` list is included by default.

---

### HellScanner: Vulnerability Scanner
A custom-built scanner for detecting application-specific vulnerabilities and logic flaws.

**Usage (Integrated)**: Called automatically by the orchestrator with `--project` and `--url` flags.

**Key Features**: Designed for deep integration with the hellSuite database and reporting engine.

---

### Nuclei Scanner: Vulnerability Scanning Engine
Leverages the power of ProjectDiscovery's Nuclei with thousands of community-powered templates.

**Usage (Integrated)**: Called automatically by the orchestrator. Scans are filtered by `tech,network,vulnerability` tags by default for optimal speed and relevance.

**Customization**: Edit `tools/hellScanner/nucleiscanner.py` to adjust scan parameters like severity, rate limit, or tags.

---

## Project Structure

```
hellSuite/
├── hellSsus/                  # Core dashboard application
│   ├── dashboard/
│   │   ├── app.py            # Flask server
│   │   └── templates/        # Web UI HTML files
│   ├── database/
│   │   └── hellSsus.db       # Central SQLite database
│   ├── integrations/         # Adapters for each tool (import results to DB)
│   └── config/               # Logging and application settings
├── tools/                    # Scanning modules
│   ├── hellRecon/
│   ├── hellFuzzer/
│   ├── hellScanner/          # Contains hellScanner.py & nucleiscanner.py
│   └── shared_tools/         # Common utilities
├── shared_data/
│   ├── scans/                # Raw JSON output from tools
│   ├── reports/              # Final generated reports
│   └── wordlists/            # Wordlists for fuzzing
├── orchestrate.py            # Main orchestration script
├── requirements.txt
└── README.md
```

---

## Database & Reporting

All tool findings are parsed and imported into a unified SQLite database (`hellSsus/database/hellSsus.db`) via dedicated adapters in `hellSsus/integrations/`.

**Tables**: `projects`, `assets`, `vulnerabilities`, `endpoints`

**View Data**: Use the web dashboard or an SQLite browser.

**Generate Reports**: Use the "Reports" section in the dashboard to create consolidated HTML reports for a project.

---

## Screenshots
**Dashboard**

![Dashboard Preview](https://8upload.com/image/18c7ed08c52ce964/dashboard.jpg)

**Endpoints**

![Endpoints Preview](https://8upload.com/image/783f0035fbb1bc32/enpoints.jpg)

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

### Development Guidelines:
- Maintain all code comments and documentation in English.
- Adhere to security best practices (OWASP Top 10).
- Test changes thoroughly before submitting a PR.

---

## Security Policy

We take the security of hellSuite and its users seriously.

### Reporting a Vulnerability
Please do not open public GitHub issues for security vulnerabilities.

If you believe you have found a security issue in hellSuite, please report it responsibly.

- **Email**: Send a detailed description to `garciamoriz@gmail.com`.
- **Details**: Include steps to reproduce, affected versions, and potential impact.
- **Response**: You can expect an acknowledgment within 48 hours and a more detailed follow-up as we investigate.

---

## License

Distributed under the MIT License. See the `LICENSE` file for more information.

This means you are free to use, modify, and distribute this software, provided any distributed modifications are also open-sourced under the same license.

---

**Happy (and responsible) hacking!**

*For educational and authorized security testing purposes only.*

---

You can buy me a coffe if you want!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>