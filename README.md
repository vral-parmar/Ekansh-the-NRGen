# Ekansh - The NRGen (Nessus Report Generator)

**Ekansh** is a powerful Python-Flask based tool designed to assist Cyber Security Auditors. It automates the process of generating comprehensive HTML reports and trackers from Nessus CSV exports, streamlining the vulnerability assessment and reporting workflow.

## Prerequisites

Before you begin, ensure you have the following installed on your system:
*   [Python 3.x](https://www.python.org/downloads/)
*   [pip](https://pip.pypa.io/en/stable/installation/) (Python Package Installer)

## Installation & Setup

1.  **Clone or Download** the repository to your local machine.

2.  **Set Up a Virtual Environment** (Recommended):
    It is best practice to run this project in a virtual environment to avoid conflicts with other system dependencies.
    ```bash
    # Create a virtual environment
    python3 -m venv venv

    # Activate the virtual environment
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install Dependencies**: Navigate to the specific module folder you want to use (see *Folder Structure* below) and run:
    ```bash
    pip install -r requirements.txt
    ```

    > **Common Dependencies**: The project generally requires the following packages which will be installed via the requirements file:
    > `flask`, `pandas`, `flask_sqlalchemy`, `flask_login`, `flask_wtf`, `wtforms`, `flask_bcrypt`, `numpy`

## Folder Structure & Module Guide

The project is divided into four distinct modules, each serving a specific reporting purpose. Choose the folder that matches your input data type:

### 1. `Infra-NRGen` (Standard Infrastructure VAPT)
*   **Purpose**: Use this for standard Nessus vulnerability scan exports.
*   **Input**: A standard CSV exported from Nessus.
*   **Key Features**: Generates reports focusing on infrastructure vulnerabilities. Accounts for standard Nessus columns.

### 2. `Infra-Data-NRGen` (Default Configuration)
*   **Purpose**: Use this if your Nessus CSV export was generated with **default configuration** settings.
*   **Scenario**: Sometimes Nessus exports might be missing specific columns like `CVSS v3`, `MSKB`, or `Metasploit`. This module is optimized to handle those restricted datasets without crashing.
*   **Input**: A "Default" config CSV from Nessus.

### 3. `compliance-NRGen` (Compliance Reporting)
*   **Purpose**: Specialized for generating Compliance reports.
*   **Input**: Nessus CSV scans focusing on compliance checks.
*   **Note**: After generation, you may still need to manually edit the resulting HTML file to fine-tune the presentation according to specific compliance standards.

### 4. `web-owasp-NRGen` (Web Application Reporting)
*   **Purpose**: specialized for Web Application Vulnerability Reporting (OWASP style).
*   **Input**: **Manual CSV Creation Required**.
*   **Requirement**: This module expects a specific CSV structure. You cannot just feed it a raw Nessus scan. You must construct a CSV file manually following the template found in `Sampleweb.csv`.
*   **Columns Expected**: `OWASP Classification`, `Severity`, `Vulnerability`, `Description`, `Impact`, `URL`, `Remediation`, `References`, `CVSS v3`, `Vector`, `CWE`.

---

## Usage Instructions

Each module operates as a standalone Flask application. Follow these steps to run the tool:

1.  **Navigate** to the desired directory:
    ```bash
    cd infra-NRGen  # OR infra-Data-NRGen, compliance-NRGen, web-owasp-NRGen
    ```

2.  **Run the Application**:
    ```bash
    python app.py
    ```

3.  **Access the Interface**:
    *   Open your web browser.
    *   Navigate to the URL shown in your terminal (usually `http://127.0.0.1:5000` or `http://0.0.0.0:80`).
    *   **Note**: `infra-NRGen` attempts to run on **Port 80**, which may require administrative privileges (sudo) or might conflict if another service is running. `web-owasp-NRGen` runs on **Port 5000**.

4.  **Login / Register**:
    *   The tools use a local database for authentication.
    *   First-time users should click **Register** to create a local account.
    *   **Login** with your new credentials to access the dashboard.

5.  **Generate Report**:
    *   Upload your `.csv` file via the dashboard.
    *   The tool will process the file.

## Workflow & Output Handling

Upon successfully uploading the CSV file, the tool automatically generates two distinct outputs:

1.  **Excel Tracker**: A spreadsheet designed for tracking vulnerability remediation status.
2.  **HTML Report**: A styled report for presentation and sharing.

**Post-Processing Note**: The generated HTML report is intended to be a starting point. For final customization and editing:
*   Open the generated HTML file using **Microsoft Word**.
*   This allows you to make manual edits, adjust formatting, and refine the content as needed.
*   Once finalized, save the document as a `.docx` or PDF report for distribution.

## Important Notes

*   **Port Conflicts**:
    *   If you see `Address already in use` errors, check if another service is using the port.
    *   You can edit the `app.run(port=...)` line at the bottom of `app.py` to change the port number if needed.
*   **Database**: Each folder has its own `database.sqlite3` instance. Accounts created in one module (e.g., Infra) will **not** work in another (e.g., Web). You need to register separately for each.
*   **CSV Formatting**: Ensure your CSV headers exactly match what the tool expects. For `infra-NRGen` and `compliance-NRGen`, use standard Nessus exports. For `web-owasp-NRGen`, strictly follow the `Sampleweb.csv` format.

## Security Notice & Disclaimer

> **⚠️ CRITICAL WARNING: DO NOT USE IN PRODUCTION**

This project is intended strictly for **LOCAL USE ONLY**.

*   **Vulnerability Risk**: The application contains multiple known security vulnerabilities and is **not** hardened for public deployment.
*   **No Responsibility**: The authors and contributors accept **no responsibility** for any security holes, data breaches, or legal consequences arising from the use or misuse of this software.
*   **Usage Constraints**: Use this tool only in a controlled, secure environment. **Do not** deploy this application on a public-facing server or an insecure network.

By using this software/code, you acknowledge that you are doing so at your own risk.


## License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this software, provided that you include the original copyright notice and license in any copies. See the [LICENSE](LICENSE) file for details.

