# API-Authentication-Checker

**API-Authentication-Checker** is a Burp Suite extension that helps identify API endpoints accessible without proper authentication. It scans your proxy history for API requests, removes authentication headers (`Cookie` and `Authorization`), resends the requests, and checks if the responses are successful, indicating potential unauthorized access.

## Features

- **Automated Scanning**: Scans Burp Suite proxy history for API endpoints.
- **Authentication Header Removal**: Strips `Cookie` and `Authorization` headers from requests.
- **Response Analysis**: Detects successful responses without authentication.
- **Issue Reporting**: Reports findings in Burp Suite's **Issues** tab.

## Installation

1. **Configure Jython in Burp Suite**:
   - Download the Jython standalone JAR file.
   - In Burp Suite, go to **Extender** > **Options**.
   - Under **Python Environment**, select the Jython JAR file.

2. **Add the Extension**:
   - Download the `API-Authentication-Checker.py` script.
   - In Burp Suite, navigate to **Extender** > **Extensions**.
   - Click **Add** and select the script.

## Usage

- **Define Target Scope**: Ensure your API endpoints are within Burp Suite's scope.
- **Generate Traffic**: Use your browser or API client to interact with the application.
- **Review Findings**: Check the **Target** > **Site map** > **"target domain"** > **Issues** tab for any reported unauthorized access.

---

**Note**: Use this extension responsibly and ensure you have permission to test the target systems.