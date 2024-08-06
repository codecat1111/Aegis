# Aegis HTML Vulnerability Analyzer 1.0

## Description

**Aegis** is a comprehensive HTML vulnerability analysis tool designed to identify and mitigate potential security weaknesses in HTML documents. Leveraging advanced parsing and validation techniques, Aegis ensures robust protection against common web vulnerabilities, thereby fortifying the security posture of web applications.

## Key Features

- **URL Validation**: Verifies the validity of the provided URL, including support for localhost and standard web URLs.
- **Form Security Analysis**: Inspects HTML forms for insecure actions, particularly those using non-HTTPS protocols, to prevent man-in-the-middle (MITM) attacks.
- **Comment Scrutiny**: Detects sensitive information embedded in HTML comments, such as keys and credentials, which should be removed to prevent information leakage.
- **Password Input Verification**: Identifies plaintext password input fields and recommends their conversion to secure password input types to protect user credentials.
- **Custom Configuration Support**: Allows for tailored analysis based on user-defined configuration files, providing flexibility and adaptability to specific security requirements.
- **Detailed Reporting**: Generates a comprehensive vulnerability report, highlighting identified issues and providing actionable recommendations for remediation.

## Technical Specifications

- **Language**: Python 3.x
- **Dependencies**: Requires `validators`, `requests`, `PyYAML`, and `BeautifulSoup4` libraries.
- **Configuration**: Supports external YAML configuration files to customize the scope and depth of the analysis.
- **Command-Line Interface**: Intuitive CLI for easy integration into existing security workflows and automation scripts.

## Installation

Ensure all dependencies are installed using pip:

```bash
pip install validators requests pyyaml beautifulsoup4
```
## Usage
Run the Aegis analyzer with the following command:
```bash
python3 aegis.py <URL> --config <path/to/config.yml>
```
Example:
```bash
python3 aegis.py https://example.com --config path/to/config.yml
```
In this example, Aegis analyzes the specified URL using the provided configuration file to check for forms, comments, and password input vulnerabilities as defined in the configuration.

## Configuration File

Aegis uses a YAML configuration file to customize the analysis. Below is an example configuration file **(config.yml)**:
```yml
forms: false
comments: true
passwords: true
```
## Report Generation
After running the analysis, Aegis generates a report summarizing the identified vulnerabilities and providing actionable recommendations.

