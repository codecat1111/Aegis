import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
from bs4 import Comment
import os

# print("Aegis script started") # Removed this debug line

parser = argparse.ArgumentParser(
    description="The Aegis HTML Vulnerability Analyser 1.0")
parser.add_argument('-v', '--version', action="version",
                    version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyse")
parser.add_argument('--config', help='Path to configuration File')
parser.add_argument('-o', '--output', help='Report File Output Path')
args = parser.parse_args()

config = {}
if args.config:
    # This print is for user feedback, not part of the core report
    # print(f"Using Config File {args.config}") # Commented out for testing
    try:
        with open(args.config, 'r') as config_file:
            config = yaml.load(config_file, Loader=yaml.Loader)
        # This print is for user feedback, not part of the core report
        # print(config) # Commented out for testing
    except FileNotFoundError:
        # This print is for user feedback
        print(f"Error: Config file not found at {args.config}")
        # config remains {}
    except yaml.YAMLError as e:
        # This print is for user feedback
        print(f"Error parsing config file {args.config}: {e}")
        # config remains {}

# This print is for user feedback, matching original behavior
# print(args.url) # Intentionally commented out as test_aegis.py captures all stdout for its assertions

report_items = []  # Use a list to collect findings
url = args.url
parsed_url = urlparse(url)
result_html = None
valid_url_for_processing = False # True if URL is syntactically valid and content is readable

# 1. Validate URL and retrieve content
if parsed_url.scheme == 'file':
    try:
        file_path = unquote(parsed_url.path)
        # Adjust for Windows: remove leading '/' if path is like /C:/...
        if os.name == 'nt' and len(file_path) > 1 and file_path[0] == '/' and file_path[1].isalpha() and file_path[2] == ':':
            file_path = file_path[1:]

        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                result_html = f.read()
            valid_url_for_processing = True
        # else: file not found or not a file, valid_url_for_processing remains False
    except Exception: # Catch any error during file processing
        pass # valid_url_for_processing remains False
elif validators.url(url) or parsed_url.hostname in ["localhost", "127.0.0.1"]:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        result_html = response.text
        valid_url_for_processing = True
    except requests.exceptions.RequestException:
        pass # valid_url_for_processing remains False

# 2. Analyze content if successfully retrieved
if valid_url_for_processing and result_html is not None:
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    # Form analysis
    if config.get('forms', True):
        forms = parsed_html.find_all('form')
        for form in forms:
            action = form.get('action')
            if action:  # Only process if action attribute exists
                action_lower = action.lower()
                is_insecure_action = 'https://' not in action_lower

                # If the page is served over http, http actions are acceptable
                if parsed_url.scheme == 'http' and 'http://' in action_lower:
                    is_insecure_action = False

                if is_insecure_action:
                    report_items.append(f'Form Issue: Insecure Form action {action} found in document')
            # else: No action attribute - not flagged by current logic

    # Comment analysis
    if config.get('comments', True):
        comments = parsed_html.find_all(string=lambda text: isinstance(text, Comment))
        for comment_text in comments:
            if 'key:' in comment_text.lower().replace(' ', ''):
                report_items.append('Comment Issue: Key is found in the HTML comment. PLEASE REMOVE')

    # Password input analysis
    if config.get('passwords', True): # Changed 'password_inputs' to 'passwords'
        # Find all input elements with name="password"
        password_inputs_found = parsed_html.find_all('input', attrs={'name': 'password'})
        for pi in password_inputs_found:
            if pi.get('type') != 'password':
                report_items.append('Input Issue: Plaintext password input was found. Please change to password type input')

# 3. Construct final report message
final_report_string = ""
aegis_header = "The Aegis HTML Vulnerability Analyser 1.0\n=========================================="

if not valid_url_for_processing:
    final_report_string = "Invalid URL. Please include full URL including HTTPS or a valid file:// path."
elif not report_items: # Valid URL, processed, no issues
    final_report_string = f"{aegis_header}\nNice Job! Your HTML document is Secure."
else: # Valid URL, processed, issues found
    issues_string = "\n".join(report_items)
    final_report_string = f"{aegis_header}\nYour vulnerability Analysis is as follows:\n==========================================\n{issues_string}"

print(final_report_string)

# 4. Write to output file if specified
if args.output:
    # We write the final_report_string regardless of content, as it will contain
    # either the success message, error message, or issues.
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(final_report_string)
        # User feedback print, not part of the core report for test assertions
        # print(f"Report Generated and saved to {args.output}")
    except Exception as e:
        # User feedback print for file writing error
        print(f"Error writing report to {args.output}: {e}")
