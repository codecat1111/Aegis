import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(
    description="The Aegis HTML Vulnerability Analyser 1.0")
parser.add_argument('-v', '--version', action="version",
                    version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyse")
parser.add_argument('--config', help='Path to configuration File')
parser.add_argument('-o', '--output', help='Report File Output Path')
args = parser.parse_args()

if args.config:
    print('Using Config File ' + args.config)
    with open(args.config, 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.Loader)
    print(config)
else:
    config = {}

print(args.url)

report = ''
url = args.url
parsed_url = urlparse(url)

# Check if the URL is valid or if it's a localhost URL
if validators.url(url) or parsed_url.hostname in ["localhost", "127.0.0.1"]:
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')
    forms = parsed_html.find_all('form')
    comments = parsed_html.find_all(
        string=lambda text: isinstance(text, Comment))
    password_inputs = parsed_html.find_all('input', {'name': 'password'})
    scripts = parsed_html.find_all('script')
    iframes = parsed_html.find_all('iframe')

    if config.get('forms', True):
        for form in forms:
            if (form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https'):
                report += 'Form Issue: Insecure Form action ' + \
                    form.get('action') + ' found in document\n'

    if config.get('comments', True):
        for comment in comments:
            if 'key: ' in comment:
                report += 'Comment Issue: Key is found in the HTML comment. PLEASE REMOVE\n'

    if config.get('password_inputs', True):
        for password_input in password_inputs:
            if password_input.get('type') != 'password':
                report += 'Input Issue: Plaintext password input was found. Please change to password type input\n'
            if config.get('password_autocomplete', True) and password_input.get('autocomplete') != 'off':
                report += 'Input Issue: Password input field does not have autocomplete="off".\n'
    
    if config.get('inline_javascript', True):
        for script in scripts:
            if not script.get('src'):
                report += 'Inline JavaScript Issue: Inline JavaScript found. Consider moving to an external file.\n'

    if config.get('iframes', True):
        if iframes:
            report += 'Iframe Issue: Found <iframe> tags. These can be a security risk if not used carefully.\n'
else:
    print("Invalid URL. Please include full URL including HTTPS")

if report == '':
    report += "The Aegis HTML Vulnerability Analyser 1.0\n"
    report += "==========================================\n"
    report += "Nice Job! Your HTML document is Secure."
else:
    header = "The Aegis HTML Vulnerability Analyser 1.0\n"
    header += "==========================================\n"
    header += "Your vulnerability Analysis is as follows:\n"
    header += "==========================================\n"
    report = header + report

print(report)
if (args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print("Report Generated and saved to "+args.output)
