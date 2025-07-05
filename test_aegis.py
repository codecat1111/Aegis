import unittest
import subprocess
import os

class TestAegis(unittest.TestCase):

    def run_aegis(self, url, config_file=None):
        command = ["python3", "Aegis.py", url] # Changed python to python3
        if config_file:
            command.extend(["--config", config_file])
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        # Print stderr for debugging if it contains anything
        if stderr:
            print("\n--- STDERR from Aegis.py ---")
            print(stderr.decode())
            print("--- END STDERR ---\n")
        return stdout.decode(), stderr.decode()

    def test_invalid_url(self):
        # This test case uses a clearly invalid URL format.
        # Aegis.py is expected to print an error message to stdout.
        stdout, stderr = self.run_aegis("invalid-url")
        self.assertIn("Invalid URL", stdout)

    def test_form_relative_action(self):
        # The test HTML file for this case is 'test_html/form_relative_action.html'.
        # It contains a form with a relative action "submit.php".
        # Aegis.py should identify this as an insecure form action.
        # Note: The URL for the test file needs to be a file URI.
        file_url = "file://" + os.path.abspath("test_html/form_relative_action.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Form Issue: Insecure Form action submit.php", stdout)

    def test_form_absolute_action(self):
        # The test HTML file for this case is 'test_html/form_absolute_action.html'.
        # It contains a form with an absolute action "/submit.php".
        # Aegis.py should identify this as an insecure form action.
        file_url = "file://" + os.path.abspath("test_html/form_absolute_action.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Form Issue: Insecure Form action /submit.php", stdout)

    def test_form_external_action(self):
        # The test HTML file for this case is 'test_html/form_external_action.html'.
        # It contains a form with an external action "http://example.com/submit.php".
        # Aegis.py should identify this as an insecure form action because it's not HTTPS.
        file_url = "file://" + os.path.abspath("test_html/form_external_action.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Form Issue: Insecure Form action http://example.com/submit.php", stdout)

    def test_form_no_action(self):
        # The test HTML file for this case is 'test_html/form_no_action.html'.
        # It contains a form with no action attribute.
        # Aegis.py should handle this gracefully, likely by not reporting a form issue,
        # as the current check is for actions not using HTTPS.
        # Depending on stricter interpretations, this could be flagged, but based on current logic, it's not.
        file_url = "file://" + os.path.abspath("test_html/form_no_action.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertNotIn("Form Issue", stdout) # Expect no form issue reported for missing action

    def test_form_ftp_action(self):
        # The test HTML file for this case is 'test_html/form_ftp_action.html'.
        # It contains a form with an FTP action "ftp://example.com/upload".
        # Aegis.py should identify this as an insecure form action.
        file_url = "file://" + os.path.abspath("test_html/form_ftp_action.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Form Issue: Insecure Form action ftp://example.com/upload", stdout)

    def test_comment_variations(self):
        # The test HTML file for this case is 'test_html/comment_variations.html'.
        # It contains comments with "Key: ", "key : ", and "KEY: ".
        # Aegis.py should identify these as issues.
        file_url = "file://" + os.path.abspath("test_html/comment_variations.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertEqual(stdout.count("Comment Issue: Key is found"), 3)

    def test_comment_multiple_keys(self):
        # The test HTML file for this case is 'test_html/comment_multiple_keys.html'.
        # It contains multiple comments with "key: ".
        # Aegis.py should identify both.
        file_url = "file://" + os.path.abspath("test_html/comment_multiple_keys.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertEqual(stdout.count("Comment Issue: Key is found"), 2)

    def test_comment_large(self):
        # The test HTML file for this case is 'test_html/comment_large.html'.
        # It contains a large comment with a key.
        # Aegis.py should find the key.
        file_url = "file://" + os.path.abspath("test_html/comment_large.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Comment Issue: Key is found", stdout)

    def test_comment_unusual_chars(self):
        # The test HTML file for this case is 'test_html/comment_unusual_chars.html'.
        # It contains comments with unusual characters and a key.
        # Aegis.py should find the key.
        file_url = "file://" + os.path.abspath("test_html/comment_unusual_chars.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Comment Issue: Key is found", stdout)

    def test_no_comments(self):
        # The test HTML file for this case is 'test_html/no_comments.html'.
        # It contains no comments.
        # Aegis.py should not report any comment issues.
        file_url = "file://" + os.path.abspath("test_html/no_comments.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertNotIn("Comment Issue", stdout)

    def test_password_text_type(self):
        # The test HTML file for this case is 'test_html/password_text_type.html'.
        # It contains a password input with type="text".
        # Aegis.py should identify this as an issue.
        file_url = "file://" + os.path.abspath("test_html/password_text_type.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Input Issue: Plaintext password input was found", stdout)

    def test_password_missing_name(self):
        # The test HTML file for this case is 'test_html/password_missing_name.html'.
        # It contains a password input missing the name="password" attribute.
        # Aegis.py should not identify this as an issue, as it specifically looks for name='password'.
        file_url = "file://" + os.path.abspath("test_html/password_missing_name.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertNotIn("Input Issue", stdout)

    def test_multiple_password_fields(self):
        # The test HTML file for this case is 'test_html/multiple_password_fields.html'.
        # It contains multiple password fields, one correctly named, one not.
        # Aegis.py should handle this correctly. If one is misconfigured (e.g. type='text'), it should be flagged.
        # In this specific HTML, both are type='password' but only one is name='password'.
        # The current check is for input with name='password' and type!='password'. So, no issue here.
        file_url = "file://" + os.path.abspath("test_html/multiple_password_fields.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertNotIn("Input Issue: Plaintext password input was found", stdout)


    def test_no_password_fields(self):
        # The test HTML file for this case is 'test_html/no_password_fields.html'.
        # It contains no password fields.
        # Aegis.py should not report any password input issues.
        file_url = "file://" + os.path.abspath("test_html/no_password_fields.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertNotIn("Input Issue", stdout)

    def test_malformed_html(self):
        # The test HTML file for this case is 'test_html/malformed.html'.
        # It contains malformed HTML.
        # Aegis.py should ideally handle this gracefully (e.g., not crash).
        # BeautifulSoup is generally robust to malformed HTML.
        file_url = "file://" + os.path.abspath("test_html/malformed.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Nice Job! Your HTML document is Secure.", stdout) # Expect no crashes and default secure message if no issues found

    def test_large_html(self):
        # The test HTML file for this case is 'test_html/large.html'.
        # It's a large HTML file with a key in a comment.
        # Aegis.py should find the key.
        file_url = "file://" + os.path.abspath("test_html/large.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Comment Issue: Key is found", stdout)

    def test_unusual_tags_html(self):
        # The test HTML file for this case is 'test_html/unusual_tags.html'.
        # It contains unusual HTML tags and a key in a comment.
        # Aegis.py should find the key. BeautifulSoup should handle custom tags.
        file_url = "file://" + os.path.abspath("test_html/unusual_tags.html")
        stdout, stderr = self.run_aegis(file_url)
        self.assertIn("Comment Issue: Key is found", stdout)

    def test_config_forms_false(self):
        # Test with forms disabled in config.
        # 'test_html/form_external_action.html' would normally report a form issue.
        # With forms: false, it should not.
        file_url = "file://" + os.path.abspath("test_html/form_external_action.html")
        # Create a temporary config file
        with open("temp_config.yml", "w") as f:
            f.write("forms: false\ncomments: true\npasswords: true")
        stdout, stderr = self.run_aegis(file_url, "temp_config.yml")
        os.remove("temp_config.yml")
        self.assertNotIn("Form Issue", stdout)
        self.assertIn("Nice Job! Your HTML document is Secure.", stdout) # As no other issues in this file

    def test_config_comments_false(self):
        # Test with comments disabled in config.
        # 'test_html/comment_variations.html' would normally report comment issues.
        # With comments: false, it should not.
        file_url = "file://" + os.path.abspath("test_html/comment_variations.html")
        with open("temp_config.yml", "w") as f:
            f.write("forms: true\ncomments: false\npasswords: true")
        stdout, stderr = self.run_aegis(file_url, "temp_config.yml")
        os.remove("temp_config.yml")
        self.assertNotIn("Comment Issue", stdout)
        self.assertIn("Nice Job! Your HTML document is Secure.", stdout)


    def test_config_passwords_false(self):
        # Test with passwords disabled in config.
        # 'test_html/password_text_type.html' would normally report a password issue.
        # With passwords: false, it should not.
        file_url = "file://" + os.path.abspath("test_html/password_text_type.html")
        with open("temp_config.yml", "w") as f:
            f.write("forms: true\ncomments: true\npasswords: false")
        stdout, stderr = self.run_aegis(file_url, "temp_config.yml")
        os.remove("temp_config.yml")
        self.assertNotIn("Input Issue", stdout) # Password issue should not be reported
                                                # Form issue from password_text_type.html should be reported
        self.assertIn("Form Issue: Insecure Form action submit.php", stdout)


if __name__ == "__main__":
    unittest.main()
