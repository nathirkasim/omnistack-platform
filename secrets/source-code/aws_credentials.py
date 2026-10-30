# VULNERABLE: Hardcoded AWS credentials in source code
AWS_ACCESS_KEY_ID = "AKIA3MF8T1K6W9P4R7N2"
AWS_SECRET_ACCESS_KEY = "x7jP2qL0zu8v9W2kLp7Qx4mR9zY1nC5vB8kM3wX9"

def upload_to_s3(file_path):
    print(f"Uploading {file_path} using {AWS_ACCESS_KEY_ID}")
