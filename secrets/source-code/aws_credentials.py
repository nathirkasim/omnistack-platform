# VULNERABLE: Hardcoded AWS credentials in source code
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def upload_to_s3(file_path):
    print(f"Uploading {file_path} using {AWS_ACCESS_KEY_ID}")
