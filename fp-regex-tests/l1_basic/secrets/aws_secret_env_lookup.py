import os, boto3

AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
session = boto3.Session(aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
