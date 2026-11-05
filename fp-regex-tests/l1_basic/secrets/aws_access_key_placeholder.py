import boto3

AWS_ACCESS_KEY_ID = "YOUR_API_KEY_HERE"
client = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
