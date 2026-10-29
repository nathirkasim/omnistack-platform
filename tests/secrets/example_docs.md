# Example Configuration Documentation

This file documents configuration examples for developer onboarding. None of these are real secrets.

## FP-SECRET-003: Example Credentials in Documentation

To configure the AWS CLI, run:

```bash
# Example test configuration (non-functional documentation example)
export AWS_ACCESS_KEY_ID="EXAMPLE_KEY_NOT_REAL"
export AWS_SECRET_ACCESS_KEY="EXAMPLE_SECRET_DO_NOT_USE_1234567890"
```

To configure Slack webhook notifications:

```json
{
  "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
}
```

Please replace all examples with your organization-approved credentials via environment variables.
