"""CloudFormation (YAML/JSON, SAM, Nested Stacks) test cases for IaC benchmark."""

CLOUDFORMATION_CASES = [
    # ---------------------------------------------------------
    # YAML CloudFormation
    # ---------------------------------------------------------
    {
        "id": "CFN-YAML-001",
        "iac_type": "cloudformation",
        "category": "datastores",
        "label": "TRUE_POSITIVE",
        "description": "CloudFormation YAML template creating an unencrypted S3 bucket with PublicRead access control",
        "why_scanner_may_fail": "Baseline CloudFormation YAML test case.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_20",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3",
                "resource": "AWS::S3::Bucket.PublicStorageBucket",
                "file": "template.yaml",
                "line": 6,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"],
        "undeliverable_static": False,
        "files": {
            "template.yaml": """AWSTemplateFormatVersion: '2010-09-09'
Description: S3 Storage Bucket with PublicRead ACL

Resources:
  PublicStorageBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: company-raw-uploads-2026
      AccessControl: PublicRead
      OwnershipControls:
        Rules:
          - ObjectOwnership: BucketOwnerPreferred
"""
        }
    },
    {
        "id": "CFN-YAML-002",
        "iac_type": "cloudformation",
        "category": "network",
        "label": "EVASIVE_MISCONFIG",
        "description": "Security group ingress CIDR 0.0.0.0/0 synthesized via Fn::FindInMap and Fn::Sub intrinsic functions",
        "why_scanner_may_fail": "Scanners without intrinsic function evaluation engine see {!Sub '${NetworkPrefix}.${Suffix}/0'} or map references instead of literal '0.0.0.0/0', causing False Negatives.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "SC-7",
                "resource": "AWS::EC2::SecurityGroup.DynamicIngressSG",
                "file": "template.yaml",
                "line": 19,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html"],
        "undeliverable_static": False,
        "files": {
            "template.yaml": """AWSTemplateFormatVersion: '2010-09-09'
Description: Security Group with Intrinsic Function Resolution

Mappings:
  NetworkMap:
    Production:
      Prefix: "0.0"
      Suffix: "0.0"

Resources:
  DynamicIngressSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Dynamic SSH Ingress SG
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: !Sub
            - "${P1}.${P2}/0"
            - P1: !FindInMap [NetworkMap, Production, Prefix]
              P2: !FindInMap [NetworkMap, Production, Suffix]
"""
        }
    },
    {
        "id": "CFN-YAML-003",
        "iac_type": "cloudformation",
        "category": "datastores",
        "label": "SAFE_LOOKALIKE",
        "description": "CloudFormation S3 Bucket fully hardened with ServerSideEncryptionRule and PublicAccessBlockConfiguration",
        "why_scanner_may_fail": "Baseline safe CloudFormation bucket; no findings should fire.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_19", "CKV_AWS_20", "CKV_AWS_53"],
        "compliance": {"cis": "2.1.1", "nist_800_53": "SC-13", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"],
        "undeliverable_static": False,
        "files": {
            "template.yaml": """AWSTemplateFormatVersion: '2010-09-09'
Description: Secure Hardened S3 Bucket

Resources:
  EncryptedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: company-secure-data-archive
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
"""
        }
    },

    # ---------------------------------------------------------
    # JSON CloudFormation & SAM & Nested Stacks
    # ---------------------------------------------------------
    {
        "id": "CFN-JSON-001",
        "iac_type": "cloudformation",
        "category": "policy-encoding",
        "label": "TRUE_POSITIVE",
        "description": "CloudFormation JSON template creating IAM Policy with Action = '*' and Resource = '*'",
        "why_scanner_may_fail": "Baseline CloudFormation JSON syntax test case.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_1",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 1.16",
                "nist": "AC-6",
                "resource": "AWS::IAM::Policy.OverlyPermissivePolicy",
                "file": "template.json",
                "line": 6,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"],
        "undeliverable_static": False,
        "files": {
            "template.json": """{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Overly Permissive IAM Policy in JSON format",
  "Resources": {
    "OverlyPermissivePolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "FullAdminPolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        },
        "Roles": ["AppExecutionRole"]
      }
    }
  }
}
"""
        }
    },
    {
        "id": "CFN-SAM-001",
        "iac_type": "cloudformation",
        "category": "policy-encoding",
        "label": "TRUE_POSITIVE",
        "description": "AWS SAM Serverless Function assigned AdministratorAccess managed policy",
        "why_scanner_may_fail": "Scanners that do not support the AWS SAM Transform macro fail to expand AWS::Serverless::Function into standard CloudFormation and miss broad IAM grants.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_1",
                "cwe": "CWE-250",
                "cis": "CIS AWS 1.4 - 1.16",
                "nist": "AC-6",
                "resource": "AWS::Serverless::Function.DataProcessorFunction",
                "file": "template.yaml",
                "line": 6,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html"],
        "undeliverable_static": False,
        "files": {
            "template.yaml": """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM function with AdministratorAccess

Resources:
  DataProcessorFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: nodejs20.x
      CodeUri: s3://example-bucket/lambda.zip
      Policies:
        - AdministratorAccess
"""
        }
    },
    {
        "id": "CFN-NEST-001",
        "iac_type": "cloudformation",
        "category": "modules",
        "label": "EVASIVE_MISCONFIG",
        "description": "Nested CloudFormation stack where parent stack delegates creation to a child template containing open security group",
        "why_scanner_may_fail": "Scanners that do not resolve local nested stack references (AWS::CloudFormation::Stack with TemplateURL ./child.yaml) miss the nested resources entirely.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "SC-7",
                "resource": "AWS::EC2::SecurityGroup.ChildOpenSG",
                "file": "child-stack.yaml",
                "line": 6,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-nested-stacks.html"],
        "undeliverable_static": False,
        "files": {
            "parent-stack.yaml": """AWSTemplateFormatVersion: '2010-09-09'
Description: Parent stack managing nested infrastructure

Resources:
  NetworkStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: ./child-stack.yaml
      Parameters:
        EnvName: Production
""",
            "child-stack.yaml": """AWSTemplateFormatVersion: '2010-09-09'
Description: Child stack defining security groups

Parameters:
  EnvName:
    Type: String

Resources:
  ChildOpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Insecure child security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""
        }
    }
]
