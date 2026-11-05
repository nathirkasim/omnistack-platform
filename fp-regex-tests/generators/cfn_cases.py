from typing import List
from .base import FixtureBuilder, TargetLine

def generate_cfn_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: CLOUDFORMATION
    # -------------------------------------------------------------

    # 1. S3 Bucket Public Read (FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_s3_public_read_flag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  AssetBucket:")
    fb.add("    Type: AWS::S3::Bucket")
    fb.add("    Properties:")
    fb.add_target(
        "      AccessControl: PublicRead",
        "FLAG", "CFN", "L1_BASIC", "CFN-001",
        "S3 bucket configured with PublicRead access control"
    )
    fb.add("      OwnershipControls:")
    fb.add("        Rules:")
    fb.add("        - ObjectOwnership: BucketOwnerPreferred")
    fixtures.append(fb)

    # 2. S3 Bucket Private (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_s3_private_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  SecureBucket:")
    fb.add("    Type: AWS::S3::Bucket")
    fb.add("    Properties:")
    fb.add_target(
        "      AccessControl: Private",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-002",
        "S3 bucket configured with restricted Private access control"
    )
    fixtures.append(fb)

    # 3. Security Group Open Ingress SSH (FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_sg_open_ssh_flag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  InsecureSG:")
    fb.add("    Type: AWS::EC2::SecurityGroup")
    fb.add("    Properties:")
    fb.add("      GroupDescription: Insecure SSH Group")
    fb.add("      SecurityGroupIngress:")
    fb.add("      - IpProtocol: tcp")
    fb.add("        FromPort: 22")
    fb.add("        ToPort: 22")
    fb.add_target(
        "        CidrIp: 0.0.0.0/0",
        "FLAG", "CFN", "L1_BASIC", "CFN-003",
        "Security group ingress exposing SSH port 22 globally"
    )
    fixtures.append(fb)

    # 4. Security Group Private Ingress SSH (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_sg_private_ssh_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  InternalSG:")
    fb.add("    Type: AWS::EC2::SecurityGroup")
    fb.add("    Properties:")
    fb.add("      GroupDescription: Internal Bastion Access")
    fb.add("      SecurityGroupIngress:")
    fb.add("      - IpProtocol: tcp")
    fb.add("        FromPort: 22")
    fb.add("        ToPort: 22")
    fb.add_target(
        "        CidrIp: 10.0.0.0/8",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-004",
        "Security group ingress restricted to private 10.0.0.0/8 prefix"
    )
    fixtures.append(fb)

    # 5. Security Group /29 CIDR Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_sg_cidr_slash29_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  BastionSG:")
    fb.add("    Type: AWS::EC2::SecurityGroup")
    fb.add("    Properties:")
    fb.add("      GroupDescription: Office Bastion")
    fb.add("      SecurityGroupIngress:")
    fb.add("      - IpProtocol: tcp")
    fb.add("        FromPort: 22")
    fb.add("        ToPort: 22")
    fb.add_target(
        "        CidrIp: 3.251.148.96/29",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-005",
        "Specific /29 subnet checking regex anchor precision on 0.0.0.0/0"
    )
    fixtures.append(fb)

    # 6. Security Group Port 2200 Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_sg_port_2200_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  CustomAppSG:")
    fb.add("    Type: AWS::EC2::SecurityGroup")
    fb.add("    Properties:")
    fb.add("      GroupDescription: Custom Port Range")
    fb.add("      SecurityGroupIngress:")
    fb.add("      - IpProtocol: tcp")
    fb.add_target(
        "        FromPort: 2200",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-006",
        "High port 2200 with digit lookalike for port 22"
    )
    fb.add("        ToPort: 2299")
    fb.add("        CidrIp: 0.0.0.0/0")
    fixtures.append(fb)

    # 7. RDS Publicly Accessible (FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_rds_public_flag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  DatabaseInstance:")
    fb.add("    Type: AWS::RDS::DBInstance")
    fb.add("    Properties:")
    fb.add("      DBInstanceClass: db.t3.micro")
    fb.add("      Engine: postgres")
    fb.add_target(
        "      PubliclyAccessible: true",
        "FLAG", "CFN", "L1_BASIC", "CFN-007",
        "Database instance marked publicly accessible"
    )
    fixtures.append(fb)

    # 8. RDS Private & Encrypted (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_rds_private_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  DatabaseInstance:")
    fb.add("    Type: AWS::RDS::DBInstance")
    fb.add("    Properties:")
    fb.add("      DBInstanceClass: db.t3.micro")
    fb.add("      Engine: postgres")
    fb.add_target(
        "      PubliclyAccessible: false",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-008",
        "Database instance isolated from public internet"
    )
    fb.add_target(
        "      StorageEncrypted: true",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-009",
        "Storage encryption enabled on RDS instance"
    )
    fixtures.append(fb)

    # 9. EBS Volume Unencrypted (FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_ebs_unencrypted_flag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  UnencryptedVolume:")
    fb.add("    Type: AWS::EC2::Volume")
    fb.add("    Properties:")
    fb.add("      AvailabilityZone: us-east-1a")
    fb.add("      Size: 100")
    fb.add_target(
        "      Encrypted: false",
        "FLAG", "CFN", "L1_BASIC", "CFN-010",
        "EBS volume with explicit false on encryption property"
    )
    fixtures.append(fb)

    # 10. EBS Volume Encrypted (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_ebs_encrypted_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  EncryptedVolume:")
    fb.add("    Type: AWS::EC2::Volume")
    fb.add("    Properties:")
    fb.add("      AvailabilityZone: us-east-1a")
    fb.add("      Size: 100")
    fb.add_target(
        "      Encrypted: true",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-011",
        "EBS volume with encryption enabled"
    )
    fixtures.append(fb)

    # 11. S3 Public Access Block Configuration (NO_FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_pab_strict_noflag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Resources:")
    fb.add("  DataArchive:")
    fb.add("    Type: AWS::S3::Bucket")
    fb.add("    Properties:")
    fb.add("      PublicAccessBlockConfiguration:")
    fb.add_target(
        "        BlockPublicAcls: true",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-012",
        "Public access block active for public ACL blocking"
    )
    fb.add_target(
        "        BlockPublicPolicy: true",
        "NO_FLAG", "CFN", "L1_BASIC", "CFN-013",
        "Public access block active for public policy blocking"
    )
    fixtures.append(fb)

    # 12. Parameter with Hardcoded Password Default (FLAG)
    fb = FixtureBuilder("l1_basic/cfn/cfn_param_default_password_flag.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Parameters:")
    fb.add("  MasterPassword:")
    fb.add("    Type: String")
    fb.add("    NoEcho: true")
    fb.add_target(
        '    Default: "P@ssw0rd12345!"',
        "FLAG", "CFN", "L1_BASIC", "CFN-014",
        "Hardcoded plaintext default value for sensitive password parameter"
    )
    fb.add("Resources:")
    fb.add("  NullResource:")
    fb.add("    Type: AWS::CloudFormation::WaitConditionHandle")
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: CLOUDFORMATION
    # -------------------------------------------------------------

    # L2-1: Network and Storage Template
    fb = FixtureBuilder("l2_intermediate/cfn/network_and_storage.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Description: Core Network and Database Infrastructure")
    fb.add("Resources:")
    fb.add("  AppSecurityGroup:")
    fb.add("    Type: AWS::EC2::SecurityGroup")
    fb.add("    Properties:")
    fb.add("      GroupDescription: Application Security Group")
    fb.add("      SecurityGroupIngress:")
    fb.add("      - IpProtocol: tcp")
    fb.add("        FromPort: 22")
    fb.add("        ToPort: 22")
    fb.add_target(
        "        CidrIp: 0.0.0.0/0",
        "FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-001",
        "Global SSH ingress rule on 0.0.0.0/0"
    )
    fb.add("      - IpProtocol: tcp")
    fb.add("        FromPort: 22")
    fb.add("        ToPort: 22")
    fb.add_target(
        "        CidrIp: 10.0.0.0/8",
        "NO_FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-002",
        "Internal SSH ingress rule on 10.0.0.0/8"
    )
    fb.add("      - IpProtocol: tcp")
    fb.add("        FromPort: 443")
    fb.add("        ToPort: 443")
    fb.add_target(
        "        CidrIp: 0.0.0.0/0",
        "DEBATABLE", "CFN", "L2_INTERMEDIATE", "CFN-L2-003",
        "Public HTTPS web traffic ingress"
    )
    fb.add("  InternalDB:")
    fb.add("    Type: AWS::RDS::DBInstance")
    fb.add("    Properties:")
    fb.add("      DBInstanceClass: db.t3.micro")
    fb.add("      Engine: postgres")
    fb.add_target(
        "      PubliclyAccessible: false",
        "NO_FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-004",
        "Database inaccessible to public traffic"
    )
    fb.add_target(
        "      StorageEncrypted: true",
        "NO_FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-005",
        "Database storage encryption enabled"
    )
    fb.add("  AppLogBucket:")
    fb.add("    Type: AWS::S3::Bucket")
    fb.add("    Properties:")
    fb.add_target(
        "      AccessControl: Private",
        "NO_FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-006",
        "Private ACL setting on S3 bucket"
    )
    fixtures.append(fb)

    # L2-2: IAM and Security Policies
    fb = FixtureBuilder("l2_intermediate/cfn/iam_and_security.yaml")
    fb.add("AWSTemplateFormatVersion: '2010-09-09'")
    fb.add("Description: IAM Roles and Permissions")
    fb.add("Resources:")
    fb.add("  SuperUserPolicy:")
    fb.add("    Type: AWS::IAM::ManagedPolicy")
    fb.add("    Properties:")
    fb.add("      PolicyDocument:")
    fb.add("        Version: '2012-10-17'")
    fb.add("        Statement:")
    fb.add("        - Effect: Allow")
    fb.add_target(
        "          Action: '*'",
        "FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-007",
        "Wildcard action in IAM policy statement"
    )
    fb.add_target(
        "          Resource: '*'",
        "FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-008",
        "Wildcard resource in IAM policy statement"
    )
    fb.add("  AuditorPolicy:")
    fb.add("    Type: AWS::IAM::ManagedPolicy")
    fb.add("    Properties:")
    fb.add("      PolicyDocument:")
    fb.add("        Version: '2012-10-17'")
    fb.add("        Statement:")
    fb.add("        - Effect: Allow")
    fb.add_target(
        "          Action: 's3:GetObject'",
        "NO_FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-009",
        "Scoped read-only action in policy"
    )
    fb.add("          Resource: 'arn:aws:s3:::audit-bucket/*'")
    fb.add("  OrgRestrictedPolicy:")
    fb.add("    Type: AWS::IAM::ManagedPolicy")
    fb.add("    Properties:")
    fb.add("      PolicyDocument:")
    fb.add("        Version: '2012-10-17'")
    fb.add("        Statement:")
    fb.add("        - Effect: Allow")
    fb.add("          Action: 's3:GetObject'")
    fb.add("          Resource: 'arn:aws:s3:::shared-docs/*'")
    fb.add("          Principal: '*'")
    fb.add("          Condition:")
    fb.add_target(
        "            StringEquals: { 'aws:PrincipalOrgID': 'o-abcdef1234' }",
        "NO_FLAG", "CFN", "L2_INTERMEDIATE", "CFN-L2-010",
        "PrincipalOrgID condition neutralizing open Principal"
    )
    fixtures.append(fb)

    return fixtures
