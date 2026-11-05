import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';

export class InsecureCdkStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    new s3.Bucket(this, 'CdkDataBucket', {
      accessControl: s3.BucketAccessControl.PUBLIC_READ,
    });
  }
}
