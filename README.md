AUTOMATED CLOUD THREAT DETECTION & INCIDENT RESPONSE USING AWS GUARDDUTY
PROJECT NAME

Automated Cloud Threat Detection & Incident Response using AWS GuardDuty

PROJECT DESCRIPTION

This project implements an automated cloud security monitoring and incident response system using AWS GuardDuty.
The system continuously monitors AWS accounts for suspicious activities and automatically responds to threats such as:

Unauthorized IAM access

Cryptocurrency mining on EC2

Malicious or abnormal API usage

The response actions are fully automated using serverless AWS services.

PROJECT OBJECTIVES

Detect AWS security threats in real time

Automate incident response using AWS Lambda

Reduce manual security intervention

Improve AWS cloud security posture

AWS SERVICES USED

AWS GuardDuty

AWS CloudTrail

Amazon VPC Flow Logs

Amazon EventBridge

AWS Lambda

Amazon SNS

AWS IAM

Amazon S3 (Optional)

ARCHITECTURE WORKFLOW

AWS GuardDuty monitors CloudTrail, VPC Flow Logs, and DNS logs

GuardDuty detects suspicious activity

GuardDuty generates a security finding

Amazon EventBridge captures the finding

EventBridge triggers an AWS Lambda function

Lambda sends alert notifications using SNS

Lambda performs automatic remediation actions

Logs are stored for auditing and analysis

IMPLEMENTATION STEPS
STEP 1: ENABLE AWS GUARDDUTY

Login to AWS Management Console

Navigate to AWS GuardDuty

Click on "Enable GuardDuty"

Keep default settings

GuardDuty starts monitoring immediately.

STEP 2: CREATE SNS TOPIC FOR ALERTS

Open Amazon SNS

Create a Topic

Topic Name: guard-duty-alert

Create a Subscription

Protocol: Email

Endpoint: Your email address

Confirm the subscription from email

This SNS topic is used for security alerts.

STEP 3: CREATE IAM ROLE FOR LAMBDA

Create an IAM role with the following permissions:

AWSLambdaBasicExecutionRole

AmazonSNSFullAccess

AmazonEC2FullAccess

IAMFullAccess

This role allows Lambda to:

Send alerts

Stop EC2 instances

Disable IAM users

Write logs to CloudWatch

STEP 4: CREATE LAMBDA FUNCTION

Open AWS Lambda

Click "Create Function"

Function Name: guardduty_auto_response

Runtime: Python 3.10

Execution Role: Use the IAM role created above

STEP 5: ADD LAMBDA FUNCTION CODE

Copy and paste the following code into the Lambda function:

---------------- LAMBDA CODE START ----------------

import json
import boto3

sns = boto3.client('sns')
ec2 = boto3.client('ec2')
iam = boto3.client('iam')

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:564686914705:guard-duty-alert"

def lambda_handler(event, context):

detail = event.get('detail', {})
finding_type = detail.get('type', 'Unknown')
severity = detail.get('severity', 'Unknown')
title = detail.get('title', 'No Title')
description = detail.get('description', 'No Description')

message = f"""


AWS GuardDuty Alert 🚨

Finding Type : {finding_type}
Severity : {severity}
Title : {title}
Description : {description}
"""

sns.publish(
    TopicArn=SNS_TOPIC_ARN,
    Subject="AWS GuardDuty Security Alert",
    Message=message
)

# Crypto-mining response
if "CryptoCurrency" in finding_type:
    try:
        instance_id = detail['resource']['instanceDetails']['instanceId']
        ec2.stop_instances(InstanceIds=[instance_id])
    except Exception as e:
        print("EC2 stop failed:", e)

# Unauthorized IAM access response
if "UnauthorizedAccess:IAMUser" in finding_type:
    try:
        user_name = detail['resource']['accessKeyDetails']['userName']

        iam.update_login_profile(
            UserName=user_name,
            PasswordResetRequired=True
        )

        keys = iam.list_access_keys(UserName=user_name)
        for key in keys['AccessKeyMetadata']:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
    except Exception as e:
        print("IAM remediation failed:", e)

return {
    "status": "processed",
    "finding_type": finding_type
}


---------------- LAMBDA CODE END ----------------

STEP 6: CREATE EVENTBRIDGE RULE

Go to Amazon EventBridge

Create a Rule

Rule Name: guardduty-event-rule

Event Pattern:
{
"source": ["aws.guardduty"]
}

Target: AWS Lambda

Select Lambda function: guardduty_auto_response

This rule triggers Lambda whenever GuardDuty detects a threat.
