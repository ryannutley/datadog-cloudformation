from __future__ import print_function
import boto3
import botocore
import time
import json
import sys
import argparse

aws_account_id=""
aws_access_key=""
aws_secret_key=""

# Quick list IAM roles
client = boto3.client('iam', aws_access_key_id='', aws_secret_access_key='')
response = client.list_roles()
print(response)

# Try to create a new IAM role
client = boto3.client('iam', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
log.info("Creating AWS IAM Role...")
response = client.create_role(
    RoleName=AWS_ROLE_NAME,
    AssumeRolePolicyDocument=json.dumps(policy)
)
# Testing creating a Lambda function
client = boto3.client('lambda', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
response = client.create_function(
    FunctionName='Datadog-Logging-Lambda',
    Runtime='python2.7',
    Role='Datadog-Lambda-Role',
    Handler='lambda_function.lambda_handler',
    Code={
        'ZipFile': 'https://github.com/DataDog/dd-aws-lambda-functions/archive/master.zip'
    },
    Description='string',
    Timeout=123,
    MemorySize=1024,
    Tags={
        'lambdaTag': 'logging-activity'
    }
)
print(response)
