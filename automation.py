# Resources from:
# https://aws.amazon.com/blogs/security/how-to-use-aws-organizations-to-automate-end-to-end-account-creation/

# The flow of this automation is as follows:
# - Create an AWS account (this will return an AWS account ID)
# - Create a Datadog account
# - Link AWS and Datadog
# - Deploy resources into AWS and create user roles for Datadog
# - Get the Lambda ARN from new AWS account for log triggers
# - Enable Datadog AWS integration to have logging
# - Do whatever we want with DD account afterwards (automate dashboard creation, user invites, monitors)
from datadog import initialize, api
import boto3
import botocore
import logging, sys
import requests
import json
import time
import sys

# Set up logging... because why not
log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.DEBUG)
log.addHandler(out_hdlr)
log.setLevel(logging.DEBUG)
log.info("Running automation script...")

# Set the master DataDog Account Credentials
MASTER_DD_API_KEY = ""
MASTER_DD_APP_KEY = ""

# Set the master AWS Organization Credetials
MASTER_AWS_ACCOUNT_ID       = ""
MASTER_AWS_ACCESS_KEY       = ''
MASTER_AWS_SECRET_KEY       = ''
MASTER_AWS_ADMIN_EMAIL      = "ryan.nutley@datadoghq.com"

# Other Params / Variables / Statics
AWS_POLICY_NAME             = "DatadogAWSIntegrationPolicy"
AWS_ROLE_NAME               = "DatadogAWSIntegrationRole"
AWS_LAMBDA_FUNCTION         = "Datadog-Logging-Lambda"
AWS_LAMBDA_ROLE             = "Datadog-Role-Lambda"
AWS_REGION                  = "us-east-1"

headers = {'Content-type': 'application/json'}

def aws_createAccount( account_name, account_email, account_role, access_to_billing, organization_unit_id, scp, aws_access_key, aws_secret_key):
    log.info("Creating new AWS account: " + account_name + " (" + account_email + ")")
    # Create a new AWS account and add it to an organization
    client = boto3.client('organizations', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    try:
        create_account_response = client.create_account(Email=account_email, AccountName=account_name, RoleName=account_role, IamUserAccessToBilling=access_to_billing)
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)
    time.sleep(10)
    account_status = 'IN_PROGRESS'
    while account_status == 'IN_PROGRESS':
        create_account_status_response = client.describe_create_account_status(
            CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        log.info("AWS account creation status..."+str(create_account_status_response))
        account_status = create_account_status_response.get('CreateAccountStatus').get('State')
    if account_status == 'SUCCEEDED':
        account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    elif account_status == 'FAILED':
        log.error("AWS account creation failed..." + create_account_status_response.get('CreateAccountStatus').get('FailureReason'))
        sys.exit(1)
    root_id = client.list_roots().get('Roots')[0].get('Id')
    # Move account to the org
    if organization_unit_id is not None:
        try :
            describe_organization_response = client.describe_organizational_unit(
                OrganizationalUnitId=organization_unit_id)
            move_account_response = client.move_account(AccountId=account_id, SourceParentId=root_id, DestinationParentId=organization_unit_id)
        except Exception as ex :
            template = "An exception of type {0} occurred. Arguments:\n{1!r} "
            message = template.format(type(ex).__name__, ex.args)
            # create_organizational_unit(organization_unit_id)
            log.error(message)
    # Attach policy to account if exists
    if scp is not None:
        attach_policy_response = client.attach_policy(PolicyId=scp, TargetId=account_id)
        log.info("Attach policy response "+str(attach_policy_response))
    log.info("AWS account created...")
    log.info("  ACC  ID: %s", account_id)
    return account_id
def aws_assumeRole(account_id, account_role):
    # Assume admin role within the newly created account and return credentials
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role( RoleArn=role_arn, RoleSessionName="NewAccountRole" )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(10)
    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']
def aws_getTemplate(template_file):
    # Read a template file and return the contents
    log.info("Reading resources from " + template_file)
    f = open(template_file, "r")
    cf_template = f.read()
    return cf_template
def aws_deployResources(externalId, credentials, template, stack_name, stack_region):
    log.info("Deploying resources as " + stack_name + " in " + stack_region)
    # Create a CloudFormation stack of resources within the new account
    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], region_name=stack_region)
    log.info("Creating stack " + stack_name + " in " + stack_region)
    creating_stack = True
    while creating_stack is True:
        try:
            creating_stack = False
            create_stack_response = client.create_stack(
                StackName=stack_name,
                TemplateBody=template,
                Parameters=[
                    {
                        'ParameterKey' : 'SharedSecret',
                        'ParameterValue' : externalId
                    }
                ],
                NotificationARNs=[],
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                OnFailure='ROLLBACK',
                Tags=[
                    {
                        'Key': 'ManagedResource',
                        'Value': 'True'
                    },
                    {
                        'Key': 'SampleTag',
                        'Value': 'SomeValue'
                    },
                    {
                        'Key': 'DeployDate',
                        'Value': datestamp
                    }
                ]
            )
        except botocore.exceptions.ClientError as e:
            creating_stack = True
            log.warning(e)
            log.info("Retrying...")
            time.sleep(6)

    stack_building = True
    print("Stack creation in process...")
    print(create_stack_response)
    while stack_building is True:
        event_list = client.describe_stack_events(StackName=stack_name).get("StackEvents")
        stack_event = event_list[0]

        if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
           stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
            stack_building = False
            print("Stack construction complete.")
        elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
              stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
            stack_building = False
            print("Stack construction failed.")
            sys.exit(1)
        else:
            print(stack_event)
            print("Stack building . . .")
            time.sleep(10)

    stack = client.describe_stacks(StackName=stack_name)
    return stack
def aws_createRoles(account_id, credentials, externalId):
    policy={
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Effect": "Allow",
          "Condition": {
            "StringEquals": {
                "sts:ExternalId" : externalId
            }
          },
          "Principal": {
            "AWS": "arn:aws:iam::464622532012:root"
          }
        }
      ]
    }
    log.info("Creating AWS IAM Policy...")
    client = boto3.client('iam', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
    response = client.create_policy(
        PolicyName=AWS_POLICY_NAME,
        PolicyDocument=open('aws_role_policy.json').read()
    )
    arn = response['Policy']['Arn']
    log.info("Creating AWS IAM Role...")
    response = client.create_role(
        RoleName=AWS_ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(policy)
    )
    log.info("Linking Role to Policy...")
    response = client.attach_role_policy(
        PolicyArn=arn,
        RoleName=AWS_ROLE_NAME
    )

## Create a DataDog Account
def dd_createAccount(account_name="Test Account"):
    data = json.dumps({'name': account_name, 'subscription': {'type': 'pro'}, 'billing': {'type': 'parent_billing'}})
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    log.info("Creating a Datadog account...")
    response = requests.post('https://app.datadoghq.com/api/v1/org', params={'api_key': MASTER_DD_API_KEY, 'application_key': MASTER_DD_APP_KEY}, data=data, headers=headers)
    log.debug(response.content)
    parsed = json.loads(response.content)
    if (parsed['org']) :
        dd_account_id       = parsed['org']['public_id']
        dd_app_key  = parsed['application_key']['hash']
        dd_api_key  = parsed['api_key']['key']
        log.info("Datadog account created...")
        log.info("  ORG  ID: %s", dd_account_id)
        log.info("  API KEY: %s", dd_api_key)
        log.info("  APP KEY: %s", dd_app_key)
        return {'account_id': dd_account_id, 'api_key': dd_api_key, 'app_key': dd_app_key}
    else:
        return None
## Add AWS integration to DataDog Account
def dd_enableIntegration_AWSInfra(t_aws_id, t_aws_role, t_dd_api, t_dd_app, tags=[]):
    data = json.dumps({"account_id": t_aws_id, "filter_tags": ["env:staging"], "host_tags": tags, "role_name": t_aws_role})
    log.info("Enabling AWS integration Datadog account...")
    response = requests.post('https://app.datadoghq.com/api/v1/integration/aws', params={'api_key': t_dd_api, 'application_key': t_dd_app}, data=data, headers=headers)
    log.debug(response.content)
    parsed = json.loads(response.content)
    if (parsed['external_id']):
        return parsed['external_id']
    else:
        return None
## Add AWS integration for logging to DataDog Acccount
def dd_enableIntegration_AWSLogging(t_aws_id, t_lambda_arn, t_dd_api, t_dd_app):
    # Link the logger to a lambda function
    data = json.dumps({"account_id": t_aws_id, "lambda_arn": t_lambda_arn })
    log.info("Enabling AWS logging integration on DataDog account...")
    response = requests.post('https://app.datadoghq.com/api/v1/integration/aws/logs', params={'api_key': t_dd_api, 'application_key': t_dd_app}, data=data, headers=headers)
    log.debug(response.content)
    # Enable the services to log
    data = json.dumps({"account_id": t_aws_id, "services": ["s3","elb","elbv2","cloudfront","redshift"] })
    response = requests.post('https://app.datadoghq.com/api/v1/integration/aws/logs/services', params={'api_key': t_dd_api, 'application_key': t_dd_app}, data=data, headers=headers)
    log.info("Enabling AWS services logging integrations on DataDog account...")
    log.debug(response.content)
## Add dashboards in DataDog Account (using the datadog SDK for python rather than raw requests lib)
#widget_json = json.load(open('resources/dashboard_1.json'))
def dd_createDashboard(widget_json, t_dd_api, t_dd_app):
    options = {'api_key': t_dd_api, 'app_key': t_dd_app}
    initialize(**options)
    board_title = "Test Automated Screenboard"
    description = "Made in a test tube"
    width = 1024
    widgets = widget_json
    api.Screenboard.create(board_title=board_title, description=description, widgets=widgets, width=width)
## Add monitors in DataDog Account (using the datadog SDK for python rather than raw requests lib)
def dd_createMonitors(t_dd_api, t_dd_app):
    options = {'api_key': t_dd_api, 'app_key': t_dd_app}
    initialize(**options)
    options = { "notify_no_data": True, "no_data_timeframe": 20 }
    tags = ["app:webserver", "frontend"]
    api.Monitor.create(type="metric alert",query="avg(last_1h):sum:system.net.bytes_rcvd{host:host0} > 100", name="Bytes received on host0", message="We may need to add web hosts if this is consistently high.", tags=tags, options=options)













# -----------------------------------------------------------------------------
# ---------------------------------- WARNING ----------------------------------
# -----------------------------------------------------------------------------
# FOR THE LOVE OF SCIENCE, MAKE SURE YOU HAVE ACCESS TO THIS EMAIL ADDRESS OR YOU'RE IN TROUBLE
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
params={
    "account_name"          : "TEST_ACC",
    "account_email"         : "test@testemail.com",
    "account_role"          : "OrganizationAccountAccessRole",
    "template_file"         : "cloudformation_template.yml",
    "stack_name"            : "DefaultStackName",
    "organization_unit_id"  : "ou-03ik-dyr4fx2b",
    "stack_region"          : "us-east-1",
    "access_key"            : MASTER_AWS_ACCESS_KEY,
    "secret_key"            : MASTER_AWS_SECRET_KEY
}
## CREATE AWS ACCOUNT
aws_account_id = aws_createAccount(params['account_name'], params['account_email'], params['account_role'], "DENY", params['organization_unit_id'], None, params['access_key'], params['secret_key'])
aws_credentials = aws_assumeRole(aws_account_id, params['account_role'])

## CREATE A DATADOG ACCOUNT
dd_credentials = dd_createAccount("CUSTOMER_1")

## LINK DATADOG TO AWS ACCOUNT
dd_externalId = dd_enableIntegration_AWSInfra(aws_account_id, AWS_ROLE_NAME, dd_credentials['api_key'], dd_credentials['app_key'], ["account:staging","account:CUSTOMER_1"])

## Create Roles in AWS
aws_createRoles(aws_account_id, aws_credentials, dd_externalId)

## DEPLOY AWS RESOURCES WITH DATADOG ID
template = aws_getTemplate(params['template_file'])
stack = aws_deployResources(dd_externalId, aws_credentials, template, params['stack_name'], params['stack_region'])
print("Resources deployed for account " + aws_account_id + " (" + params['account_email'] + ")")

# Enable the logging integration
dd_enableIntegration_AWSLogging(aws_account_id, "arn:aws:lambda:"+AWS_REGION+":"+aws_account_id+":function:"+AWS_LAMBDA_FUNCTION, dd_credentials['api_key'], dd_credentials['app_key'])

## BUILD SOME RESOURCES WITHIN DATADOG
dd_createDashboard( json.load(open('resources/dashboard_1.json')), dd_credentials['api_key'], dd_credentials['app_key'] )
dd_createDashboard( json.load(open('resources/dashboard_2.json')), dd_credentials['api_key'], dd_credentials['app_key'] )
