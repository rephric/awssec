import re
import click
from truffleHog import truffleHog
import json
import boto3
from botocore.exceptions import ClientError
import os
import logging
import time
import base64
import csv


class AwsAccessKey(click.ParamType):
    # Search for access key IDs: (?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).
    name = 'aws_access_key'

    def convert(self, value, param, ctx):
        found = re.match(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', value)

        if not found:
            self.fail(
                'AWS Access Key is not a AWS Access Key IDs',
                param
            )

        return value


class AwsSecretAccessKey(click.ParamType):
    # Search for secret access keys: (?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=]).
    name = 'aws_secret_access_key'

    def convert(self, value, param, ctx):
        found = re.match(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', value)

        if not found:
            self.fail(
                'AWS Secret Access Key is not a AWS Secret Access Key IDs',
                param
            )

        return value


def truffle(git_url, do_regex, custom_regex):
    if do_regex:
        strings_found = truffleHog.find_strings(git_url=git_url, since_commit=None, max_depth=1000000,
                                                printJson=True, do_regex=True, do_entropy=True,
                                                surpress_output=True)
    if not do_regex:
        strings_found = truffleHog.find_strings(git_url=git_url, since_commit=None,
                                                max_depth=1000000, printJson=True, do_entropy=True,
                                                surpress_output=True)
    found_issues = strings_found['foundIssues']
    found = {}
    count = 0
    for issues in found_issues:
        with open(issues, 'r') as issue:
            data = json.loads([line.rstrip() for line in issue][0], strict=False)
            found['issue%s' % count] = data
        count += 1
    return found


def def_config(accesskey, secretkey, session_token):
    if session_token.strip() == '':
        session_token = None
    client = boto3.client(
        'iam',
        aws_access_key_id=accesskey,
        aws_secret_access_key=secretkey,
        aws_session_token=session_token
    )
    users = client.list_users()
    for user in users['Users']:
        user = (user['UserName'])
        try:
            response = client.get_login_profile(UserName=user)
        except Exception as e:
            logging.error('User %s does not have a login account set up.' % user)
            logging.error(e)
            continue
        try:
            response = client.get_credential_report()
        except Exception as e:
            logging.error('No credential report could be retrieved.')
            logging.error(e)
        user_info = base64.b64decode(response['Content'])
    return users


def check_policy(accesskey, secretkey, sessiontoken):
    access_key_id = accesskey
    secret_access_key = secretkey
    session_token = sessiontoken

    if accesskey is None or secretkey is None:
        print('IAM keys not passed in as arguments, enter them below:')
        access_key_id = click.prompt("Please enter your AWS Access Key", type=AwsAccessKey(),
                                     hide_input=True, default=accesskey)
        secret_access_key = click.prompt("Please enter your AWS Secret Access Key", hide_input=True,
                                         type=AwsSecretAccessKey(), default=secretkey)
        session_token = click.prompt("Please enter your AWS Session Token", hide_input=True, type=sessiontoken)
        if session_token.strip() == '':
            session_token = None

    # Begin permissions enumeration
    current_user = None
    users = []
    client = boto3.client(
        'iam',
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token
    )
    all_users = True
    if all_users is True:
        response = client.list_users()
        for user in response['Users']:
            users.append({'UserName': user['UserName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
        while 'IsTruncated' in response and response['IsTruncated'] is True:
            response = client.list_users(
                Marker=response['Marker']
            )
            for user in response['Users']:
                users.append({'UserName': user['UserName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
    elif args.user_name is not None:
        users.append({'UserName': args.user_name, 'Permissions': {'Allow': {}, 'Deny': {}}})
    else:
        current_user = client.get_user()['User']
        current_user = {
            'UserName': current_user['UserName'],
            'Permissions': {
                'Allow': {},
                'Deny': {}
            }
        }
        users.append(current_user)
    print('Collecting policies for {} users...'.format(len(users)))
    for user in users:
        user['Groups'] = []
        user['Policies'] = []
        try:
            policies = []

            # Get groups that the user is in
            try:
                res = client.list_groups_for_user(
                    UserName=user['UserName']
                )
                user['Groups'] = res['Groups']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_groups_for_user(
                        UserName=user['UserName'],
                        Marker=groups['Marker']
                    )
                    user['Groups'] += res['Groups']
            except Exception as e:
                print('List groups for user failed: {}'.format(e))
                user['PermissionsConfirmed'] = False

            # Get inline and attached group policies
            for group in user['Groups']:
                group['Policies'] = []
                # Get inline group policies
                try:
                    res = client.list_group_policies(
                        GroupName=group['GroupName']
                    )
                    policies = res['PolicyNames']
                    while 'IsTruncated' in res and res['IsTruncated'] is True:
                        res = client.list_group_policies(
                            GroupName=group['GroupName'],
                            Marker=res['Marker']
                        )
                        policies += res['PolicyNames']
                except Exception as e:
                    print('List group policies failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                # Get document for each inline policy
                for policy in policies:
                    group['Policies'].append({ # Add policies to list of policies for this group
                        'PolicyName': policy
                    })
                    try:
                        document = client.get_group_policy(
                            GroupName=group['GroupName'],
                            PolicyName=policy
                        )['PolicyDocument']
                    except Exception as e:
                        print('Get group policy failed: {}'.format(e))
                        user['PermissionsConfirmed'] = False
                    user = parse_document(document, user)

                # Get attached group policies
                attached_policies = []
                try:
                    res = client.list_attached_group_policies(
                        GroupName=group['GroupName']
                    )
                    attached_policies = res['AttachedPolicies']
                    while 'IsTruncated' in res and res['IsTruncated'] is True:
                        res = client.list_attached_group_policies(
                            GroupName=group['GroupName'],
                            Marker=res['Marker']
                        )
                        attached_policies += res['AttachedPolicies']
                    group['Policies'] += attached_policies
                except Exception as e:
                    print('List attached group policies failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                user = parse_attached_policies(client, attached_policies, user)

            # Get inline user policies
            policies = []
            if 'Policies' not in user:
                user['Policies'] = []
            try:
                res = client.list_user_policies(
                    UserName=user['UserName']
                )
                policies = res['PolicyNames']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_user_policies(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    policies += res['PolicyNames']
                for policy in policies:
                    user['Policies'].append({
                        'PolicyName': policy
                    })
            except Exception as e:
                print('List user policies failed: {}'.format(e))
                user['PermissionsConfirmed'] = False
            # Get document for each inline policy
            for policy in policies:
                try:
                    document = client.get_user_policy(
                        UserName=user['UserName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except Exception as e:
                    print('Get user policy failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                user = parse_document(document, user)
            # Get attached user policies
            attached_policies = []
            try:
                res = client.list_attached_user_policies(
                    UserName=user['UserName']
                )
                attached_policies = res['AttachedPolicies']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_attached_user_policies(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    attached_policies += res['AttachedPolicies']
                user['Policies'] += attached_policies
            except Exception as e:
                print('List attached user policies failed: {}'.format(e))
                user['PermissionsConfirmed'] = False
            user = parse_attached_policies(client, attached_policies, user)
            user.pop('Groups', None)
            user.pop('Policies', None)
        except Exception as e:
            print('Error, skipping user {}:\n{}'.format(user['UserName'], e))
        print('  {}... done!'.format(user['UserName']))

    print('  Done.\n')

    # Begin privesc scanning
    all_perms = [
        'iam:AddUserToGroup',
        'iam:AttachGroupPolicy',
        'iam:AttachRolePolicy',
        'iam:AttachUserPolicy',
        'iam:CreateAccessKey',
        'iam:CreatePolicyVersion',
        'iam:CreateLoginProfile',
        'iam:PassRole',
        'iam:PutGroupPolicy',
        'iam:PutRolePolicy',
        'iam:PutUserPolicy',
        'iam:SetDefaultPolicyVersion',
        'iam:UpdateAssumeRolePolicy',
        'iam:UpdateLoginProfile',
        'sts:AssumeRole',
        'ec2:RunInstances',
        'lambda:CreateEventSourceMapping',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'lambda:UpdateFunctionCode',
        'dynamodb:CreateTable',
        'dynamodb:PutItem',
        'glue:CreateDevEndpoint',
        'glue:UpdateDevEndpoint',
        'cloudformation:CreateStack',
        'datapipeline:CreatePipeline'
    ]

    escalation_methods = {
        'CreateNewPolicyVersion': {
            'iam:CreatePolicyVersion': True
        },
        'SetExistingDefaultPolicyVersion': {
            'iam:SetDefaultPolicyVersion': True
        },
        'CreateEC2WithExistingIP': {
            'iam:PassRole': True,
            'ec2:RunInstances': True
        },
        'CreateAccessKey': {
            'iam:CreateAccessKey': True
        },
        'CreateLoginProfile': {
            'iam:CreateLoginProfile': True
        },
        'UpdateLoginProfile': {
            'iam:UpdateLoginProfile': True
        },
        'AttachUserPolicy': {
            'iam:AttachUserPolicy': True
        },
        'AttachGroupPolicy': {
            'iam:AttachGroupPolicy': True
        },
        'AttachRolePolicy': {
            'iam:AttachRolePolicy': True,
            'sts:AssumeRole': True
        },
        'PutUserPolicy': {
            'iam:PutUserPolicy': True
        },
        'PutGroupPolicy': {
            'iam:PutGroupPolicy': True
        },
        'PutRolePolicy': {
            'iam:PutRolePolicy': True,
            'sts:AssumeRole': True
        },
        'AddUserToGroup': {
            'iam:AddUserToGroup': True
        },
        'UpdateRolePolicyToAssumeIt': {
            'iam:UpdateAssumeRolePolicy': True,
            'sts:AssumeRole': True
        },
        'PassExistingRoleToNewLambdaThenInvoke': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True,
            'lambda:InvokeFunction': True
        },
        'PassExistingRoleToNewLambdaThenTriggerWithNewDynamo': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True,
            'lambda:CreateEventSourceMapping': True,
            'dynamodb:CreateTable': True,
            'dynamodb:PutItem': True
        },
        'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True,
            'lambda:CreateEventSourceMapping': True
        },
        'PassExistingRoleToNewGlueDevEndpoint': {
            'iam:PassRole': True,
            'glue:CreateDevEndpoint': True
        },
        'UpdateExistingGlueDevEndpoint': {
            'glue:UpdateDevEndpoint': True
        },
        'PassExistingRoleToCloudFormation': {
            'iam:PassRole': True,
            'cloudformation:CreateStack': True
        },
        'PassExistingRoleToNewDataPipeline': {
            'iam:PassRole': True,
            'datapipeline:CreatePipeline': True
        },
        'EditExistingLambdaFunctionWithRole': {
            'lambda:UpdateFunctionCode': True
        }
    }
    import re
    for user in users:
        print('User: {}'.format(user['UserName']))
        checked_perms = {'Allow': {}, 'Deny': {}}
        # Preliminary check to see if these permissions have already been enumerated in this session
        if 'Permissions' in user and 'Allow' in user['Permissions']:
            # Are they an admin already?
            if '*' in user['Permissions']['Allow'] and user['Permissions']['Allow']['*'] == ['*']:
                user['CheckedMethods'] = {'admin': {}, 'Confirmed':{}, 'Potential': {}}
                print('  Already an admin!\n')
                continue
            for perm in all_perms:
                for effect in ['Allow', 'Deny']:
                    if perm in user['Permissions'][effect]:
                        checked_perms[effect][perm] = user['Permissions'][effect][perm]
                    else:
                        for user_perm in user['Permissions'][effect].keys():
                            if '*' in user_perm:
                                pattern = re.compile(user_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = user['Permissions'][effect][user_perm]

        checked_methods = {
            'Potential': [],
            'Confirmed': []
        }

        # Ditch each escalation method that has been confirmed not to be possible
        for method in escalation_methods:
            potential = True
            confirmed = True
            for perm in escalation_methods[method]:
                if perm not in checked_perms['Allow']: # If this permission isn't Allowed, then this method won't work
                    potential = confirmed = False
                    break
                elif perm in checked_perms['Deny'] and perm in checked_perms['Allow']: # Permission is both Denied and Allowed, leave as potential, not confirmed
                    confirmed = False
                elif perm in checked_perms['Allow'] and perm not in checked_perms['Deny']: # It is Allowed and not Denied
                    if not checked_perms['Allow'][perm] == ['*']:
                        confirmed = False
            if confirmed is True:
                print('  CONFIRMED: {}\n'.format(method))
                checked_methods['Confirmed'].append(method)
            elif potential is True:
                print('  POTENTIAL: {}\n'.format(method))
                checknetflixed_methods['Potential'].append(method)
        user['CheckedMethods'] = checked_methods
        if checked_methods['Potential'] == [] and checked_methods['Confirmed'] == []:
            print('  No methods possible.\n')

    now = time.time()
    headers = 'CreateNewPolicyVersion,SetExistingDefaultPolicyVersion,CreateEC2WithExistingIP,CreateAccessKey,' \
              'CreateLoginProfile,UpdateLoginProfile,AttachUserPolicy,AttachGroupPolicy,AttachRolePolicy,' \
              'PutUserPolicy,PutGroupPolicy,PutRolePolicy,AddUserToGroup,UpdateRolePolicyToAssumeIt,' \
              'PassExistingRoleToNewLambdaThenInvoke,PassExistingRoleToNewLambdaThenTriggerWithNewDynamo,' \
              'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo,PassExistingRoleToNewGlueDevEndpoint,' \
              'UpdateExistingGlueDevEndpoint,PassExistingRoleToCloudFormation,PassExistingRoleToNewDataPipeline,' \
              'EditExistingLambdaFunctionWithRole'
    file_name = 'all_user_privesc_scan_results_{}.csv'.format(now)
    file = open(file_name, 'w+')
    for user in users:
        if 'admin' in user['CheckedMethods']:
            file.write(',{} (Admin)'.format(user['UserName']))
        else:
            file.write(',{}'.format(user['UserName']))
    file.write('\n')
    for method in headers.split(','):
        file.write('{},'.format(method))
        for user in users:
            if method in user['CheckedMethods']['Confirmed']:
                file.write('Confirmed,')
            elif method in user['CheckedMethods']['Potential']:
                file.write('Potential,')
            else:
                file.write(',')
        file.write('\n')
    file.close()
    print('Privilege escalation check completed. Results stored to ./all_user_privesc_scan_results_{}.csv'.format(now))


# https://stackoverflow.com/a/24893252
def remove_empty_from_dict(d):
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d


# Pull permissions from each policy document
def parse_attached_policies(client, attached_policies, user):
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyArn'])
        if document is False:
            user['PermissionsConfirmed'] = False
        else:
            user = parse_document(document, user)
    return user


# Get the policy document of an attached policy
def get_attached_policy(client, policy_arn):
    try:
        policy = client.get_policy(
            PolicyArn=policy_arn
        )['Policy']
        version = policy['DefaultVersionId']
        can_get = True
    except Exception as e:
        print('Get policy failed: {}'.format(e))
        return False

    try:
        if can_get is True:
            document = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )['PolicyVersion']['Document']
            return document
    except Exception as e:
        print('Get policy version failed: {}'.format(e))
        return False


# Loop permissions and the resources they apply to
def parse_document(document, user):
    if type(document['Statement']) is dict:
        document['Statement'] = [document['Statement']]
    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and type(statement['Action']) is list: # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][action] = [statement['Resource']]
                    user['Permissions']['Allow'][action] = list(set(user['Permissions']['Allow'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['Action']] = list(set(user['Permissions']['Allow'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action] = [statement['Resource']]
                    user['Permissions']['Deny'][not_action] = list(set(user['Permissions']['Deny'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['NotAction']] = list(set(user['Permissions']['Deny'][statement['NotAction']])) # Remove duplicate resources
        if statement['Effect'] == 'Deny':
            if 'Action' in statement and type(statement['Action']) is list:
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][action] = [statement['Resource']]
                    user['Permissions']['Deny'][action] = list(set(user['Permissions']['Deny'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['Action']] = list(set(user['Permissions']['Deny'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action] = [statement['Resource']]
                    user['Permissions']['Allow'][not_action] = list(set(user['Permissions']['Allow'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['NotAction']] = list(set(user['Permissions']['Allow'][statement['NotAction']])) # Remove duplicate resources
    return user


@click.group()
@click.pass_context
def main(self):
    """
    \b
        ___                _____
      / _ \              /  ___|
     / /_\ \_      _____ \ `--.  ___  ___
    |  _  \ \ /\ / / __| `--. \/ _ \/ __|
    | | | |\ V  V /\__ \/\__/ /  __/ (__
    \_| |_/ \_/\_/ |___/\____/ \___|\___|

    AWWSEC, AWS Security, is a project written for users to check their AWS S3 credentials, and account policies.
    Often times, the biggest security flaw roots back to the user. Not changing the default username and creating a
    strong password will guarantee that your cloud infrastructure is in danger of being compromised. This tool will
    reinforce the basic configuration and security of your AWS S3 infrastructures.

    One feature of this tool is to utilize an open-source project called truffleHog, to perform entropy
    tests on Github repositories to search for exposed AWS keys. If any suspicious strings are found to trigger the
    test, it shall print out the hash of the Git Commit for the user to perform further inspection.

    The second feature of this tool is to pull all users policies that are on an AWS account and enumerate through
    them to detect any weak configurations that are vulnerable to exploits like privilege escalation.  It will create a
    .csv file that can be opened up in Excel or Libre Calc.

    """
    pass


@main.command()
@click.option('--profile', type=str, help='AWS IAM profile name')
@click.option('--accesskey', '-a', type=AwsAccessKey(), hide_input=True,
              help='AWS Access Key ID')
@click.option('--secretkey', '-s', type=AwsSecretAccessKey(), hide_input=True,
              help='AWS Secret Access Key')
@click.option('--sessiontoken', '-t', type=str, default='',
              help='AWS Session Token')
@click.option('--policy', '-p', type=bool, help="Checks your AWS IAM policy configuration")
@click.pass_context
def aws(self, profile, accesskey, secretkey, sessiontoken, policy):
    """Uses a premade profile from the aws configuration file or creates a session based off the access key, the secret
    key, and the session token (optional).
    """
    if profile and not secretkey:
        try:
            session = boto3.Session(profile_name=profile)
        except ClientError as e:
            logging.error("Profile cannot be found")
            quit()
    if policy:
        check_policy(accesskey, secretkey, sessiontoken)
    elif secretkey and accesskey:
        accesskey = click.prompt("Please enter your AWS Access Key", type=AwsAccessKey(),
                                 hide_input=True, default=accesskey)
        secretkey = click.prompt("Please enter your AWS Secret Access Key", hide_input=True,
                                 type=AwsSecretAccessKey(), default=secretkey)
        sessiontoken = click.prompt("Please enter your AWS Session Token", hide_input=True,
                                    type=str, default='')
        results = def_config(accesskey, secretkey, sessiontoken)

    # print(accesskey)
    # print(secretkey)
    # print(profile)
    # results = config(accesskey, secretkey, sessiontoken)
    # print(results)


@main.command()
@click.argument('git_url')
@click.option('--do_regex', '-r', is_flag=True, help='Do custom regex searches while scanning the github repository.')
@click.option('--custom_regex', '-c', type=str, default='{}', help='Provide the custom regex to be applied.')
@click.pass_context
def git(self, git_url, do_regex, custom_regex):
    """
    Uses truffleHog to do an entropy test on github repositories.
    """
    th = truffle(git_url, do_regex, custom_regex)
    print(json.dumps(th))


if __name__ == "__main__":
    main()
