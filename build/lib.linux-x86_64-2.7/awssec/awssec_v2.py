from truffleHog import truffleHog
import click
import boto3
import os
import base64
import re
import json


class AwsAccessKey(click.ParamType):
    # Search for access key IDs: (?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).
    # In English, this regular expression says: Find me 20-character, uppercase, alphanumeric strings that don’t have
    # any uppercase, alphanumeric characters immediately before or after.
    name = 'aws_access_key'

    def convert(self, value, param, ctx):
        found = re.match(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', value)

        if not found:
            self.fail(
                f'{value} is not a AWS Access Key IDs',
                param,
                ctx,
            )

        return value


class AwsSecretAccessKey(click.ParamType):
    # Search for secret access keys: (?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=]).
    # In English, this regular expression says: Find me 40-character, base-64 strings that don’t have any base 64
    # characters immediately before or after.
    name = 'aws_secret_access_key'

    def convert(self, value, param, ctx):
        found = re.match(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', value)

        if not found:
            self.fail(
                f'{value} is not a AWS Secret Access Key IDs',
                param,
                ctx,
            )

        return value


class GitUrl(click.ParamType):
    # Makes sure the user sent a real github url
    name = 'git_url'

    def convert(self, value, param, ctx):
        found = re.match(r'((git|ssh|http(s)?)|(git@[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/)?', value)

        if not found:
            self.fail(
                f'{value} is not a AWS Secret Access Key IDs',
                param,
                ctx,
            )

        return value


@click.group()
@click.option('--aws_access_key', '--access', type=AwsAccessKey(), hide_input=True,
              help='AWS Access Key ID to interact with the boto3 api.')
@click.option('--aws_secret_access_key', '--secret', type=AwsSecretAccessKey(), hide_input=True,
              help='AWS Secret Access Key to interact with the boto3 api')
@click.option('--git_url', type=GitUrl(), help='The github repository url that is going to be searched')
@click.option('--do_regex', is_flag=True, help='Do custom regex searches while scanning the github repository.')
@click.option('--custom_regex', type=str, default='{}', help='Provide the custom regex to be applied.')
@click.option('--config_file', '-c', type=bool, help='Use aws_profile from AWS configuration file')
@click.option('--aws_profile', type=str, help='Create or choose an AWS profile name to use ex. dev_environment')
@click.pass_context
def main(ctx, git_url, do_regex, custom_regex, aws_access_key, aws_secret_access_key, config_file, aws_profile):
    """
    /b

    """
    """
            WORK IN PROGRESS: Calls all the functions at the given time, the orchestrator of the program.
    """
    # Stores configuration values for AWS keys in cfg obj

    if config_file:
        config_file = '~/.aws/credentials'
    if aws_access_key and aws_secret_access_key and not aws_profile:
        aws_profile = 'default'

    ctx.obj = {
        'git_url': git_url,
        'config_file': config_file,
        'do_regex': do_regex,
        'custom_regex': custom_regex,
        'aws_access_key': aws_access_key,
        'aws_secret_access_key': aws_secret_access_key,
        'aws_profile': aws_profile
    }


@main.command()
@click.pass_context
def aws_config(ctx):
    """ Stores AWS configuration values in a file """
    config_file = ctx.obj['config_file']
    aws_profile = ctx.obj['aws_profile']

    aws_access_key = click.prompt("Please enter your AWS Access Key", default=ctx.obj.get('aws_access_key', ''))
    aws_secret_access_key = click.prompt("Please enter your AWS Secret Access Key",
                                         default=ctx.obj.get('aws_secret_access_key', ''))
    # Creates the AWS config file or appends the aws_profile
    if aws_secret_access_key and aws_access_key and aws_profile:
        with open(config_file, 'a') as cfg:
            cfg.write('\n')
            cfg.write('[%s]' % aws_profile)
            cfg.write('aws_access_key_id=%s' % aws_access_key)
            cfg.write('aws_secret_access_key_id=%s' % aws_secret_access_key)
    # Checks to see if the provided aws_profile is created in the file.
    if not aws_secret_access_key and not aws_access_key and aws_profile:
        with open(config_file, 'r') as cfg:
            for x in cfg:
                if x is '[%s]' % aws_profile:
                    continue
                if x is not '[%s]' % aws_profile:
                    logging.error('The aws_profile name provided has not been created yet.')
                    logging.error('Please provide a valid aws_profile or the aws_access_'
                                  'key and aws_secret_access_key')
                break


@main.command()
@click.argument('scan_git')
@click.pass_context
def scan_git(ctx):
    """ Uses truffleHog to do an entropy test on github repositories."""
    do_regex = ctx.obj['do_regex']
    git_url = ctx.obj['git_url']
    custom_regex = ctx.obj['custom_regex']
    strings_found = None

    if do_regex:
        strings_found = truffleHog.find_strings(git_url=git_url, since_commit=None, max_depth=1000000,
                                                printJson=True, do_regex=True, do_entropy=True,
                                                surpress_output=True, custom_regexes=custom_regex)
    if not do_regex:
            strings_found = truffleHog.find_strings(git_url=git_url, since_commit=None,
                                                    max_depth=1000000, printJson=True, do_entropy=True,
                                                    surpress_output=True)
    print(json.dumps(strings_found))


@main.command()
@click.argument('aws_cred')
@click.pass_context
def aws_cred(ctx):
    """ Uses both AWS keys to check for weak S3 bucket credentials"""
    # Sets up the file by either:
    # 1. Creating the credentials file and then using the profile that got created
    # 2. Reads from the credential file a preexisting profile that was made by user
    # One variable I need is the name of the profile, that is either seeing if a preexisting profile is made
    # If not, then it will use the name to create the profile name, if name not provided then it will
    # Append to a default profile name of awssec_0, awssec_1 etc...

    print(ctx.obj['aws_profile'])


if __name__ == '__main__':
    main()
