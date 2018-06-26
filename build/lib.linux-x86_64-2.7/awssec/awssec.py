import re
import click
from truffleHog import truffleHog
import json
import boto3
import os


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
                                                surpress_output=True, custom_regexes=custom_regex)
    if not do_regex:
        strings_found = truffleHog.find_strings(git_url=git_url, since_commit=None,
                                                max_depth=1000000, printJson=True, do_entropy=True,
                                                surpress_output=True)
    return strings_found


def config(accesskey, secretkey, profile):
    if profile:
        session = boto3.Session(profile_name=profile)
        pass
    if secretkey and accesskey:
        session = boto3.Session(
            aws_access_key_id=accesskey,
            aws_secret_access_key=secretkey,
        )
    return "done"


@click.group()
@click.pass_context
def main(self):
    """AWWSEC, AWS Security, is a project written for users to check their AWS S3 credentials. Often times,
    the biggest security flaw roots back to the user. Not changing the default username and creating a strong password
    will guarantee that your cloud infrastructure is in danger of being compromised. This tool will reinforce the
    basic configuration and security of your AWS S3 infrastructures.

    Another feature of this tool is to utilize an open-source project called truffleHog, to perform entropy
    tests on Github repositories to search for exposed AWS keys. If any suspicious strings are found to trigger the
    test, it shall print out the hash of the Git Commit for the user to perform further inspection.


    \b
        ___                _____
      / _ \              /  ___|
     / /_\ \_      _____ \ `--.  ___  ___
    |  _  \ \ /\ / / __| `--. \/ _ \/ __|
    | | | |\ V  V /\__ \/\__/ /  __/ (__
    \_| |_/ \_/\_/ |___/\____/ \___|\___|



    """
    pass


@main.command()
@click.argument('profile')
@click.option('--accesskey', '-a', type=AwsAccessKey(), hide_input=True,
              help='AWS Access Key ID to interact with the boto3 api.')
@click.option('--secretkey', '-s', type=AwsSecretAccessKey(), hide_input=True,
              help='AWS Secret Access Key to interact with the boto3 api')
@click.option('--configfile', '-c', type=click.Path(), default='~/.aws/credentials',
              help='Use aws_profile from AWS configuration file')
@click.pass_context
def aws(self, profile, accesskey, secretkey, configfile):
    """
    Stores AWS configuration values in a file
    """
    if profile and not secretkey:
        accesskey = click.prompt("Please enter your AWS Access Key", type=AwsAccessKey(),
                                 hide_input=True, default=accesskey)
        secretkey = click.prompt("Please enter your AWS Secret Access Key", hide_input=True,
                                 type=AwsSecretAccessKey(), default=secretkey)

    results = config(accesskey, secretkey, profile)
    print(accesskey)
    print(secretkey)
    print(profile)
    print(results)



@main.command()
@click.argument('git_url')
@click.option('--do_regex', '-r', is_flag=True, help='Do custom regex searches while scanning the github repository.')
@click.option('--custom_regex', '-c', type=str, default='{}', help='Provide the custom regex to be applied.')
@click.pass_context
def scan(self, git_url, do_regex, custom_regex):
    """
    Uses truffleHog to do an entropy test on github repositories.
    """
    th = truffle(git_url, do_regex, custom_regex)
    print(json.dumps(th))


if __name__ == "__main__":
    main()