from truffleHog import truffleHog
import click
import boto3
import os
import base64
import re


class AwsAccesskey(click.ParamType):
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


class AwsSecretAccesskey(click.ParamType):
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


class AwsSec:

    def __init__(self):

        self.ctx.obj = {}

    @click.group()
    @click.option('--aws_access_key', '--access', type=AwsAccesskey(), hide_input=True,
                  help='AWS Access Key ID to interact with the boto3 api.')
    @click.option('--aws_secret_access_key', '--secret', type=AwsSecretAccesskey(), hide_input=True,
                  help='AWS Secret Access Key to interact with the boto3 api')
    @click.option('--git_url', type=GitUrl(), help='The github repository url that is going to be searched')
    @click.option('--do_regex', is_flag=True, help='Do custom regex searches while scanning the github repository.')
    @click.option('--custom_regexes', type=str, default='{}', help='Provide the custom regexes to be applied.')
    @click.pass_context
    def main(self, ctx, git_url, do_regex, custom_regexes, aws_access_key, aws_secret_access_key):
        """
        /b
           ___                _____
          / _ \              /  ___|
         / /_\ \_      _____ \ `--.  ___  ___
        |  _  \ \ /\ / / __| `--. \/ _ \/ __|
        | | | |\ V  V /\__ \/\__/ /  __/ (__
        \_| |_/ \_/\_/ |___/\____/ \___|\___|


        WORK IN PROGRESS: Calls all the functions at the given time, the orchestrator of the program.
        """

        # Stores configuration values for AWS keys.

        ctx.obj = {
            'aws_access_key': aws_access_key,
            'aws_secret_access_key': aws_secret_access_key,
            'git_url': git_url,
            'custom_regexes': custom_regexes,
            'do_regex': do_regex

        }

    @main.command()
    @click.argument('scan_git')
    @click.pass_context
    def scan_git(self, ctx, git_url, do_regex, custom_regexes):
        """ Uses trufflehog to do an entropy test on github repositories."""

        if ctx.obj['do_regex']:
            strings_found = truffleHog.find_strings(git_url=ctx.obj['git_url'], since_commit=None, max_depth=1000000,
                                                    printJson=True, do_regex=True, do_entropy=True,
                                                    surpress_output=True, custom_regexes=ctx.obj['custom_regexes'])
        elif not ctx.obj['do_regex']:
                strings_found = truffleHog.find_strings(git_url=ctx.obj['git_url'], since_commit=None,
                                                        max_depth=1000000, printJson=True, do_entropy=True,
                                                        surpress_output=True)

        return strings_found()

    if __name__ == '__main__':
        main()
