import re
import click
from truffleHog import truffleHog
import json


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

# def config(aws_access_key, aws_secret_access_key):


@click.group()
@click.pass_context
def main(self):
    """
    /b
        ___                _____
      / _ \              /  ___|
     / /_\ \_      _____ \ `--.  ___  ___
    |  _  \ \ /\ / / __| `--. \/ _ \/ __|
    | | | |\ V  V /\__ \/\__/ /  __/ (__
    \_| |_/ \_/\_/ |___/\____/ \___|\___|
    /b
    """
    pass


@main.command()
@click.argument('profile')
@click.option('--aws_access_key', '-a', type=AwsAccessKey(), hide_input=True,
              help='AWS Access Key ID to interact with the boto3 api.')
@click.option('--aws_secret_access_key', '-s', type=AwsSecretAccessKey(), hide_input=True,
              help='AWS Secret Access Key to interact with the boto3 api')
@click.pass_context
def aws(self, profile, aws_access_key, aws_secret_access_key):
    """
    Stores AWS configuration values in a file
    """
    if profile and not aws_secret_access_key:
        aws_access_key = click.prompt("Please enter your AWS Access Key", type=AwsAccessKey(),
                                      hide_input=True, default=aws_access_key)
        aws_secret_access_key = click.prompt("Please enter your AWS Secret Access Key", hide_input=True,
                                             type=AwsSecretAccessKey(), default=aws_secret_access_key)
    print(aws_access_key)
    print(aws_secret_access_key)
    print(profile)


@main.command()
@click.argument('git_url')
@click.option('--do_regex', is_flag=True, help='Do custom regex searches while scanning the github repository.')
@click.option('--custom_regex', type=str, default='{}', help='Provide the custom regex to be applied.')
@click.pass_context
def scan(self, git_url, do_regex, custom_regex):
    """
    Uses truffleHog to do an entropy test on github repositories.
    """
    th = truffle(git_url, do_regex, custom_regex)
    print(json.dumps(th))


if __name__ == "__main__":
    main()