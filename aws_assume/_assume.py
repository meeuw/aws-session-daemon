#!/usr/bin/env python3
import boto3
import os
import fileinput
import ykman.cli.__main__
import io
import time
import contextlib
import sys
import botocore.exceptions
import click

"""
.config/systemd/user/aws_assume@.service

[Unit]
Description=Amazon Web Services token daemon

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u %h/bin/_assume --rolearn='...%i...' --oath_slot=... --serialnumber=... --profile_name='...%i...'
Restart=on-failure

[Install]
WantedBy=default.target
"""

"""
.aws/credentials

[default]
aws_access_key_id = ...
aws_secret_access_key = ...

[...]
aws_access_key_id = ...
aws_secret_access_key = ...
aws_session_token = ...
"""

def ykman_main(*args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        with contextlib.redirect_stdout(stdout):
            try: ykman.cli.__main__.cli.main(args=args)
            except SystemExit: pass
    return stdout.getvalue().splitlines(), stderr.getvalue().splitlines()

@click.command()
@click.option("--rolearn")
@click.option("--oath_slot")
@click.option("--serialnumber")
@click.option("--profile_name")
def main(rolearn, oath_slot, serialnumber, profile_name):
    invalid_token = None
    while 1:
        client = boto3.client('sts')
        while 1:
            stdout, stderr = ykman_main("oath", "code", "-s", oath_slot)
            if len(stdout) == 1:
                token, = stdout
                if token == invalid_token:
                    print("invalid token, wait for new token")
                    time.sleep(1)
                    continue

                try:
                    response = client.assume_role(
                        RoleArn=rolearn,
                        RoleSessionName='assume-py-{}'.format(os.getpid()),
                        DurationSeconds=3600,
                        SerialNumber=serialnumber,
                        TokenCode=token
                    )
                    break

                except botocore.exceptions.ClientError as e:
                    client = boto3.client('sts')
                    invalid_token = token

            time.sleep(1)

        credentials_file = os.path.expanduser("~/.aws/credentials")
        # rotate credentials files
        for i in range(5, 0, -1):
            original = "{}.{}".format(credentials_file, i)
            if os.path.exists(original):
               os.rename(original, "{}.{}".format(credentials_file, i + 1))

        # update credentials file
        updated = {}
        profile = False
        for line in fileinput.input(credentials_file, inplace=True, backup=".1"):
            if profile and line[0] == '[': profile = False
            if line == '[{}]\n'.format(profile_name):
                updated["profile"] = True
                profile = True
            if profile and line.startswith('aws_access_key_id'):
                updated["aws_access_key_id"] = True
                line = 'aws_access_key_id = {}\n'.format(response['Credentials']['AccessKeyId'])
            if profile and line.startswith('aws_secret_access_key'):
                updated["aws_secret_access_key"] = True
                line = 'aws_secret_access_key = {}\n'.format(response['Credentials']['SecretAccessKey'])
            if profile and line.startswith('aws_session_token'):
                updated["aws_session_token"] = True
                line = 'aws_session_token = {}\n'.format(response['Credentials']['SessionToken'])
            print(line, end='')

        if len(updated) == 0:
            print("Profile [{}] not found in ~/.aws/credentials".format(profile_name))
        if len(updated) < 4:
            for k in ["aws_access_key_id", "aws_secret_access_key", "aws_session_token"]:
                if not k in updated:
                    print("{} not found in ~/.aws/credentials profile [{}]".format(k, profile_name))

        time.sleep(60 * 15)

if __name__ == '__main__':
    main()
