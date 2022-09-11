#!/usr/bin/env python3
import os
import fileinput
import sys
import click
import aws_credential_process
import time
import configparser
import toml

"""
.config/systemd/user/aws-session-daemon@.service

[Unit]
Description=Amazon Web Services token daemon

[Service]
Type=simple
ExecStart=%h/bin/aws-session-daemon --config-section='%i'
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


def traverse_config(config, accumulated, flattened):
    for k, v in config.items():
        if isinstance(v, list):
            for i in v:
                accumulated_copy = accumulated.copy()
                flattened[k] = traverse_config(i, accumulated_copy, flattened)
        else:
            accumulated[k] = v

    return accumulated


class NoYubiKeyException(Exception):
    pass


def main(
    assume_role_arn,
    assume_role_source_identity,
    mfa_oath_slot,
    mfa_serial_number,
    profile_name,
    access_key_id,
    secret_access_key,
    mfa_session_duration,
    credentials_section,
    assume_session_duration,
):
    """
    aws session daemon
    """
    if not access_key_id:
        access_key_id, secret_access_key = aws_credential_process.get_credentials(
            credentials_section
        )

    if access_key_id is None:
        click.echo(
            "Missing access_key_id, please use --access-key-id or add to ~/.aws/credentials"
        )
        sys.exit(1)
    if secret_access_key is None:
        click.echo(
            "Missing secret_access_key, please use --secret-access-key or add to ~/.aws/credentials"
        )
        sys.exit(1)

    access_key = aws_credential_process.AWSCred(access_key_id, secret_access_key)

    def token_code():
        stdout, _ = aws_credential_process.ykman_main(
            "oath", "accounts", "code", "-s", mfa_oath_slot
        )

        if len(stdout) == 1:
            (token_code,) = stdout
            return token_code

        raise NoYubiKeyException()

    if mfa_session_duration == 0:
        mfa_session_request = (
            access_key,
            mfa_session_duration,
        )
    else:
        mfa_session_request = (
            access_key,
            mfa_session_duration,
            mfa_serial_number,
            token_code,
        )

    while 1:
        mfa_session = None

        if assume_role_arn:
            if mfa_session_duration != 0:
                for tri in range(300):
                    if tri > 0:
                        time.sleep(1)
                    try:
                        mfa_session = aws_credential_process.get_mfa_session_cached(
                            *mfa_session_request
                        )
                        break
                    except NoYubiKeyException:
                        pass

            if mfa_session_duration == 0:
                session = aws_credential_process.get_assume_session(
                    access_key,
                    mfa_session,
                    assume_role_arn,
                    None,
                    None,
                    assume_role_source_identity,
                    assume_session_duration,
                    mfa_serial_number,
                    token_code,
                )
            else:
                session = aws_credential_process.get_assume_session(
                    access_key,
                    mfa_session,
                    assume_role_arn,
                    None,
                    None,
                    assume_role_source_identity,
                    assume_session_duration,
                )
        else:
            if mfa_session_duration == 0:
                print("Cannot do MFA without session")
                sys.exit(1)

            session = aws_credential_process.get_mfa_session(*mfa_session_request)

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
            if profile and line[0] == "[":
                profile = False
            if line == "[{}]\n".format(profile_name):
                updated["profile"] = True
                profile = True
            if profile and line.startswith("aws_access_key_id"):
                updated["aws_access_key_id"] = True
                line = "aws_access_key_id = {}\n".format(session.awscred.access_key_id)
            if profile and line.startswith("aws_secret_access_key"):
                updated["aws_secret_access_key"] = True
                line = "aws_secret_access_key = {}\n".format(
                    session.awscred.secret_access_key
                )
            if profile and line.startswith("aws_session_token"):
                updated["aws_session_token"] = True
                line = "aws_session_token = {}\n".format(session.session_token)
            print(line, end="")

        if len(updated) == 0:
            print("Profile [{}] not found in ~/.aws/credentials".format(profile_name))
        if len(updated) < 4:
            for k in [
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
            ]:
                if not k in updated:
                    print(
                        "{} not found in ~/.aws/credentials profile [{}]".format(
                            k, profile_name
                        )
                    )

        time.sleep(60 * 15)


@click.command()
@click.option("--config-section", required=True)
@click.option("--key", required=True)
def get_config(config_section, key):
    with open(os.path.expanduser("~/.config/aws-session-daemon/config.toml")) as f:
        parsed_config = aws_credential_process.parse_config(toml.load(f))
    if config_section in parsed_config:
        if key in parsed_config[config_section]:
            click.echo(parsed_config[config_section][key])


@click.command()
@click.option("--assume-session-duration", type=int)
@click.option("--assume-role-arn")
@click.option("--assume-role-source-identity")
@click.option("--mfa-oath-slot")
@click.option("--mfa-serial-number")
@click.option("--profile_name")
@click.option("--access-key-id")
@click.option("--secret-access-key")
@click.option("--mfa-session-duration", type=int)
@click.option("--credentials-section")
@click.option("--config-section")
def click_main(
    assume_session_duration,
    assume_role_arn,
    assume_role_source_identity,
    mfa_oath_slot,
    mfa_serial_number,
    profile_name,
    access_key_id,
    secret_access_key,
    mfa_session_duration,
    credentials_section,
    config_section,
):
    """
    aws session daemon
    """
    config = {}
    with open(os.path.expanduser("~/.config/aws-credential-process/config.toml")) as f:
        parsed_config = aws_credential_process.parse_config(toml.load(f))
    if config_section:
        if config_section in parsed_config:
            config = parsed_config[config_section]
        else:
            click.echo("Config section {config_section} not found", err=True)
            sys.exit(1)

    if profile_name:
        config["profile_name"] = profile_name
    if access_key_id:
        config["access_key_id"] = access_key_id
    if mfa_serial_number:
        config["mfa_serial_number"] = mfa_serial_number
    if mfa_oath_slot:
        config["mfa_oath_slot"] = mfa_oath_slot
    if mfa_session_duration is not None:
        config["mfa_session_duration"] = mfa_session_duration
    if secret_access_key:
        config["secret_access_key"] = secret_access_key
    if assume_session_duration:
        config["assume_session_duration"] = assume_session_duration
    if assume_role_arn:
        config["assume_role_arn"] = assume_role_arn
    if credentials_section:
        config["credentials_section"] = credentials_section
    if assume_role_source_identity:
        config["assume_role_source_identity"] = assume_role_source_identity

    main(
        config.get("assume_role_arn"),
        config.get("assume_role_source_identity"),
        config.get("mfa_oath_slot"),
        config.get("mfa_serial_number"),
        config.get("profile_name"),
        config.get("access_key_id"),
        config.get("secret_access_key"),
        config.get("mfa_session_duration"),
        config.get("credentials_section", "default"),
        config.get("assume_session_duration"),
    )
