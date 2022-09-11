import datetime
import textwrap
import unittest.mock

import pytest
from click.testing import CliRunner
import freezegun

import aws_session_daemon

UTC = datetime.timezone.utc


class MyTestException(Exception):
    pass


@pytest.fixture
def setup(monkeypatch):
    freezegun.freeze_time("2019-01-01")
    boto3_client = unittest.mock.MagicMock()
    boto3_client.return_value.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "123",
            "SecretAccessKey": "456",
            "SessionToken": "789",
            "Expiration": datetime.datetime(2019, 1, 1, 12, tzinfo=UTC),
        }
    }
    boto3_client.return_value.get_session_token.return_value = {
        "Credentials": {
            "AccessKeyId": "123",
            "SecretAccessKey": "456",
            "SessionToken": "789",
            "Expiration": datetime.datetime(2019, 1, 1, 12, tzinfo=UTC),
        }
    }
    monkeypatch.setattr("boto3.client", boto3_client)
    os_rename = unittest.mock.MagicMock()
    monkeypatch.setattr("os.rename", os_rename)
    fileinput_input = unittest.mock.MagicMock()
    fileinput_input.return_value = iter(
        textwrap.dedent(
            """
            [testprofile]
            aws_access_key_id =
            aws_secret_access_key =
            aws_session_token =
        """
        ).splitlines(True)
    )
    monkeypatch.setattr("fileinput.input", fileinput_input)
    result = {
        "assume_role": boto3_client.return_value.assume_role,
        "get_session_token": boto3_client.return_value.get_session_token,
        "fileinput_input": fileinput_input,
        "token": "012345",
        "iterations": 1,
    }

    def mock_sleep(args):
        raise MyTestException

    mock_sleep.iteration = 0
    monkeypatch.setattr("time.sleep", mock_sleep)

    def mock_ykman(args):
        if result["token"] is not None:
            print(result["token"])

    monkeypatch.setattr("ykman.cli.__main__.cli.main", mock_ykman)

    keyring_get_password = unittest.mock.MagicMock(
        return_value='{"expiration": "2019-01-01T12:10:00+00:00", "access_key_id": "1234", "secret_access_key": "1234", "session_token": "1234"}'
    )
    monkeypatch.setattr("keyring.get_password", keyring_get_password)

    keyring_set_password = unittest.mock.MagicMock()
    monkeypatch.setattr("keyring.set_password", keyring_set_password)

    return result


def test_happy_flow(setup):
    runner = CliRunner()
    arguments = {
        "assume-role-arn": "abc",
        "mfa-oath-slot": "def",
        "mfa-serial-number": "ghi",
        "mfa-session-duration": "300",
        "profile_name": "testprofile",
        "access-key-id": "test-key",
        "secret-access-key": "test-secret",
    }
    result = runner.invoke(
        aws_session_daemon.click_main,
        list("--" + "=".join(k) for k in arguments.items()),
    )
    assert isinstance(result.exception, MyTestException), result.output
    assert setup["get_session_token"].mock_calls == [
        unittest.mock.call(
            DurationSeconds=int(arguments["mfa-session-duration"]),
            SerialNumber=arguments["mfa-serial-number"],
            TokenCode="012345",
        )
    ]
    assert setup["assume_role"].mock_calls == [
        unittest.mock.call(
            RoleArn=arguments["assume-role-arn"],
            RoleSessionName="aws_credential_process",
        )
    ]
    assert result.output == textwrap.dedent(
        """
        [testprofile]
        aws_access_key_id = {AccessKeyId}
        aws_secret_access_key = {SecretAccessKey}
        aws_session_token = {SessionToken}
    """.format(
            **setup["assume_role"].return_value["Credentials"]
        )
    )


def test_no_yubikey(setup):
    setup["token"] = None
    runner = CliRunner()
    arguments = {
        "assume-role-arn": "abc",
        "mfa-oath-slot": "def",
        "mfa-serial-number": "ghi",
        "profile_name": "testprofile",
        "access-key-id": "test-key",
        "secret-access-key": "test-secret",
    }
    result = runner.invoke(
        aws_session_daemon.click_main,
        list("--" + "=".join(k) for k in arguments.items()),
    )
    assert isinstance(result.exception, MyTestException), result.exception
    assert setup["assume_role"].mock_calls == []
