from aws_assume import __version__

import aws_assume._assume
from click.testing import CliRunner
import traceback
import pytest
import unittest.mock
import textwrap
import collections
import os

class MyTestException(Exception): pass

def test_version():
    assert __version__ == '0.1.0'

@pytest.fixture
def setup(monkeypatch):
    boto3_client = unittest.mock.MagicMock()
    boto3_client.return_value.assume_role.return_value = {'Credentials': {'AccessKeyId':'123', 'SecretAccessKey': '456', 'SessionToken': '789'}}
    monkeypatch.setattr('boto3.client', boto3_client)
    os_rename = unittest.mock.MagicMock()
    monkeypatch.setattr('os.rename', os_rename)
    fileinput_input = unittest.mock.MagicMock()
    fileinput_input.return_value = iter(textwrap.dedent("""
       [testprofile]
       aws_access_key_id =
       aws_secret_access_key =
       aws_session_token =
    """).splitlines(True))
    monkeypatch.setattr('fileinput.input', fileinput_input)
    result = {
        'assume_role': boto3_client.return_value.assume_role,
        'fileinput_input': fileinput_input,
        'token': "012345",
        'iterations': 0
    }
    def mock_sleep(args):
        mock_sleep.iteration += 1
        if mock_sleep.iteration > result['iterations']: raise MyTestException
    mock_sleep.iteration = 0
    monkeypatch.setattr('time.sleep', mock_sleep)
    def mock_ykman(args):
        if result['token'] is not None:
            print(result['token'])
    monkeypatch.setattr('ykman.cli.__main__.cli.main', mock_ykman)

    return result

def test_happy_flow(setup):
    runner = CliRunner()
    arguments = {
        "rolearn": "abc",
        "oath_slot": "def",
        "serialnumber": "ghi",
        "profile_name": "testprofile"
    }
    result = runner.invoke(
        aws_assume._assume.main,
        list("--" + "=".join(k) for k in arguments.items())
    )
    assert isinstance(result.exception, MyTestException), result.exception
    assert unittest.mock.call(
        DurationSeconds=3600,
        RoleArn=arguments["rolearn"],
        RoleSessionName='assume-py-{}'.format(os.getpid()),
        SerialNumber=arguments["serialnumber"],
        TokenCode=setup["token"]
    ) in setup["assume_role"].mock_calls
    assert result.output == textwrap.dedent("""
        [testprofile]
        aws_access_key_id = {AccessKeyId}
        aws_secret_access_key = {SecretAccessKey}
        aws_session_token = {SessionToken}
    """.format(**setup["assume_role"].return_value["Credentials"]))

def test_no_yubikey(setup):
    setup["token"] = None
    runner = CliRunner()
    arguments = {
        "rolearn": "abc",
        "oath_slot": "def",
        "serialnumber": "ghi",
        "profile_name": "testprofile"
    }
    result = runner.invoke(
        aws_assume._assume.main,
        list("--" + "=".join(k) for k in arguments.items())
    )
    assert isinstance(result.exception, MyTestException), result.exception
    assert setup["assume_role"].mock_calls == []
